//! Proxy session — links a server transaction to its client transaction(s).
//!
//! When the proxy receives a request (creating a server transaction) and relays
//! it downstream (creating one or more client transactions), a [`ProxySession`]
//! ties them together. This replaces the manual `PendingBranch` / `retransmit_map`
//! approach with proper transaction-layer state.
//!
//! The [`ProxySessionStore`] provides concurrent lookup by both client key
//! (for response routing) and server key (for CANCEL propagation).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use pyo3::prelude::*;

use crate::proxy::fork::ForkAggregator;
use crate::sip::message::SipMessage;
use crate::transaction::key::TransactionKey;
use crate::transport::{ConnectionId, Transport};

// ---------------------------------------------------------------------------
// ClientBranch — per-fork-branch downstream info
// ---------------------------------------------------------------------------

/// Downstream destination info for a single client transaction branch.
#[derive(Debug, Clone)]
pub struct ClientBranch {
    /// Where the relayed request was sent.
    pub destination: SocketAddr,
    /// Transport used for the downstream leg.
    pub transport: Transport,
    /// Connection ID for the downstream leg.
    pub connection_id: ConnectionId,
}

// ---------------------------------------------------------------------------
// ProxySession
// ---------------------------------------------------------------------------

/// A proxy session linking an inbound (server) transaction to one or more
/// outbound (client) transactions.
#[derive(Debug, Clone)]
pub struct ProxySession {
    /// Server transaction key (from the inbound request's Via branch + method).
    pub server_key: TransactionKey,
    /// Client transaction key(s) — one per fork branch.
    pub client_keys: Vec<TransactionKey>,
    /// Where to send responses back to the UAC.
    pub source_addr: SocketAddr,
    /// Connection ID for the original inbound transport.
    pub connection_id: ConnectionId,
    /// Transport type for the original inbound connection.
    pub transport: Transport,
    /// The original inbound request (for ACK generation, CANCEL, response building).
    pub original_request: SipMessage,
    /// Per-client-branch downstream destination info (for CANCEL forwarding).
    pub client_branches: HashMap<TransactionKey, ClientBranch>,
    /// Fork aggregator for multi-target forking (None for single-target relay).
    pub fork_aggregator: Option<Arc<Mutex<ForkAggregator>>>,
    /// Maps client transaction key → branch index in the ForkAggregator.
    pub branch_index_map: HashMap<TransactionKey, usize>,
    /// Whether `record_route()` was called by the script.
    pub record_routed: bool,
    /// When this session was created (for TTL-based cleanup).
    pub created_at: Instant,
    /// Per-relay on_reply Python callback (called with `(request, reply)`).
    pub on_reply_callback: Option<Py<PyAny>>,
    /// Per-relay on_failure Python callback (called with `(request, code, reason)`).
    pub on_failure_callback: Option<Py<PyAny>>,
}

impl ProxySession {
    /// Create a new session with no client keys yet.
    pub fn new(
        server_key: TransactionKey,
        source_addr: SocketAddr,
        connection_id: ConnectionId,
        transport: Transport,
        original_request: SipMessage,
        record_routed: bool,
    ) -> Self {
        Self {
            server_key,
            client_keys: Vec::new(),
            client_branches: HashMap::new(),
            fork_aggregator: None,
            branch_index_map: HashMap::new(),
            source_addr,
            connection_id,
            transport,
            original_request,
            record_routed,
            created_at: Instant::now(),
            on_reply_callback: None,
            on_failure_callback: None,
        }
    }

    /// Add a client transaction key (one per relay/fork branch).
    pub fn add_client_key(&mut self, key: TransactionKey) {
        self.client_keys.push(key);
    }

    /// Register downstream destination info for a client branch.
    pub fn set_client_branch(&mut self, key: TransactionKey, branch: ClientBranch) {
        self.client_branches.insert(key, branch);
    }

    /// Get downstream destination info for a client branch.
    pub fn get_client_branch(&self, key: &TransactionKey) -> Option<&ClientBranch> {
        self.client_branches.get(key)
    }
}

// ---------------------------------------------------------------------------
// ProxySessionStore
// ---------------------------------------------------------------------------

/// Concurrent store for proxy sessions with three lookup indices.
///
/// - **Primary index**: client transaction key → session (for response routing).
/// - **Reverse index**: server transaction key → list of client keys (for CANCEL).
/// - **Call-ID index**: SIP Call-ID → session (for ACK-2xx routing).
#[derive(Debug)]
pub struct ProxySessionStore {
    /// client_key → session.
    by_client_key: DashMap<TransactionKey, Arc<RwLock<ProxySession>>>,
    /// server_key → list of client keys.
    server_to_clients: DashMap<TransactionKey, Vec<TransactionKey>>,
    /// SIP Call-ID → session (for ACK-2xx end-to-end routing).
    by_call_id: DashMap<String, Arc<RwLock<ProxySession>>>,
}

impl ProxySessionStore {
    pub fn new() -> Self {
        Self {
            by_client_key: DashMap::new(),
            server_to_clients: DashMap::new(),
            by_call_id: DashMap::new(),
        }
    }

    /// Insert a session, indexing it by all its client keys, server key, and Call-ID.
    pub fn insert(&self, session: ProxySession) {
        let server_key = session.server_key.clone();
        let client_keys: Vec<TransactionKey> = session.client_keys.clone();
        let call_id = session.original_request.headers.get("Call-ID").map(|s| s.to_string());
        let session_arc = Arc::new(RwLock::new(session));

        for client_key in &client_keys {
            self.by_client_key
                .insert(client_key.clone(), Arc::clone(&session_arc));
        }

        if let Some(call_id) = call_id {
            self.by_call_id.insert(call_id, Arc::clone(&session_arc));
        }

        self.server_to_clients
            .entry(server_key)
            .and_modify(|existing| {
                for key in &client_keys {
                    if !existing.contains(key) {
                        existing.push(key.clone());
                    }
                }
            })
            .or_insert(client_keys);
    }

    /// Add a client key to an existing session (for fork branches added after initial insert).
    pub fn add_client_key(
        &self,
        server_key: &TransactionKey,
        client_key: TransactionKey,
    ) -> bool {
        // Find the session via any existing client key for this server
        let session_arc = match self.server_to_clients.get(server_key) {
            Some(keys) => {
                if let Some(first) = keys.first() {
                    self.by_client_key.get(first).map(|e| Arc::clone(e.value()))
                } else {
                    None
                }
            }
            None => None,
        };

        let session_arc = match session_arc {
            Some(arc) => arc,
            None => return false,
        };

        // Update session
        if let Ok(mut session) = session_arc.write() {
            session.add_client_key(client_key.clone());
        }

        // Update indices
        self.by_client_key
            .insert(client_key.clone(), session_arc);
        self.server_to_clients
            .entry(server_key.clone())
            .and_modify(|keys| {
                if !keys.contains(&client_key) {
                    keys.push(client_key.clone());
                }
            })
            .or_insert_with(|| vec![client_key]);

        true
    }

    /// Look up a session by client transaction key.
    pub fn get_by_client_key(
        &self,
        client_key: &TransactionKey,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        self.by_client_key
            .get(client_key)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a session by its server transaction key.
    ///
    /// Returns the session via the first client key registered for this server key.
    pub fn get_by_server_key(
        &self,
        server_key: &TransactionKey,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        let client_keys = self.server_to_clients.get(server_key)?;
        let first_client_key = client_keys.first()?;
        self.by_client_key
            .get(first_client_key)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a session by SIP Call-ID (for ACK-2xx end-to-end routing).
    pub fn get_by_call_id(
        &self,
        call_id: &str,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        self.by_call_id
            .get(call_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Get all client keys for a given server transaction key.
    pub fn get_client_keys_for_server(
        &self,
        server_key: &TransactionKey,
    ) -> Option<Vec<TransactionKey>> {
        self.server_to_clients
            .get(server_key)
            .map(|entry| entry.value().clone())
    }

    /// Remove a session by its server key, cleaning up all indices.
    pub fn remove_by_server_key(&self, server_key: &TransactionKey) {
        if let Some((_, client_keys)) = self.server_to_clients.remove(server_key) {
            // Remove Call-ID index entry via the session's original request
            if let Some(first) = client_keys.first() {
                if let Some(session_ref) = self.by_client_key.get(first) {
                    if let Ok(session) = session_ref.value().read() {
                        if let Some(call_id) = session.original_request.headers.get("Call-ID") {
                            self.by_call_id.remove(call_id);
                        }
                    }
                }
            }
            for client_key in &client_keys {
                self.by_client_key.remove(client_key);
            }
        }
    }

    /// Remove a single client key from the store.
    ///
    /// If the session has no remaining client keys, removes the session entirely.
    /// Returns `true` if a session was found and the key removed.
    pub fn remove_client_key(&self, client_key: &TransactionKey) -> bool {
        let session_arc = match self.by_client_key.remove(client_key) {
            Some((_, arc)) => arc,
            None => return false,
        };

        let server_key = {
            let session = session_arc.read().unwrap();
            session.server_key.clone()
        };

        // Update reverse index
        let mut should_remove_server = false;
        self.server_to_clients.entry(server_key.clone()).and_modify(|keys| {
            keys.retain(|key| key != client_key);
            if keys.is_empty() {
                should_remove_server = true;
            }
        });

        if should_remove_server {
            self.server_to_clients.remove(&server_key);
        }

        true
    }

    /// Sweep sessions older than `ttl`, returning the number removed.
    pub fn sweep_stale(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut stale_server_keys = Vec::new();

        // Find stale sessions by checking any client key's session
        for entry in self.by_client_key.iter() {
            if let Ok(session) = entry.value().read() {
                if now.duration_since(session.created_at) > ttl {
                    let server_key = session.server_key.clone();
                    if !stale_server_keys.contains(&server_key) {
                        stale_server_keys.push(server_key);
                    }
                }
            }
        }

        let count = stale_server_keys.len();
        for server_key in &stale_server_keys {
            self.remove_by_server_key(server_key);
        }
        count
    }

    /// Number of sessions (counted by unique server keys).
    pub fn session_count(&self) -> usize {
        self.server_to_clients.len()
    }

    /// Number of client key entries.
    pub fn client_key_count(&self) -> usize {
        self.by_client_key.len()
    }
}

impl Default for ProxySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn dummy_request() -> SipMessage {
        SipMessageBuilder::new()
            .request(Method::Options, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("session-test".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn server_key() -> TransactionKey {
        TransactionKey::new("z9hG4bK-srv".to_string(), Method::Options, "10.0.0.1:5060".to_string())
    }

    fn client_key(suffix: &str) -> TransactionKey {
        TransactionKey::new(format!("z9hG4bK-cli-{suffix}"), Method::Options, "10.0.0.1:5060".to_string())
    }

    fn source_addr() -> SocketAddr {
        "10.0.0.1:5060".parse().unwrap()
    }

    fn make_session() -> ProxySession {
        let mut session = ProxySession::new(
            server_key(),
            source_addr(),
            ConnectionId::default(),
            Transport::Udp,
            dummy_request(),
            false,
        );
        session.add_client_key(client_key("1"));
        session
    }

    // -- ProxySession tests --

    #[test]
    fn session_construction() {
        let session = make_session();
        assert_eq!(session.server_key, server_key());
        assert_eq!(session.client_keys.len(), 1);
        assert_eq!(session.source_addr, source_addr());
        assert!(!session.record_routed);
    }

    #[test]
    fn session_add_client_keys() {
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        session.add_client_key(client_key("3"));
        assert_eq!(session.client_keys.len(), 3);
    }

    // -- ProxySessionStore tests --

    #[test]
    fn store_insert_and_lookup_by_client_key() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let found = store.get_by_client_key(&client_key("1"));
        assert!(found.is_some());
        let session_arc = found.unwrap();
        let session = session_arc.read().unwrap();
        assert_eq!(session.server_key, server_key());
    }

    #[test]
    fn store_lookup_unknown_key_returns_none() {
        let store = ProxySessionStore::new();
        assert!(store.get_by_client_key(&client_key("unknown")).is_none());
    }

    #[test]
    fn store_server_to_client_lookup() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let client_keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(client_keys.len(), 1);
        assert_eq!(client_keys[0], client_key("1"));
    }

    #[test]
    fn store_multiple_client_keys() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        // Both client keys should find the same session
        let session1 = store.get_by_client_key(&client_key("1")).unwrap();
        let session2 = store.get_by_client_key(&client_key("2")).unwrap();
        assert!(Arc::ptr_eq(&session1, &session2));

        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn store_add_client_key_after_insert() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let added = store.add_client_key(&server_key(), client_key("2"));
        assert!(added);

        // New key should find the session
        let found = store.get_by_client_key(&client_key("2"));
        assert!(found.is_some());

        // Server-to-clients should have both keys
        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 2);

        // Session object should have both keys
        let session = store.get_by_client_key(&client_key("1")).unwrap();
        let session = session.read().unwrap();
        assert_eq!(session.client_keys.len(), 2);
    }

    #[test]
    fn store_add_client_key_unknown_server_returns_false() {
        let store = ProxySessionStore::new();
        let unknown = TransactionKey::new("z9hG4bK-nope".to_string(), Method::Options, "10.0.0.1:5060".to_string());
        assert!(!store.add_client_key(&unknown, client_key("x")));
    }

    #[test]
    fn store_remove_by_server_key() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        store.remove_by_server_key(&server_key());

        assert!(store.get_by_client_key(&client_key("1")).is_none());
        assert!(store.get_by_client_key(&client_key("2")).is_none());
        assert!(store.get_client_keys_for_server(&server_key()).is_none());
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
    }

    #[test]
    fn store_remove_client_key() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        let removed = store.remove_client_key(&client_key("1"));
        assert!(removed);

        // Client key 1 should be gone, client key 2 should remain
        assert!(store.get_by_client_key(&client_key("1")).is_none());
        assert!(store.get_by_client_key(&client_key("2")).is_some());
        assert_eq!(store.client_key_count(), 1);

        // Server-to-clients should only have key 2
        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], client_key("2"));
    }

    #[test]
    fn store_remove_last_client_key_removes_session() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        store.remove_client_key(&client_key("1"));

        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
        assert!(store.get_client_keys_for_server(&server_key()).is_none());
    }

    #[test]
    fn store_remove_unknown_client_key_returns_false() {
        let store = ProxySessionStore::new();
        assert!(!store.remove_client_key(&client_key("unknown")));
    }

    #[test]
    fn store_sweep_stale() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        // With a zero TTL, everything is stale
        let swept = store.sweep_stale(std::time::Duration::ZERO);
        assert_eq!(swept, 1);
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
    }

    #[test]
    fn store_sweep_preserves_fresh() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        // With a large TTL, nothing is stale
        let swept = store.sweep_stale(std::time::Duration::from_secs(3600));
        assert_eq!(swept, 0);
        assert_eq!(store.session_count(), 1);
    }

    #[test]
    fn store_session_and_client_key_counts() {
        let store = ProxySessionStore::new();
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);

        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        assert_eq!(store.session_count(), 1);
        assert_eq!(store.client_key_count(), 2);
    }

    #[test]
    fn store_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ProxySessionStore::new());
        let mut handles = Vec::new();

        // Spawn threads that each insert a session
        for index in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let server = TransactionKey::new(
                    format!("z9hG4bK-srv-{index}"),
                    Method::Options,
                    "10.0.0.1:5060".to_string(),
                );
                let client = TransactionKey::new(
                    format!("z9hG4bK-cli-{index}"),
                    Method::Options,
                    "10.0.0.1:5060".to_string(),
                );
                let mut session = ProxySession::new(
                    server,
                    source_addr(),
                    ConnectionId::default(),
                    Transport::Udp,
                    dummy_request(),
                    false,
                );
                session.add_client_key(client);
                store.insert(session);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.session_count(), 10);
        assert_eq!(store.client_key_count(), 10);
    }

    // -- get_by_server_key tests --

    #[test]
    fn store_get_by_server_key() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let found = store.get_by_server_key(&server_key());
        assert!(found.is_some());
        let session_arc = found.unwrap();
        let session = session_arc.read().unwrap();
        assert_eq!(session.server_key, server_key());
        assert_eq!(session.client_keys.len(), 1);
    }

    #[test]
    fn store_get_by_server_key_unknown_returns_none() {
        let store = ProxySessionStore::new();
        let unknown = TransactionKey::new("z9hG4bK-nope".to_string(), Method::Options, "10.0.0.1:5060".to_string());
        assert!(store.get_by_server_key(&unknown).is_none());
    }

    // -- ClientBranch tests --

    #[test]
    fn session_client_branch_set_and_get() {
        let mut session = make_session();
        let key = client_key("1");
        session.set_client_branch(key.clone(), ClientBranch {
            destination: "10.0.0.2:5060".parse().unwrap(),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
        });

        let branch = session.get_client_branch(&key);
        assert!(branch.is_some());
        assert_eq!(branch.unwrap().destination, "10.0.0.2:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn session_client_branch_unknown_returns_none() {
        let session = make_session();
        assert!(session.get_client_branch(&client_key("unknown")).is_none());
    }

    // -- Fork aggregator integration tests --

    #[test]
    fn session_with_fork_aggregator() {
        use crate::proxy::fork::{ForkAggregator, ForkStrategy};
        use crate::sip::uri::SipUri;

        let mut session = ProxySession::new(
            server_key(),
            source_addr(),
            ConnectionId::default(),
            Transport::Udp,
            dummy_request(),
            false,
        );

        let targets = vec![
            SipUri::new("target1.example.com".to_string()),
            SipUri::new("target2.example.com".to_string()),
        ];
        let aggregator = Arc::new(Mutex::new(
            ForkAggregator::new(targets, ForkStrategy::Parallel),
        ));
        session.fork_aggregator = Some(Arc::clone(&aggregator));

        // Add two client branches with index mapping
        let key1 = client_key("1");
        let key2 = client_key("2");
        session.add_client_key(key1.clone());
        session.add_client_key(key2.clone());
        session.branch_index_map.insert(key1, 0);
        session.branch_index_map.insert(key2, 1);

        assert!(session.fork_aggregator.is_some());
        assert_eq!(session.branch_index_map.len(), 2);
        let agg = aggregator.lock().unwrap();
        assert_eq!(agg.branch_count(), 2);
    }

    #[test]
    fn session_without_fork_aggregator() {
        let session = make_session();
        assert!(session.fork_aggregator.is_none());
        assert!(session.branch_index_map.is_empty());
    }
}
