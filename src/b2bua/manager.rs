//! B2BUA call manager — tracks active calls and bridges A/B legs.
//!
//! Each call has an A-leg (inbound INVITE) and one or more B-legs (outbound
//! INVITEs). The manager correlates responses from B-legs back to the A-leg
//! and fires Python script events.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;

use crate::b2bua::transfer::TransferContext;
use crate::sip::message::SipMessage;
use crate::transport::{ConnectionId, Transport};

/// Tracks the negotiated session timer state for a call (RFC 4028).
#[derive(Debug, Clone)]
pub struct SessionTimerState {
    /// Negotiated Session-Expires value in seconds.
    pub session_expires: u32,
    /// Who is refreshing: "uac" or "uas" (RFC 4028).
    pub refresher: String,
    /// When the timer was last reset (on 200 OK or successful refresh).
    pub last_refresh: std::time::Instant,
}

/// State of a B2BUA call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// A-leg INVITE received, waiting for script to dial/fork.
    Calling,
    /// B-leg(s) ringing.
    Ringing,
    /// B-leg answered, call connected.
    Answered,
    /// Call terminated (BYE received or sent).
    Terminated,
}

/// Tracks the A-leg (inbound) side of a B2BUA call.
#[derive(Debug, Clone)]
pub struct ALeg {
    /// Source address of the A-leg caller.
    pub source_addr: SocketAddr,
    /// Connection ID for the A-leg transport.
    pub connection_id: ConnectionId,
    /// Transport type for the A-leg.
    pub transport: Transport,
    /// Via branch from the A-leg INVITE.
    pub branch: String,
    /// Call-ID from the A-leg.
    pub call_id: String,
    /// From-tag from the A-leg.
    pub from_tag: String,
}

/// Tracks a B-leg (outbound) side of a B2BUA call.
#[derive(Debug, Clone)]
pub struct BLeg {
    /// Destination address for this B-leg.
    pub destination: SocketAddr,
    /// Transport type.
    pub transport: Transport,
    /// Our generated branch for this B-leg.
    pub branch: String,
    /// Target URI (or "reinvite:a2b"/"reinvite:b2a" for re-INVITE tracking).
    pub target_uri: String,
    /// B-leg Call-ID (generated fresh to decouple from A-leg dialog).
    pub call_id: String,
    /// Our From-tag for this B-leg (always unique per leg).
    pub from_tag: String,
    /// Stored Via headers from the re-INVITE originator (for response routing).
    #[allow(dead_code)]
    pub stored_vias: Vec<String>,
}

/// A complete B2BUA call — A-leg + B-leg(s).
#[derive(Debug)]
pub struct Call {
    /// Unique call identifier (UUID).
    pub id: String,
    /// Current state.
    pub state: CallState,
    /// The inbound (A) leg.
    pub a_leg: ALeg,
    /// The outbound (B) leg(s).
    pub b_legs: Vec<BLeg>,
    /// Index of the winning B-leg (after answer).
    pub winner: Option<usize>,
    /// When the call was created.
    pub created_at: std::time::Instant,
    /// Original A-leg INVITE message (stored for reconstructing PyCall in
    /// on_answer/on_failure/on_bye handlers).
    pub a_leg_invite: Option<Arc<Mutex<SipMessage>>>,
    /// RFC 4028 session timer state (set after 200 OK negotiation).
    pub session_timer: Option<SessionTimerState>,
    /// Per-call session timer override from Python script.
    pub session_timer_override: Option<crate::script::api::call::SessionTimerOverride>,
    /// Active transfer context (set when REFER is received, cleared on completion).
    pub transfer: Option<TransferContext>,
    /// Outbound digest credentials for B-leg 401/407 retry (set by script via call.set_credentials).
    pub outbound_credentials: Option<(String, String)>,
    /// SIPREC recording session URI (set by script via call.record).
    pub recording_srs: Option<String>,
    /// When true, copy the A-leg Call-ID to B-leg instead of generating a new one.
    /// From-tag is always regenerated regardless of this flag.
    pub preserve_call_id: bool,
}

/// Generate a fresh Call-ID for a B-leg dialog.
pub fn generate_b_leg_call_id() -> String {
    format!("b2b-{}", uuid::Uuid::new_v4())
}

/// Generate a fresh From-tag for a B-leg dialog.
pub fn generate_b_leg_from_tag() -> String {
    format!("sb-{}", &uuid::Uuid::new_v4().as_simple().to_string()[..12])
}

/// Rewrite dialog headers (Call-ID + From/To tags) when bridging between legs.
///
/// Replaces the Call-ID and swaps occurrences of `old_tag` → `new_tag` in
/// From and To headers. This handles both directions:
/// - B→A: swap B-leg identifiers to A-leg identifiers
/// - A→B: swap A-leg identifiers to B-leg identifiers
pub fn rewrite_dialog_headers(
    message: &mut SipMessage,
    new_call_id: &str,
    old_tag: &str,
    new_tag: &str,
) {
    message.headers.set("Call-ID", new_call_id.to_string());

    let old_pattern = format!("tag={}", old_tag);
    let new_pattern = format!("tag={}", new_tag);

    if let Some(from) = message.headers.get("From").or_else(|| message.headers.get("f")) {
        if from.contains(&old_pattern) {
            let new_from = from.replace(&old_pattern, &new_pattern);
            message.headers.set("From", new_from);
        }
    }
    if let Some(to) = message.headers.get("To").or_else(|| message.headers.get("t")) {
        if to.contains(&old_pattern) {
            let new_to = to.replace(&old_pattern, &new_pattern);
            message.headers.set("To", new_to);
        }
    }
}

/// Manages all active B2BUA calls.
#[derive(Debug)]
pub struct CallManager {
    /// call_id → Call
    calls: DashMap<String, Call>,
    /// b_leg_branch → call_id (for routing B-leg responses back to calls)
    branch_to_call: DashMap<String, String>,
}

impl CallManager {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            branch_to_call: DashMap::new(),
        }
    }

    /// Number of active calls.
    pub fn count(&self) -> usize {
        self.calls.len()
    }

    /// Create a new call for an inbound INVITE.
    pub fn create_call(&self, a_leg: ALeg) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let call = Call {
            id: id.clone(),
            state: CallState::Calling,
            a_leg,
            b_legs: Vec::new(),
            winner: None,
            created_at: std::time::Instant::now(),
            a_leg_invite: None,
            session_timer: None,
            session_timer_override: None,
            transfer: None,
            outbound_credentials: None,
            recording_srs: None,
            preserve_call_id: false,
        };
        self.calls.insert(id.clone(), call);
        id
    }

    /// Add a B-leg to an existing call and register its branch for response routing.
    pub fn add_b_leg(&self, call_id: &str, b_leg: BLeg) -> bool {
        let branch = b_leg.branch.clone();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.b_legs.push(b_leg);
            self.branch_to_call.insert(branch, call_id.to_string());
            true
        } else {
            false
        }
    }

    /// Remove a B-leg entry by index (e.g. after re-INVITE completion).
    pub fn remove_b_leg(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if index < call.b_legs.len() {
                let removed = call.b_legs.remove(index);
                self.branch_to_call.remove(&removed.branch);
            }
        }
    }

    /// Look up which call a B-leg branch belongs to.
    pub fn call_id_for_branch(&self, branch: &str) -> Option<String> {
        self.branch_to_call.get(branch).map(|v| v.clone())
    }

    /// Get a call by ID.
    pub fn get_call(&self, call_id: &str) -> Option<dashmap::mapref::one::Ref<'_, String, Call>> {
        self.calls.get(call_id)
    }

    /// Get a mutable reference to a call by ID.
    pub fn get_call_mut(&self, call_id: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, Call>> {
        self.calls.get_mut(call_id)
    }

    /// Update call state.
    pub fn set_state(&self, call_id: &str, state: CallState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.state = state;
        }
    }

    /// Set the winning B-leg.
    pub fn set_winner(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.winner = Some(index);
            call.state = CallState::Answered;
        }
    }

    /// Remove a call (on termination).
    pub fn remove_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            for b_leg in &call.b_legs {
                self.branch_to_call.remove(&b_leg.branch);
            }
        }
    }

    /// Store the original A-leg INVITE message on the call.
    pub fn set_a_leg_invite(&self, call_id: &str, message: Arc<Mutex<SipMessage>>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.a_leg_invite = Some(message);
        }
    }

    /// Set the session timer state on a call (after 200 OK negotiation).
    pub fn set_session_timer(&self, call_id: &str, timer_state: SessionTimerState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.session_timer = Some(timer_state);
        }
    }

    /// Reset the session timer's last_refresh timestamp (after successful refresh).
    pub fn reset_session_timer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(ref mut timer) = call.session_timer {
                timer.last_refresh = std::time::Instant::now();
            }
        }
    }

    /// Iterate over all active calls (for session timer sweep).
    pub fn iter_calls(&self) -> dashmap::iter::Iter<'_, String, Call> {
        self.calls.iter()
    }

    /// Find call ID by SIP Call-ID header (searches both A-leg and B-leg Call-IDs).
    pub fn find_by_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        for entry in self.calls.iter() {
            if entry.a_leg.call_id == sip_call_id {
                return Some(entry.id.clone());
            }
            for b_leg in &entry.b_legs {
                if b_leg.call_id == sip_call_id {
                    return Some(entry.id.clone());
                }
            }
        }
        None
    }

    /// Find a call matching a Replaces header (for attended transfer).
    ///
    /// Searches all active calls for one whose A-leg Call-ID and tags match
    /// the Replaces parameters. Returns the internal call ID if found.
    pub fn find_by_replaces(
        &self,
        replaces_call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<String> {
        for entry in self.calls.iter() {
            if crate::b2bua::transfer::replaces_matches(
                &crate::sip::headers::refer::Replaces {
                    call_id: replaces_call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.to_string(),
                    early_only: false,
                },
                &entry.a_leg.call_id,
                &entry.a_leg.from_tag,
                // The remote's from-tag is stored as the INVITE's From tag
                // We compare against A-leg from_tag as local_tag
                from_tag,
            ) {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Set the transfer context on a call.
    pub fn set_transfer(&self, call_id: &str, transfer: TransferContext) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = Some(transfer);
        }
    }

    /// Clear the transfer context on a call.
    pub fn clear_transfer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = None;
        }
    }

    /// Sweep stale calls older than the given duration.
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let mut removed = 0;
        let stale_ids: Vec<String> = self.calls.iter()
            .filter(|entry| now.duration_since(entry.created_at) > max_age)
            .map(|entry| entry.id.clone())
            .collect();
        for call_id in stale_ids {
            self.remove_call(&call_id);
            removed += 1;
        }
        removed
    }
}

impl Default for CallManager {
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
    use std::net::{IpAddr, Ipv4Addr};

    fn make_a_leg() -> ALeg {
        ALeg {
            source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            branch: "z9hG4bK-aleg1".to_string(),
            call_id: "call-1@10.0.0.1".to_string(),
            from_tag: "tag-alice".to_string(),
        }
    }

    fn make_b_leg(index: usize) -> BLeg {
        BLeg {
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060),
            transport: Transport::Udp,
            branch: format!("z9hG4bK-bleg{}", index),
            target_uri: format!("sip:bob{}@10.0.0.2", index),
            call_id: format!("b2b-bleg{}", index),
            from_tag: format!("sb-bleg{}", index),
            stored_vias: vec![],
        }
    }

    #[test]
    fn create_and_lookup_call() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        assert_eq!(manager.count(), 1);
        assert!(manager.get_call(&call_id).is_some());
    }

    #[test]
    fn add_b_leg_and_route_response() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let branch = b_leg.branch.clone();
        assert!(manager.add_b_leg(&call_id, b_leg));
        assert_eq!(manager.call_id_for_branch(&branch), Some(call_id));
    }

    #[test]
    fn set_winner_and_state() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        manager.add_b_leg(&call_id, make_b_leg(0));
        manager.set_winner(&call_id, 0);
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    #[test]
    fn remove_call_cleans_up_branches() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let branch = b_leg.branch.clone();
        manager.add_b_leg(&call_id, b_leg);
        manager.remove_call(&call_id);
        assert_eq!(manager.count(), 0);
        assert!(manager.call_id_for_branch(&branch).is_none());
    }

    #[test]
    fn find_by_sip_call_id() {
        let manager = CallManager::new();
        let a_leg = make_a_leg();
        let sip_call_id = a_leg.call_id.clone();
        let call_id = manager.create_call(a_leg);
        assert_eq!(manager.find_by_sip_call_id(&sip_call_id), Some(call_id));
        assert!(manager.find_by_sip_call_id("nonexistent").is_none());
    }

    #[test]
    fn set_and_get_a_leg_invite() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());

        // Initially no invite stored
        {
            let call = manager.get_call(&call_id).unwrap();
            assert!(call.a_leg_invite.is_none());
        }

        // Store an invite
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("example.com".to_string())
                    .with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=abc".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("test-call@10.0.0.1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let invite_arc = Arc::new(Mutex::new(invite));
        manager.set_a_leg_invite(&call_id, Arc::clone(&invite_arc));

        // Verify it's stored
        let call = manager.get_call(&call_id).unwrap();
        assert!(call.a_leg_invite.is_some());
        let stored = call.a_leg_invite.as_ref().unwrap().lock().unwrap();
        assert_eq!(
            stored.headers.get("Call-ID").map(|s| s.as_str()),
            Some("test-call@10.0.0.1")
        );
    }

    #[test]
    fn remove_call_cleans_up_a_leg_invite() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("example.com".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x".to_string())
            .from("<sip:a@b>;tag=1".to_string())
            .to("<sip:c@d>".to_string())
            .call_id("cleanup-test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        manager.set_a_leg_invite(&call_id, Arc::new(Mutex::new(invite)));
        manager.remove_call(&call_id);
        assert!(manager.get_call(&call_id).is_none());
    }

    #[test]
    fn set_and_get_session_timer() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());

        // Initially no timer
        {
            let call = manager.get_call(&call_id).unwrap();
            assert!(call.session_timer.is_none());
        }

        // Set timer
        let timer = SessionTimerState {
            session_expires: 1800,
            refresher: "uac".to_string(),
            last_refresh: std::time::Instant::now(),
        };
        manager.set_session_timer(&call_id, timer);

        let call = manager.get_call(&call_id).unwrap();
        let stored = call.session_timer.as_ref().unwrap();
        assert_eq!(stored.session_expires, 1800);
        assert_eq!(stored.refresher, "uac");
    }

    #[test]
    fn reset_session_timer_updates_last_refresh() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());

        let timer = SessionTimerState {
            session_expires: 1800,
            refresher: "uac".to_string(),
            last_refresh: std::time::Instant::now() - std::time::Duration::from_secs(900),
        };
        manager.set_session_timer(&call_id, timer);

        let before = {
            let call = manager.get_call(&call_id).unwrap();
            call.session_timer.as_ref().unwrap().last_refresh
        };

        manager.reset_session_timer(&call_id);

        let after = {
            let call = manager.get_call(&call_id).unwrap();
            call.session_timer.as_ref().unwrap().last_refresh
        };

        assert!(after > before);
    }

    #[test]
    fn sweep_stale() {
        let manager = CallManager::new();
        manager.create_call(make_a_leg());
        // Nothing stale yet (just created)
        assert_eq!(manager.sweep_stale(std::time::Duration::from_secs(60)), 0);
        assert_eq!(manager.count(), 1);
        // Sweep with zero TTL removes everything
        assert_eq!(manager.sweep_stale(std::time::Duration::ZERO), 1);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn find_by_b_leg_call_id() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let b_cid = b_leg.call_id.clone();
        manager.add_b_leg(&call_id, b_leg);
        // Should find via A-leg Call-ID
        assert_eq!(manager.find_by_sip_call_id("call-1@10.0.0.1"), Some(call_id.clone()));
        // Should also find via B-leg Call-ID
        assert_eq!(manager.find_by_sip_call_id(&b_cid), Some(call_id));
        // Nonexistent returns None
        assert!(manager.find_by_sip_call_id("nonexistent").is_none());
    }

    #[test]
    fn b_leg_dialog_ids_are_stored() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        manager.add_b_leg(&call_id, make_b_leg(0));
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs[0].call_id, "b2b-bleg0");
        assert_eq!(call.b_legs[0].from_tag, "sb-bleg0");
        // A-leg and B-leg Call-IDs must differ
        assert_ne!(call.a_leg.call_id, call.b_legs[0].call_id);
        assert_ne!(call.a_leg.from_tag, call.b_legs[0].from_tag);
    }

    #[test]
    fn generate_b_leg_ids_are_unique() {
        let id1 = generate_b_leg_call_id();
        let id2 = generate_b_leg_call_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("b2b-"));

        let tag1 = generate_b_leg_from_tag();
        let tag2 = generate_b_leg_from_tag();
        assert_ne!(tag1, tag2);
        assert!(tag1.starts_with("sb-"));
    }

    #[test]
    fn rewrite_dialog_headers_swaps_call_id_and_tags() {
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::uri::SipUri;

        let mut msg = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=old-tag".to_string())
            .to("<sip:bob@example.com>;tag=bob-tag".to_string())
            .call_id("old-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        rewrite_dialog_headers(&mut msg, "new-call-id", "old-tag", "new-tag");

        assert_eq!(msg.headers.get("Call-ID").unwrap(), "new-call-id");
        assert!(msg.headers.get("From").unwrap().contains("tag=new-tag"));
        assert!(!msg.headers.get("From").unwrap().contains("tag=old-tag"));
        // To-tag should be unchanged (bob-tag doesn't match old-tag)
        assert!(msg.headers.get("To").unwrap().contains("tag=bob-tag"));
    }

    #[test]
    fn rewrite_dialog_headers_swaps_to_tag_when_matched() {
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:bob@example.com>;tag=bob-tag".to_string())
            .to("<sip:alice@example.com>;tag=our-b-tag".to_string())
            .call_id("b-leg-call-id".to_string())
            .cseq("1 BYE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        // Simulate BYE from B→A: swap B-leg identifiers to A-leg
        rewrite_dialog_headers(&mut msg, "a-leg-call-id", "our-b-tag", "a-leg-from-tag");

        assert_eq!(msg.headers.get("Call-ID").unwrap(), "a-leg-call-id");
        // From has bob-tag (no match for our-b-tag), so unchanged
        assert!(msg.headers.get("From").unwrap().contains("tag=bob-tag"));
        // To had our-b-tag → should now be a-leg-from-tag
        assert!(msg.headers.get("To").unwrap().contains("tag=a-leg-from-tag"));
        assert!(!msg.headers.get("To").unwrap().contains("tag=our-b-tag"));
    }

    #[test]
    fn preserve_call_id_defaults_to_false() {
        let manager = CallManager::new();
        let call_id = manager.create_call(make_a_leg());
        let call = manager.get_call(&call_id).unwrap();
        assert!(!call.preserve_call_id);
    }
}
