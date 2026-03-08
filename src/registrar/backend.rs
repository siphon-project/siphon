//! Pluggable registrar backend trait and implementations.
//!
//! The in-memory DashMap is always the L1 cache. Backends provide L2 persistence
//! via write-through semantics: writes go to both L1 and L2; reads check L1 first.

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
use std::collections::hash_map::DefaultHasher;
#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Serializable contact binding for persistence backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    /// Contact URI as a string.
    pub uri: String,
    /// Quality value.
    pub q: f32,
    /// Expires duration in seconds (from the time of storage).
    pub expires_secs: u64,
    /// Call-ID that created this binding.
    pub call_id: String,
    /// CSeq sequence number.
    pub cseq: u32,
    /// Source address (if known).
    pub source_addr: Option<String>,
    /// RFC 5627 sip.instance.
    pub sip_instance: Option<String>,
    /// RFC 5626 reg-id.
    pub reg_id: Option<u32>,
}

impl StoredContact {
    /// Convert from the in-memory Contact type.
    pub fn from_contact(contact: &super::Contact) -> Self {
        Self {
            uri: contact.uri.to_string(),
            q: contact.q,
            expires_secs: contact.remaining_seconds(),
            call_id: contact.call_id.clone(),
            cseq: contact.cseq,
            source_addr: contact.source_addr.map(|a| a.to_string()),
            sip_instance: contact.sip_instance.clone(),
            reg_id: contact.reg_id,
        }
    }

    /// Convert to an in-memory Contact type.
    pub fn to_contact(&self) -> Option<super::Contact> {
        use crate::sip::parser::parse_uri_standalone;

        let uri = parse_uri_standalone(&self.uri).ok()?;
        let source_addr = self
            .source_addr
            .as_ref()
            .and_then(|s| s.parse::<SocketAddr>().ok());

        Some(super::Contact {
            uri,
            q: self.q,
            registered_at: std::time::Instant::now(),
            expires: Duration::from_secs(self.expires_secs),
            call_id: self.call_id.clone(),
            cseq: self.cseq,
            source_addr,
            sip_instance: self.sip_instance.clone(),
            reg_id: self.reg_id,
            pending: false,
        })
    }
}

/// Async trait for registrar persistence backends.
///
/// All methods are async to support network I/O (Redis, PostgreSQL).
/// The in-memory registrar wraps these with write-through semantics.
#[allow(async_fn_in_trait)]
pub trait RegistrarBackend: Send + Sync + std::fmt::Debug {
    /// Store contacts for an AoR, replacing any existing bindings.
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError>;

    /// Load contacts for an AoR.
    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError>;

    /// Remove all contacts for an AoR.
    async fn remove(&self, aor: &str) -> Result<(), BackendError>;

    /// Check if an AoR exists in the backend.
    async fn exists(&self, aor: &str) -> Result<bool, BackendError>;

    /// List all AoRs with stored contacts.
    async fn all_aors(&self) -> Result<Vec<String>, BackendError>;
}

/// Backend errors.
#[derive(Debug, Clone)]
pub enum BackendError {
    /// Connection error (Redis, PostgreSQL).
    Connection(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Query error.
    Query(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Connection(message) => write!(f, "backend connection error: {message}"),
            BackendError::Serialization(message) => {
                write!(f, "backend serialization error: {message}")
            }
            BackendError::Query(message) => write!(f, "backend query error: {message}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Compute a deterministic shard index for an AoR string.
#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
fn shard_index(aor: &str, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    aor.hash(&mut hasher);
    hasher.finish() as usize % shard_count
}

// ---------------------------------------------------------------------------
// In-memory backend (for testing and as a reference implementation)
// ---------------------------------------------------------------------------

/// In-memory backend using DashMap. Primarily for testing the backend trait.
#[derive(Debug)]
pub struct MemoryBackend {
    data: dashmap::DashMap<String, Vec<StoredContact>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: dashmap::DashMap::new(),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrarBackend for MemoryBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        if contacts.is_empty() {
            self.data.remove(aor);
        } else {
            self.data.insert(aor.to_string(), contacts.to_vec());
        }
        Ok(())
    }

    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        Ok(self
            .data
            .get(aor)
            .map(|entry| entry.value().clone())
            .unwrap_or_default())
    }

    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.data.remove(aor);
        Ok(())
    }

    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        Ok(self.data.contains_key(aor))
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(self.data.iter().map(|entry| entry.key().clone()).collect())
    }
}

// ---------------------------------------------------------------------------
// Redis backend — real implementation (feature-gated)
// ---------------------------------------------------------------------------

/// Redis backend configuration.
#[derive(Debug, Clone)]
pub struct RedisBackendConfig {
    /// Redis connection URL (e.g., "redis://127.0.0.1:6379").
    /// Used when `shard_count` is 0.
    pub url: String,
    /// List of shard URLs. Must have `shard_count` entries when sharding is enabled.
    pub urls: Vec<String>,
    /// Key prefix for registrar entries.
    pub key_prefix: String,
    /// Number of shards. 0 = no sharding (use `url`), >0 = shard by AoR hash.
    pub shard_count: usize,
}

impl Default for RedisBackendConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            urls: Vec::new(),
            key_prefix: "siphon:reg:".to_string(),
            shard_count: 0,
        }
    }
}

#[cfg(feature = "redis-backend")]
mod redis_real {
    use super::*;
    use redis::AsyncCommands;

    /// Redis registrar backend.
    ///
    /// Stores contacts as JSON in Redis hashes, with TTL aligned to contact expiry.
    /// Supports optional auto-sharding across multiple Redis instances.
    #[derive(Debug)]
    pub struct RedisBackend {
        config: RedisBackendConfig,
        /// Connections — single element when not sharding, multiple when sharding.
        connections: Vec<redis::aio::MultiplexedConnection>,
    }

    impl RedisBackend {
        /// Connect to Redis (single instance or sharded).
        pub async fn connect(config: RedisBackendConfig) -> Result<Self, BackendError> {
            let connections = if config.shard_count > 0 {
                if config.urls.len() != config.shard_count {
                    return Err(BackendError::Connection(format!(
                        "shard_count is {} but {} URLs provided",
                        config.shard_count,
                        config.urls.len()
                    )));
                }
                let mut connections = Vec::with_capacity(config.shard_count);
                for url in &config.urls {
                    let client = redis::Client::open(url.as_str())
                        .map_err(|error| BackendError::Connection(error.to_string()))?;
                    let connection = client
                        .get_multiplexed_async_connection()
                        .await
                        .map_err(|error| BackendError::Connection(error.to_string()))?;
                    connections.push(connection);
                }
                tracing::info!(
                    shard_count = config.shard_count,
                    "redis registrar backend connected (sharded)"
                );
                connections
            } else {
                let client = redis::Client::open(config.url.as_str())
                    .map_err(|error| BackendError::Connection(error.to_string()))?;
                let connection = client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(|error| BackendError::Connection(error.to_string()))?;
                tracing::info!("redis registrar backend connected");
                vec![connection]
            };

            Ok(Self {
                config,
                connections,
            })
        }

        /// The Redis key for an AoR.
        fn key(&self, aor: &str) -> String {
            format!("{}{}", self.config.key_prefix, aor)
        }

        /// Get a cloned connection for the given AoR (shard-aware).
        fn connection_for(&self, aor: &str) -> redis::aio::MultiplexedConnection {
            if self.connections.len() == 1 {
                self.connections[0].clone()
            } else {
                let index = shard_index(aor, self.connections.len());
                self.connections[index].clone()
            }
        }

        /// Get all connections (for operations that span all shards).
        fn all_connections(&self) -> Vec<redis::aio::MultiplexedConnection> {
            self.connections.iter().cloned().collect()
        }
    }

    impl RegistrarBackend for RedisBackend {
        async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);

            if contacts.is_empty() {
                let _: () = connection
                    .del(&key)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                return Ok(());
            }

            // Delete existing hash to replace all bindings, then set new ones.
            let _: () = connection
                .del(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            let mut max_ttl: u64 = 0;
            for contact in contacts {
                let json = serde_json::to_string(contact)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                let _: () = connection
                    .hset(&key, &contact.uri, &json)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                if contact.expires_secs > max_ttl {
                    max_ttl = contact.expires_secs;
                }
            }

            // Set TTL to the longest contact expiry (minimum 1 second).
            if max_ttl > 0 {
                let _: () = connection
                    .expire(&key, max_ttl as i64)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
            }

            Ok(())
        }

        async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);

            let entries: Vec<(String, String)> = connection
                .hgetall(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            let mut contacts = Vec::with_capacity(entries.len());
            for (_field, value) in entries {
                let contact: StoredContact = serde_json::from_str(&value)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                contacts.push(contact);
            }
            Ok(contacts)
        }

        async fn remove(&self, aor: &str) -> Result<(), BackendError> {
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);
            let _: () = connection
                .del(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);
            let result: bool = connection
                .exists(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(result)
        }

        async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
            let pattern = format!("{}*", self.config.key_prefix);
            let prefix_len = self.config.key_prefix.len();
            let mut all_aors = Vec::new();

            for mut connection in self.all_connections() {
                let mut cursor: u64 = 0;
                loop {
                    let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(100)
                        .query_async(&mut connection)
                        .await
                        .map_err(|error| BackendError::Query(error.to_string()))?;

                    for key in keys {
                        if key.len() > prefix_len {
                            all_aors.push(key[prefix_len..].to_string());
                        }
                    }

                    cursor = next_cursor;
                    if cursor == 0 {
                        break;
                    }
                }
            }

            Ok(all_aors)
        }
    }
}

#[cfg(feature = "redis-backend")]
pub use redis_real::RedisBackend;

/// Stub Redis backend when the `redis-backend` feature is not enabled.
#[cfg(not(feature = "redis-backend"))]
#[derive(Debug)]
pub struct RedisBackend {
    config: RedisBackendConfig,
}

#[cfg(not(feature = "redis-backend"))]
impl RedisBackend {
    pub fn new(config: RedisBackendConfig) -> Self {
        Self { config }
    }

    /// The Redis key for an AoR.
    fn key(&self, aor: &str) -> String {
        format!("{}{}", self.config.key_prefix, aor)
    }
}

#[cfg(not(feature = "redis-backend"))]
impl RegistrarBackend for RedisBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        let _key = self.key(aor);
        let _json = serde_json::to_string(contacts)
            .map_err(|error| BackendError::Serialization(error.to_string()))?;
        tracing::warn!("redis backend stub: save is a no-op (enable redis-backend feature)");
        Ok(())
    }

    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        let _key = self.key(aor);
        tracing::warn!("redis backend stub: load returns empty (enable redis-backend feature)");
        Ok(Vec::new())
    }

    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        let _key = self.key(aor);
        tracing::warn!("redis backend stub: remove is a no-op (enable redis-backend feature)");
        Ok(())
    }

    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        let _key = self.key(aor);
        tracing::warn!("redis backend stub: exists returns false (enable redis-backend feature)");
        Ok(false)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        tracing::warn!(
            "redis backend stub: all_aors returns empty (enable redis-backend feature)"
        );
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL backend — real implementation (feature-gated)
// ---------------------------------------------------------------------------

/// PostgreSQL backend configuration.
#[derive(Debug, Clone)]
pub struct PostgresBackendConfig {
    /// PostgreSQL connection URL.
    /// Used when `shard_count` is 0.
    pub url: String,
    /// List of shard URLs. Must have `shard_count` entries when sharding is enabled.
    pub urls: Vec<String>,
    /// Table name for registrations.
    pub table: String,
    /// Number of shards. 0 = no sharding (use `url`), >0 = shard by AoR hash.
    pub shard_count: usize,
}

impl Default for PostgresBackendConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/siphon".to_string(),
            urls: Vec::new(),
            table: "registrations".to_string(),
            shard_count: 0,
        }
    }
}

#[cfg(feature = "postgres-backend")]
mod postgres_real {
    use super::*;
    use std::sync::Arc;

    /// PostgreSQL registrar backend.
    ///
    /// Stores contacts in a table with `(aor, contact_uri)` as the primary key.
    /// Contact data is stored as TEXT (JSON string). Expired rows are filtered
    /// on read and can be cleaned up periodically.
    ///
    /// Supports optional auto-sharding across multiple PostgreSQL instances.
    #[derive(Debug)]
    pub struct PostgresBackend {
        config: PostgresBackendConfig,
        /// Clients — single element when not sharding, multiple when sharding.
        clients: Vec<Arc<tokio_postgres::Client>>,
    }

    impl PostgresBackend {
        /// Connect to PostgreSQL and create the registrations table if needed.
        pub async fn connect(config: PostgresBackendConfig) -> Result<Self, BackendError> {
            let clients = if config.shard_count > 0 {
                if config.urls.len() != config.shard_count {
                    return Err(BackendError::Connection(format!(
                        "shard_count is {} but {} URLs provided",
                        config.shard_count,
                        config.urls.len()
                    )));
                }
                let mut clients = Vec::with_capacity(config.shard_count);
                for url in &config.urls {
                    let client = Self::connect_one(url, &config.table).await?;
                    clients.push(client);
                }
                tracing::info!(
                    shard_count = config.shard_count,
                    table = %config.table,
                    "postgres registrar backend connected (sharded)"
                );
                clients
            } else {
                let client = Self::connect_one(&config.url, &config.table).await?;
                tracing::info!(table = %config.table, "postgres registrar backend connected");
                vec![client]
            };

            Ok(Self { config, clients })
        }

        /// Connect to a single PostgreSQL instance and ensure the table exists.
        async fn connect_one(
            url: &str,
            table: &str,
        ) -> Result<Arc<tokio_postgres::Client>, BackendError> {
            let (client, connection) =
                tokio_postgres::connect(url, tokio_postgres::NoTls)
                    .await
                    .map_err(|error| BackendError::Connection(error.to_string()))?;

            // Spawn the connection task so it runs in the background.
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::error!("postgres connection error: {error}");
                }
            });

            // Create the registrations table if it does not exist.
            // Data is stored as TEXT (JSON string) to avoid requiring the
            // `with-serde_json-1` feature on tokio-postgres.
            let create_table_query = format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    aor TEXT NOT NULL,
                    contact_uri TEXT NOT NULL,
                    data TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (aor, contact_uri)
                )",
                table
            );
            client
                .execute(&create_table_query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            Ok(Arc::new(client))
        }

        /// Get the client for the given AoR (shard-aware).
        fn client_for(&self, aor: &str) -> &tokio_postgres::Client {
            if self.clients.len() == 1 {
                &self.clients[0]
            } else {
                let index = shard_index(aor, self.clients.len());
                &self.clients[index]
            }
        }
    }

    impl RegistrarBackend for PostgresBackend {
        async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            if contacts.is_empty() {
                let query = format!("DELETE FROM {} WHERE aor = $1", table);
                client
                    .execute(&query, &[&aor])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                return Ok(());
            }

            // Upsert each contact individually.
            let query = format!(
                "INSERT INTO {} (aor, contact_uri, data, expires_at)
                 VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 second')
                 ON CONFLICT (aor, contact_uri) DO UPDATE
                 SET data = $3, expires_at = NOW() + $4 * INTERVAL '1 second'",
                table
            );

            for contact in contacts {
                let json = serde_json::to_string(contact)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                let expires_secs = contact.expires_secs as f64;

                client
                    .execute(&query, &[&aor, &contact.uri, &json, &expires_secs])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
            }

            Ok(())
        }

        async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            let query = format!(
                "SELECT data FROM {} WHERE aor = $1 AND expires_at > NOW()",
                table
            );
            let rows = client
                .query(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            let mut contacts = Vec::with_capacity(rows.len());
            for row in rows {
                let data: &str = row.get(0);
                let contact: StoredContact = serde_json::from_str(data)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                contacts.push(contact);
            }
            Ok(contacts)
        }

        async fn remove(&self, aor: &str) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            let query = format!("DELETE FROM {} WHERE aor = $1", table);
            client
                .execute(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            let query = format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE aor = $1 AND expires_at > NOW())",
                table
            );
            let row = client
                .query_one(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            let result: bool = row.get(0);
            Ok(result)
        }

        async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
            let mut all_aors = Vec::new();

            for client in &self.clients {
                let query = format!(
                    "SELECT DISTINCT aor FROM {} WHERE expires_at > NOW()",
                    self.config.table
                );
                let rows = client
                    .query(&query, &[])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;

                for row in rows {
                    let aor: String = row.get(0);
                    all_aors.push(aor);
                }
            }

            Ok(all_aors)
        }
    }
}

#[cfg(feature = "postgres-backend")]
pub use postgres_real::PostgresBackend;

/// Stub PostgreSQL backend when the `postgres-backend` feature is not enabled.
#[cfg(not(feature = "postgres-backend"))]
#[derive(Debug)]
pub struct PostgresBackend {
    _config: PostgresBackendConfig,
}

#[cfg(not(feature = "postgres-backend"))]
impl PostgresBackend {
    pub fn new(config: PostgresBackendConfig) -> Self {
        Self { _config: config }
    }
}

#[cfg(not(feature = "postgres-backend"))]
impl RegistrarBackend for PostgresBackend {
    async fn save(&self, _aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        let _json = serde_json::to_string(contacts)
            .map_err(|error| BackendError::Serialization(error.to_string()))?;
        tracing::warn!(
            "postgres backend stub: save is a no-op (enable postgres-backend feature)"
        );
        Ok(())
    }

    async fn load(&self, _aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        tracing::warn!(
            "postgres backend stub: load returns empty (enable postgres-backend feature)"
        );
        Ok(Vec::new())
    }

    async fn remove(&self, _aor: &str) -> Result<(), BackendError> {
        tracing::warn!(
            "postgres backend stub: remove is a no-op (enable postgres-backend feature)"
        );
        Ok(())
    }

    async fn exists(&self, _aor: &str) -> Result<bool, BackendError> {
        tracing::warn!(
            "postgres backend stub: exists returns false (enable postgres-backend feature)"
        );
        Ok(false)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        tracing::warn!(
            "postgres backend stub: all_aors returns empty (enable postgres-backend feature)"
        );
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stored_contact() -> StoredContact {
        StoredContact {
            uri: "sip:alice@10.0.0.1".to_string(),
            q: 1.0,
            expires_secs: 3600,
            call_id: "call-1".to_string(),
            cseq: 1,
            source_addr: None,
            sip_instance: None,
            reg_id: None,
        }
    }

    #[test]
    fn stored_contact_roundtrip() {
        let stored = sample_stored_contact();
        let contact = stored.to_contact().unwrap();
        assert_eq!(contact.uri.to_string(), "sip:alice@10.0.0.1");
        assert_eq!(contact.q, 1.0);
        assert_eq!(contact.call_id, "call-1");

        let back = StoredContact::from_contact(&contact);
        assert_eq!(back.uri, stored.uri);
        assert_eq!(back.q, stored.q);
        assert_eq!(back.call_id, stored.call_id);
    }

    #[test]
    fn stored_contact_with_instance() {
        let stored = StoredContact {
            sip_instance: Some("<urn:uuid:abc>".to_string()),
            reg_id: Some(1),
            ..sample_stored_contact()
        };
        let contact = stored.to_contact().unwrap();
        assert_eq!(contact.sip_instance.as_deref(), Some("<urn:uuid:abc>"));
        assert_eq!(contact.reg_id, Some(1));
    }

    #[test]
    fn stored_contact_serialization() {
        let stored = sample_stored_contact();
        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredContact = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uri, stored.uri);
        assert_eq!(deserialized.q, stored.q);
    }

    #[tokio::test]
    async fn memory_backend_save_and_load() {
        let backend = MemoryBackend::new();
        let contacts = vec![sample_stored_contact()];

        backend
            .save("sip:alice@example.com", &contacts)
            .await
            .unwrap();
        let loaded = backend.load("sip:alice@example.com").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].uri, "sip:alice@10.0.0.1");
    }

    #[tokio::test]
    async fn memory_backend_remove() {
        let backend = MemoryBackend::new();
        let contacts = vec![sample_stored_contact()];

        backend
            .save("sip:alice@example.com", &contacts)
            .await
            .unwrap();
        assert!(backend.exists("sip:alice@example.com").await.unwrap());

        backend.remove("sip:alice@example.com").await.unwrap();
        assert!(!backend.exists("sip:alice@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn memory_backend_all_aors() {
        let backend = MemoryBackend::new();
        backend
            .save("sip:a@x.com", &[sample_stored_contact()])
            .await
            .unwrap();
        backend
            .save("sip:b@x.com", &[sample_stored_contact()])
            .await
            .unwrap();

        let aors = backend.all_aors().await.unwrap();
        assert_eq!(aors.len(), 2);
    }

    #[tokio::test]
    async fn memory_backend_empty_save_removes() {
        let backend = MemoryBackend::new();
        backend
            .save("sip:a@x.com", &[sample_stored_contact()])
            .await
            .unwrap();
        backend.save("sip:a@x.com", &[]).await.unwrap();
        assert!(!backend.exists("sip:a@x.com").await.unwrap());
    }

    #[test]
    fn redis_backend_key_format() {
        let backend = RedisBackend::new(RedisBackendConfig::default());
        assert_eq!(
            backend.key("sip:alice@example.com"),
            "siphon:reg:sip:alice@example.com"
        );
    }

    #[test]
    fn backend_error_display() {
        let error = BackendError::Connection("timeout".to_string());
        assert!(error.to_string().contains("timeout"));
    }

    #[test]
    fn shard_index_deterministic() {
        let index_a = shard_index("sip:alice@example.com", 4);
        let index_b = shard_index("sip:alice@example.com", 4);
        assert_eq!(index_a, index_b);
        assert!(index_a < 4);
    }

    #[test]
    fn shard_index_distributes() {
        // With enough distinct AoRs, we should hit multiple shards.
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let aor = format!("sip:user{}@example.com", i);
            seen.insert(shard_index(&aor, 4));
        }
        // With 100 distinct AoRs and 4 shards, we should hit all 4.
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn redis_config_default_no_sharding() {
        let config = RedisBackendConfig::default();
        assert_eq!(config.shard_count, 0);
        assert!(config.urls.is_empty());
    }

    #[test]
    fn postgres_config_default_no_sharding() {
        let config = PostgresBackendConfig::default();
        assert_eq!(config.shard_count, 0);
        assert!(config.urls.is_empty());
        assert_eq!(config.table, "registrations");
    }
}
