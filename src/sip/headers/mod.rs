pub mod via;
pub mod nameaddr;
pub mod cseq;
pub mod refer;
pub mod route;
pub mod session_timer;
pub mod rseq;

use indexmap::IndexMap;
use std::sync::Arc;

/// SIP Headers container.
///
/// Internally uses a copy-on-write design — `Clone` is just an `Arc` bump
/// rather than a deep copy of every header value. The first mutating call
/// after a clone pays for `Arc::make_mut` (deep copy if shared, no-op
/// otherwise); subsequent mutations on the same instance are direct.
///
/// This matters because `SipMessage` is cloned heavily on the proxy hot
/// path (transaction caches, per-event copies, dispatched-to-handler
/// snapshots). Many of those clones are read-only — with COW they reduce
/// to a refcount bump.
#[derive(Debug, Clone)]
pub struct SipHeaders {
    inner: Arc<HeadersInner>,
}

#[derive(Debug, Clone)]
struct HeadersInner {
    headers: IndexMap<String, Vec<String>>, // Lowercase name -> values (insertion-ordered)
    original_names: IndexMap<String, String>, // Lowercase name -> original name (insertion-ordered)
}

impl HeadersInner {
    fn new() -> Self {
        Self {
            headers: IndexMap::new(),
            original_names: IndexMap::new(),
        }
    }
}

impl SipHeaders {
    pub fn new() -> Self {
        Self { inner: Arc::new(HeadersInner::new()) }
    }

    fn make_mut(&mut self) -> &mut HeadersInner {
        Arc::make_mut(&mut self.inner)
    }

    /// Add a header value (appends if header already exists)
    pub fn add(&mut self, name: &str, value: String) {
        let key = name.to_lowercase();
        let inner = self.make_mut();
        inner.original_names.entry(key.clone()).or_insert_with(|| name.to_string());
        inner.headers.entry(key).or_default().push(value);
    }

    /// Set a header value (replaces existing, preserves position in header order)
    pub fn set(&mut self, name: &str, value: String) {
        let key = name.to_lowercase();
        let inner = self.make_mut();
        inner.original_names.insert(key.clone(), name.to_string());
        inner.headers.insert(key, vec![value]);
    }

    /// Set multiple values for a header (replaces existing, preserves position in header order).
    ///
    /// Use this when replacing a multi-value header like Via where you need to
    /// keep insertion ordering but supply more than one value.
    pub fn set_all(&mut self, name: &str, values: Vec<String>) {
        let key = name.to_lowercase();
        let inner = self.make_mut();
        inner.original_names.insert(key.clone(), name.to_string());
        inner.headers.insert(key, values);
    }

    /// Get first value of a header
    pub fn get(&self, name: &str) -> Option<&String> {
        self.inner.headers.get(&name.to_lowercase()).and_then(|v| v.first())
    }

    /// Get all values of a header
    pub fn get_all(&self, name: &str) -> Option<&Vec<String>> {
        self.inner.headers.get(&name.to_lowercase())
    }

    /// Remove a header
    pub fn remove(&mut self, name: &str) {
        let key = name.to_lowercase();
        let inner = self.make_mut();
        inner.headers.shift_remove(&key);
        inner.original_names.shift_remove(&key);
    }

    /// Check if header exists
    pub fn has(&self, name: &str) -> bool {
        self.inner.headers.contains_key(&name.to_lowercase())
    }

    /// Get all header names (in original case)
    pub fn names(&self) -> Vec<&String> {
        self.inner.original_names.values().collect()
    }

    /// Iterate over headers
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.inner.headers.iter()
    }

    /// Convenience methods for common headers
    pub fn via(&self) -> Option<&String> {
        self.get("Via")
    }

    pub fn to(&self) -> Option<&String> {
        self.get("To")
    }

    pub fn from(&self) -> Option<&String> {
        self.get("From")
    }

    pub fn call_id(&self) -> Option<&String> {
        self.get("Call-ID")
    }

    pub fn cseq(&self) -> Option<&String> {
        self.get("CSeq")
    }

    pub fn contact(&self) -> Option<&String> {
        self.get("Contact")
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("Content-Length")
            .and_then(|s| s.trim().parse().ok())
    }

    pub fn content_type(&self) -> Option<&String> {
        self.get("Content-Type")
    }

    pub fn max_forwards(&self) -> Option<u8> {
        self.get("Max-Forwards")
            .and_then(|s| s.trim().parse().ok())
    }
}

impl Default for SipHeaders {
    fn default() -> Self {
        Self::new()
    }
}



