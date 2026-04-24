//! Intercept target store — provisioned via X1, matched against SIP traffic.
//!
//! Each target represents a lawful intercept warrant with a unique LIID
//! (Lawful Intercept Identifier). Targets are stored in a `DashMap` keyed
//! by normalized identity for O(1) lookup on every SIP message.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Unique identifier for an intercept (LIID per ETSI TS 102 232).
pub type Liid = String;

/// What the intercept matches against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetIdentity {
    /// Full SIP URI match (e.g. "sip:alice@example.com").
    SipUri(String),
    /// Phone number / user-part match (e.g. "+1234567890").
    /// Matches against RURI user, From user, and To user.
    PhoneNumber(String),
    /// Source IP address match.
    IpAddress(IpAddr),
}

/// What to deliver for this intercept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryType {
    /// X2 only — signaling metadata (IRI).
    IriOnly,
    /// X2 + X3 — signaling metadata + media content (IRI + CC).
    IriAndCc,
}

impl DeliveryType {
    /// Whether this delivery type requires X3 content capture.
    pub fn includes_content(self) -> bool {
        matches!(self, Self::IriAndCc)
    }
}

/// A single intercept target provisioned via X1.
#[derive(Debug, Clone)]
pub struct InterceptTarget {
    /// LIID — unique intercept identifier assigned by LEA.
    pub liid: Liid,
    /// What to match against.
    pub target_identity: TargetIdentity,
    /// IRI-only or IRI+CC delivery.
    pub delivery_type: DeliveryType,
    /// Whether this intercept is currently active.
    pub active: bool,
    /// When this intercept was activated.
    pub activated_at: SystemTime,
    /// Opaque warrant reference (for audit trail).
    pub warrant_ref: Option<String>,
    /// Optional mediation device identifier (when multiple LEAs).
    pub mediation_id: Option<String>,
}

/// Normalized key for fast DashMap lookup.
///
/// We normalize identities to a canonical form so that matching is consistent:
/// - SIP URIs are lowercased
/// - Phone numbers have non-digit prefix stripped (keep leading +)
/// - IP addresses use their canonical representation
fn normalize_key(identity: &TargetIdentity) -> String {
    match identity {
        TargetIdentity::SipUri(uri) => uri.to_lowercase(),
        TargetIdentity::PhoneNumber(number) => {
            // Keep leading + and digits only
            let cleaned: String = number.chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            cleaned
        }
        TargetIdentity::IpAddress(ip) => ip.to_string(),
    }
}

/// Thread-safe intercept target store.
///
/// Keyed by normalized identity string for O(1) lookup.
/// Multiple targets can match the same identity (different LIIDs from different LEAs).
#[derive(Debug, Clone)]
pub struct TargetStore {
    /// Primary index: normalized identity → list of targets.
    by_identity: Arc<DashMap<String, Vec<InterceptTarget>>>,
    /// Secondary index: LIID → normalized identity key (for X1 CRUD by LIID).
    by_liid: Arc<DashMap<Liid, String>>,
}

impl TargetStore {
    pub fn new() -> Self {
        Self {
            by_identity: Arc::new(DashMap::new()),
            by_liid: Arc::new(DashMap::new()),
        }
    }

    /// Add or replace an intercept target. Returns `true` if this is a new target.
    pub fn activate(&self, target: InterceptTarget) -> bool {
        let key = normalize_key(&target.target_identity);
        let liid = target.liid.clone();
        let is_new = !self.by_liid.contains_key(&liid);

        // Remove existing entry for this LIID if it exists (ModifyTask).
        if !is_new {
            self.deactivate(&liid);
        }

        self.by_liid.insert(liid.clone(), key.clone());
        self.by_identity
            .entry(key)
            .or_default()
            .push(target);

        is_new
    }

    /// Remove an intercept target by LIID. Returns the removed target if found.
    pub fn deactivate(&self, liid: &str) -> Option<InterceptTarget> {
        if let Some((_, key)) = self.by_liid.remove(liid) {
            if let Some(mut targets) = self.by_identity.get_mut(&key) {
                if let Some(position) = targets.iter().position(|t| t.liid == liid) {
                    let removed = targets.remove(position);
                    // Clean up empty vec
                    if targets.is_empty() {
                        drop(targets);
                        self.by_identity.remove(&key);
                    }
                    return Some(removed);
                }
            }
        }
        None
    }

    /// Look up a target by LIID (for X1 GET/status).
    pub fn get_by_liid(&self, liid: &str) -> Option<InterceptTarget> {
        let key = self.by_liid.get(liid)?;
        let targets = self.by_identity.get(key.value())?;
        targets.iter().find(|t| t.liid == liid).cloned()
    }

    /// List all active intercepts (for X1 listing). Returns (liid, target) pairs.
    pub fn list_all(&self) -> Vec<InterceptTarget> {
        self.by_identity
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    /// Match a SIP URI against the target store. Returns all matching targets.
    pub fn match_sip_uri(&self, uri: &str) -> Vec<InterceptTarget> {
        let key = uri.to_lowercase();
        self.by_identity
            .get(&key)
            .map(|targets| targets.clone())
            .unwrap_or_default()
    }

    /// Match a phone number / user-part against the target store.
    pub fn match_phone_number(&self, number: &str) -> Vec<InterceptTarget> {
        let key: String = number.chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect();
        self.by_identity
            .get(&key)
            .map(|targets| targets.clone())
            .unwrap_or_default()
    }

    /// Match a source IP against the target store.
    pub fn match_ip(&self, ip: IpAddr) -> Vec<InterceptTarget> {
        let key = ip.to_string();
        self.by_identity
            .get(&key)
            .map(|targets| targets.clone())
            .unwrap_or_default()
    }

    /// Check if any intercept matches the given SIP message fields.
    /// Returns all matching targets (may be from different LEAs).
    ///
    /// Checks against: RURI, From URI, To URI, and source IP.
    pub fn match_message(
        &self,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<InterceptTarget> {
        let mut matches = Vec::new();
        let mut seen_liids = std::collections::HashSet::new();

        // Check SIP URIs
        for uri in [request_uri, from_uri, to_uri].into_iter().flatten() {
            for target in self.match_sip_uri(uri) {
                if seen_liids.insert(target.liid.clone()) {
                    matches.push(target);
                }
            }
            // Also try matching user-part as phone number
            if let Some(user) = extract_user_part(uri) {
                for target in self.match_phone_number(&user) {
                    if seen_liids.insert(target.liid.clone()) {
                        matches.push(target);
                    }
                }
            }
        }

        // Check source IP
        if let Some(ip) = source_ip {
            for target in self.match_ip(ip) {
                if seen_liids.insert(target.liid.clone()) {
                    matches.push(target);
                }
            }
        }

        matches
    }

    /// Number of active intercept targets.
    pub fn count(&self) -> usize {
        self.by_liid.len()
    }
}

impl Default for TargetStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract user-part from a SIP URI (e.g. "sip:+1234@example.com" → "+1234").
fn extract_user_part(uri: &str) -> Option<String> {
    let uri = uri.strip_prefix("sip:").or_else(|| uri.strip_prefix("sips:"))?;
    let user_part = uri.split('@').next()?;
    if user_part.is_empty() || user_part == uri {
        return None; // No @ found or empty user
    }
    Some(user_part.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_target(liid: &str, identity: TargetIdentity, delivery: DeliveryType) -> InterceptTarget {
        InterceptTarget {
            liid: liid.to_string(),
            target_identity: identity,
            delivery_type: delivery,
            active: true,
            activated_at: SystemTime::now(),
            warrant_ref: Some("W-2026-001".to_string()),
            mediation_id: None,
        }
    }

    #[test]
    fn activate_and_lookup_by_liid() {
        let store = TargetStore::new();
        let target = make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriAndCc,
        );
        assert!(store.activate(target));
        assert_eq!(store.count(), 1);

        let found = store.get_by_liid("LI-001").unwrap();
        assert_eq!(found.liid, "LI-001");
        assert_eq!(found.delivery_type, DeliveryType::IriAndCc);
    }

    #[test]
    fn deactivate_removes_target() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriOnly,
        ));
        assert_eq!(store.count(), 1);

        let removed = store.deactivate("LI-001").unwrap();
        assert_eq!(removed.liid, "LI-001");
        assert_eq!(store.count(), 0);
        assert!(store.get_by_liid("LI-001").is_none());
    }

    #[test]
    fn deactivate_nonexistent_returns_none() {
        let store = TargetStore::new();
        assert!(store.deactivate("LI-999").is_none());
    }

    #[test]
    fn match_sip_uri_case_insensitive() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:Alice@Example.COM".to_string()),
            DeliveryType::IriOnly,
        ));

        let matches = store.match_sip_uri("sip:alice@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].liid, "LI-001");
    }

    #[test]
    fn match_phone_number_strips_formatting() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-002",
            TargetIdentity::PhoneNumber("+1-234-567-8900".to_string()),
            DeliveryType::IriAndCc,
        ));

        // Match with different formatting
        let matches = store.match_phone_number("+12345678900");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].liid, "LI-002");
    }

    #[test]
    fn match_ip_address() {
        let store = TargetStore::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        store.activate(make_target(
            "LI-003",
            TargetIdentity::IpAddress(ip),
            DeliveryType::IriOnly,
        ));

        let matches = store.match_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(matches.len(), 1);

        let no_match = store.match_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(no_match.is_empty());
    }

    #[test]
    fn match_message_checks_all_fields() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:bob@biloxi.com".to_string()),
            DeliveryType::IriAndCc,
        ));

        // Match via To URI
        let matches = store.match_message(
            Some("sip:target@other.com"),
            Some("sip:alice@atlanta.com"),
            Some("sip:bob@biloxi.com"),
            None,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].liid, "LI-001");
    }

    #[test]
    fn match_message_via_phone_number_in_uri() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-004",
            TargetIdentity::PhoneNumber("+15551234567".to_string()),
            DeliveryType::IriOnly,
        ));

        // Phone number appears as user-part of From URI
        let matches = store.match_message(
            None,
            Some("sip:+15551234567@carrier.com"),
            None,
            None,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].liid, "LI-004");
    }

    #[test]
    fn match_message_deduplicates_across_fields() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriOnly,
        ));

        // Same URI appears in both From and To — should only match once
        let matches = store.match_message(
            None,
            Some("sip:alice@example.com"),
            Some("sip:alice@example.com"),
            None,
        );
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn multiple_targets_same_identity() {
        let store = TargetStore::new();
        // Two LEAs targeting the same person
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriOnly,
        ));
        store.activate(make_target(
            "LI-002",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriAndCc,
        ));

        assert_eq!(store.count(), 2);
        let matches = store.match_sip_uri("sip:alice@example.com");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn modify_target_replaces_existing() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriOnly,
        ));

        // Modify: same LIID, upgrade to IRI+CC
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriAndCc,
        ));

        assert_eq!(store.count(), 1);
        let found = store.get_by_liid("LI-001").unwrap();
        assert_eq!(found.delivery_type, DeliveryType::IriAndCc);
    }

    #[test]
    fn list_all_returns_every_target() {
        let store = TargetStore::new();
        store.activate(make_target(
            "LI-001",
            TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            DeliveryType::IriOnly,
        ));
        store.activate(make_target(
            "LI-002",
            TargetIdentity::PhoneNumber("+15551234567".to_string()),
            DeliveryType::IriAndCc,
        ));

        let all = store.list_all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn extract_user_part_works() {
        assert_eq!(extract_user_part("sip:alice@example.com"), Some("alice".to_string()));
        assert_eq!(extract_user_part("sips:+1234@example.com"), Some("+1234".to_string()));
        assert_eq!(extract_user_part("sip:example.com"), None); // no @
        assert_eq!(extract_user_part("tel:+1234"), None); // not sip:
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(TargetStore::new());
        let mut handles = Vec::new();

        // Spawn writers
        for i in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store.activate(make_target(
                    &format!("LI-{i:03}"),
                    TargetIdentity::SipUri(format!("sip:user{i}@example.com")),
                    DeliveryType::IriOnly,
                ));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.count(), 10);

        // Concurrent reads
        let mut read_handles = Vec::new();
        for i in 0..10 {
            let store = Arc::clone(&store);
            read_handles.push(thread::spawn(move || {
                store.get_by_liid(&format!("LI-{i:03}")).is_some()
            }));
        }

        for handle in read_handles {
            assert!(handle.join().unwrap());
        }
    }
}
