//! Integration tests for NAT keepalive failure tracking.
//!
//! The `FailureTracker` struct is crate-private, so these tests validate the
//! same DashMap-based failure tracking pattern from the consumer perspective,
//! and test the registrar interactions that the keepalive system depends on.

use std::sync::Arc;
use std::thread;

use dashmap::DashMap;
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::sip::uri::SipUri;

/// A test-local replica of the FailureTracker pattern used in `src/nat/mod.rs`.
/// Since the real struct is crate-private, we replicate it here to validate
/// the same concurrent DashMap logic that the keepalive system relies on.
struct FailureTracker {
    failures: DashMap<String, u32>,
}

impl FailureTracker {
    fn new() -> Self {
        Self {
            failures: DashMap::new(),
        }
    }

    fn record_success(&self, key: &str) {
        self.failures.remove(key);
    }

    fn record_failure(&self, key: &str) -> u32 {
        let mut entry = self.failures.entry(key.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }
}

#[test]
fn failure_tracker_starts_with_zero_failures() {
    let tracker = FailureTracker::new();
    assert!(tracker.failures.is_empty());
}

#[test]
fn record_failure_increments_count() {
    let tracker = FailureTracker::new();
    let key = "sip:alice@example.com|sip:alice@10.0.0.1";

    assert_eq!(tracker.record_failure(key), 1);
    assert_eq!(tracker.record_failure(key), 2);
    assert_eq!(tracker.record_failure(key), 3);
}

#[test]
fn record_success_resets_count() {
    let tracker = FailureTracker::new();
    let key = "sip:alice@example.com|sip:alice@10.0.0.1";

    tracker.record_failure(key);
    tracker.record_failure(key);
    assert_eq!(*tracker.failures.get(key).unwrap(), 2);

    tracker.record_success(key);
    assert!(
        tracker.failures.get(key).is_none(),
        "success should remove the entry entirely"
    );
}

#[test]
fn multiple_failures_accumulate() {
    let tracker = FailureTracker::new();
    let key = "sip:bob@example.com|sip:bob@10.0.0.2";

    for expected in 1..=10 {
        assert_eq!(tracker.record_failure(key), expected);
    }
    assert_eq!(*tracker.failures.get(key).unwrap(), 10);
}

#[test]
fn different_contacts_tracked_independently() {
    let tracker = FailureTracker::new();
    let key_alice = "sip:alice@example.com|sip:alice@10.0.0.1";
    let key_bob = "sip:bob@example.com|sip:bob@10.0.0.2";

    tracker.record_failure(key_alice);
    tracker.record_failure(key_alice);
    tracker.record_failure(key_bob);

    assert_eq!(*tracker.failures.get(key_alice).unwrap(), 2);
    assert_eq!(*tracker.failures.get(key_bob).unwrap(), 1);

    // Success on alice should not affect bob
    tracker.record_success(key_alice);
    assert!(tracker.failures.get(key_alice).is_none());
    assert_eq!(*tracker.failures.get(key_bob).unwrap(), 1);
}

#[test]
fn after_success_failure_starts_from_one() {
    let tracker = FailureTracker::new();
    let key = "sip:carol@example.com|sip:carol@10.0.0.3";

    tracker.record_failure(key);
    tracker.record_failure(key);
    tracker.record_failure(key);
    assert_eq!(*tracker.failures.get(key).unwrap(), 3);

    tracker.record_success(key);

    // After reset, next failure should be 1
    assert_eq!(tracker.record_failure(key), 1);
}

#[test]
fn concurrent_failure_recording() {
    let tracker = Arc::new(FailureTracker::new());
    let key = "sip:dave@example.com|sip:dave@10.0.0.4";
    let num_threads = 8;
    let failures_per_thread = 100;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let tracker = Arc::clone(&tracker);
        let key = key.to_string();
        handles.push(thread::spawn(move || {
            for _ in 0..failures_per_thread {
                tracker.record_failure(&key);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let total = *tracker.failures.get(key).unwrap();
    assert_eq!(
        total,
        num_threads * failures_per_thread,
        "all concurrent failures should be recorded"
    );
}

#[test]
fn registrar_deregister_on_threshold() {
    // Validate the pattern: after N failures, remove contact from registrar
    let registrar = Arc::new(Registrar::new(RegistrarConfig::default()));
    let tracker = FailureTracker::new();
    let threshold: u32 = 3;

    let aor = "sip:eve@example.com";
    let contact_uri = SipUri::new("10.0.0.5".to_string()).with_user("eve".to_string());
    let contact_uri_string = contact_uri.to_string();

    registrar
        .save(aor, contact_uri, 3600, 1.0, "call-id-eve".to_string(), 1)
        .unwrap();
    assert!(registrar.is_registered(aor));

    let tracker_key = format!("{aor}|{contact_uri_string}");

    // Simulate failures below threshold — contact should remain
    for i in 1..threshold {
        let count = tracker.record_failure(&tracker_key);
        assert_eq!(count, i);
        assert!(
            registrar.is_registered(aor),
            "contact should remain registered below threshold"
        );
    }

    // One more failure reaches threshold — deregister
    let count = tracker.record_failure(&tracker_key);
    assert_eq!(count, threshold);
    registrar.remove_contact(aor, &contact_uri_string);

    assert!(
        !registrar.is_registered(aor),
        "contact should be deregistered after reaching threshold"
    );
}
