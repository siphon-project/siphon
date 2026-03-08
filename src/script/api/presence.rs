//! Python API for the SIP Presence subsystem.
//!
//! Scripts use:
//! ```python
//! from siphon import presence
//!
//! presence.publish("sip:alice@example.com", pidf_xml, expires=3600)
//! doc = presence.lookup("sip:alice@example.com")
//!
//! sub_id = presence.subscribe("sip:bob@example.com", "sip:alice@example.com",
//!                              event="presence", expires=3600)
//! presence.unsubscribe(sub_id)
//!
//! for watcher in presence.subscribers("sip:alice@example.com"):
//!     log.info(f"watcher: {watcher['subscriber']}")
//! ```

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::presence::{PresenceStore, Subscription};

/// Python-visible presence namespace.
#[pyclass(name = "PresenceNamespace", skip_from_py_object)]
pub struct PyPresence {
    store: Arc<PresenceStore>,
}

impl PyPresence {
    pub fn new(store: Arc<PresenceStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PyPresence {
    /// Publish a presence document for a presentity.
    ///
    /// Creates a new PIDF document (application/pidf+xml) for the given entity.
    /// Returns the etag assigned to the document, which can be used for
    /// conditional updates.
    ///
    /// Args:
    ///     entity: Presentity URI (e.g. "sip:alice@example.com").
    ///     pidf_xml: PIDF XML body string.
    ///     expires: Document expiry in seconds (default: 3600).
    ///
    /// Returns:
    ///     The etag string assigned to the published document.
    #[pyo3(signature = (entity, pidf_xml, expires=3600))]
    fn publish(&self, entity: &str, pidf_xml: &str, expires: u64) -> String {
        self.store.publish(
            entity,
            "application/pidf+xml".to_string(),
            pidf_xml.to_string(),
            None,
            Duration::from_secs(expires),
        )
    }

    /// Look up the current presence document for a URI.
    ///
    /// Returns the PIDF XML body of the latest non-expired document,
    /// or None if no document exists for the entity.
    ///
    /// Args:
    ///     entity: Presentity URI to look up.
    ///
    /// Returns:
    ///     PIDF XML string, or None if not found.
    fn lookup(&self, entity: &str) -> Option<String> {
        self.store
            .get_presence(entity)
            .map(|document| document.body)
    }

    /// Subscribe to presence for a resource.
    ///
    /// Creates a new subscription in the presence store and returns the
    /// subscription ID. The subscription starts in Init state.
    ///
    /// Args:
    ///     subscriber: Watcher URI (e.g. "sip:bob@example.com").
    ///     resource: Presentity URI to watch (e.g. "sip:alice@example.com").
    ///     event: Event package name (default: "presence").
    ///     expires: Subscription duration in seconds (default: 3600).
    ///
    /// Returns:
    ///     Subscription ID string.
    #[pyo3(signature = (subscriber, resource, event="presence", expires=3600))]
    fn subscribe(
        &self,
        subscriber: &str,
        resource: &str,
        event: &str,
        expires: u64,
    ) -> String {
        let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
        let subscription = Subscription::new(
            subscription_id.clone(),
            subscriber.to_string(),
            resource.to_string(),
            event.to_string(),
            Duration::from_secs(expires),
            None,
            vec!["application/pidf+xml".to_string()],
        );
        self.store.add_subscription(subscription);
        subscription_id
    }

    /// Unsubscribe by subscription ID.
    ///
    /// Removes the subscription from the store entirely.
    ///
    /// Args:
    ///     subscription_id: The subscription ID returned by subscribe().
    ///
    /// Returns:
    ///     True if the subscription was found and removed, False otherwise.
    fn unsubscribe(&self, subscription_id: &str) -> bool {
        let exists = self.store.get_subscription(subscription_id).is_some();
        if exists {
            self.store.remove_subscription(subscription_id);
        }
        exists
    }

    /// List subscribers (watchers) for a resource.
    ///
    /// Returns active, non-expired subscriptions for the given resource URI.
    ///
    /// Args:
    ///     resource: Presentity URI to query.
    ///
    /// Returns:
    ///     List of dicts with keys: id, subscriber, event, state, remaining.
    fn subscribers<'py>(
        &self,
        python: Python<'py>,
        resource: &str,
    ) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let subscriptions = self.store.subscriptions_for(resource);
        let mut result = Vec::with_capacity(subscriptions.len());
        for subscription in subscriptions {
            let dict = PyDict::new(python);
            dict.set_item("id", &subscription.id)?;
            dict.set_item("subscriber", &subscription.subscriber)?;
            dict.set_item("event", &subscription.event)?;
            dict.set_item("state", subscription.state.to_string())?;
            dict.set_item("remaining", subscription.remaining_seconds())?;
            result.push(dict);
        }
        Ok(result)
    }

    /// Get the total number of subscriptions in the store.
    fn subscription_count(&self) -> usize {
        self.store.subscription_count()
    }

    /// Get the total number of entities with published documents.
    fn document_count(&self) -> usize {
        self.store.document_count()
    }

    /// Remove expired subscriptions and documents.
    fn expire_stale(&self) {
        self.store.expire_stale();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<PresenceStore> {
        Arc::new(PresenceStore::new())
    }

    #[test]
    fn publish_and_lookup() {
        let store = make_store();
        let presence = PyPresence::new(store);

        let etag = presence.publish("sip:alice@example.com", "<presence/>", 3600);
        assert!(!etag.is_empty());

        let body = presence.lookup("sip:alice@example.com");
        assert_eq!(body.as_deref(), Some("<presence/>"));
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert!(presence.lookup("sip:nobody@example.com").is_none());
    }

    #[test]
    fn subscribe_and_unsubscribe() {
        let store = make_store();
        let presence = PyPresence::new(store);

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "presence",
            3600,
        );
        assert!(subscription_id.starts_with("sub-"));
        assert_eq!(presence.subscription_count(), 1);

        let removed = presence.unsubscribe(&subscription_id);
        assert!(removed);
        assert_eq!(presence.subscription_count(), 0);
    }

    #[test]
    fn unsubscribe_nonexistent_returns_false() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert!(!presence.unsubscribe("sub-nonexistent"));
    }

    #[test]
    fn document_count() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert_eq!(presence.document_count(), 0);
        presence.publish("sip:alice@example.com", "<presence/>", 3600);
        assert_eq!(presence.document_count(), 1);
    }

    #[test]
    fn subscribe_default_event_and_expires() {
        let store = make_store();
        let presence = PyPresence::new(store.clone());

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "presence",
            3600,
        );

        let subscription = store.get_subscription(&subscription_id).unwrap();
        assert_eq!(subscription.event, "presence");
        assert_eq!(subscription.expires, Duration::from_secs(3600));
    }

    #[test]
    fn subscribe_custom_event() {
        let store = make_store();
        let presence = PyPresence::new(store.clone());

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "dialog",
            1800,
        );

        let subscription = store.get_subscription(&subscription_id).unwrap();
        assert_eq!(subscription.event, "dialog");
        assert_eq!(subscription.expires, Duration::from_secs(1800));
    }

    #[test]
    fn expire_stale_cleans_up() {
        let store = make_store();
        let presence = PyPresence::new(store);

        // Publish with zero expiry (immediately expired)
        presence.publish("sip:alice@example.com", "<presence/>", 0);
        assert_eq!(presence.document_count(), 1);

        presence.expire_stale();
        assert_eq!(presence.document_count(), 0);
    }
}
