//! PyO3 wrapper for outbound registration — exposed to Python as `registration`.
//!
//! Scripts use:
//! ```python
//! from siphon import registration
//!
//! registration.add("sip:bob@carrier.com", "sip:registrar.carrier.com",
//!                   user="bob", password="pass123", interval=3600)
//! registration.remove("sip:bob@carrier.com")
//! registration.refresh("sip:bob@carrier.com")
//!
//! for reg in registration.list():
//!     log.info(f"{reg['aor']}: {reg['state']} expires_in={reg['expires_in']}")
//! ```

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager};
use crate::transport::Transport;

/// Python-visible registration namespace.
#[pyclass(name = "RegistrationNamespace", skip_from_py_object)]
pub struct PyRegistration {
    inner: Arc<RegistrantManager>,
    _local_addr: std::net::SocketAddr,
}

impl PyRegistration {
    pub fn new(manager: Arc<RegistrantManager>, local_addr: std::net::SocketAddr) -> Self {
        Self {
            inner: manager,
            _local_addr: local_addr,
        }
    }
}

#[pymethods]
impl PyRegistration {
    /// Add a new outbound registration.
    ///
    /// Args:
    ///     aor: Address-of-Record (e.g. "sip:alice@carrier.com").
    ///     registrar: Registrar URI (e.g. "sip:registrar.carrier.com:5060").
    ///     user: Authentication username.
    ///     password: Authentication password.
    ///     interval: Registration interval in seconds (default: manager default).
    ///     realm: Optional realm hint (derived from 401 if omitted).
    ///     contact: Optional Contact URI (auto-generated if omitted).
    ///     transport: Transport protocol: "udp" (default), "tcp", "tls".
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (aor, registrar, /, user, password, interval=None, realm=None, contact=None, transport=None))]
    fn add(
        &self,
        aor: &str,
        registrar: &str,
        user: &str,
        password: &str,
        interval: Option<u32>,
        realm: Option<String>,
        contact: Option<String>,
        transport: Option<&str>,
    ) -> PyResult<()> {
        let transport_type = match transport {
            Some("tcp") => Transport::Tcp,
            Some("tls") => Transport::Tls,
            _ => Transport::Udp,
        };

        // Resolve registrar address from URI
        let registrar_host = registrar
            .strip_prefix("sip:")
            .or_else(|| registrar.strip_prefix("sips:"))
            .unwrap_or(registrar);

        let destination: std::net::SocketAddr = registrar_host
            .parse()
            .unwrap_or_else(|_| {
                // Try adding default port
                format!("{registrar_host}:5060")
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:5060".parse().unwrap())
            });

        let entry = RegistrantEntry::new(
            aor.to_string(),
            registrar.to_string(),
            destination,
            transport_type,
            RegistrantCredentials {
                username: user.to_string(),
                password: password.to_string(),
                realm,
            },
            interval.unwrap_or(self.inner.default_interval),
            contact,
        );

        self.inner.add(entry);
        Ok(())
    }

    /// Remove an outbound registration by AoR.
    fn remove(&self, aor: &str) -> bool {
        self.inner.remove(aor).is_some()
    }

    /// Force an immediate re-registration for an AoR.
    fn refresh(&self, aor: &str) -> bool {
        self.inner.refresh(aor)
    }

    /// List all registrations with their current state.
    ///
    /// Returns a list of dicts with keys: aor, state, expires_in.
    fn list<'py>(&self, python: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let entries = self.inner.list();
        let mut result = Vec::with_capacity(entries.len());
        for (aor, state, expires_in) in entries {
            let dict = PyDict::new(python);
            dict.set_item("aor", aor)?;
            dict.set_item("state", state.to_string())?;
            dict.set_item("expires_in", expires_in)?;
            result.push(dict);
        }
        Ok(result)
    }

    /// Get the state of a specific registration.
    ///
    /// Returns state string or None if not found.
    fn status(&self, aor: &str) -> Option<String> {
        self.inner.state(aor).map(|state| state.to_string())
    }

    /// Number of configured registrations.
    fn count(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_manager() -> Arc<RegistrantManager> {
        Arc::new(RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
        ))
    }

    #[test]
    fn py_registration_count_empty() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(py_reg.count(), 0);
    }

    #[test]
    fn py_registration_status_none_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(py_reg.status("sip:nobody@example.com").is_none());
    }

    #[test]
    fn py_registration_remove_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.remove("sip:nobody@example.com"));
    }

    #[test]
    fn py_registration_refresh_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.refresh("sip:nobody@example.com"));
    }
}
