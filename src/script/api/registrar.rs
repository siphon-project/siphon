//! PyO3 `registrar` namespace — bridges Python `registrar.save(request)` to the
//! Rust [`Registrar`] backend.
//!
//! The Python-side `registrar` singleton is replaced at startup with this Rust
//! object so that calls like `registrar.lookup(uri)` execute in Rust, not Python.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::registrar::{Contact, Registrar, RegistrarError, reginfo};
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::SipMessage;
use super::request::PyRequest;

/// Python-visible contact object returned from `registrar.lookup()`.
#[pyclass(name = "Contact", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyContact {
    /// The contact URI as a string.
    uri_string: String,
    /// Quality value (0.0–1.0).
    q_value: f32,
    /// Seconds remaining until this contact expires.
    expires_remaining: u64,
    /// Source address of the REGISTER (for NAT traversal routing).
    /// Format: "sip:ip:port;transport=proto" — like OpenSIPS received_avp.
    received_string: Option<String>,
}

#[pymethods]
impl PyContact {
    /// The contact URI as a string.
    #[getter]
    fn uri(&self) -> &str {
        &self.uri_string
    }

    /// Quality value (0.0–1.0).
    #[getter]
    fn q(&self) -> f32 {
        self.q_value
    }

    /// Seconds remaining until this contact expires.
    #[getter]
    fn expires(&self) -> u64 {
        self.expires_remaining
    }

    /// The received address (source IP:port of the REGISTER).
    ///
    /// Returns `None` if the contact was not saved with source address info.
    /// When present, this should be used for routing instead of `uri` — the
    /// Contact URI may contain a private/NAT address, while `received` has
    /// the actual reachable address (like OpenSIPS `received_avp`).
    #[getter]
    fn received(&self) -> Option<&str> {
        self.received_string.as_deref()
    }

    fn __str__(&self) -> &str {
        &self.uri_string
    }

    fn __repr__(&self) -> String {
        format!(
            "Contact(uri={}, q={}, expires={})",
            self.uri_string, self.q_value, self.expires_remaining
        )
    }
}

impl PyContact {
    pub fn from_rust_contact(contact: &Contact) -> Self {
        let received_string = contact.source_addr.map(|addr| {
            // Build a SIP URI from source address + transport, matching the
            // format OpenSIPS uses for its received_avp / $param(received).
            let transport = contact.source_transport.as_deref().unwrap_or("udp");
            format!("sip:{}:{};transport={}", addr.ip(), addr.port(), transport)
        });
        Self {
            uri_string: contact.uri.to_string(),
            q_value: contact.q,
            expires_remaining: contact.remaining_seconds(),
            received_string,
        }
    }
}

/// Python-visible registrar namespace.
///
/// Scripts use: `from siphon import registrar` then `registrar.save(request)`.
#[pyclass(name = "RegistrarNamespace")]
pub struct PyRegistrar {
    inner: Arc<Registrar>,
}

impl PyRegistrar {
    pub fn new(registrar: Arc<Registrar>) -> Self {
        Self { inner: registrar }
    }

    /// Access the inner Registrar for event subscription.
    pub fn registrar(&self) -> &Arc<Registrar> {
        &self.inner
    }

    /// Rust-side lookup by string (for tests and internal use).
    pub fn lookup_str(&self, uri: &str) -> Vec<PyContact> {
        let aor = normalize_aor(uri);
        self.inner
            .lookup(&aor)
            .iter()
            .map(PyContact::from_rust_contact)
            .collect()
    }

    /// Rust-side is_registered by string (for tests and internal use).
    pub fn is_registered_str(&self, uri: &str) -> bool {
        let aor = normalize_aor(uri);
        self.inner.is_registered(&aor)
    }
}

#[pymethods]
impl PyRegistrar {
    /// Save contact bindings from a REGISTER request.
    ///
    /// Extracts the AoR from the To header and the Contact header(s) from the
    /// message. If `force` is True, all existing contacts are removed first.
    #[pyo3(signature = (request, force=false))]
    fn save(&self, request: &PyRequest, force: bool) -> PyResult<()> {
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // AoR from To header, normalized to strip transport params etc.
        let aor = normalize_aor(&extract_aor(&message)?);

        if force {
            self.inner.clear_bindings(&aor);
        }

        // Check for wildcard Contact: *
        if let Some(contact_raw) = message.headers.get("Contact") {
            if contact_raw.trim() == "*" {
                self.inner.remove_all(&aor);
                return Ok(());
            }
        }

        // Extract source address for NAT traversal (like OpenSIPS received_avp).
        let source_addr = request.source_socket_addr();
        let source_transport = Some(request.transport_name().to_string());

        // Extract expires from Expires header or default
        let default_expires = message
            .headers
            .get("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(self.inner.config.default_expires);

        // Extract CSeq sequence number
        let cseq_seq = message
            .headers
            .cseq()
            .and_then(|raw| {
                crate::sip::headers::cseq::CSeq::parse(raw)
                    .ok()
                    .map(|cseq| cseq.sequence)
            })
            .unwrap_or(1);

        let call_id = message
            .headers
            .call_id()
            .cloned()
            .unwrap_or_default();

        // Parse Contact headers
        let contact_values = message
            .headers
            .get_all("Contact")
            .cloned()
            .unwrap_or_default();

        for raw in &contact_values {
            let nameaddrs = match NameAddr::parse_multi(raw) {
                Ok(addrs) => addrs,
                Err(_) => continue,
            };

            for nameaddr in nameaddrs {
                let expires = nameaddr
                    .expires
                    .unwrap_or(default_expires);
                let q = nameaddr.q.unwrap_or(1.0);

                self.inner
                    .save_with_source(
                        &aor,
                        nameaddr.uri,
                        expires,
                        q,
                        call_id.clone(),
                        cseq_seq,
                        source_addr,
                        source_transport.clone(),
                    )
                    .map_err(|error| match error {
                        RegistrarError::IntervalTooBrief { min_expires } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "423 Interval Too Brief (min: {min_expires}s)"
                            ))
                        }
                        RegistrarError::TooManyContacts { max } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "too many contacts (max: {max})"
                            ))
                        }
                    })?;
            }
        }

        Ok(())
    }

    /// Look up contacts for a URI string or SipUri.
    ///
    /// Returns a list of `Contact` objects sorted by q-value descending.
    /// Accepts either a string ("sip:alice@example.com") or a SipUri object.
    fn lookup(&self, uri: &Bound<'_, PyAny>) -> PyResult<Vec<PyContact>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner
            .lookup(&aor)
            .iter()
            .map(PyContact::from_rust_contact)
            .collect())
    }

    /// Force-expire (remove) all contacts for a URI.
    ///
    /// Used for explicit de-REGISTER handling (Expires: 0).
    /// Accepts either a string or a SipUri object.
    fn expire(&self, uri: &Bound<'_, PyAny>) -> PyResult<()> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        self.inner.remove_all(&aor);
        Ok(())
    }

    /// Check if a URI has any registered contacts.
    /// Accepts either a string or a SipUri object.
    fn is_registered(&self, uri: &Bound<'_, PyAny>) -> PyResult<bool> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.is_registered(&aor))
    }

    /// Get stored Service-Route headers for a URI (RFC 3608).
    ///
    /// Returns a list of Route URI strings, or an empty list if none stored.
    fn service_route(&self, uri: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.service_routes(&aor))
    }

    /// Store Service-Route headers for an AoR (RFC 3608).
    ///
    /// Called after SAR success in the S-CSCF to record the routes that
    /// subsequent requests from this UE should traverse.
    ///
    /// Args:
    ///     aor: Address-of-record string (e.g. ``"sip:alice@ims.example.com"``).
    ///     routes: List of Route URI strings.
    fn set_service_routes(&self, aor: &str, routes: Vec<String>) -> PyResult<()> {
        self.inner.set_service_routes(aor, routes);
        Ok(())
    }

    /// Save a contact in pending state (IMS: awaiting SAR confirmation).
    ///
    /// The contact is stored but marked as pending until `confirm_pending()`
    /// is called after SAR success.
    #[pyo3(signature = (request))]
    fn save_pending(&self, request: &PyRequest) -> PyResult<()> {
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        let aor = extract_aor(&message)?;

        let default_expires = message
            .headers
            .get("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(self.inner.config.default_expires);

        let cseq_seq = message
            .headers
            .cseq()
            .and_then(|raw| {
                crate::sip::headers::cseq::CSeq::parse(raw)
                    .ok()
                    .map(|cseq| cseq.sequence)
            })
            .unwrap_or(1);

        let call_id = message
            .headers
            .call_id()
            .cloned()
            .unwrap_or_default();

        let contact_values = message
            .headers
            .get_all("Contact")
            .cloned()
            .unwrap_or_default();

        for raw in &contact_values {
            let nameaddrs = match NameAddr::parse_multi(raw) {
                Ok(addrs) => addrs,
                Err(_) => continue,
            };
            for nameaddr in nameaddrs {
                let expires = nameaddr.expires.unwrap_or(default_expires);
                let q = nameaddr.q.unwrap_or(1.0);
                self.inner.save_pending(
                    &aor,
                    nameaddr.uri,
                    expires,
                    q,
                    call_id.clone(),
                    cseq_seq,
                );
            }
        }
        Ok(())
    }

    /// Confirm pending contacts for a URI (IMS: SAR succeeded).
    ///
    /// Promotes all pending contacts to active state.
    fn confirm_pending(&self, uri: &Bound<'_, PyAny>) -> PyResult<()> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        self.inner.confirm_pending(&aor);
        Ok(())
    }

    /// Look up stored P-Asserted-Identity for a URI.
    ///
    /// Returns the identity string if one was stored via SAR user profile,
    /// or None if not available.
    fn asserted_identity(&self, uri: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.asserted_identity(&aor))
    }

    /// Decorator to register a handler for registration state changes.
    ///
    /// The handler receives (aor, event_type, contacts) where:
    ///   - aor: str — Address of Record (e.g. "sip:alice@example.com")
    ///   - event_type: str — "registered", "refreshed", "deregistered", or "expired"
    ///   - contacts: list[Contact] — current contact bindings
    #[staticmethod]
    fn on_change(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("registrar.on_change", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Generate RFC 3680 reginfo XML for an AoR.
    ///
    /// Returns the XML document as a string. Used to build NOTIFY bodies
    /// for reg event subscriptions.
    ///
    /// Args:
    ///     aor: Address of Record (e.g. "sip:alice@example.com")
    ///     state: "full" or "partial" (default "full")
    ///     version: reginfo version counter (default 0)
    #[pyo3(signature = (aor, state="full", version=0))]
    fn reginfo_xml(&self, aor: &str, state: &str, version: u32) -> PyResult<String> {
        let aor = normalize_aor(aor);
        let contacts = self.inner.lookup(&aor);
        let reginfo_state = match state {
            "partial" => reginfo::ReginfoState::Partial,
            _ => reginfo::ReginfoState::Full,
        };
        let body = reginfo::build_full_reginfo(&aor, &contacts, version);
        // Override the state from the builder (which always uses Full)
        let body = reginfo::ReginfoBody {
            state: reginfo_state,
            ..body
        };
        Ok(body.to_xml())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the AoR (Address of Record) from the To header of a SIP message.
fn extract_aor(message: &SipMessage) -> PyResult<String> {
    let to_raw = message.headers.to().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("missing To header in REGISTER")
    })?;

    let nameaddr = NameAddr::parse(to_raw).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid To header: {error}"))
    })?;

    Ok(nameaddr.uri.to_string())
}

/// Extract a URI string from a Python argument.
///
/// Accepts either a plain string or any object with `__str__()` (e.g. PySipUri).
fn extract_uri_string(uri: &Bound<'_, PyAny>) -> PyResult<String> {
    // Try extracting as &str first (most common case)
    if let Ok(s) = uri.extract::<String>() {
        return Ok(s);
    }
    // Fall back to calling str() / __str__()
    let string_repr = uri.str()?;
    Ok(string_repr.to_string())
}

/// Normalize a URI string to an AoR format.
///
/// - If the input doesn't start with "sip:" or "sips:", prepend "sip:".
/// - Strip URI parameters (e.g. `transport=tls`) so that the same user@host
///   is always matched regardless of transport or other parameters.
/// - Strip the default port (:5060 for sip, :5061 for sips) so that
///   `sip:bob@host` and `sip:bob@host:5060` map to the same AoR.
fn normalize_aor(uri: &str) -> String {
    // Strip angle brackets first
    let uri = uri.trim_start_matches('<').trim_end_matches('>');

    let uri = if uri.starts_with("sip:") || uri.starts_with("sips:") {
        uri.to_string()
    } else {
        format!("sip:{uri}")
    };

    // Strip URI parameters (everything after ';') and headers (after '?')
    // AoR should be just scheme:user@host[:port]
    let uri = uri.split(';').next().unwrap_or(&uri).to_string();
    let uri = uri.split('?').next().unwrap_or(&uri).to_string();

    // Strip default port for consistent AoR matching
    if uri.starts_with("sips:") {
        uri.trim_end_matches(":5061").to_string()
    } else {
        uri.trim_end_matches(":5060").to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::RegistrarConfig;
    use crate::sip::uri::SipUri;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use std::sync::Mutex;

    fn make_registrar() -> Arc<Registrar> {
        Arc::new(Registrar::new(RegistrarConfig {
            default_expires: 3600,
            max_expires: 7200,
            min_expires: 60,
            max_contacts: 10,
        }))
    }

    fn make_register_request(
        to: &str,
        contact: &str,
        registrar: &Arc<Registrar>,
    ) -> (PyRequest, PyRegistrar) {
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to(to.to_string())
            .from(format!("{to};tag=reg-tag"))
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", contact.to_string())
            .content_length(0)
            .build()
            .unwrap();

        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        let py_registrar = PyRegistrar::new(Arc::clone(registrar));
        (request, py_registrar)
    }

    #[test]
    fn save_and_lookup() {
        let registrar = make_registrar();
        let (request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1:5060>", &registrar);

        py_reg.save(&request, false).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("alice"));
        assert!(contacts[0].uri().contains("10.0.0.1"));
        assert_eq!(contacts[0].q(), 1.0);
        assert!(contacts[0].expires() > 3500);
    }

    #[test]
    fn is_registered_after_save() {
        let registrar = make_registrar();
        let (request, py_reg) =
            make_register_request("<sip:bob@example.com>", "<sip:bob@10.0.0.2>", &registrar);

        assert!(!py_reg.is_registered_str("sip:bob@example.com"));
        py_reg.save(&request, false).unwrap();
        assert!(py_reg.is_registered_str("sip:bob@example.com"));
    }

    #[test]
    fn wildcard_deregister() {
        let registrar = make_registrar();
        let (request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);

        py_reg.save(&request, false).unwrap();
        assert!(py_reg.is_registered_str("sip:alice@example.com"));

        // Wildcard Contact: *
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dereg".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=dereg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("2 REGISTER".to_string())
            .header("Contact", "*".to_string())
            .header("Expires", "0".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let dereg_request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        py_reg.save(&dereg_request, false).unwrap();
        assert!(!py_reg.is_registered_str("sip:alice@example.com"));
    }

    #[test]
    fn force_save_clears_existing() {
        let registrar = make_registrar();
        let (request1, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);
        py_reg.save(&request1, false).unwrap();

        let (request2, _) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.2>", &registrar);
        py_reg.save(&request2, true).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("10.0.0.2"));
    }

    #[test]
    fn lookup_returns_empty_for_unknown() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(registrar);
        assert!(py_reg.lookup_str("sip:nobody@example.com").is_empty());
    }

    #[test]
    fn normalize_aor_adds_sip_prefix() {
        assert_eq!(normalize_aor("sip:alice@example.com"), "sip:alice@example.com");
        assert_eq!(normalize_aor("sips:alice@example.com"), "sips:alice@example.com");
        assert_eq!(normalize_aor("alice@example.com"), "sip:alice@example.com");
    }

    #[test]
    fn normalize_aor_strips_default_port() {
        assert_eq!(normalize_aor("sip:bob@127.0.0.1:5060"), "sip:bob@127.0.0.1");
        assert_eq!(normalize_aor("sip:bob@127.0.0.1:5080"), "sip:bob@127.0.0.1:5080");
        assert_eq!(normalize_aor("sips:bob@host:5061"), "sips:bob@host");
        assert_eq!(normalize_aor("sips:bob@host:5060"), "sips:bob@host:5060");
    }

    #[test]
    fn normalize_aor_strips_uri_params() {
        assert_eq!(
            normalize_aor("sip:alice@example.com;transport=tcp"),
            "sip:alice@example.com"
        );
        assert_eq!(
            normalize_aor("sip:alice@example.com:5060;transport=tls"),
            "sip:alice@example.com"
        );
        assert_eq!(
            normalize_aor("sip:alice@example.com:5061;transport=tls"),
            "sip:alice@example.com:5061"
        );
        assert_eq!(
            normalize_aor("<sip:alice@example.com;transport=tcp>"),
            "sip:alice@example.com"
        );
    }

    #[test]
    fn lookup_ignores_transport_param() {
        let registrar = make_registrar();
        let (request, py_reg) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1:5060>",
            &registrar,
        );
        py_reg.save(&request, false).unwrap();

        // Lookup with transport param should still find the contact
        let contacts = py_reg.lookup_str("sip:alice@example.com;transport=tcp");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("alice"));
    }

    #[test]
    fn py_contact_display() {
        let contact = PyContact {
            uri_string: "sip:alice@10.0.0.1".to_string(),
            q_value: 1.0,
            expires_remaining: 3600,
            received_string: None,
        };
        assert_eq!(contact.__str__(), "sip:alice@10.0.0.1");
        assert!(contact.__repr__().contains("q=1"));
    }

    #[test]
    fn contact_with_q_and_expires_params() {
        let registrar = make_registrar();
        let (request, py_reg) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1>;q=0.7;expires=1800",
            &registrar,
        );

        py_reg.save(&request, false).unwrap();
        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!((contacts[0].q() - 0.7).abs() < 0.01);
        // expires should be ~1800, not the default 3600
        assert!(contacts[0].expires() <= 1800);
        assert!(contacts[0].expires() > 1790);
    }

    #[test]
    fn expire_removes_all_contacts() {
        let registrar = make_registrar();
        let (request, py_reg) =
            make_register_request("<sip:carol@example.com>", "<sip:carol@10.0.0.3>", &registrar);

        py_reg.save(&request, false).unwrap();
        assert!(py_reg.is_registered_str("sip:carol@example.com"));

        // expire() should remove all contacts
        registrar.remove_all("sip:carol@example.com");
        assert!(!py_reg.is_registered_str("sip:carol@example.com"));
        assert!(py_reg.lookup_str("sip:carol@example.com").is_empty());
    }
}
