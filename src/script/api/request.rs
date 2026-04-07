//! PyO3 wrapper for SIP requests — the `Request` object passed to Python scripts.
//!
//! This is the primary interface between Python scripts and the Rust SIP engine.
//! Scripts interact with this object via `@proxy.on_request` handlers.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use pyo3::prelude::*;

use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::headers::route::RouteEntry;
use crate::sip::headers::via::Via;
use crate::sip::message::{SipMessage, StartLine};
use crate::sip::parser::parse_uri_standalone;
use crate::sip::uri::format_sip_host;
use super::sip_uri::PySipUri;

/// Shared list of local domains from config.
pub type LocalDomains = Arc<Vec<String>>;

/// The action the script chose for this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    /// No action taken — silent drop.
    None,
    /// Send a response.
    Reply { code: u16, reason: String },
    /// Relay to the Request-URI (or an explicit next-hop).
    Relay { next_hop: Option<String> },
    /// Fork to multiple targets.
    Fork {
        targets: Vec<String>,
        strategy: String,
    },
}

/// Python-visible SIP request object.
#[pyclass(name = "Request")]
pub struct PyRequest {
    message: Arc<Mutex<SipMessage>>,
    /// Transport protocol this request arrived on.
    transport_name: String,
    /// Source IP address.
    source_ip: String,
    /// Source port.
    source_port: u16,
    /// Whether Record-Route was requested.
    record_routed: bool,
    /// The action the script chose.
    action: RequestAction,
    /// Authenticated username (set after digest auth succeeds).
    auth_user: Option<String>,
    /// Local domains from config (for `ruri.is_local`).
    local_domains: Option<LocalDomains>,
    /// Transport override for Via header (set by `force_send_via`).
    via_transport_override: Option<String>,
    /// Target override for Via header (set by `force_send_via`).
    via_target_override: Option<String>,
    /// Per-relay on_reply callback (set by `relay(on_reply=...)`)
    on_reply_callback: Option<Py<PyAny>>,
    /// Per-relay on_failure callback (set by `relay(on_failure=...)`)
    on_failure_callback: Option<Py<PyAny>>,
    /// Extra headers to include in the response (set by `set_reply_header`).
    reply_headers: Vec<(String, String)>,
}

impl PyRequest {
    pub fn new(
        message: Arc<Mutex<SipMessage>>,
        transport_name: String,
        source_ip: String,
        source_port: u16,
    ) -> Self {
        Self {
            message,
            transport_name,
            source_ip,
            source_port,
            record_routed: false,
            action: RequestAction::None,
            auth_user: None,
            local_domains: None,
            via_transport_override: None,
            via_target_override: None,
            on_reply_callback: None,
            on_failure_callback: None,
            reply_headers: vec![],
        }
    }

    /// Create with local domain awareness for `ruri.is_local`.
    pub fn with_local_domains(
        message: Arc<Mutex<SipMessage>>,
        transport_name: String,
        source_ip: String,
        source_port: u16,
        local_domains: LocalDomains,
    ) -> Self {
        Self {
            message,
            transport_name,
            source_ip,
            source_port,
            record_routed: false,
            action: RequestAction::None,
            auth_user: None,
            local_domains: Some(local_domains),
            via_transport_override: None,
            via_target_override: None,
            on_reply_callback: None,
            on_failure_callback: None,
            reply_headers: vec![],
        }
    }

    /// Get the action the script chose.
    pub fn action(&self) -> &RequestAction {
        &self.action
    }

    /// Whether the script called record_route().
    pub fn is_record_routed(&self) -> bool {
        self.record_routed
    }

    /// Set the authenticated username (called from auth module after digest check).
    pub fn set_auth_user(&mut self, username: String) {
        self.auth_user = Some(username);
    }

    /// Get the authenticated username (Rust-side accessor).
    pub fn get_auth_user(&self) -> Option<&str> {
        self.auth_user.as_deref()
    }

    /// Set a reply action from Rust code (e.g., auth challenges).
    pub fn set_reply(&mut self, code: u16, reason: String) {
        self.action = RequestAction::Reply { code, reason };
    }

    /// Get the underlying SIP message.
    pub fn message(&self) -> Arc<Mutex<SipMessage>> {
        Arc::clone(&self.message)
    }

    /// Get the source IP as a string reference (Rust-side accessor).
    pub fn source_ip_str(&self) -> &str {
        &self.source_ip
    }

    /// Get the transport name (Rust-side accessor).
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    /// Get the source address as a SocketAddr (for registrar received tracking).
    pub fn source_socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.source_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, self.source_port))
    }

    /// Get Via transport override (set by `force_send_via`).
    pub fn via_transport_override(&self) -> Option<&str> {
        self.via_transport_override.as_deref()
    }

    /// Get Via target override (set by `force_send_via`).
    pub fn via_target_override(&self) -> Option<&str> {
        self.via_target_override.as_deref()
    }

    /// Take the per-relay on_reply callback (consumes it).
    pub fn take_on_reply_callback(&mut self) -> Option<Py<PyAny>> {
        self.on_reply_callback.take()
    }

    /// Take the per-relay on_failure callback (consumes it).
    pub fn take_on_failure_callback(&mut self) -> Option<Py<PyAny>> {
        self.on_failure_callback.take()
    }

    /// Take the accumulated reply headers (consumed by the dispatcher).
    pub fn take_reply_headers(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.reply_headers)
    }

    // --- CDR helper accessors (Rust-side, no PyResult) ---

    /// SIP method string for CDR.
    pub fn cdr_method(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_method, using poisoned guard");
                poisoned.into_inner()
            }
        };
        match &message.start_line {
            StartLine::Request(request_line) => request_line.method.as_str().to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    /// Call-ID for CDR.
    pub fn cdr_call_id(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_call_id, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.call_id().cloned().unwrap_or_default()
    }

    /// From URI string for CDR.
    pub fn cdr_from_uri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_from_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.from()
            .and_then(|v| NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
            .unwrap_or_default()
    }

    /// To URI string for CDR.
    pub fn cdr_to_uri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_to_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.to()
            .and_then(|v| NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
            .unwrap_or_default()
    }

    /// Request-URI string for CDR.
    pub fn cdr_ruri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_ruri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        match &message.start_line {
            StartLine::Request(request_line) => request_line.request_uri.to_string(),
            _ => String::new(),
        }
    }

    /// Source IP for CDR.
    pub fn cdr_source_ip(&self) -> String {
        self.source_ip.clone()
    }

    /// Transport name for CDR.
    pub fn cdr_transport(&self) -> String {
        self.transport_name.clone()
    }

    // --- LI helper accessors (Rust-side, no PyResult) ---

    /// SIP method for LI.
    pub fn li_method(&self) -> String {
        self.cdr_method()
    }

    /// Call-ID for LI correlation.
    pub fn li_call_id(&self) -> String {
        self.cdr_call_id()
    }

    /// From URI for LI target matching.
    pub fn li_from_uri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in li_from_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.from()
            .and_then(|v| NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
    }

    /// To URI for LI target matching.
    pub fn li_to_uri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in li_to_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.to()
            .and_then(|v| NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
    }

    /// Request-URI for LI target matching.
    pub fn li_ruri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in li_ruri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        match &message.start_line {
            StartLine::Request(request_line) => Some(request_line.request_uri.to_string()),
            _ => None,
        }
    }

    /// Source IP for LI target matching.
    pub fn li_source_ip(&self) -> Option<std::net::IpAddr> {
        self.source_ip.parse().ok()
    }
}

#[pymethods]
impl PyRequest {
    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /// SIP method as a string (e.g. "INVITE", "REGISTER").
    #[getter]
    fn method(&self) -> PyResult<String> {
        let message = self.lock()?;
        match &message.start_line {
            StartLine::Request(request_line) => Ok(request_line.method.as_str().to_string()),
            _ => Err(pyo3::exceptions::PyRuntimeError::new_err("not a request")),
        }
    }

    /// Request-URI as a PySipUri.
    #[getter]
    fn ruri(&self) -> PyResult<PySipUri> {
        let message = self.lock()?;
        match &message.start_line {
            StartLine::Request(request_line) => {
                let uri = request_line.request_uri.clone();
                match &self.local_domains {
                    Some(domains) => Ok(PySipUri::with_local_domains(uri, Arc::clone(domains))),
                    None => Ok(PySipUri::new(uri)),
                }
            }
            _ => Err(pyo3::exceptions::PyRuntimeError::new_err("not a request")),
        }
    }

    /// Set the Request-URI from a string ("sip:user@host:port") or a SipUri object.
    #[setter]
    fn set_ruri(&self, value: &Bound<'_, PyAny>) -> PyResult<()> {
        // Try extracting as PySipUri first
        if let Ok(py_uri) = value.cast::<PySipUri>() {
            let mut message = self.lock_mut()?;
            if let StartLine::Request(ref mut request_line) = message.start_line {
                request_line.request_uri = py_uri.borrow().inner().clone();
            }
            return Ok(());
        }
        // Fall back to string parsing
        let uri_string: String = value.extract().or_else(|_| {
            value.str().map(|s| s.to_string())
        }).map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "ruri must be a string or SipUri object"
            )
        })?;
        let parsed = parse_uri_standalone(&uri_string).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid SIP URI: {error}"))
        })?;
        let mut message = self.lock_mut()?;
        if let StartLine::Request(ref mut request_line) = message.start_line {
            request_line.request_uri = parsed;
        }
        Ok(())
    }

    /// From URI parsed from the From header.
    #[getter]
    #[allow(clippy::wrong_self_convention)]
    fn from_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.lock()?;
        Ok(parse_nameaddr_uri(message.headers.from()))
    }

    /// To URI parsed from the To header.
    #[getter]
    fn to_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.lock()?;
        Ok(parse_nameaddr_uri(message.headers.to()))
    }

    /// From-tag.
    #[getter]
    #[allow(clippy::wrong_self_convention)]
    fn from_tag(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(parse_nameaddr_tag(message.headers.from()))
    }

    /// To-tag (None for initial requests).
    #[getter]
    fn to_tag(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(parse_nameaddr_tag(message.headers.to()))
    }

    /// Call-ID header value.
    #[getter]
    fn call_id(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(message.headers.call_id().cloned())
    }

    /// CSeq as a tuple (sequence_number, method_string).
    #[getter]
    fn cseq(&self) -> PyResult<Option<(u32, String)>> {
        let message = self.lock()?;
        match message.headers.cseq() {
            Some(raw) => match CSeq::parse(raw) {
                Ok(cseq) => Ok(Some((cseq.sequence, cseq.method.as_str().to_string()))),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Whether the request is in-dialog (has both From-tag and To-tag).
    #[getter]
    fn in_dialog(&self) -> PyResult<bool> {
        let from_tag = self.from_tag()?;
        let to_tag = self.to_tag()?;
        Ok(from_tag.is_some() && to_tag.is_some())
    }

    /// Max-Forwards value.
    #[getter]
    fn max_forwards(&self) -> PyResult<u8> {
        let message = self.lock()?;
        Ok(message.headers.max_forwards().unwrap_or(70))
    }

    /// Message body as bytes, or None if empty.
    #[getter]
    fn body(&self) -> PyResult<Option<Vec<u8>>> {
        let message = self.lock()?;
        if message.body.is_empty() {
            Ok(None)
        } else {
            Ok(Some(message.body.clone()))
        }
    }

    /// Content-Type header value.
    #[getter]
    fn content_type(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(message.headers.content_type().cloned())
    }

    /// Transport protocol ("udp", "tcp", "tls", "ws", "wss").
    #[getter]
    fn transport(&self) -> String {
        self.transport_name.clone()
    }

    /// Source IP address.
    #[getter]
    fn source_ip(&self) -> String {
        self.source_ip.clone()
    }

    /// User-Agent header value.
    #[getter]
    fn user_agent(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(message.headers.get("User-Agent").cloned())
    }

    /// Authenticated username (set after digest auth succeeds).
    #[getter]
    fn auth_user(&self) -> Option<String> {
        self.auth_user.clone()
    }

    /// Contact expires value — from the Contact header `expires` parameter,
    /// or the `Expires` header, or `None` if neither is present.
    ///
    /// Used to classify REGISTER as de-register (expires == 0).
    #[getter]
    fn contact_expires(&self) -> PyResult<Option<u32>> {
        let message = self.lock()?;
        // Check Contact header for expires= parameter first
        if let Some(raw) = message.headers.get("Contact") {
            if let Ok(nameaddr) = NameAddr::parse(raw) {
                if let Some(expires) = nameaddr.expires {
                    return Ok(Some(expires));
                }
            }
        }
        // Fall back to Expires header
        Ok(message.headers.get("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok()))
    }

    /// Event header value (e.g. "reg", "presence").
    #[getter]
    fn event(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(message.headers.get("Event").cloned())
    }

    // -----------------------------------------------------------------------
    // Methods
    // -----------------------------------------------------------------------

    /// Send a response with the given status code and reason phrase.
    fn reply(&mut self, code: u16, reason: &str) {
        self.action = RequestAction::Reply {
            code,
            reason: reason.to_string(),
        };
    }

    /// Relay the request to its Request-URI, or to an explicit next-hop.
    ///
    /// Optional callbacks:
    /// - `on_reply`: called with `(request, reply)` when a response arrives
    /// - `on_failure`: called with `(request, code, reason)` on error response
    #[pyo3(signature = (next_hop=None, on_reply=None, on_failure=None))]
    fn relay(
        &mut self,
        next_hop: Option<String>,
        on_reply: Option<Py<PyAny>>,
        on_failure: Option<Py<PyAny>>,
    ) {
        self.on_reply_callback = on_reply;
        self.on_failure_callback = on_failure;
        self.action = RequestAction::Relay { next_hop };
    }

    /// Fork to multiple targets.
    #[pyo3(signature = (targets, strategy="parallel"))]
    fn fork(&mut self, targets: Vec<String>, strategy: &str) {
        self.action = RequestAction::Fork {
            targets,
            strategy: strategy.to_string(),
        };
    }

    /// Mark that Record-Route should be inserted.
    fn record_route(&mut self) {
        self.record_routed = true;
    }

    /// Process loose routing per RFC 3261 §16.4 / §16.12.
    ///
    /// Checks whether the top Route header points to **this** server
    /// (matches a configured domain/address) and has the `lr` parameter.
    /// If so, removes it (and any subsequent Routes that also match us)
    /// and returns `True`.  Otherwise returns `False` with Routes intact.
    ///
    /// Per RFC 3261 §16.4, a proxy MUST only consume Route entries that
    /// identify itself.  A Route addressed to another server (e.g. the
    /// S-CSCF Route seen by a TAS) must be left for relay().
    fn loose_route(&self) -> PyResult<bool> {
        let mut message = self.lock_mut()?;

        // No Route header at all — nothing to consume, relay to R-URI.
        if message.headers.get("Route").is_none() {
            return Ok(true);
        }

        // Check if top Route has ;lr
        let is_lr = crate::proxy::core::check_loose_route(&message.headers);
        if !is_lr {
            return Ok(false);
        }

        // Per RFC 3261 §16.4: only consume Route entries that identify *this*
        // server.  If the top Route host doesn't match our local domains,
        // leave it intact — relay() will forward to it.
        if let Some(ref domains) = self.local_domains {
            let top_is_local = crate::proxy::core::top_route_is_local(
                &message.headers, domains,
            );
            if !top_is_local {
                return Ok(false);
            }
        }

        // Pop the first (topmost) Route — it was addressed to us.
        crate::proxy::core::pop_top_route(&mut message.headers);

        // Pop any additional Routes that also point to us (double
        // Record-Route from transport bridging).
        if let Some(ref domains) = self.local_domains {
            crate::proxy::core::pop_local_routes(&mut message.headers, domains);
        }
        Ok(true)
    }

    /// Get the first value of a header, or None.
    fn get_header(&self, name: &str) -> PyResult<Option<String>> {
        let message = self.lock()?;
        Ok(message.headers.get(name).cloned())
    }

    /// Alias for get_header (confirmed: CNAM-AS script).
    fn header(&self, name: &str) -> PyResult<Option<String>> {
        self.get_header(name)
    }

    /// Set (replace) a header value on the request message.
    fn set_header(&self, name: &str, value: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        message.headers.set(name, value.to_string());
        Ok(())
    }

    /// Set an extra header to include in the response (200 OK, 401, etc.).
    ///
    /// Unlike ``set_header`` which modifies the request, this stores headers
    /// that the dispatcher injects into the reply built by ``request.reply()``
    /// or ``registrar.save()``.  Multiple calls with the same name append
    /// (multi-value headers like P-Associated-URI, Service-Route).
    fn set_reply_header(&mut self, name: &str, value: &str) {
        self.reply_headers.push((name.to_string(), value.to_string()));
    }

    /// Remove a header entirely.
    fn remove_header(&self, name: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        message.headers.remove(name);
        Ok(())
    }

    /// Remove all headers whose names start with a given prefix (case-insensitive).
    fn remove_headers_matching(&self, prefix: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        let prefix_lower = prefix.to_lowercase();
        let names_to_remove: Vec<String> = message.headers.names()
            .iter()
            .filter(|name| name.to_lowercase().starts_with(&prefix_lower))
            .map(|name| name.to_string())
            .collect();
        for name in names_to_remove {
            message.headers.remove(&name);
        }
        Ok(())
    }

    /// Check if a header exists.
    fn has_header(&self, name: &str) -> PyResult<bool> {
        let message = self.lock()?;
        Ok(message.headers.has(name))
    }

    /// Check if the body matches a given content type.
    fn has_body(&self, content_type: &str) -> PyResult<bool> {
        let message = self.lock()?;
        if message.body.is_empty() {
            return Ok(false);
        }
        Ok(message
            .headers
            .content_type()
            .map(|ct| ct.starts_with(content_type))
            .unwrap_or(false))
    }

    // -----------------------------------------------------------------------
    // R-URI mutation
    // -----------------------------------------------------------------------

    /// Set the user part of the Request-URI.
    fn set_ruri_user(&self, value: Option<String>) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let StartLine::Request(ref mut request_line) = message.start_line {
            request_line.request_uri.user = value;
        }
        Ok(())
    }

    /// Set the host part of the Request-URI.
    fn set_ruri_host(&self, value: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let StartLine::Request(ref mut request_line) = message.start_line {
            request_line.request_uri.host = value.to_string();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Header manipulation
    // -----------------------------------------------------------------------

    /// Set a header only if it is not already present.
    fn ensure_header(&self, name: &str, value: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if !message.headers.has(name) {
            message.headers.set(name, value.to_string());
        }
        Ok(())
    }

    /// Remove a specific value from a multi-value (comma-separated) header.
    ///
    /// If the header contains `"A, B, C"` and you remove `"B"`, the result is `"A, C"`.
    /// Matching is case-insensitive and whitespace-trimmed.
    fn remove_from_header_list(&self, name: &str, value: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let Some(values) = message.headers.get_all(name) {
            let mut remaining = Vec::new();
            for header_value in values {
                for part in header_value.split(',') {
                    let part = part.trim();
                    if !part.eq_ignore_ascii_case(value.trim()) {
                        remaining.push(part.to_string());
                    }
                }
            }
            if remaining.is_empty() {
                message.headers.remove(name);
            } else {
                message.headers.set(name, remaining.join(", "));
            }
        }
        Ok(())
    }

    /// Prepend a `Path: <uri;lr>` header.
    fn add_path(&self, uri: &str) -> PyResult<()> {
        let path_value = format!("<{uri};lr>");
        let mut message = self.lock_mut()?;
        let existing = message.headers.get("Path").cloned();
        match existing {
            Some(old) => message.headers.set("Path", format!("{path_value}, {old}")),
            None => message.headers.set("Path", path_value),
        }
        Ok(())
    }

    /// Prepend a `Route: <uri;lr>` header.
    fn prepend_route(&self, uri: &str) -> PyResult<()> {
        let route_value = format!("<{uri};lr>");
        let mut message = self.lock_mut()?;
        let existing = message.headers.get("Route").cloned();
        match existing {
            Some(old) => message.headers.set("Route", format!("{route_value}, {old}")),
            None => message.headers.set("Route", route_value),
        }
        Ok(())
    }

    /// Rewrite the display name in the From header.
    fn set_from_display(&self, display_name: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        rewrite_display_name(&mut message, "From", display_name)
    }

    /// Rewrite the display name in the To header.
    fn set_to_display(&self, display_name: &str) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        rewrite_display_name(&mut message, "To", display_name)
    }

    /// Append `;alias` parameter to the Contact URI for NAT traversal.
    fn add_contact_alias(&self) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let Some(raw) = message.headers.get("Contact").cloned() {
            if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
                nameaddr.uri.params.push(("alias".to_string(), None));
                message.headers.set("Contact", nameaddr.to_string());
            }
        }
        Ok(())
    }

    /// User part of the top Route header URI, or None.
    #[getter]
    fn route_user(&self) -> PyResult<Option<String>> {
        let message = self.lock()?;
        if let Some(raw) = message.headers.get("Route") {
            if let Ok(entry) = RouteEntry::parse(raw.split(',').next().unwrap_or(raw)) {
                return Ok(entry.uri.user);
            }
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // NAT fixup
    // -----------------------------------------------------------------------

    /// Fix NAT for REGISTER: add `received=` and `rport=` to the top Via
    /// using the actual source IP and port.
    fn fix_nated_register(&self) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let Some(raw_via) = message.headers.get("Via").cloned() {
            if let Ok(mut via) = Via::parse(&raw_via) {
                via.received = Some(self.source_ip.clone());
                via.rport = Some(Some(self.source_port));
                message.headers.set("Via", via.to_string());
            }
        }
        Ok(())
    }

    /// Fix NAT for Contact: rewrite Contact URI host:port with source IP:port.
    fn fix_nated_contact(&self) -> PyResult<()> {
        let mut message = self.lock_mut()?;
        if let Some(raw) = message.headers.get("Contact").cloned() {
            if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
                nameaddr.uri.host = format_sip_host(&self.source_ip);
                nameaddr.uri.port = Some(self.source_port);
                message.headers.set("Contact", nameaddr.to_string());
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Transport control
    // -----------------------------------------------------------------------

    /// Force the Via header to use a specific transport and target for sending.
    fn force_send_via(&mut self, transport: &str, target: &str) {
        self.via_transport_override = Some(transport.to_string());
        self.via_target_override = Some(target.to_string());
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /// Generate a unique ICID for P-Charging-Vector.
    fn generate_icid(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Check if the source IP is within any of the given CIDR ranges.
    ///
    /// Example: `request.source_ip_in(["10.0.0.0/8", "172.16.0.0/12"])`
    fn source_ip_in(&self, cidr_list: Vec<String>) -> PyResult<bool> {
        let source_ip: IpAddr = self
            .source_ip
            .parse()
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(format!("bad source IP: {error}")))?;
        for cidr in &cidr_list {
            if let Ok(network) = cidr.parse::<IpNet>() {
                if network.contains(&source_ip) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

impl PyRequest {
    fn lock(&self) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
        self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })
    }

    fn lock_mut(&self) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
        self.lock()
    }
}

/// Rewrite the display name in a From or To header.
fn rewrite_display_name(
    message: &mut SipMessage,
    header_name: &str,
    display_name: &str,
) -> PyResult<()> {
    if let Some(raw) = message.headers.get(header_name).cloned() {
        if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
            nameaddr.display_name = Some(display_name.to_string());
            message.headers.set(header_name, nameaddr.to_string());
        }
    }
    Ok(())
}

/// Parse a NameAddr from a raw header value and extract the URI.
fn parse_nameaddr_uri(raw: Option<&String>) -> Option<PySipUri> {
    raw.and_then(|value| NameAddr::parse(value).ok())
        .map(|nameaddr| PySipUri::new(nameaddr.uri))
}

/// Parse a NameAddr from a raw header value and extract the tag.
fn parse_nameaddr_tag(raw: Option<&String>) -> Option<String> {
    raw.and_then(|value| NameAddr::parse(value).ok())
        .and_then(|nameaddr| nameaddr.tag)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::headers::SipHeaders;
    use crate::sip::message::{Method, RequestLine, StartLine, Version};
    use crate::sip::uri::SipUri;

    fn invite_request_message() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("\"Alice\" <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33".to_string())
            .cseq("314159 INVITE".to_string())
            .max_forwards(70)
            .header("User-Agent", "SIPhon/0.1".to_string())
            .header("Event", "reg".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn make_request() -> PyRequest {
        let message = Arc::new(Mutex::new(invite_request_message()));
        PyRequest::new(message, "udp".to_string(), "10.0.0.1".to_string(), 5060)
    }

    #[test]
    fn method_returns_invite() {
        let request = make_request();
        assert_eq!(request.method().unwrap(), "INVITE");
    }

    #[test]
    fn ruri_properties() {
        let request = make_request();
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().user.as_deref(), Some("bob"));
        assert_eq!(ruri.inner().host, "biloxi.com");
    }

    #[test]
    fn from_uri_and_tag() {
        let request = make_request();
        let from = request.from_uri().unwrap().unwrap();
        assert_eq!(from.inner().user.as_deref(), Some("alice"));
        assert_eq!(from.inner().host, "atlanta.com");
        assert_eq!(request.from_tag().unwrap().as_deref(), Some("1928301774"));
    }

    #[test]
    fn to_uri_and_no_tag() {
        let request = make_request();
        let to = request.to_uri().unwrap().unwrap();
        assert_eq!(to.inner().user.as_deref(), Some("bob"));
        // Initial INVITE has no To-tag
        assert_eq!(request.to_tag().unwrap(), None);
    }

    #[test]
    fn call_id_accessor() {
        let request = make_request();
        assert_eq!(
            request.call_id().unwrap().as_deref(),
            Some("a84b4c76e66710@pc33")
        );
    }

    #[test]
    fn cseq_returns_tuple() {
        let request = make_request();
        let (seq, method) = request.cseq().unwrap().unwrap();
        assert_eq!(seq, 314159);
        assert_eq!(method, "INVITE");
    }

    #[test]
    fn in_dialog_false_for_initial_request() {
        let request = make_request();
        assert!(!request.in_dialog().unwrap());
    }

    #[test]
    fn in_dialog_true_when_both_tags() {
        let message = SipMessageBuilder::new()
            .request(Method::Bye, SipUri::new("biloxi.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bye".to_string())
            .to("<sip:bob@biloxi.com>;tag=bob-tag".to_string())
            .from("<sip:alice@atlanta.com>;tag=alice-tag".to_string())
            .call_id("dialog-call".to_string())
            .cseq("2 BYE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "tcp".to_string(),
            "10.0.0.2".to_string(),
            5060,
        );
        assert!(request.in_dialog().unwrap());
    }

    #[test]
    fn max_forwards_accessor() {
        let request = make_request();
        assert_eq!(request.max_forwards().unwrap(), 70);
    }

    #[test]
    fn body_none_when_empty() {
        let request = make_request();
        assert!(request.body().unwrap().is_none());
    }

    #[test]
    fn transport_and_source_ip() {
        let request = make_request();
        assert_eq!(request.transport(), "udp");
        assert_eq!(request.source_ip(), "10.0.0.1");
    }

    #[test]
    fn user_agent_accessor() {
        let request = make_request();
        assert_eq!(request.user_agent().unwrap().as_deref(), Some("SIPhon/0.1"));
    }

    #[test]
    fn event_accessor() {
        let request = make_request();
        assert_eq!(request.event().unwrap().as_deref(), Some("reg"));
    }

    #[test]
    fn reply_sets_action() {
        let mut request = make_request();
        request.reply(200, "OK");
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 200,
                reason: "OK".to_string()
            }
        );
    }

    #[test]
    fn relay_sets_action() {
        let mut request = make_request();
        request.relay(None, None, None);
        assert_eq!(
            *request.action(),
            RequestAction::Relay { next_hop: None }
        );
    }

    #[test]
    fn relay_with_next_hop() {
        let mut request = make_request();
        request.relay(Some("sip:proxy@next.com:5060".to_string()), None, None);
        assert_eq!(
            *request.action(),
            RequestAction::Relay {
                next_hop: Some("sip:proxy@next.com:5060".to_string())
            }
        );
    }

    #[test]
    fn fork_sets_action() {
        let mut request = make_request();
        request.fork(
            vec!["sip:a@host".to_string(), "sip:b@host".to_string()],
            "sequential",
        );
        assert_eq!(
            *request.action(),
            RequestAction::Fork {
                targets: vec!["sip:a@host".to_string(), "sip:b@host".to_string()],
                strategy: "sequential".to_string(),
            }
        );
    }

    #[test]
    fn record_route_flag() {
        let mut request = make_request();
        assert!(!request.is_record_routed());
        request.record_route();
        assert!(request.is_record_routed());
    }

    #[test]
    fn loose_route_no_route_header() {
        let request = make_request();
        assert!(request.loose_route().unwrap());
    }

    #[test]
    fn loose_route_non_local_route_not_consumed() {
        // RFC 3261 §16.4: a proxy must only consume Routes that match itself.
        // A TAS (domain 172.16.0.152) receiving a Route to scscf.example.com
        // must NOT consume it — relay() should follow the Route to the S-CSCF.
        let message = SipMessage {
            start_line: StartLine::Request(RequestLine {
                method: Method::Invite,
                request_uri: crate::sip::uri::SipUri::new("example.com".to_string()),
                version: Version::sip_2_0(),
            }),
            headers: {
                let mut headers = SipHeaders::new();
                headers.add("Via", "SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1".into());
                headers.add("Route", "<sip:orig@scscf.example.com;lr>".into());
                headers
            },
            body: vec![],
        };
        let local_domains = Arc::new(vec!["172.16.0.152".to_string()]);
        let request = PyRequest::with_local_domains(
            Arc::new(Mutex::new(message)),
            "tcp".to_string(),
            "10.0.0.1".to_string(),
            5060,
            local_domains,
        );

        // loose_route() should return false — Route doesn't match us
        assert!(!request.loose_route().unwrap());

        // Route header must still be intact
        let msg_arc = request.message();
        let msg = msg_arc.lock().unwrap();
        assert!(msg.headers.get("Route").is_some());
    }

    #[test]
    fn loose_route_local_route_consumed() {
        // When the Route DOES match our domain, consume it normally.
        let message = SipMessage {
            start_line: StartLine::Request(RequestLine {
                method: Method::Invite,
                request_uri: crate::sip::uri::SipUri::new("bob.example.com".to_string()),
                version: Version::sip_2_0(),
            }),
            headers: {
                let mut headers = SipHeaders::new();
                headers.add("Via", "SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1".into());
                headers.add("Route", "<sip:orig@scscf.example.com;lr>".into());
                headers
            },
            body: vec![],
        };
        let local_domains = Arc::new(vec!["scscf.example.com".to_string()]);
        let request = PyRequest::with_local_domains(
            Arc::new(Mutex::new(message)),
            "tcp".to_string(),
            "10.0.0.1".to_string(),
            5060,
            local_domains,
        );

        // loose_route() should return true and consume the Route
        assert!(request.loose_route().unwrap());

        // Route header should be gone
        let msg_arc = request.message();
        let msg = msg_arc.lock().unwrap();
        assert!(msg.headers.get("Route").is_none());
    }

    #[test]
    fn header_operations() {
        let request = make_request();
        assert!(request.has_header("Via").unwrap());
        assert!(!request.has_header("X-Custom").unwrap());

        request.set_header("X-Custom", "value").unwrap();
        assert_eq!(
            request.get_header("X-Custom").unwrap(),
            Some("value".to_string())
        );
        assert_eq!(
            request.header("X-Custom").unwrap(),
            Some("value".to_string())
        );

        request.remove_header("X-Custom").unwrap();
        assert!(!request.has_header("X-Custom").unwrap());
    }

    #[test]
    fn remove_headers_matching_prefix() {
        let request = make_request();
        request.set_header("X-Foo", "1").unwrap();
        request.set_header("X-Bar", "2").unwrap();
        request.set_header("P-Custom", "3").unwrap();

        request.remove_headers_matching("X-").unwrap();
        assert!(!request.has_header("X-Foo").unwrap());
        assert!(!request.has_header("X-Bar").unwrap());
        assert!(request.has_header("P-Custom").unwrap());
    }

    #[test]
    fn has_body_false_when_empty() {
        let request = make_request();
        assert!(!request.has_body("application/sdp").unwrap());
    }

    #[test]
    fn auth_user_default_none() {
        let request = make_request();
        assert!(request.auth_user().is_none());
    }

    #[test]
    fn set_auth_user() {
        let mut request = make_request();
        request.set_auth_user("alice".to_string());
        assert_eq!(request.auth_user(), Some("alice".to_string()));
    }

    #[test]
    fn default_action_is_none() {
        let request = make_request();
        assert_eq!(*request.action(), RequestAction::None);
    }

    // --- R-URI mutation tests ---

    #[test]
    fn set_ruri_user_changes_request_uri() {
        let request = make_request();
        request.set_ruri_user(Some("newuser".to_string())).unwrap();
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().user.as_deref(), Some("newuser"));
    }

    #[test]
    fn set_ruri_user_to_none() {
        let request = make_request();
        request.set_ruri_user(None).unwrap();
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().user, None);
    }

    #[test]
    fn set_ruri_host_changes_request_uri() {
        let request = make_request();
        request.set_ruri_host("newhost.com").unwrap();
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().host, "newhost.com");
    }

    // --- Header manipulation tests ---

    #[test]
    fn ensure_header_sets_when_absent() {
        let request = make_request();
        request.ensure_header("X-New", "value").unwrap();
        assert_eq!(request.get_header("X-New").unwrap(), Some("value".to_string()));
    }

    #[test]
    fn ensure_header_skips_when_present() {
        let request = make_request();
        request.set_header("X-Existing", "original").unwrap();
        request.ensure_header("X-Existing", "replacement").unwrap();
        assert_eq!(request.get_header("X-Existing").unwrap(), Some("original".to_string()));
    }

    #[test]
    fn remove_from_header_list_removes_one_value() {
        let request = make_request();
        request.set_header("X-Multi", "A, B, C").unwrap();
        request.remove_from_header_list("X-Multi", "B").unwrap();
        assert_eq!(request.get_header("X-Multi").unwrap(), Some("A, C".to_string()));
    }

    #[test]
    fn remove_from_header_list_removes_all() {
        let request = make_request();
        request.set_header("X-Solo", "only").unwrap();
        request.remove_from_header_list("X-Solo", "only").unwrap();
        assert!(!request.has_header("X-Solo").unwrap());
    }

    #[test]
    fn add_path_prepends() {
        let request = make_request();
        request.add_path("sip:proxy1.example.com").unwrap();
        let path = request.get_header("Path").unwrap().unwrap();
        assert!(path.starts_with("<sip:proxy1.example.com;lr>"));
    }

    #[test]
    fn add_path_prepends_before_existing() {
        let request = make_request();
        request.set_header("Path", "<sip:old.example.com;lr>").unwrap();
        request.add_path("sip:new.example.com").unwrap();
        let path = request.get_header("Path").unwrap().unwrap();
        assert!(path.starts_with("<sip:new.example.com;lr>"));
        assert!(path.contains("old.example.com"));
    }

    #[test]
    fn prepend_route_adds_before_existing() {
        let request = make_request();
        request.set_header("Route", "<sip:proxy2.example.com;lr>").unwrap();
        request.prepend_route("sip:proxy1.example.com").unwrap();
        let route = request.get_header("Route").unwrap().unwrap();
        assert!(route.starts_with("<sip:proxy1.example.com;lr>"));
        assert!(route.contains("proxy2.example.com"));
    }

    #[test]
    fn set_from_display_rewrites_display_name() {
        let request = make_request();
        request.set_from_display("New Name").unwrap();
        let from = request.get_header("From").unwrap().unwrap();
        assert!(from.contains("\"New Name\""));
        assert!(from.contains("alice@atlanta.com"));
    }

    #[test]
    fn set_to_display_rewrites_display_name() {
        let request = make_request();
        request.set_to_display("Robert").unwrap();
        let to = request.get_header("To").unwrap().unwrap();
        assert!(to.contains("\"Robert\""));
        assert!(to.contains("bob@biloxi.com"));
    }

    #[test]
    fn add_contact_alias_appends_param() {
        let request = make_request();
        request.set_header("Contact", "<sip:alice@10.0.0.1:5060>").unwrap();
        request.add_contact_alias().unwrap();
        let contact = request.get_header("Contact").unwrap().unwrap();
        assert!(contact.contains(";alias"));
    }

    #[test]
    fn route_user_returns_user_part() {
        let request = make_request();
        request.set_header("Route", "<sip:service@proxy.example.com;lr>").unwrap();
        assert_eq!(request.route_user().unwrap(), Some("service".to_string()));
    }

    #[test]
    fn route_user_none_when_no_route() {
        let request = make_request();
        request.remove_header("Route").unwrap();
        assert_eq!(request.route_user().unwrap(), None);
    }

    // --- NAT fixup tests ---

    #[test]
    fn fix_nated_register_adds_received_and_rport() {
        let request = make_request();
        request.fix_nated_register().unwrap();
        let via = request.get_header("Via").unwrap().unwrap();
        assert!(via.contains("received=10.0.0.1"));
        assert!(via.contains("rport=5060"));
    }

    #[test]
    fn fix_nated_contact_rewrites_contact_uri() {
        let request = make_request();
        request.set_header("Contact", "<sip:alice@192.168.1.100:6000>").unwrap();
        request.fix_nated_contact().unwrap();
        let contact = request.get_header("Contact").unwrap().unwrap();
        assert!(contact.contains("10.0.0.1"));
        assert!(contact.contains(":5060"));
    }

    // --- Transport control tests ---

    #[test]
    fn force_send_via_sets_overrides() {
        let mut request = make_request();
        request.force_send_via("tcp", "10.0.0.2:5060");
        assert_eq!(request.via_transport_override(), Some("tcp"));
        assert_eq!(request.via_target_override(), Some("10.0.0.2:5060"));
    }

    // --- Utility tests ---

    #[test]
    fn generate_icid_returns_uuid() {
        let request = make_request();
        let icid = request.generate_icid();
        assert_eq!(icid.len(), 36); // UUID v4 format: 8-4-4-4-12
        assert!(icid.contains('-'));
    }

    #[test]
    fn source_ip_in_matching_cidr() {
        let request = make_request(); // source_ip = "10.0.0.1"
        assert!(request
            .source_ip_in(vec!["10.0.0.0/8".to_string()])
            .unwrap());
    }

    #[test]
    fn source_ip_in_non_matching_cidr() {
        let request = make_request(); // source_ip = "10.0.0.1"
        assert!(!request
            .source_ip_in(vec!["192.168.0.0/16".to_string()])
            .unwrap());
    }

    #[test]
    fn source_ip_in_multiple_cidrs() {
        let request = make_request();
        assert!(request
            .source_ip_in(vec![
                "192.168.0.0/16".to_string(),
                "10.0.0.0/8".to_string(),
            ])
            .unwrap());
    }

    #[test]
    fn source_ip_in_empty_list() {
        let request = make_request();
        assert!(!request.source_ip_in(vec![]).unwrap());
    }

    // --- R-URI setter tests ---

    #[test]
    fn set_ruri_from_string() {
        let request = make_request();
        // Use the Rust-level method directly (bypasses PyO3 Bound)
        let parsed = crate::sip::parser::parse_uri_standalone("sip:newuser@newhost.com:5080").unwrap();
        {
            let message_arc = request.message();
            let mut message = message_arc.lock().unwrap();
            if let StartLine::Request(ref mut request_line) = message.start_line {
                request_line.request_uri = parsed;
            }
        }
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().user.as_deref(), Some("newuser"));
        assert_eq!(ruri.inner().host, "newhost.com");
        assert_eq!(ruri.inner().port, Some(5080));
    }

    #[test]
    fn set_ruri_from_sip_uri() {
        let request = make_request();
        let new_uri = SipUri::new("replacement.com".to_string()).with_user("carol".to_string());
        {
            let message_arc = request.message();
            let mut message = message_arc.lock().unwrap();
            if let StartLine::Request(ref mut request_line) = message.start_line {
                request_line.request_uri = new_uri;
            }
        }
        let ruri = request.ruri().unwrap();
        assert_eq!(ruri.inner().user.as_deref(), Some("carol"));
        assert_eq!(ruri.inner().host, "replacement.com");
    }

    // --- contact_expires tests ---

    #[test]
    fn contact_expires_from_expires_header() {
        let message = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=reg".to_string())
            .call_id("reg-call".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:alice@10.0.0.1>".to_string())
            .header("Expires", "3600".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(), "10.0.0.1".to_string(), 5060,
        );
        assert_eq!(request.contact_expires().unwrap(), Some(3600));
    }

    #[test]
    fn contact_expires_zero_for_deregister() {
        let message = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dereg".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=dereg".to_string())
            .call_id("dereg-call".to_string())
            .cseq("2 REGISTER".to_string())
            .header("Contact", "*".to_string())
            .header("Expires", "0".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(), "10.0.0.1".to_string(), 5060,
        );
        assert_eq!(request.contact_expires().unwrap(), Some(0));
    }

    #[test]
    fn contact_expires_none_when_absent() {
        let request = make_request(); // INVITE has no Expires
        assert_eq!(request.contact_expires().unwrap(), None);
    }
}
