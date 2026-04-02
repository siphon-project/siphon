//! Proxy namespace utility methods — rate limiting, sanity checking, ENUM lookup.
//!
//! These are injected onto the Python `proxy` namespace alongside the
//! decorator methods defined in `siphon_package.py`.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::headers::cseq::CSeq;
use crate::sip::message::{Method, StartLine};
use crate::sip::parser::parse_uri_standalone;
use crate::transport::Transport;
use crate::uac::UacSender;

use super::request::PyRequest;

/// Global UacSender — set once from main.rs after transport channels are ready.
static UAC_SENDER: OnceLock<Arc<UacSender>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Deferred message queue — ensures NOTIFY is sent after the reply (RFC 3265)
// ---------------------------------------------------------------------------

use crate::sip::message::SipMessage;

/// A message waiting to be sent after the current reply is dispatched.
pub struct DeferredMessage {
    pub message: SipMessage,
    pub destination: std::net::SocketAddr,
    pub transport: Transport,
}

thread_local! {
    /// When a request handler is active, deferred messages are queued here
    /// and flushed by the dispatcher after the reply is sent.
    static DEFERRED_SENDS: std::cell::RefCell<Option<Vec<DeferredMessage>>> =
        const { std::cell::RefCell::new(None) };
}

/// Enable deferred sending mode for the current thread.
/// Call before invoking Python handlers.
pub fn enable_deferred_sends() {
    DEFERRED_SENDS.with(|cell| {
        *cell.borrow_mut() = Some(Vec::new());
    });
}

/// Drain and return all deferred messages, disabling deferred mode.
/// Call after the reply has been sent to wire.
pub fn drain_deferred_sends() -> Vec<DeferredMessage> {
    DEFERRED_SENDS.with(|cell| {
        cell.borrow_mut().take().unwrap_or_default()
    })
}

/// Try to queue a message for deferred sending.  Returns `true` if deferred
/// mode is active and the message was queued; `false` if no request handler
/// is active (caller should send immediately).
pub(crate) fn try_defer_send(message: SipMessage, destination: std::net::SocketAddr, transport: Transport) -> bool {
    DEFERRED_SENDS.with(|cell| {
        let mut guard = cell.borrow_mut();
        if let Some(ref mut queue) = *guard {
            queue.push(DeferredMessage { message, destination, transport });
            true
        } else {
            false
        }
    })
}

/// Global DNS resolver for send_request — set alongside the UAC sender.
static SEND_RESOLVER: OnceLock<Arc<SipResolver>> = OnceLock::new();

/// Wire the UacSender + DNS resolver so `proxy.send_request()` can originate
/// outbound SIP requests. Called once from main.rs.
pub fn set_uac_sender(sender: Arc<UacSender>, resolver: Arc<SipResolver>) {
    let _ = UAC_SENDER.set(sender);
    let _ = SEND_RESOLVER.set(resolver);
}

/// Get the global UAC sender (for use by other script API modules like presence).
pub(crate) fn uac_sender() -> Option<&'static Arc<UacSender>> {
    UAC_SENDER.get()
}

/// Get the global SIP resolver (for use by other script API modules like presence).
pub(crate) fn send_resolver() -> Option<&'static Arc<SipResolver>> {
    SEND_RESOLVER.get()
}

/// Rate limiter using a sliding window counter per source IP.
pub struct RateLimiter {
    /// Map of source IP → list of request timestamps.
    windows: DashMap<String, Vec<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            windows: DashMap::new(),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Proxy utility methods exposed to Python.
#[pyclass(name = "ProxyUtils")]
pub struct PyProxyUtils {
    rate_limiter: Arc<RateLimiter>,
    dns_resolver: Arc<SipResolver>,
}

impl PyProxyUtils {
    pub fn new(dns_resolver: Arc<SipResolver>) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new()),
            dns_resolver,
        }
    }
}

#[pymethods]
impl PyProxyUtils {
    /// Check if a request exceeds the rate limit for its source IP.
    ///
    /// Returns `True` if the request is within the limit (allowed),
    /// `False` if it exceeds the limit (should be blocked/dropped).
    fn rate_limit(&self, request: &PyRequest, window_secs: f64, max_requests: usize) -> bool {
        let source_ip = request.source_ip_str().to_string();
        let now = Instant::now();
        let window = std::time::Duration::from_secs_f64(window_secs);

        let mut entry = self.rate_limiter.windows.entry(source_ip).or_default();
        // Prune expired entries
        entry.retain(|timestamp| now.duration_since(*timestamp) < window);
        if entry.len() >= max_requests {
            return false;
        }
        entry.push(now);
        true
    }

    /// Perform basic RFC 3261 sanity checks on a request.
    ///
    /// Returns `True` if the request passes all checks, `False` otherwise.
    /// Checks: mandatory headers present, Max-Forwards > 0, CSeq method
    /// matches request method, Content-Length matches body length.
    fn sanity_check(&self, request: &PyRequest) -> PyResult<bool> {
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // Must be a request
        let request_line = match &message.start_line {
            StartLine::Request(request_line) => request_line,
            _ => return Ok(false),
        };

        // Mandatory headers
        for header_name in &["Via", "From", "To", "Call-ID", "CSeq"] {
            if !message.headers.has(header_name) {
                return Ok(false);
            }
        }

        // Max-Forwards > 0
        if let Some(max_forwards) = message.headers.max_forwards() {
            if max_forwards == 0 {
                return Ok(false);
            }
        }

        // CSeq method must match request method
        if let Some(raw_cseq) = message.headers.cseq() {
            if let Ok(cseq) = CSeq::parse(raw_cseq) {
                if cseq.method.as_str() != request_line.method.as_str() {
                    return Ok(false);
                }
            } else {
                return Ok(false); // Unparseable CSeq
            }
        }

        // Content-Length must match body length (if present)
        if let Some(content_length) = message.headers.content_length() {
            if content_length != message.body.len() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Look up a phone number via ENUM (DNS NAPTR) query.
    ///
    /// Converts a number like "+12125551234" to a DNS query against
    /// `4.3.2.1.5.5.5.2.1.2.1.e164.arpa` and returns the SIP URI
    /// from the first matching NAPTR record, or `None`.
    #[pyo3(signature = (number, suffix="e164.arpa.", service="E2U+sip"))]
    fn enum_lookup<'py>(
        &self,
        py: Python<'py>,
        number: String,
        suffix: &str,
        service: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let resolver = Arc::clone(&self.dns_resolver);
        let suffix = suffix.to_string();
        let service = service.to_string();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let enum_result = enum_naptr_lookup(&resolver, &number, &suffix, &service).await;
            Ok(enum_result)
        })
    }

    /// Originate an outbound SIP request (fire-and-forget).
    ///
    /// Used to send NOTIFY, MESSAGE, and other requests from Python scripts.
    ///
    /// Args:
    ///     method: SIP method name (e.g. "NOTIFY", "MESSAGE")
    ///     ruri: Request-URI string (e.g. "sip:alice@10.0.0.1:5060")
    ///     headers: Optional dict of header name → value to add
    ///     body: Optional body string
    #[pyo3(signature = (method, ruri, headers=None, body=None, next_hop=None))]
    fn send_request(
        &self,
        method: &str,
        ruri: &str,
        headers: Option<&Bound<'_, PyDict>>,
        body: Option<&str>,
        next_hop: Option<&str>,
    ) -> PyResult<()> {
        let uac_sender = UAC_SENDER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "proxy.send_request() unavailable: UAC sender not initialized",
            )
        })?;
        let resolver = SEND_RESOLVER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "proxy.send_request() unavailable: DNS resolver not initialized",
            )
        })?;

        // Parse the request URI (used in the Request-Line)
        let uri = parse_uri_standalone(ruri).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid request URI '{ruri}': {error}"))
        })?;

        // Resolve the transport destination.
        // When next_hop is provided (e.g. Path from registrar), resolve that
        // instead of the R-URI. The R-URI stays in the Request-Line but the
        // message is sent to next_hop (like Route-based forwarding).
        let resolve_uri = if let Some(hop) = next_hop {
            parse_uri_standalone(hop).map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid next_hop URI '{hop}': {error}"
                ))
            })?
        } else {
            uri.clone()
        };

        let transport_hint = resolve_uri.get_param("transport").map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(resolver);
        let host = resolve_uri.host.clone();
        let port = resolve_uri.port;
        let scheme = resolve_uri.scheme.clone();

        let destination = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(resolver_clone.resolve(
                &host,
                port,
                &scheme,
                transport_hint.as_deref(),
            ))
        });

        let target = destination.into_iter().next().ok_or_else(|| {
            let resolve_target = next_hop.unwrap_or(ruri);
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_target}'"
            ))
        })?;

        // Determine transport
        let transport = match target
            .transport
            .as_deref()
            .or(transport_hint.as_deref())
        {
            Some(hint) => match hint.to_lowercase().as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                "sctp" => Transport::Sctp,
                _ => Transport::Udp,
            },
            None => if scheme == "sips" { Transport::Tls } else { Transport::Udp },
        };

        // Build the SIP message
        let sip_method = Method::from_str(method);
        let branch = format!("z9hG4bK-py-{}", uuid::Uuid::new_v4());
        let via = format!("SIP/2.0/{} {};branch={}", transport, target.address, branch);
        let call_id = format!("py-{}", uuid::Uuid::new_v4());
        let cseq_str = format!("1 {}", sip_method.as_str());

        let mut builder = SipMessageBuilder::new()
            .request(sip_method, uri)
            .via(via)
            .call_id(call_id)
            .cseq(cseq_str)
            .max_forwards(70);

        // Merge user-provided headers
        if let Some(header_dict) = headers {
            for (key, value) in header_dict.iter() {
                let name: String = key.extract().map_err(|error| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "header name must be str: {error}"
                    ))
                })?;
                let val: String = value.extract().map_err(|error| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "header value must be str: {error}"
                    ))
                })?;
                builder = builder.header(&name, val);
            }
        }

        // Set body if provided
        if let Some(body_str) = body {
            builder = builder.body_str(body_str);
        } else {
            builder = builder.content_length(0);
        }

        let message = builder.build().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to build SIP message: {error}"
            ))
        })?;

        uac_sender.send_request(message, target.address, transport);
        Ok(())
    }

    /// Return approximate RSS memory usage as a percentage (0-100).
    ///
    /// Reads `/proc/self/status` on Linux. Returns 0 on non-Linux platforms.
    fn memory_used_pct(&self) -> u32 {
        #[cfg(target_os = "linux")]
        {
            memory_pct_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}

/// Perform ENUM NAPTR lookup for a phone number.
async fn enum_naptr_lookup(
    resolver: &SipResolver,
    number: &str,
    suffix: &str,
    _service: &str,
) -> Option<String> {
    // Strip leading '+' and non-digit characters
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }

    // Reverse digits and join with dots: +12125551234 → 4.3.2.1.5.5.5.2.1.2.1
    let reversed: String = digits
        .chars()
        .rev()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(".");

    let query_name = format!("{reversed}.{suffix}");

    // Use the resolver's inner hickory resolver for NAPTR
    match resolver.naptr_lookup(&query_name).await {
        Some(uri) => Some(uri),
        None => {
            tracing::debug!(query = %query_name, "ENUM NAPTR lookup returned no results");
            None
        }
    }
}

/// Read RSS and total memory from /proc on Linux.
#[cfg(target_os = "linux")]
fn memory_pct_linux() -> u32 {
    use std::fs;

    let rss_kb = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .unwrap_or(0);

    let total_kb = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo
                .lines()
                .find(|line| line.starts_with("MemTotal:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .unwrap_or(1); // Avoid divide by zero

    if total_kb == 0 {
        return 0;
    }
    ((rss_kb * 100) / total_kb) as u32
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
    use std::sync::Mutex;

    fn make_request() -> PyRequest {
        let message = SipMessageBuilder::new()
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
            .content_length(0)
            .build()
            .unwrap();
        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    fn make_proxy_utils() -> PyProxyUtils {
        let resolver = Arc::new(SipResolver::from_system().unwrap());
        PyProxyUtils::new(resolver)
    }

    #[test]
    fn rate_limit_allows_under_limit() {
        let utils = make_proxy_utils();
        let request = make_request();
        assert!(utils.rate_limit(&request, 10.0, 5));
        assert!(utils.rate_limit(&request, 10.0, 5));
    }

    #[test]
    fn rate_limit_blocks_over_limit() {
        let utils = make_proxy_utils();
        let request = make_request();
        for _ in 0..3 {
            assert!(utils.rate_limit(&request, 60.0, 3));
        }
        // 4th request should be blocked
        assert!(!utils.rate_limit(&request, 60.0, 3));
    }

    #[test]
    fn sanity_check_valid_invite() {
        let utils = make_proxy_utils();
        let request = make_request();
        assert!(utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_missing_via() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_cseq_method_mismatch() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 REGISTER".to_string()) // Mismatch: request is INVITE
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_max_forwards_zero() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 INVITE".to_string())
            .max_forwards(0)
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_used_pct_returns_reasonable_value() {
        let utils = make_proxy_utils();
        let pct = utils.memory_used_pct();
        // Should be between 0 and 100 for any running process
        assert!(pct <= 100, "memory_used_pct returned {pct}");
    }
}
