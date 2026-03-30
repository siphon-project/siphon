//! PyO3 wrapper for RTPEngine — the `rtpengine` namespace in Python scripts.
//!
//! Scripts interact via:
//!   from siphon import rtpengine
//!   rtpengine.offer(request, profile="srtp_to_rtp")   # proxy script
//!   rtpengine.offer(call, profile="srtp_to_rtp")      # B2BUA script
//!   rtpengine.answer(reply, profile="srtp_to_rtp")
//!   rtpengine.delete(request)
//!   rtpengine.delete(call)
//!   rtpengine.ping()

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use tracing::{debug, warn};

use crate::rtpengine::client::RtpEngineSet;
use crate::rtpengine::profile::ProfileRegistry;
use crate::rtpengine::session::{MediaSession, MediaSessionStore};
use crate::sip::message::SipMessage;

use super::call::PyCall;
use super::reply::PyReply;
use super::request::PyRequest;

/// Python-visible RTPEngine namespace.
///
/// Injected as `siphon.rtpengine` when media config is present.
#[pyclass(name = "RtpEngineNamespace")]
pub struct PyRtpEngine {
    client: Arc<RtpEngineSet>,
    sessions: Arc<MediaSessionStore>,
    registry: Arc<ProfileRegistry>,
}

impl PyRtpEngine {
    pub fn new(
        client: Arc<RtpEngineSet>,
        sessions: Arc<MediaSessionStore>,
        registry: Arc<ProfileRegistry>,
    ) -> Self {
        Self { client, sessions, registry }
    }
}

/// Default profile name when none is specified.
const DEFAULT_PROFILE: &str = "rtp_passthrough";

/// Extract `Arc<Mutex<SipMessage>>` from a Python object that is either
/// a `Request`, `Reply`, or `Call`.
pub(super) fn extract_message(object: &Bound<'_, PyAny>) -> PyResult<Arc<Mutex<SipMessage>>> {
    // Try PyRequest first.
    if let Ok(request) = object.cast::<PyRequest>() {
        return Ok(request.borrow().message());
    }
    // Try PyReply.
    if let Ok(reply) = object.cast::<PyReply>() {
        return Ok(reply.borrow().message());
    }
    // Try PyCall.
    if let Ok(call) = object.cast::<PyCall>() {
        return Ok(call.borrow().message());
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "expected a Request, Reply, or Call object",
    ))
}

#[pymethods]
impl PyRtpEngine {
    /// Send an RTPEngine `offer` command.
    ///
    /// Extracts SDP from the object body, sends it to RTPEngine, and replaces
    /// the body with the rewritten SDP. Returns True on success.
    ///
    /// Args:
    ///     request: A Request or Call object containing the INVITE with SDP.
    ///     profile: RTP profile name (default: "rtp_passthrough").
    #[pyo3(signature = (request, profile=None))]
    fn offer<'py>(
        &self,
        python: Python<'py>,
        request: &Bound<'py, PyAny>,
        profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let profile_name = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = self.registry.get(profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.offer.clone();

        let message = extract_message(request)?;
        let (call_id, from_tag, sdp) = extract_offer_params(&message)?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);
        let profile_str = profile_name.to_string();

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .offer(&call_id, &from_tag, &sdp, &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.offer failed: {error}"
                    ))
                })?;

            debug!(
                call_id = %call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine offer: SDP rewritten"
            );

            replace_body(&message, &rewritten_sdp)?;

            sessions.insert(MediaSession {
                call_id,
                from_tag,
                to_tag: None,
                profile: profile_str,
                created_at: std::time::Instant::now(),
            });

            Ok(true)
        })
    }

    /// Send an RTPEngine `answer` command.
    ///
    /// Extracts SDP from the object body, sends it to RTPEngine, and replaces
    /// the body with the rewritten SDP.
    ///
    /// In B2BUA mode the offer was keyed by the A-leg Call-ID/From-tag, but the
    /// reply carries B-leg identifiers. The A-leg identifiers are resolved
    /// automatically when the reply carries an A-leg reference (set by the
    /// dispatcher), or via an explicit `call` parameter.
    ///
    /// Args:
    ///     reply: A Reply or Call object containing the 200 OK with SDP.
    ///     profile: RTP profile name (default: "rtp_passthrough").
    ///     call: Optional Call object — when provided, Call-ID and From-tag are
    ///           taken from this object (matching the earlier `offer`), while
    ///           To-tag and SDP body still come from `reply`.
    #[pyo3(signature = (reply, profile=None, call=None))]
    fn answer<'py>(
        &self,
        python: Python<'py>,
        reply: &Bound<'py, PyAny>,
        profile: Option<&str>,
        call: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let profile_name = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = self.registry.get(profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.answer.clone();

        let message = extract_message(reply)?;

        // Resolve A-leg identifiers for RTPEngine correlation:
        // 1. Explicit `call` parameter (backward compat / proxy-with-call)
        // 2. Automatic: PyReply carries A-leg INVITE ref set by B2BUA dispatcher
        // 3. Fallback: extract from the reply itself (proxy mode, same Call-ID)
        let a_leg_msg: Option<Arc<Mutex<SipMessage>>> = if let Some(call_obj) = call {
            Some(extract_message(call_obj)?)
        } else if let Ok(py_reply) = reply.cast::<PyReply>() {
            py_reply.borrow().a_leg_message()
        } else {
            None
        };

        let (call_id, from_tag, to_tag, sdp) = if let Some(ref a_msg) = a_leg_msg {
            let (cid, ftag, _sdp) = extract_offer_params(a_msg)?;
            let (_reply_cid, _reply_ftag, ttag, reply_sdp) = extract_answer_params(&message)?;
            (cid, ftag, ttag, reply_sdp)
        } else {
            extract_answer_params(&message)?
        };

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .answer(&call_id, &from_tag, &to_tag, &sdp, &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.answer failed: {error}"
                    ))
                })?;

            debug!(
                call_id = %call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine answer: SDP rewritten"
            );

            replace_body(&message, &rewritten_sdp)?;

            sessions.set_to_tag(&call_id, to_tag);

            Ok(true)
        })
    }

    /// Send an RTPEngine `delete` command to tear down the media session.
    ///
    /// Args:
    ///     request: A Request or Call object (used to extract Call-ID/From-tag).
    #[pyo3(signature = (request,))]
    fn delete<'py>(
        &self,
        python: Python<'py>,
        request: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message = extract_message(request)?;
        let (call_id, from_tag) = extract_delete_params(&message)?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match client.delete(&call_id, &from_tag).await {
                Ok(()) => {
                    debug!(call_id = %call_id, "RTPEngine session deleted");
                }
                Err(error) => {
                    // Log but don't fail — the session may already be gone.
                    warn!(call_id = %call_id, error = %error, "RTPEngine delete failed");
                }
            }

            sessions.remove(&call_id);
            Ok(true)
        })
    }

    /// Ping the RTPEngine instance(s). Returns True if healthy.
    fn ping<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match client.ping().await {
                Ok(()) => Ok(true),
                Err(error) => {
                    warn!(error = %error, "RTPEngine ping failed");
                    Ok(false)
                }
            }
        })
    }

    /// Number of active media sessions being tracked.
    #[getter]
    fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Number of configured RTPEngine instances.
    #[getter]
    fn instance_count(&self) -> usize {
        self.client.instance_count()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock_message(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
    message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })
}

/// Extract the SDP body from a SIP message, handling multipart/mixed bodies.
///
/// If the Content-Type is `multipart/mixed`, extracts the `application/sdp`
/// part from the multipart body. Otherwise returns the raw body as-is.
pub(super) fn extract_sdp_body(message: &SipMessage) -> PyResult<Vec<u8>> {
    let body = &message.body;
    if body.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "message has no SDP body",
        ));
    }

    let empty_string = String::new();
    let content_type = message.headers.get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .unwrap_or(&empty_string);

    if content_type.to_ascii_lowercase().contains("multipart/mixed") {
        // Parse multipart body and extract the SDP part.
        let parts = crate::siprec::multipart::parse_multipart(content_type, body)
            .map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "failed to parse multipart body: {error}"
                ))
            })?;
        let sdp_part = crate::siprec::multipart::find_part(&parts, "application/sdp")
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "multipart body has no application/sdp part"
                )
            })?;
        Ok(sdp_part.body.clone())
    } else {
        Ok(body.clone())
    }
}

/// Extract call-id, from-tag, and SDP body from a SIP message (offer direction).
fn extract_offer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, Vec<u8>)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    let sdp = extract_sdp_body(&message)?;

    Ok((call_id, from_tag, sdp))
}

/// Extract call-id, from-tag, to-tag, and SDP body from a SIP message (answer direction).
fn extract_answer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, String, Vec<u8>)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    let to_raw = message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing To header")
        })?;

    let to_tag = extract_tag(to_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("To header missing tag parameter")
    })?;

    let sdp = extract_sdp_body(&message)?;

    Ok((call_id, from_tag, to_tag, sdp))
}

/// Extract call-id and from-tag from a SIP message (delete direction — no SDP required).
fn extract_delete_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    Ok((call_id, from_tag))
}

/// Extract the `tag=` parameter from a From/To header value.
fn extract_tag(header_value: &str) -> Option<String> {
    // Look for ";tag=" (case-insensitive).
    let lower = header_value.to_lowercase();
    let tag_start = lower.find(";tag=")?;
    let value_start = tag_start + 5; // skip ";tag="
    let rest = &header_value[value_start..];
    // Tag ends at next ';', '>', or end of string.
    let end = rest
        .find([';', '>'])
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Replace the SIP message body with new SDP and update Content-Length.
pub(super) fn replace_body(
    message: &Arc<Mutex<SipMessage>>,
    new_body: &[u8],
) -> PyResult<()> {
    let mut message = message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;
    message.body = new_body.to_vec();
    message
        .headers
        .set("Content-Length", new_body.len().to_string());
    message
        .headers
        .set("Content-Type", "application/sdp".to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_resolves_builtins() {
        let registry = ProfileRegistry::new();
        assert!(registry.get(DEFAULT_PROFILE).is_some());
        assert!(registry.get("ws_to_rtp").is_some());
        assert!(registry.get("wss_to_rtp").is_some());
        assert!(registry.get("rtp_passthrough").is_some());
    }

    #[test]
    fn registry_rejects_unknown() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("invalid").is_none());
    }

    #[test]
    fn extract_tag_from_header() {
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>;tag=abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_tag("\"Alice\" <sip:alice@atlanta.com>;tag=xyz;other=val"),
            Some("xyz".to_string())
        );
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>"),
            None,
        );
    }

    #[test]
    fn extract_tag_case_insensitive() {
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>;Tag=ABC"),
            Some("ABC".to_string())
        );
    }

    /// Helper to build a minimal SIP message for testing.
    fn test_message(content_type: Option<&str>, body: &[u8]) -> SipMessage {
        use crate::sip::message::{RequestLine, StartLine, Version, Method};
        use crate::sip::uri::SipUri;
        use crate::sip::headers::SipHeaders;

        let mut headers = SipHeaders::new();
        if let Some(content_type) = content_type {
            headers.set("Content-Type", content_type.to_string());
        }

        SipMessage {
            start_line: StartLine::Request(RequestLine {
                method: Method::Invite,
                request_uri: SipUri::new("10.0.0.1".to_string()),
                version: Version::sip_2_0(),
            }),
            headers,
            body: body.to_vec(),
        }
    }

    #[test]
    fn extract_sdp_body_plain() {
        let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";
        let message = test_message(Some("application/sdp"), body);

        let sdp = extract_sdp_body(&message).unwrap();
        assert_eq!(sdp, body);
    }

    #[test]
    fn extract_sdp_body_multipart() {
        let multipart_body = concat!(
            "--srec-abc123\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
            "\r\n",
            "--srec-abc123\r\n",
            "Content-Type: application/rs-metadata+xml\r\n",
            "\r\n",
            "<recording xmlns='urn:ietf:params:xml:ns:recording:1'/>\r\n",
            "\r\n",
            "--srec-abc123--\r\n",
        );

        let message = test_message(
            Some("multipart/mixed;boundary=srec-abc123"),
            multipart_body.as_bytes(),
        );

        let sdp = extract_sdp_body(&message).unwrap();
        let sdp_str = String::from_utf8_lossy(&sdp);

        // Should contain only the SDP, not the multipart boundaries or XML.
        assert!(sdp_str.starts_with("v=0"));
        assert!(sdp_str.contains("a=recvonly"));
        assert!(!sdp_str.contains("--srec-abc123"));
        assert!(!sdp_str.contains("recording"));
    }

    #[test]
    fn extract_sdp_body_empty() {
        let message = test_message(None, b"");
        assert!(extract_sdp_body(&message).is_err());
    }

    #[test]
    fn replace_body_always_sets_content_type() {
        let message = test_message(Some("multipart/mixed;boundary=abc"), b"old body");
        let message_arc = Arc::new(Mutex::new(message));
        let new_body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";

        replace_body(&message_arc, new_body).unwrap();

        let guard = message_arc.lock().unwrap();
        assert_eq!(
            guard.headers.get("Content-Type"),
            Some(&"application/sdp".to_string())
        );
        assert_eq!(
            guard.headers.get("Content-Length"),
            Some(&new_body.len().to_string())
        );
        assert_eq!(guard.body, new_body);
    }
}
