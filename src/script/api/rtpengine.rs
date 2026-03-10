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
const DEFAULT_PROFILE: &str = "srtp_to_rtp";

/// Extract `Arc<Mutex<SipMessage>>` from a Python object that is either
/// a `Request`, `Reply`, or `Call`.
fn extract_message(object: &Bound<'_, PyAny>) -> PyResult<Arc<Mutex<SipMessage>>> {
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
    ///     profile: RTP profile name (default: "srtp_to_rtp").
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
    /// reply carries B-leg identifiers. Pass the original `call` object so that
    /// the correct (A-leg) Call-ID and From-tag are used for the RTPEngine
    /// `answer` command.
    ///
    /// Args:
    ///     reply: A Reply or Call object containing the 200 OK with SDP.
    ///     profile: RTP profile name (default: "srtp_to_rtp").
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

        // When a `call` object is provided (B2BUA mode), use its Call-ID and
        // From-tag so they match the earlier `offer`.  SDP and To-tag still
        // come from the reply (the 200 OK).
        let (call_id, from_tag, to_tag, sdp) = if let Some(call_obj) = call {
            let call_msg = extract_message(call_obj)?;
            let (cid, ftag, _sdp) = extract_offer_params(&call_msg)?;
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

    let sdp = message.body.clone();
    if sdp.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "message has no SDP body",
        ));
    }

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

    let sdp = message.body.clone();
    if sdp.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "message has no SDP body",
        ));
    }

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
fn replace_body(
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
    if message.headers.get("Content-Type").is_none() {
        message
            .headers
            .set("Content-Type", "application/sdp".to_string());
    }
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
}
