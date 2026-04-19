//! PyO3 wrapper for the generic SUBSCRIBE dialog manager.
//!
//! Exposed to scripts as ``proxy.subscribe_state``.  See
//! [`crate::subscribe_state`] for the underlying store + persistence
//! semantics.

use std::sync::{Arc, OnceLock};

use pyo3::prelude::*;
use tracing::debug;
use uuid::Uuid;

use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::subscribe_state::{SubscribeDialog, SubscribeStore};
use crate::transport::Transport;
use crate::uac::UacSender;

use super::reply::PyReply;
use super::request::PyRequest;

static UAC_SENDER: OnceLock<Arc<UacSender>> = OnceLock::new();
static SEND_RESOLVER: OnceLock<Arc<SipResolver>> = OnceLock::new();

/// One-time wire-up from ``server.rs`` — the UAC and resolver are shared
/// with [`super::proxy_utils`].
pub fn set_uac_sender(sender: Arc<UacSender>) {
    let _ = UAC_SENDER.set(sender);
}

pub fn set_resolver(resolver: Arc<SipResolver>) {
    let _ = SEND_RESOLVER.set(resolver);
}

/// Python-visible namespace — injected as ``proxy.subscribe_state``.
#[pyclass(name = "SubscribeStateNamespace")]
pub struct PySubscribeState {
    store: Arc<SubscribeStore>,
}

impl PySubscribeState {
    pub fn new(store: Arc<SubscribeStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PySubscribeState {
    /// Capture the dialog from an incoming SUBSCRIBE request and return a
    /// handle for later NOTIFY/terminate operations.
    ///
    /// The handle id is durable — when ``media.cache``/``cache:`` Redis
    /// is configured for ``subscribe_state.cache``, the dialog survives
    /// restarts and is visible to other siphon replicas.  Store the id
    /// via :attr:`SubscribeHandle.id` and pass it to :meth:`get` later.
    #[pyo3(signature = (request, expires=None))]
    fn create(
        &self,
        request: &Bound<'_, PyRequest>,
        expires: Option<u64>,
    ) -> PyResult<PySubscribeHandle> {
        let borrowed = request.borrow();
        let message_arc = borrowed.message();
        let message = message_arc.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        let call_id = message
            .headers
            .get("Call-ID")
            .or_else(|| message.headers.get("i"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Call-ID")
            })?;

        let from_raw = message
            .headers
            .get("From")
            .or_else(|| message.headers.get("f"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing From")
            })?;
        let to_raw = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing To")
            })?;

        let contact_raw = message
            .headers
            .get("Contact")
            .or_else(|| message.headers.get("m"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Contact")
            })?;

        let event = message
            .headers
            .get("Event")
            .or_else(|| message.headers.get("o"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "SUBSCRIBE missing Event header",
                )
            })?;

        let remote_tag = extract_tag(&from_raw).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("SUBSCRIBE From has no tag")
        })?;

        // The SUBSCRIBE's To-tag is the notifier's (our) tag.  If the
        // SUBSCRIBE had no To-tag (first-in-dialog), we mint one now so
        // our NOTIFYs carry a stable tag.
        let local_tag = extract_tag(&to_raw).unwrap_or_else(|| short_uuid());

        let local_uri = strip_nameaddr(&to_raw);
        let remote_uri = strip_nameaddr(&from_raw);
        let remote_target = strip_nameaddr(&contact_raw);

        // Record-Route values are copied left-to-right; NOTIFY Route
        // headers are the reverse (RFC 3261 §12.1).
        let route_set: Vec<String> = message
            .headers
            .get_all("Record-Route")
            .map(|entries| entries.iter().rev().cloned().collect())
            .unwrap_or_default();

        let expires_secs = expires
            .or_else(|| {
                message
                    .headers
                    .get("Expires")
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
            .unwrap_or(3600);

        let id = short_uuid();
        let dialog = SubscribeDialog {
            id: id.clone(),
            call_id,
            local_tag,
            remote_tag,
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            event,
            expires_secs,
            created_at_unix: now_unix(),
            cseq: 0,
            terminated: false,
        };

        drop(message);
        self.store.put(dialog);
        debug!(id, "subscribe_state: dialog created");

        Ok(PySubscribeHandle {
            store: Arc::clone(&self.store),
            id,
        })
    }

    /// Look up a previously-created handle by id.  Returns ``None`` if
    /// the dialog is unknown, expired, or terminated.
    #[pyo3(signature = (id))]
    fn get(&self, id: &str) -> PyResult<Option<PySubscribeHandle>> {
        let store = Arc::clone(&self.store);
        let id_owned = id.to_string();
        let found = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(store.get(&id_owned))
        });
        Ok(found.map(|dialog| PySubscribeHandle {
            store: Arc::clone(&self.store),
            id: dialog.id,
        }))
    }

    /// Number of subscribe dialogs currently held in the in-process
    /// cache (excludes cache-only entries on other replicas).
    #[getter]
    fn local_count(&self) -> usize {
        self.store.local_count()
    }
}

/// Handle returned by :meth:`PySubscribeState.create` / ``get``.
#[pyclass(name = "SubscribeHandle")]
pub struct PySubscribeHandle {
    store: Arc<SubscribeStore>,
    id: String,
}

#[pymethods]
impl PySubscribeHandle {
    /// The durable id — pass to ``proxy.subscribe_state.get()`` to
    /// retrieve this handle from another worker or after restart.
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// The SIP Event package (copied from the SUBSCRIBE).
    #[getter]
    fn event(&self) -> PyResult<String> {
        let dialog = self.load_sync()?;
        Ok(dialog.event)
    }

    /// Seconds remaining until the dialog expires.
    #[getter]
    fn expires(&self) -> PyResult<u64> {
        let dialog = self.load_sync()?;
        Ok(dialog.remaining_secs())
    }

    fn __repr__(&self) -> String {
        format!("SubscribeHandle(id={:?})", self.id)
    }

    /// Send an in-dialog NOTIFY with ``body``/``content_type``.
    ///
    /// ``state`` is the full ``Subscription-State`` header value.  When
    /// omitted, siphon emits ``active;expires=<remaining>``.  Set it
    /// explicitly for ``pending``, ``active;expires=N;reason=...``, or
    /// to override the expiry.
    ///
    /// Returns ``True`` on success, ``False`` if the dialog has been
    /// terminated or is unknown.
    #[pyo3(signature = (body=None, content_type=None, state=None))]
    fn notify(
        &self,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
        state: Option<&str>,
    ) -> PyResult<bool> {
        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return Ok(false),
        };

        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };

        let subscription_state = state
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("active;expires={}", dialog.remaining_secs()));

        send_notify(&dialog, &subscription_state, content_type, body_bytes.as_deref())?;
        Ok(true)
    }

    /// Send a terminating NOTIFY with ``Subscription-State:
    /// terminated;reason=<reason>`` and remove the dialog from the store.
    ///
    /// ``reason`` defaults to ``"noresource"`` (RFC 6665 §4.2.2).
    #[pyo3(signature = (reason=None, body=None, content_type=None))]
    fn terminate(
        &self,
        reason: Option<&str>,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
    ) -> PyResult<bool> {
        let reason_str = reason.unwrap_or("noresource");
        let subscription_state = format!("terminated;reason={reason_str}");

        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return Ok(false),
        };

        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };

        send_notify(&dialog, &subscription_state, content_type, body_bytes.as_deref())?;

        // Mark terminated + remove.  Mark-then-remove gives a brief
        // window where get() returns None even if the cache still has
        // the entry (race-safe for cross-instance lookups).
        self.store.update(&self.id, |dialog| dialog.terminated = true);
        self.store.remove(&self.id);
        Ok(true)
    }

    /// Send a final NOTIFY using an already-built
    /// ``Subscription-State`` value built elsewhere (advanced).
    ///
    /// Wraps :meth:`notify` but without the automatic
    /// ``active;expires=...`` default.
    #[pyo3(signature = (reply))]
    #[allow(dead_code)]
    fn mirror_reply(&self, reply: &Bound<'_, PyReply>) -> PyResult<bool> {
        // Kept as a placeholder for a later convenience that builds a
        // NOTIFY body from an existing :class:`Reply`.  For now just
        // no-ops so the attribute exists; scripts should use notify().
        let _ = reply;
        Ok(false)
    }
}

impl PySubscribeHandle {
    fn load_sync(&self) -> PyResult<SubscribeDialog> {
        let store = Arc::clone(&self.store);
        let id = self.id.clone();
        let found = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(store.get(&id))
        });
        found.ok_or_else(|| {
            pyo3::exceptions::PyLookupError::new_err(format!(
                "subscribe_state dialog '{}' not found",
                self.id
            ))
        })
    }

    /// Increment CSeq and return the updated dialog snapshot, or
    /// ``None`` if the dialog has disappeared.
    fn bump_cseq(&self) -> PyResult<Option<SubscribeDialog>> {
        // Ensure L1 is hydrated (cross-replica case).
        let _ = self.load_sync()?;
        let updated = self.store.update(&self.id, |dialog| {
            dialog.next_cseq();
        });
        Ok(updated)
    }
}

// ---------------------------------------------------------------------------
// Wire helpers — borrowed from proxy_utils / presence patterns
// ---------------------------------------------------------------------------

fn send_notify(
    dialog: &SubscribeDialog,
    subscription_state: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> PyResult<()> {
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: UAC sender not initialized",
        )
    })?;
    let resolver = SEND_RESOLVER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: DNS resolver not initialized",
        )
    })?;

    // Determine transport destination: first Route URI or remote_target.
    let resolve_target: String = dialog
        .route_set
        .first()
        .map(|route| route.trim().trim_start_matches('<').trim_end_matches('>').to_string())
        .unwrap_or_else(|| dialog.remote_target.clone());

    let resolve_uri = parse_uri_standalone(&resolve_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid route/target URI '{resolve_target}': {error}"
        ))
    })?;
    let ruri = parse_uri_standalone(&dialog.remote_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid remote_target URI '{}': {error}",
            dialog.remote_target
        ))
    })?;

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
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cannot resolve destination for '{resolve_target}'"
        ))
    })?;

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

    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!("SIP/2.0/{} {};branch={}", transport, target.address, branch);
    let cseq_str = format!("{} NOTIFY", dialog.cseq);

    // NOTIFY tag orientation (RFC 6665 §4.4.1): From = notifier (us),
    // To = subscriber (peer).
    let from_header = format!("<{}>;tag={}", dialog.local_uri, dialog.local_tag);
    let to_header = format!("<{}>;tag={}", dialog.remote_uri, dialog.remote_tag);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Notify, ruri)
        .via(via)
        .call_id(dialog.call_id.clone())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header)
        .to(to_header)
        .header("Event", dialog.event.clone())
        .header("Subscription-State", subscription_state.to_string());

    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }

    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct.to_string());
    }

    if let Some(body_bytes) = body {
        builder = builder.body(body_bytes.to_vec());
    } else {
        builder = builder.content_length(0);
    }

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to build NOTIFY: {error}"
        ))
    })?;

    // If called from inside a request handler, the dispatcher may defer
    // until after the SUBSCRIBE reply is sent (RFC 6665 §4.1).
    if !super::proxy_utils::try_defer_send(message.clone(), target.address, transport) {
        uac_sender.send_request(message, target.address, transport);
    }
    debug!(id = %dialog.id, "subscribe_state: NOTIFY sent");
    Ok(())
}

fn short_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pull ``tag=...`` from a From/To header value.
fn extract_tag(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let tag_start = lower.find(";tag=")?;
    let rest = &value[tag_start + 5..];
    let end = rest.find([';', '>']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Strip display-name and angle-brackets from a name-addr header value,
/// returning only the URI portion.  Falls back to the whole trimmed
/// value on parse failure.
fn strip_nameaddr(value: &str) -> String {
    let trimmed = value.trim();
    if let (Some(l), Some(r)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if l < r {
            return trimmed[l + 1..r].to_string();
        }
    }
    // No angle brackets — strip any trailing ;tag=… or other params.
    trimmed.split(';').next().unwrap_or(trimmed).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tag_basic() {
        assert_eq!(
            extract_tag("<sip:alice@ex>;tag=abc;foo=1"),
            Some("abc".to_string())
        );
        assert_eq!(extract_tag("<sip:alice@ex>"), None);
    }

    #[test]
    fn strip_nameaddr_removes_brackets_and_display_name() {
        assert_eq!(
            strip_nameaddr("\"Alice\" <sip:alice@ex>;tag=abc"),
            "sip:alice@ex"
        );
        assert_eq!(strip_nameaddr("sip:alice@ex;tag=abc"), "sip:alice@ex");
    }
}
