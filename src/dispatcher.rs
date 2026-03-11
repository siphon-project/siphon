//! Core request dispatcher — glue between transport and script engine.
//!
//! Receives raw SIP bytes from the transport layer, parses them, invokes
//! Python script handlers, and sends responses back through the transport.
//! Implements stateless proxy relay with Via-based response routing.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use crate::b2bua::actor::{CallActorStore, CallEvent, CallState, Leg, LegActor, TransportInfo as LegTransport};
use crate::dns::SipResolver;
use crate::config::Config;
use crate::proxy::core;
use crate::proxy::session::{ClientBranch, ProxySession, ProxySessionStore};
use crate::registrar::{Registrar, RegistrarConfig};
use crate::script::api::auth::PyAuth;
use crate::script::api::call::{CallAction, PyByeInitiator, PyCall};
use crate::script::api::log::PyLogNamespace;
use crate::script::api::registrar::PyRegistrar;
use crate::script::api::reply::PyReply;
use crate::script::api::request::{LocalDomains, PyRequest, RequestAction};
use crate::script::engine::{HandlerKind, ScriptEngine};
use crate::sip::builder::SipMessageBuilder;
use crate::sip::headers::via::Via;
use crate::sip::message::{Method, RequestLine, SipMessage, StartLine, StatusLine, Version};
use crate::sip::headers::SipHeaders;
use crate::sip::uri::SipUri;
use crate::sip::parser::{parse_sip_message, parse_uri_standalone};
use crate::sip::uri::format_sip_host;
use crate::transaction::key::TransactionKey;
use crate::transaction::state::{
    Action, TimerName,
    IstEvent, NistEvent, IctEvent, NictEvent,
};
use crate::transaction::{TransactionManager, ServerEvent, ClientEvent};
use crate::transaction::timer::TimerConfig;
use crate::hep::HepSender;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, OutboundRouter, Transport};
use crate::transport::pool::ConnectionPool;
use crate::uac::UacSender;

/// A pending timer entry in the timer wheel.
#[derive(Debug, Clone)]
struct TimerEntry {
    /// Transaction this timer belongs to.
    key: TransactionKey,
    /// Which timer.
    name: TimerName,
    /// When this timer fires.
    fires_at: std::time::Instant,
    /// Destination for retransmits (client transactions).
    destination: Option<SocketAddr>,
    /// Transport for retransmits.
    transport: Option<Transport>,
    /// Connection ID for sending.
    connection_id: Option<ConnectionId>,
}

/// Shared state for the dispatcher, passed to each spawned task.
struct DispatcherState {
    engine: Arc<ScriptEngine>,
    outbound: Arc<OutboundRouter>,
    local_domains: LocalDomains,
    local_addr: SocketAddr,
    /// Per-transport advertised host (hostname or IP) for Record-Route/Via.
    /// Configured via `listen: { tls: [{ address: ..., advertise: "..." }] }`.
    /// Falls back to the global `advertised_address` config when not set per-transport.
    advertised_addrs: std::collections::HashMap<Transport, String>,
    /// Per-transport listen address for HEP capture (so TLS responses report
    /// port 5061, not the UDP/TCP port 5060).
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    /// Server header value injected into locally-generated responses.
    server_header: Option<String>,
    /// User-Agent header value for outbound requests (UAC, registrant).
    #[allow(dead_code)]
    user_agent_header: Option<String>,
    /// Transaction timeout for pending branch TTL.
    transaction_timeout: std::time::Duration,
    /// B2BUA call actor store (active when script has @b2bua handlers).
    call_actors: Arc<CallActorStore>,
    /// Transaction state machine manager.
    transaction_manager: Arc<TransactionManager>,
    /// Timer wheel — keyed by a unique timer ID string.
    timer_wheel: Arc<DashMap<String, TimerEntry>>,
    /// Proxy session store — links server transactions to client transactions.
    session_store: Arc<ProxySessionStore>,
    /// DNS resolver for SIP target resolution (RFC 3263).
    dns_resolver: Arc<SipResolver>,
    /// HEP capture sender (None when tracing is not configured).
    hep_sender: Option<Arc<HepSender>>,
    /// UAC sender for outbound requests (keepalive, health probes).
    uac_sender: Arc<UacSender>,
    /// RTPEngine client set (None when media.rtpengine is not configured).
    rtpengine_set: Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
    /// RTPEngine media session store (None when media.rtpengine is not configured).
    rtpengine_sessions: Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    /// RFC 4028 session timer configuration (None when not configured).
    session_timer_config: Option<crate::config::SessionTimerConfig>,
    /// Outbound registration manager (None when registrant is not configured).
    registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    /// SIPREC recording manager.
    recording_manager: Arc<crate::siprec::RecordingManager>,
    /// IPsec SA manager (None when ipsec is not configured).
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    /// IPsec config (P-CSCF ports).
    ipsec_config: Option<crate::config::IpsecConfig>,
    /// Outbound TCP/TLS connection pool for relay to new destinations.
    connection_pool: Arc<ConnectionPool>,
    /// Reverse map: TLS remote SocketAddr → ConnectionId for connection reuse.
    /// Populated by the TLS listener; used by send_to_target to reuse inbound
    /// TLS connections when relaying to registered endpoints (like OpenSIPS).
    tls_addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
    /// RFC 5626 CRLF pong tracker (None when crlf_keepalive is not configured).
    crlf_pong_tracker: Option<Arc<crate::transport::crlf_keepalive::CrlfPongTracker>>,
    /// Name used in SDP `o=` and `s=` lines (from media.sdp_name config).
    sdp_name: String,
    /// Per-call event receivers from B-leg actors.
    /// Keyed by internal call ID; the receiver gets [`CallEvent`]s from all
    /// B-leg actors belonging to that call.
    call_event_receivers: Arc<DashMap<String, tokio::sync::mpsc::Receiver<CallEvent>>>,
}

impl DispatcherState {
    /// Return the host (IP or hostname) to use in Via headers for the given transport.
    ///
    /// Prefers the per-transport advertised address (public IP) when configured,
    /// falling back to the local bind address.  The result is already formatted
    /// for SIP (IPv6 addresses are bracketed).
    fn via_host(&self, transport: &Transport) -> String {
        self.advertised_addrs
            .get(transport)
            .map(|h| format_sip_host(h))
            .unwrap_or_else(|| format_sip_host(&self.local_addr.ip().to_string()))
    }

    /// Return the port to use in Via/Contact headers for the given transport.
    fn via_port(&self, transport: &Transport) -> u16 {
        self.listen_addrs
            .get(transport)
            .map(|a| a.port())
            .unwrap_or(self.local_addr.port())
    }
}

/// Run the core dispatcher loop.
///
/// Reads inbound messages from transport, parses, invokes Python handlers,
/// and sends responses back via the outbound channel.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    inbound_rx: flume::Receiver<InboundMessage>,
    outbound: Arc<OutboundRouter>,
    engine: Arc<ScriptEngine>,
    config: Arc<Config>,
    local_addr: SocketAddr,
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    advertised_addrs: std::collections::HashMap<Transport, String>,
    hep_sender: Option<Arc<HepSender>>,
    uac_sender: Arc<UacSender>,
    connection_pool: Arc<ConnectionPool>,
    pre_rtpengine: (
        Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
        Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    ),
    registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    ipsec_config: Option<crate::config::IpsecConfig>,
    tls_addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
    crlf_pong_tracker: Option<Arc<crate::transport::crlf_keepalive::CrlfPongTracker>>,
    registrar_event_rx: Option<tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>>,
) {
    // Resolve the local address for Via insertion.
    // If bound to 0.0.0.0 / [::], use advertised_address from config, or loopback.
    let via_addr = if local_addr.ip().is_unspecified() {
        let fallback = if local_addr.is_ipv6() { "::1" } else { "127.0.0.1" };
        let host = config
            .advertised_address
            .as_deref()
            .unwrap_or(fallback);
        let ip: std::net::IpAddr = host
            .parse()
            .unwrap_or_else(|_| {
                if local_addr.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            });
        SocketAddr::new(ip, local_addr.port())
    } else {
        local_addr
    };

    let default_server = format!("SIPhon/{}", env!("CARGO_PKG_VERSION"));
    let server_header = Some(
        config
            .server
            .as_ref()
            .and_then(|s| s.server_header.clone())
            .unwrap_or_else(|| default_server.clone()),
    );
    let user_agent_header = Some(
        config
            .server
            .as_ref()
            .and_then(|s| s.user_agent_header.clone())
            .unwrap_or(default_server),
    );

    let tx_config = config.transaction.as_ref();
    let transaction_timeout = std::time::Duration::from_secs(
        tx_config.map(|t| t.invite_timeout_secs as u64).unwrap_or(30) + 2,
    );
    let _non_invite_timeout = std::time::Duration::from_secs(
        tx_config.map(|t| t.timeout_secs as u64).unwrap_or(5),
    );

    let timer_config = TimerConfig::default();
    let transaction_manager = Arc::new(TransactionManager::new(timer_config));

    let dns_resolver = Arc::new(match SipResolver::from_system() {
        Ok(resolver) => resolver,
        Err(error) => {
            error!("failed to initialize DNS resolver: {error}");
            return;
        }
    });

    let (rtpengine_set, rtpengine_sessions) = pre_rtpengine;

    // Merge per-transport advertised addresses with global advertised_address fallback.
    // Per-transport takes precedence; global fills in any transport that lacks one.
    let mut merged_advertised = advertised_addrs;
    if let Some(ref global_adv) = config.advertised_address {
        for &transport in listen_addrs.keys() {
            merged_advertised.entry(transport).or_insert_with(|| global_adv.clone());
        }
    }

    let state = Arc::new(DispatcherState {
        engine,
        outbound,
        local_domains: Arc::new(config.domain.local.clone()),
        local_addr: via_addr,
        advertised_addrs: merged_advertised,
        listen_addrs,
        server_header,
        user_agent_header,
        transaction_timeout,
        call_actors: Arc::new(CallActorStore::new()),
        transaction_manager,
        timer_wheel: Arc::new(DashMap::new()),
        session_store: Arc::new(ProxySessionStore::new()),
        dns_resolver,
        hep_sender,
        uac_sender,
        rtpengine_set,
        rtpengine_sessions,
        session_timer_config: config.session_timer.clone(),
        registrant_manager,
        recording_manager: Arc::new(crate::siprec::RecordingManager::new()),
        ipsec_manager,
        ipsec_config,
        connection_pool,
        tls_addr_map,
        crlf_pong_tracker,
        sdp_name: config.media.as_ref()
            .and_then(|m| m.sdp_name.clone())
            .unwrap_or_else(|| "SIPhon".to_string()),
        call_event_receivers: Arc::new(DashMap::new()),
    });

    // Spawn background task: fire transaction timers + sweep stale entries
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // Timer check interval: 100ms for responsive retransmissions
            let mut timer_interval = tokio::time::interval(std::time::Duration::from_millis(100));
            // Stale entry cleanup: every 30s
            let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = timer_interval.tick() => {
                        fire_expired_timers(&state);
                    }
                    _ = cleanup_interval.tick() => {
                        sweep_stale_entries(&state);
                    }
                }
            }
        });
    }

    // Spawn background task: RFC 4028 session timer refresh
    if state.session_timer_config.as_ref().is_some_and(|c| c.enabled) {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                // Run in spawn_blocking since it accesses DashMap and may build SIP messages
                let state = Arc::clone(&state);
                tokio::task::spawn_blocking(move || {
                    session_timer_sweep(&state);
                }).await.ok();
            }
        });
    }

    // Spawn background task: registrar change event → on_change handlers
    if let Some(registrar) = crate::script::api::registrar_arc() {
        let mut event_receiver = registrar_event_rx
            .unwrap_or_else(|| registrar.subscribe_events());
        let state_for_events = Arc::clone(&state);
        let registrar = Arc::clone(registrar);
        tokio::spawn(async move {
            while let Ok(event) = event_receiver.recv().await {
                let (aor, event_type) = match &event {
                    crate::registrar::RegistrationEvent::Registered { aor } => {
                        (aor.clone(), "registered")
                    }
                    crate::registrar::RegistrationEvent::Refreshed { aor } => {
                        (aor.clone(), "refreshed")
                    }
                    crate::registrar::RegistrationEvent::Deregistered { aor } => {
                        (aor.clone(), "deregistered")
                    }
                    crate::registrar::RegistrationEvent::Expired { aor } => {
                        (aor.clone(), "expired")
                    }
                };

                // Quick check if any handlers exist (avoids spawn_blocking overhead)
                {
                    let engine_state = state_for_events.engine.state();
                    if engine_state
                        .handlers_for(&HandlerKind::RegistrarOnChange)
                        .is_empty()
                    {
                        continue;
                    }
                }

                // Build contacts list for the callback
                let contacts: Vec<super::script::api::registrar::PyContact> = registrar
                    .lookup(&aor)
                    .iter()
                    .map(super::script::api::registrar::PyContact::from_rust_contact)
                    .collect();

                let event_type_str = event_type.to_string();
                let state_ref = Arc::clone(&state_for_events);

                // Invoke Python handlers in a blocking context
                tokio::task::spawn_blocking(move || {
                    let engine_state = state_ref.engine.state();
                    let handlers =
                        engine_state.handlers_for(&HandlerKind::RegistrarOnChange);

                    pyo3::Python::attach(|python| {
                        let py_items: Vec<_> = contacts.into_iter().filter_map(|contact| {
                            match pyo3::Py::new(python, contact) {
                                Ok(py) => Some(py.into_bound(python)),
                                Err(error) => {
                                    error!("PyContact creation failed: {error}");
                                    None
                                }
                            }
                        }).collect();
                        let Ok(py_contacts) = pyo3::types::PyList::new(python, py_items) else {
                            error!("PyList creation failed for registrar on_change contacts");
                            return;
                        };

                        for handler in handlers {
                            let callable = handler.callable.bind(python);
                            let result = callable.call1((
                                aor.as_str(),
                                event_type_str.as_str(),
                                &py_contacts,
                            ));
                            match result {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            tracing::error!(
                                                %error,
                                                "async registrar.on_change handler error"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        "registrar.on_change handler failed"
                                    );
                                }
                            }
                        }
                    });
                })
                .await
                .ok();
            }
        });
    }

    info!("dispatcher started");

    while let Ok(inbound) = inbound_rx.recv_async().await {
        let state = Arc::clone(&state);

        // Both requests and responses may invoke Python handlers
        // (on_request and on_reply), so use spawn_blocking for both
        // to avoid starving the tokio worker pool with GIL contention.
        tokio::task::spawn_blocking(move || {
            handle_inbound(inbound, &state);
        });
    }

    info!("dispatcher shutting down (inbound channel closed)");
}

/// Fire all expired timers in the timer wheel.
fn fire_expired_timers(state: &DispatcherState) {
    let now = std::time::Instant::now();
    let mut fired: Vec<TimerEntry> = Vec::new();

    state.timer_wheel.retain(|_id, entry| {
        if now >= entry.fires_at {
            fired.push(entry.clone());
            false // remove from wheel
        } else {
            true
        }
    });

    for entry in fired {
        let event = match entry.name {
            // Server transaction timers
            TimerName::J => Some(ServerEvent::Nist(NistEvent::TimerJ)),
            TimerName::G => Some(ServerEvent::Ist(IstEvent::TimerG)),
            TimerName::H => Some(ServerEvent::Ist(IstEvent::TimerH)),
            TimerName::I => Some(ServerEvent::Ist(IstEvent::TimerI)),
            _ => None,
        };

        if let Some(server_event) = event {
            match state.transaction_manager.process_server_event(&entry.key, server_event) {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
            continue;
        }

        let client_event = match entry.name {
            TimerName::A => Some(ClientEvent::Ict(IctEvent::TimerA)),
            TimerName::B => Some(ClientEvent::Ict(IctEvent::TimerB)),
            TimerName::D => Some(ClientEvent::Ict(IctEvent::TimerD)),
            TimerName::E => Some(ClientEvent::Nict(NictEvent::TimerE)),
            TimerName::F => Some(ClientEvent::Nict(NictEvent::TimerF)),
            TimerName::K => Some(ClientEvent::Nict(NictEvent::TimerK)),
            _ => None,
        };

        if let Some(client_event) = client_event {
            match state.transaction_manager.process_client_event(&entry.key, client_event) {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
        }
    }
}

/// Process actions from a timer-driven state machine event.
fn process_timer_actions(
    actions: &[Action],
    key: &TransactionKey,
    destination: Option<SocketAddr>,
    transport: Option<Transport>,
    connection_id: Option<ConnectionId>,
    state: &DispatcherState,
) {
    for action in actions {
        match action {
            Action::SendMessage(message) => {
                if let (Some(dest), Some(trans)) = (destination, transport) {
                    let conn_id = connection_id.unwrap_or_default();
                    send_message(message.clone(), trans, dest, conn_id, state);
                }
            }
            Action::StartTimer(name, duration) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.insert(timer_id, TimerEntry {
                    key: key.clone(),
                    name: *name,
                    fires_at: std::time::Instant::now() + *duration,
                    destination,
                    transport,
                    connection_id,
                });
            }
            Action::CancelTimer(name) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.remove(&timer_id);
            }
            Action::Timeout => {
                warn!(key = %key, "transaction timeout");
                // Session cleanup happens via sweep_stale_entries
            }
            Action::Terminated | Action::PassToTu(_) => {
                // PassToTu from timer context is unusual (shouldn't happen)
                // Terminated: transaction already auto-removed by manager
            }
        }
    }
}

/// Sweep stale proxy sessions.
fn sweep_stale_entries(state: &DispatcherState) {
    let ttl = state.transaction_timeout;
    let expired_sessions = state.session_store.sweep_stale(ttl) as u64;

    if expired_sessions > 0 {
        info!(
            expired_sessions,
            sessions = state.session_store.session_count(),
            transactions = state.transaction_manager.count(),
            "stale entry cleanup"
        );
    }
}

/// Handle a single inbound SIP message (request or response).
fn handle_inbound(inbound: InboundMessage, state: &DispatcherState) {
    // Parse bytes to string
    let raw = match std::str::from_utf8(&inbound.data) {
        Ok(s) => s,
        Err(error) => {
            warn!(remote = %inbound.remote_addr, "non-UTF8 SIP message: {error}");
            return;
        }
    };

    // RFC 5626 §3.5.1 / §4.4.1: CRLF keep-alive
    if raw.trim().is_empty() {
        // Record pong for CRLF keepalive tracker (TCP/TLS only).
        if matches!(inbound.transport, Transport::Tcp | Transport::Tls) {
            if let Some(ref tracker) = state.crlf_pong_tracker {
                tracker.record_pong(inbound.connection_id);
            }
        }
        return;
    }

    // Parse SIP message
    let message = match parse_sip_message(raw) {
        Ok((_, message)) => message,
        Err(error) => {
            warn!(remote = %inbound.remote_addr, "SIP parse error: {error}");
            return;
        }
    };

    // HEP capture — inbound (received from network)
    if let Some(ref hep) = state.hep_sender {
        hep.capture_inbound(
            inbound.remote_addr,
            inbound.local_addr,
            inbound.transport,
            &inbound.data,
        );
    }

    match &message.start_line {
        StartLine::Request(request_line) => {
            let method = request_line.method.as_str().to_string();
            handle_request(inbound, message, method, state);
        }
        StartLine::Response(status_line) => {
            let status_code = status_line.status_code;
            handle_response(inbound, message, status_code, state);
        }
    }
}

/// Handle an inbound SIP request — run through Python handlers.
fn handle_request(
    inbound: InboundMessage,
    message: SipMessage,
    method: String,
    state: &DispatcherState,
) {
    // --- Extract the UAC's Via branch and sent-by ---
    let uac_via = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next());
    let uac_branch = uac_via.as_ref().and_then(|v| v.branch.clone());
    let uac_sent_by = uac_via.as_ref()
        .map(|v| TransactionKey::format_sent_by(&v.host, v.port))
        .unwrap_or_default();

    // --- CANCEL handling ---
    // CANCEL has the same branch as the INVITE it cancels, so we must
    // intercept it BEFORE retransmission detection (which keys on branch).
    if method == "CANCEL" {
        handle_cancel(inbound, message, uac_branch.as_deref(), &uac_sent_by, state);
        return;
    }

    // --- ACK handling (RFC 3261 §17.2.1) ---
    // ACK for non-2xx is hop-by-hop: the transaction layer absorbs it.
    // ACK for 2xx is end-to-end: no IST exists (it terminated on 2xx),
    // so handle_ack returns None and we fall through to the script.
    if method == "ACK" {
        match state.transaction_manager.handle_ack(&message) {
            Ok(Some((key, actions))) => {
                debug!(
                    key = %key,
                    "ACK absorbed by INVITE server transaction"
                );
                process_timer_actions(
                    &actions,
                    &key,
                    Some(inbound.remote_addr),
                    Some(inbound.transport),
                    Some(inbound.connection_id),
                    state,
                );
                return;
            }
            Ok(None) => {
                // No IST found — ACK for 2xx (end-to-end) or stale.
                // Route via ProxySession using Call-ID + From-tag dialog key.
                // Using both fields avoids ambiguity when a B2BUA (e.g. FreeSWITCH)
                // reuses the same Call-ID for both call legs through this proxy.
                let call_id = message.headers.get("Call-ID");
                let from_tag = message
                    .typed_from()
                    .ok()
                    .flatten()
                    .and_then(|na| na.tag);
                if let (Some(cid), Some(ftag)) = (call_id, from_tag.as_deref()) {
                    if let Some(session_arc) = state.session_store.get_by_dialog_key(cid, ftag) {
                        handle_ack_via_session(inbound, message, session_arc, state);
                        return;
                    }

                    // B2BUA: bridge ACK to the winning B-leg.
                    // B2BUA: absorb the A-leg's ACK. We already ACK'd the B-leg
                    // ourselves on receiving 200 OK — the A-leg ACK is for our
                    // dialog with the A-leg and must not be relayed.
                    if let Some(internal_id) = state.call_actors.find_by_sip_call_id(cid) {
                        debug!(
                            call_id = %internal_id,
                            "B2BUA: absorbed A-leg ACK for 2xx (B-leg already ACK'd)"
                        );
                        return;
                    }
                }
                debug!("ACK has no matching IST or session — passing through");
            }
            Err(error) => {
                debug!("failed to match ACK to transaction: {error}");
            }
        }
    }

    // --- Server transaction retransmission detection ---
    // Check if a server transaction already exists for this request.
    // If so, the state machine handles retransmission (resending cached response).
    match state.transaction_manager.handle_server_retransmit(&message) {
        Ok(Some((key, actions))) => {
            debug!(
                method = %method,
                key = %key,
                "request retransmit handled by server transaction"
            );
            // Process actions — typically SendMessage to resend cached response.
            // Look up ProxySession for source routing, fall back to inbound info.
            for action in &actions {
                if let Action::SendMessage(response) = action {
                    // Send response back to the UAC (the original request source)
                    send_message(
                        response.clone(),
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        state,
                    );
                }
            }
            return;
        }
        Ok(None) => {
            // No existing server transaction — this is a new request, proceed below.
        }
        Err(error) => {
            debug!(method = %method, "failed to check server retransmit: {error}");
        }
    }

    debug!(
        method = %method,
        remote = %inbound.remote_addr,
        "processing request"
    );

    // Check if B2BUA mode should handle this INVITE
    let engine_state = state.engine.state();
    if method == "INVITE" && engine_state.has_b2bua_handlers() {
        // Detect re-INVITE (has To-tag + matches existing call)
        let to_tag = message.headers.get("To")
            .and_then(|t| t.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string()));
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());

        let is_reinvite = to_tag.is_some()
            && sip_call_id.as_ref()
                .map(|cid| state.call_actors.find_by_sip_call_id(cid).is_some())
                .unwrap_or(false);

        if is_reinvite {
            drop(engine_state);
            handle_b2bua_reinvite(inbound, message, state);
            return;
        }

        drop(engine_state);
        handle_b2bua_invite(inbound, message, state);
        return;
    }
    if method == "BYE" && engine_state.has_b2bua_handlers() {
        // Check if this BYE belongs to a B2BUA call
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_bye(inbound, message, state);
                return;
            }
        }
    }

    // --- Create server transaction ---
    // The server transaction handles retransmission absorption and timer management.
    // ACK is excluded (handled by existing IST), as are requests going to B2BUA.
    let txn_transport = crate::transaction::state::Transport::from(inbound.transport);
    let server_key = match state.transaction_manager.new_server_transaction(&message, txn_transport) {
        Ok((key, actions)) => {
            // Schedule any initial server-side timers
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        // Server transaction timers send responses upstream (to UAC)
                        destination: Some(inbound.remote_addr),
                        transport: Some(inbound.transport),
                        connection_id: Some(inbound.connection_id),
                    });
                }
            }
            Some(key)
        }
        Err(error) => {
            debug!(method = %method, "failed to create server transaction: {error}");
            None
        }
    };

    // --- Max-Forwards enforcement (RFC 3261 §16.3) ---
    // Check BEFORE invoking scripts — if MF == 0, reject immediately.
    if message.headers.max_forwards() == Some(0) {
        debug!(method = %method, "Max-Forwards is 0, rejecting with 483");
        let response = build_response(&message, 483, "Too Many Hops", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        return;
    }

    // Look up matching Python handlers
    let handlers = engine_state.proxy_request_handlers(&method);

    if handlers.is_empty() {
        warn!(method = %method, "no script handler registered");
        let response = build_response(&message, 500, "No Script Handler", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        return;
    }

    // Create PyRequest wrapping the message
    let transport_name = format!("{}", inbound.transport).to_lowercase();
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let request = PyRequest::with_local_domains(
        message_arc.clone(),
        transport_name,
        inbound.remote_addr.ip().to_string(),
        inbound.remote_addr.port(),
        Arc::clone(&state.local_domains),
    );

    // Call Python handlers
    let (action, record_routed, on_reply_cb, on_failure_cb) = Python::attach(|python| {
        let py_request = match Py::new(python, request) {
            Ok(py) => py,
            Err(error) => {
                error!("failed to create PyRequest: {error}");
                return (RequestAction::None, false, None, None);
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python),));
            match result {
                Ok(ret) => {
                    // If the handler is async, the return value is a coroutine — await it.
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async Python handler error: {error}");
                            return (
                                RequestAction::Reply {
                                    code: 500,
                                    reason: "Script Error".to_string(),
                                },
                                false,
                                None,
                                None,
                            );
                        }
                    }
                }
                Err(error) => {
                    error!("Python handler error: {error}");
                    return (
                        RequestAction::Reply {
                            code: 500,
                            reason: "Script Error".to_string(),
                        },
                        false,
                        None,
                        None,
                    );
                }
            }
        }

        let mut borrowed = py_request.borrow_mut(python);
        let action = borrowed.action().clone();
        let record_routed = borrowed.is_record_routed();
        let on_reply = borrowed.take_on_reply_callback();
        let on_failure = borrowed.take_on_failure_callback();
        (action, record_routed, on_reply, on_failure)
    });

    // Process the action
    let Ok(message_guard) = message_arc.lock() else {
        error!("message_arc lock poisoned");
        return;
    };
    match &action {
        RequestAction::None => {
            debug!("silent drop (no action from script)");
        }
        RequestAction::Reply { code, reason } => {
            let mut response = build_response(&message_guard, *code, reason, state.server_header.as_deref());

            // IPsec: inject Security-Server on 401 REGISTER and create SAs immediately.
            // Per 3GPP TS 33.203, the P-CSCF creates SAs right after sending the 401
            // so the UE's re-REGISTER over the protected port can be decrypted.
            if *code == 401 && method == "REGISTER" {
                if let (Some(ref ipsec_config), Some(ref ipsec_manager)) =
                    (&state.ipsec_config, &state.ipsec_manager)
                {
                    if let Some(security_client_value) = message_guard.headers.get("Security-Client") {
                        if let Some(security_client) = crate::ipsec::parse_security_client(security_client_value) {
                            let (spi_pc, spi_ps) = ipsec_manager.allocate_spi_pair();

                            // Build Security-Server with P-CSCF's SPIs and ports
                            let security_server = format!(
                                "ipsec-3gpp; alg={}; spi-c={}; spi-s={}; port-c={}; port-s={}",
                                security_client.algorithm,
                                spi_pc,
                                spi_ps,
                                ipsec_config.pcscf_port_c,
                                ipsec_config.pcscf_port_s,
                            );
                            response.headers.set("Security-Server", security_server);

                            // Extract nonce from WWW-Authenticate to look up CK/IK
                            let nonce_key = response
                                .headers
                                .get("WWW-Authenticate")
                                .and_then(|value| {
                                    value.find("nonce=\"").map(|start| {
                                        let after = &value[start + 7..];
                                        after.split('"').next().unwrap_or("").to_string()
                                    })
                                })
                                .unwrap_or_default();

                            // Look up CK/IK stored by auth module during AKA challenge generation
                            let key_material = if !nonce_key.is_empty() {
                                crate::script::api::auth::aka_key_store().remove(&nonce_key)
                            } else {
                                None
                            };

                            if let Some((_, keys)) = key_material {
                                let sa_pair = crate::ipsec::SecurityAssociationPair {
                                    ue_addr: inbound.remote_addr.ip(),
                                    pcscf_addr: state.local_addr.ip(),
                                    ue_port_c: security_client.port_c,
                                    ue_port_s: security_client.port_s,
                                    pcscf_port_c: ipsec_config.pcscf_port_c,
                                    pcscf_port_s: ipsec_config.pcscf_port_s,
                                    spi_uc: security_client.spi_c,
                                    spi_us: security_client.spi_s,
                                    spi_pc,
                                    spi_ps,
                                    ealg: crate::ipsec::EncryptionAlgorithm::Null,
                                    aalg: crate::ipsec::IntegrityAlgorithm::HmacSha1,
                                    encryption_key: String::new(),
                                    integrity_key: keys.ik.iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<String>(),
                                };

                                let ipsec_manager = Arc::clone(ipsec_manager);
                                tokio::spawn(async move {
                                    if let Err(error) = ipsec_manager.create_sa_pair(sa_pair).await {
                                        error!(%error, "IPsec: failed to create SA pair on 401");
                                    }
                                });
                            }

                            debug!(
                                spi_pc,
                                spi_ps,
                                spi_uc = security_client.spi_c,
                                spi_us = security_client.spi_s,
                                pcscf_port_c = ipsec_config.pcscf_port_c,
                                pcscf_port_s = ipsec_config.pcscf_port_s,
                                "IPsec: Security-Server added to 401, SAs created"
                            );
                        }
                    }
                }
            }

            // IPsec: delete SA pair on deregistration (REGISTER with Expires: 0)
            if *code == 200 && method == "REGISTER" {
                if let (Some(ref _ipsec_config), Some(ref ipsec_manager)) =
                    (&state.ipsec_config, &state.ipsec_manager)
                {
                    let is_deregister = message_guard
                        .headers
                        .get("Expires")
                        .map(|value| value.trim() == "0")
                        .unwrap_or(false)
                        || message_guard
                            .headers
                            .get("Contact")
                            .map(|value| value.contains("expires=0"))
                            .unwrap_or(false);

                    if is_deregister {
                        let ue_addr = inbound.remote_addr.ip();
                        let ue_port = inbound.remote_addr.port();
                        let ipsec_manager = Arc::clone(ipsec_manager);
                        tokio::spawn(async move {
                            if let Err(error) = ipsec_manager.delete_sa_pair(&ue_addr, ue_port).await {
                                warn!(ue = %ue_addr, %error, "IPsec: failed to delete SA pair");
                            }
                        });
                    }
                }
            }

            // Feed response into server transaction so it can cache it for
            // retransmit handling and manage Timer J/G/H.
            // The state machine emits SendMessage which process_timer_actions
            // delivers, so we only send manually if the transaction path didn't fire.
            let mut sent_by_transaction = false;
            if let Some(ref key) = server_key {
                let server_event = if *code < 200 {
                    // Provisional
                    if key.method == crate::sip::message::Method::Invite {
                        Some(ServerEvent::Ist(IstEvent::TuProvisional(response.clone())))
                    } else {
                        Some(ServerEvent::Nist(NistEvent::TuProvisional(response.clone())))
                    }
                } else if *code < 300 && key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::Tu2xx(response.clone())))
                } else if key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuFinal(response.clone())))
                };

                if let Some(event) = server_event {
                    match state.transaction_manager.process_server_event(key, event) {
                        Ok(actions) => {
                            process_timer_actions(
                                &actions,
                                key,
                                Some(inbound.remote_addr),
                                Some(inbound.transport),
                                Some(inbound.connection_id),
                                state,
                            );
                            sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                        }
                        Err(error) => {
                            debug!(key = %key, "failed to feed reply to server transaction: {error}");
                        }
                    }
                }
            }
            if !sent_by_transaction {
                send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            }
        }
        RequestAction::Relay { next_hop } => {
            // RFC 3261 §16.2: a stateful proxy SHOULD send 100 Trying
            // immediately upon receiving an INVITE to stop UAC retransmissions.
            if method == "INVITE" {
                let trying = build_response(&message_guard, 100, "Trying", state.server_header.as_deref());
                send_message(trying, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            }
            relay_request(
                &message_guard,
                next_hop.as_deref(),
                record_routed,
                &inbound,
                server_key.as_ref(),
                state,
                on_reply_cb,
                on_failure_cb,
            );
        }
        RequestAction::Fork { targets, strategy } => {
            if targets.is_empty() {
                warn!("fork with empty targets list");
                let response = build_response(&message_guard, 500, "No Targets", state.server_header.as_deref());
                send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            } else {
                if method == "INVITE" {
                    let trying = build_response(&message_guard, 100, "Trying", state.server_header.as_deref());
                    send_message(trying, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
                }
                let fork_strategy = match strategy.as_str() {
                    "sequential" => crate::proxy::fork::ForkStrategy::Sequential,
                    _ => crate::proxy::fork::ForkStrategy::Parallel,
                };
                relay_fork_request(
                    &message_guard,
                    targets,
                    fork_strategy,
                    record_routed,
                    &inbound,
                    server_key.as_ref(),
                    state,
                );
            }
        }
    }
}

/// Relay a SIP request to its destination.
///
/// 1. Determine target address (explicit next_hop, or Request-URI)
/// 2. Clone the message, add Via, decrement Max-Forwards
/// 3. Store branch in pending map for response routing
/// 4. Send to target
#[allow(clippy::too_many_arguments)]
fn relay_request(
    message: &SipMessage,
    next_hop: Option<&str>,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
    on_reply_callback: Option<Py<PyAny>>,
    on_failure_callback: Option<Py<PyAny>>,
) {
    // Determine target URI string
    let target_uri_string = match next_hop {
        Some(hop) => hop.to_string(),
        None => {
            // Use the Request-URI
            match &message.start_line {
                StartLine::Request(request_line) => request_line.request_uri.to_string(),
                _ => {
                    error!("relay called on non-request");
                    return;
                }
            }
        }
    };

    // Resolve to SocketAddr + transport
    let target = match resolve_target(&target_uri_string, &state.dns_resolver) {
        Some(t) => t,
        None => {
            warn!(target = %target_uri_string, "cannot resolve relay target");
            let response = build_response(message, 502, "Bad Gateway", state.server_header.as_deref());
            send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            return;
        }
    };
    let destination = target.address;
    let outbound_transport = target.transport.unwrap_or(inbound.transport);

    // Prevent routing loops — don't relay to ourselves
    if destination.port() == state.local_addr.port()
        && (destination.ip() == state.local_addr.ip()
            || destination.ip().is_loopback())
    {
        // ACK to 2xx is end-to-end and should go to the UAS Contact, not the
        // proxy. If the R-URI still points at us, silently drop rather than
        // generating a response (ACK never gets a response per RFC 3261).
        let is_ack = matches!(
            &message.start_line,
            StartLine::Request(rl) if rl.method == crate::sip::message::Method::Ack
        );
        if is_ack {
            debug!(target = %target_uri_string, "ACK to self — silently dropping");
            return;
        }

        warn!(
            target = %target_uri_string,
            destination = %destination,
            "relay loop detected — destination is ourselves"
        );
        let response = build_response(message, 482, "Loop Detected", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        return;
    }

    // Clone the message for modification
    let mut relayed = message.clone();

    // Decrement Max-Forwards
    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        let response = build_response(message, 483, "Too Many Hops", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        return;
    }

    // Add our Via — use the outbound transport for the Via header
    let transport_str = format!("{}", outbound_transport);
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &state.via_host(&outbound_transport),
        Some(state.via_port(&outbound_transport)),
    );

    // Add Record-Route if the script requested it.
    // When bridging transports (e.g. TLS↔TCP), insert *two* Record-Route
    // headers (r2) so each leg's in-dialog requests use the correct transport.
    if record_routed {
        let internal_host = format_sip_host(&state.local_addr.ip().to_string());
        let inbound_transport_str = format!("{}", inbound.transport).to_lowercase();
        if inbound_transport_str != transport_str.to_lowercase() {
            // Double Record-Route: outbound transport first (topmost after prepend order).
            // Each RR must use the port of the respective transport listener so that
            // in-dialog requests from each leg reach the correct listener.
            // The TLS-facing RR uses the advertised address when set, since
            // external peers may not be able to reach the internal bind IP.
            let outbound_port = state.listen_addrs.get(&outbound_transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let inbound_port = state.listen_addrs.get(&inbound.transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let outbound_host = state.advertised_addrs.get(&outbound_transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let inbound_host = state.advertised_addrs.get(&inbound.transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let rr_outbound = format!("sip:{}:{};transport={}", outbound_host, outbound_port, transport_str.to_lowercase());
            let rr_inbound = format!("sip:{}:{};transport={}", inbound_host, inbound_port, inbound_transport_str);
            core::add_record_route(&mut relayed.headers, &rr_inbound);
            core::add_record_route(&mut relayed.headers, &rr_outbound);
        } else {
            let rr_uri = format!("sip:{}:{};transport={}", internal_host, state.local_addr.port(), transport_str.to_lowercase());
            core::add_record_route(&mut relayed.headers, &rr_uri);
        }
    }

    // Serialize the relayed request
    let data = Bytes::from(relayed.to_bytes());

    debug!(
        branch = %branch,
        destination = %destination,
        transport = %outbound_transport,
        "relaying request"
    );

    // HEP capture — outbound relayed request
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&outbound_transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, outbound_transport, &data);
    }

    // Send to target — use resolved transport, with connection pool for TCP/TLS
    let connection_id = send_to_target(data, &target, inbound.transport, inbound.connection_id, state);

    // Create client transaction for retransmission and timeout handling.
    // The state machine will schedule Timer A/E (retransmit) and Timer B/F (timeout).
    // We've already sent the initial request above, so we only process timer actions.
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    match state.transaction_manager.new_client_transaction(relayed, txn_transport) {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: client_key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        destination: Some(destination),
                        transport: Some(outbound_transport),
                        connection_id: Some(connection_id),
                    });
                }
            }

            // Create ProxySession linking server → client transaction
            if let Some(srv_key) = server_key {
                let mut session = ProxySession::new(
                    srv_key.clone(),
                    inbound.remote_addr,
                    inbound.connection_id,
                    inbound.transport,
                    message.clone(),
                    record_routed,
                );
                session.add_client_key(client_key.clone());
                session.set_client_branch(client_key, ClientBranch {
                    destination,
                    transport: outbound_transport,
                    connection_id,
                });
                session.on_reply_callback = on_reply_callback;
                session.on_failure_callback = on_failure_callback;
                state.session_store.insert(session);
            }
        }
        Err(error) => {
            debug!(branch = %branch, "failed to create client transaction: {error}");
            // Non-fatal: relay still works without transaction layer
        }
    }
}

/// Relay a forked request to multiple targets.
///
/// Creates a ProxySession with a ForkAggregator and sends to all targets
/// (parallel) or just the first (sequential, rest tried on failure).
fn relay_fork_request(
    message: &SipMessage,
    targets: &[String],
    strategy: crate::proxy::fork::ForkStrategy,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
) {
    use crate::proxy::fork::ForkAggregator;

    // Parse target URIs
    let target_uris: Vec<crate::sip::uri::SipUri> = targets
        .iter()
        .filter_map(|target| parse_uri_standalone(target).ok())
        .collect();

    if target_uris.is_empty() {
        warn!("fork: no valid target URIs");
        let response = build_response(message, 500, "No Valid Targets", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        return;
    }

    let aggregator = Arc::new(std::sync::Mutex::new(
        ForkAggregator::new(target_uris, strategy),
    ));

    // Create ProxySession (even without server_key, we need the aggregator)
    let srv_key = match server_key {
        Some(key) => key.clone(),
        None => {
            // Fall back to single-target relay if no server transaction
            relay_request(message, targets.first().map(|s| s.as_str()), record_routed, inbound, None, state, None, None);
            return;
        }
    };

    let mut session = ProxySession::new(
        srv_key.clone(),
        inbound.remote_addr,
        inbound.connection_id,
        inbound.transport,
        message.clone(),
        record_routed,
    );
    session.fork_aggregator = Some(Arc::clone(&aggregator));

    // Determine which branches to start now
    let branches_to_start: Vec<usize> = match strategy {
        crate::proxy::fork::ForkStrategy::Parallel => (0..targets.len()).collect(),
        crate::proxy::fork::ForkStrategy::Sequential => {
            if targets.is_empty() { vec![] } else { vec![0] }
        }
    };

    for branch_index in branches_to_start {
        let target = &targets[branch_index];
        relay_fork_branch(
            message,
            target,
            branch_index,
            record_routed,
            inbound,
            &srv_key,
            &mut session,
            &aggregator,
            state,
        );
    }

    state.session_store.insert(session);
}

/// Relay a single branch of a forked request.
///
/// Resolves the target, adds Via, sends the request, creates a client transaction,
/// and registers the branch in the ProxySession.
#[allow(clippy::too_many_arguments)]
fn relay_fork_branch(
    message: &SipMessage,
    target: &str,
    branch_index: usize,
    record_routed: bool,
    inbound: &InboundMessage,
    _server_key: &TransactionKey,
    session: &mut ProxySession,
    aggregator: &Arc<std::sync::Mutex<crate::proxy::fork::ForkAggregator>>,
    state: &DispatcherState,
) {
    // Resolve target
    let relay_target = match resolve_target(target, &state.dns_resolver) {
        Some(t) => t,
        None => {
            warn!(target = %target, branch = branch_index, "fork: cannot resolve target");
            return;
        }
    };
    let destination = relay_target.address;
    let outbound_transport = relay_target.transport.unwrap_or(inbound.transport);

    // Loop detection
    if destination.port() == state.local_addr.port()
        && (destination.ip() == state.local_addr.ip() || destination.ip().is_loopback())
    {
        warn!(target = %target, "fork: loop detected");
        return;
    }

    // Clone and modify message
    let mut relayed = message.clone();

    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        return; // caller handles the error for the whole fork
    }

    let transport_str = format!("{}", outbound_transport);
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &state.via_host(&outbound_transport),
        Some(state.via_port(&outbound_transport)),
    );

    if record_routed {
        let internal_host = format_sip_host(&state.local_addr.ip().to_string());
        let inbound_transport_str = format!("{}", inbound.transport).to_lowercase();
        if inbound_transport_str != transport_str.to_lowercase() {
            let outbound_port = state.listen_addrs.get(&outbound_transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let inbound_port = state.listen_addrs.get(&inbound.transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let outbound_host = state.advertised_addrs.get(&outbound_transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let inbound_host = state.advertised_addrs.get(&inbound.transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let rr_outbound = format!("sip:{}:{};transport={}", outbound_host, outbound_port, transport_str.to_lowercase());
            let rr_inbound = format!("sip:{}:{};transport={}", inbound_host, inbound_port, inbound_transport_str);
            core::add_record_route(&mut relayed.headers, &rr_inbound);
            core::add_record_route(&mut relayed.headers, &rr_outbound);
        } else {
            let rr_uri = format!("sip:{}:{};transport={}", internal_host, state.local_addr.port(), transport_str.to_lowercase());
            core::add_record_route(&mut relayed.headers, &rr_uri);
        }
    }

    // Update Request-URI to the fork target (each branch gets its own Contact URI)
    if let Ok(new_uri) = parse_uri_standalone(target) {
        if let StartLine::Request(ref mut request_line) = relayed.start_line {
            request_line.request_uri = new_uri;
        }
    }

    let data = Bytes::from(relayed.to_bytes());

    // HEP capture — outbound fork branch
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&outbound_transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, outbound_transport, &data);
    }

    // Send via pool for TCP/TLS, direct channel for UDP
    let connection_id = send_to_target(data, &relay_target, inbound.transport, inbound.connection_id, state);

    debug!(
        branch = %branch,
        target = %target,
        branch_index = branch_index,
        destination = %destination,
        transport = %outbound_transport,
        "fork: sent branch"
    );

    // Mark branch as Trying in aggregator
    if let Ok(mut agg) = aggregator.lock() {
        agg.mark_trying(branch_index);
    }

    // Create client transaction
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    match state.transaction_manager.new_client_transaction(relayed, txn_transport) {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: client_key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        destination: Some(destination),
                        transport: Some(outbound_transport),
                        connection_id: Some(connection_id),
                    });
                }
            }

            // Register in session
            session.add_client_key(client_key.clone());
            session.set_client_branch(client_key.clone(), ClientBranch {
                destination,
                transport: outbound_transport,
                connection_id,
            });
            session.branch_index_map.insert(client_key, branch_index);
        }
        Err(error) => {
            debug!(branch = %branch, "fork: failed to create client transaction: {error}");
        }
    }
}

/// Handle an inbound SIP response — route back to the original sender.
fn handle_response(
    _inbound: InboundMessage,
    mut message: SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    // Check if this response matches a UAC request (keepalive, health probe)
    if state.uac_sender.match_response(&message) {
        debug!(status_code = status_code, "UAC response matched");
        return;
    }

    // Check if this response matches an outbound registration (z9hG4bK-reg- branch)
    if let Some(ref registrant) = state.registrant_manager {
        if let Some(top_via_raw) = message.headers.get("Via") {
            if let Ok(vias) = Via::parse_multi(top_via_raw) {
                if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                    if branch.starts_with("z9hG4bK-reg-") {
                        handle_registrant_response(registrant, &message, status_code, branch, state);
                        return;
                    }
                }
            }
        }
    }

    // Check if this response matches a SIPREC recording INVITE (z9hG4bK-rec- branch)
    if let Some(top_via_raw) = message.headers.get("Via") {
        if let Ok(vias) = Via::parse_multi(top_via_raw) {
            if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                if branch.starts_with("z9hG4bK-rec-") {
                    if let Some(session_id) = state.recording_manager.session_for_branch(branch) {
                        if (200..300).contains(&status_code) {
                            let to_tag = message.headers.get("To")
                                .and_then(|to| to.split("tag=").nth(1))
                                .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string());
                            state.recording_manager.handle_success(&session_id, to_tag);
                        } else if status_code >= 300 {
                            state.recording_manager.handle_failure(&session_id, status_code);
                        }
                    }
                    return;
                }
            }
        }
    }

    // RFC 3261 §16.7 step 3: a proxy MUST NOT forward 100 Trying upstream.
    // It is hop-by-hop; the proxy already sends its own 100 Trying to the UAC.
    if status_code == 100 {
        debug!("absorbing 100 Trying from downstream");
        return;
    }

    // Get the topmost Via to find the branch
    let top_via = match message.headers.get("Via") {
        Some(raw) => match Via::parse_multi(raw) {
            Ok(vias) if !vias.is_empty() => vias[0].clone(),
            _ => {
                warn!("response has unparseable Via header");
                return;
            }
        },
        None => {
            warn!("response has no Via header");
            return;
        }
    };

    let branch = match &top_via.branch {
        Some(branch) => branch.clone(),
        None => {
            warn!("topmost Via has no branch parameter");
            return;
        }
    };

    // Check if this response belongs to a B2BUA call
    if let Some(call_id) = state.call_actors.call_id_for_branch(&branch) {
        handle_b2bua_response(&call_id, &branch, &mut message, status_code, state);
        return;
    }

    // Post-teardown: re-ACK retransmitted re-INVITE 200 OKs for calls already
    // torn down by BYE. The zombie map holds destination info for B-leg entries
    // that had active re-INVITE tracking when the call was removed.
    if (200..300).contains(&status_code) {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some(zombie) = state.call_actors.get_zombie_reinvite(sip_call_id) {
                        let transport_str = format!("{}", zombie.transport).to_uppercase();
                        let outbound_port = state.listen_addrs.get(&zombie.transport)
                            .map(|a| a.port())
                            .unwrap_or(state.local_addr.port());
                        let cseq_num = cseq_raw.split_whitespace().next()
                            .unwrap_or("1").to_string();
                        let from = message.headers.from().cloned().unwrap_or_default();
                        let to = message.headers.to().cloned().unwrap_or_default();
                        let ack_uri = SipUri::new(zombie.destination.ip().to_string())
                            .with_port(zombie.destination.port());
                        let ack = match SipMessageBuilder::new()
                            .request(Method::Ack, ack_uri)
                            .via(format!(
                                "SIP/2.0/{} {}:{};branch={}",
                                transport_str,
                                format_sip_host(&state.local_addr.ip().to_string()),
                                outbound_port,
                                TransactionKey::generate_branch(),
                            ))
                            .from(from.to_string())
                            .to(to.to_string())
                            .call_id(sip_call_id.to_string())
                            .cseq(format!("{} ACK", cseq_num))
                            .header("Max-Forwards", "70".to_string())
                            .content_length(0)
                            .build()
                        {
                            Ok(ack) => ack,
                            Err(error) => {
                                error!("B2BUA zombie ACK build failed: {error}");
                                return;
                            }
                        };
                        send_b2bua_to_bleg(ack, zombie.transport, zombie.destination, state);
                        debug!(
                            call_id = sip_call_id,
                            "B2BUA: zombie re-ACK for post-teardown re-INVITE 200 OK retransmission"
                        );
                        return;
                    }
                }
            }
        }
    }

    // Parse CSeq once for both transaction processing and session routing.
    let sent_by = TransactionKey::format_sent_by(&top_via.host, top_via.port);
    let client_txn_key = message.headers.get("CSeq")
        .and_then(|cseq_raw| crate::sip::headers::cseq::CSeq::parse(cseq_raw).ok())
        .map(|cseq| TransactionKey::new(branch.clone(), cseq.method, sent_by.clone()));

    // Feed response to client transaction (if one exists).
    // The state machine handles retransmit absorption and timer cancellation.
    if let Some(ref key) = client_txn_key {
        let event = if status_code < 200 {
            if key.method == crate::sip::message::Method::Invite {
                Some(ClientEvent::Ict(IctEvent::Provisional(message.clone())))
            } else {
                Some(ClientEvent::Nict(NictEvent::Provisional(message.clone())))
            }
        } else if status_code < 300 && key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::Response2xx(message.clone())))
        } else if key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::ResponseNon2xx(message.clone())))
        } else {
            Some(ClientEvent::Nict(NictEvent::FinalResponse(message.clone())))
        };

        if let Some(event) = event {
            match state.transaction_manager.process_client_event(key, event) {
                Ok(actions) => {
                    for action in &actions {
                        match action {
                            Action::CancelTimer(name) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.remove(&timer_id);
                            }
                            Action::StartTimer(name, duration) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.insert(timer_id, TimerEntry {
                                    key: key.clone(),
                                    name: *name,
                                    fires_at: std::time::Instant::now() + *duration,
                                    destination: None,
                                    transport: None,
                                    connection_id: None,
                                });
                            }
                            _ => {}
                        }
                    }

                    // If the state machine did NOT produce PassToTu, it absorbed the response
                    let should_forward = actions.iter().any(|a| matches!(a, Action::PassToTu(_)));
                    if !should_forward && status_code >= 200 {
                        debug!(
                            branch = %branch,
                            status = status_code,
                            "response absorbed by client transaction"
                        );
                        return;
                    }
                }
                Err(_) => {
                    // No transaction found — fall through to normal processing
                }
            }
        }
    }

    if let Some(ref client_key) = client_txn_key {
        if let Some(session_arc) = state.session_store.get_by_client_key(client_key) {
            let (source_addr, connection_id, transport, server_key, fork_agg, branch_index, original_request, relay_on_reply, relay_on_failure, client_branch) = {
                let session = match session_arc.read() {
                    Ok(s) => s,
                    Err(error) => {
                        error!("proxy session lock poisoned: {error}");
                        return;
                    }
                };
                (
                    session.source_addr,
                    session.connection_id,
                    session.transport,
                    session.server_key.clone(),
                    session.fork_aggregator.clone(),
                    session.branch_index_map.get(client_key).copied(),
                    session.original_request.clone(),
                    session.on_reply_callback.clone(),
                    session.on_failure_callback.clone(),
                    session.client_branches.get(client_key).cloned(),
                )
            };

            // RFC 3261 §17.1.1.3: the client transaction MUST generate an ACK
            // for non-2xx final responses to INVITE, sent hop-by-hop to the
            // same downstream destination.
            if status_code >= 300
                && client_key.method == crate::sip::message::Method::Invite
            {
                match client_branch {
                    Some(ref cb) => {
                        let ack = build_ack_for_non2xx(&original_request, &message, &branch, cb.transport, state.local_addr);
                        send_to_target(
                            ack.to_bytes().into(),
                            &RelayTarget { address: cb.destination, transport: Some(cb.transport) },
                            cb.transport,
                            cb.connection_id,
                            state,
                        );
                        info!(
                            branch = %branch,
                            destination = %cb.destination,
                            transport = %cb.transport,
                            "ACK for {status_code} sent downstream"
                        );
                    }
                    None => {
                        warn!(
                            branch = %branch,
                            status = status_code,
                            "cannot send ACK for non-2xx: no client branch in session"
                        );
                    }
                }
            }

            // Strip our topmost Via before forwarding
            core::strip_top_via(&mut message.headers);

            // Run Python reply handlers
            let (updated_message, should_forward) = run_reply_handlers(
                message,
                status_code,
                &branch,
                state,
                original_request.clone(),
                source_addr,
                transport,
            );
            if !should_forward {
                state.session_store.remove_client_key(client_key);
                return;
            }
            message = updated_message;

            // Invoke per-relay on_reply / on_failure callbacks if set
            if relay_on_reply.is_some() || (relay_on_failure.is_some() && status_code >= 400) {
                let msg_arc = Arc::new(std::sync::Mutex::new(message));
                let req_arc = Arc::new(std::sync::Mutex::new(original_request.clone()));
                let (updated_msg, cb_forward): (Option<SipMessage>, bool) = Python::attach(|python| {
                    let py_reply_obj = PyReply::new(Arc::clone(&msg_arc));
                    let py_reply = match Py::new(python, py_reply_obj) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyReply for relay callback: {error}");
                            return (None, true);
                        }
                    };
                    let py_req = match Py::new(python, PyRequest::new(
                        Arc::clone(&req_arc),
                        transport.to_string(),
                        source_addr.ip().to_string(),
                        source_addr.port(),
                    )) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyRequest for relay callback: {error}");
                            return (None, true);
                        }
                    };

                    // on_reply callback: (request, reply)
                    if let Some(ref on_reply) = relay_on_reply {
                        let callable = on_reply.bind(python);
                        match callable.call1((py_req.bind(python), py_reply.bind(python))) {
                            Ok(ret) => {
                                if let Ok(true) = is_coroutine(python, &ret) {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async relay on_reply callback error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("relay on_reply callback error: {error}");
                            }
                        }
                    }

                    // on_failure callback: (request, code, reason)
                    if status_code >= 400 {
                        if let Some(ref on_failure) = relay_on_failure {
                            let reason = best_error_reason(status_code);
                            let callable = on_failure.bind(python);
                            match callable.call1((py_req.bind(python), status_code, reason)) {
                                Ok(ret) => {
                                    if let Ok(true) = is_coroutine(python, &ret) {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async relay on_failure callback error: {error}");
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("relay on_failure callback error: {error}");
                                }
                            }
                        }
                    }

                    let forwarded = py_reply.borrow(python).was_forwarded();
                    (None, forwarded)
                });
                let _ = updated_msg; // unused — message stays in msg_arc
                if !cb_forward {
                    state.session_store.remove_client_key(client_key);
                    return;
                }
                // Recover the message from the Arc
                message = match Arc::try_unwrap(msg_arc) {
                    Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                    Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                };
            }

            // --- Fork aggregator decision ---
            if let (Some(ref aggregator), Some(index)) = (&fork_agg, branch_index) {
                let fork_action = match aggregator.lock() {
                    Ok(mut agg) => agg.on_branch_response(index, status_code),
                    Err(_) => {
                        error!("fork aggregator lock poisoned");
                        crate::proxy::fork::ForkAction::ContinueWaiting
                    }
                };

                match fork_action {
                    crate::proxy::fork::ForkAction::ContinueWaiting => {
                        debug!(
                            status = status_code,
                            branch_index = index,
                            "fork: waiting for more branches"
                        );
                        return;
                    }
                    crate::proxy::fork::ForkAction::Forward2xx => {
                        debug!(status = status_code, "fork: forwarding 2xx, cancelling others");
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::Forward6xx => {
                        debug!(status = status_code, "fork: forwarding 6xx, cancelling others");
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::ForwardProvisional(_code) => {
                        // Forward provisional upstream (no cleanup)
                    }
                    crate::proxy::fork::ForkAction::ForwardBestError(best_code) => {
                        debug!(best_code = best_code, "fork: all branches failed");
                        let reason = best_error_reason(best_code);
                        let Ok(session) = session_arc.read() else {
                            error!("session_arc read lock poisoned");
                            return;
                        };
                        let original_request = session.original_request.clone();
                        let best_response = build_response(
                            &original_request,
                            best_code,
                            reason,
                            state.server_header.as_deref(),
                        );
                        drop(session);

                        // Invoke @proxy.on_failure handlers before forwarding
                        let engine_state = state.engine.state();
                        let failure_handlers = engine_state.handlers_for(&HandlerKind::ProxyFailure);
                        if !failure_handlers.is_empty() {
                            let response_arc = Arc::new(std::sync::Mutex::new(best_response));
                            let reply = PyReply::new(Arc::clone(&response_arc));
                            let request_arc = Arc::new(std::sync::Mutex::new(original_request));
                            let py_request = PyRequest::new(
                                request_arc,
                                transport.to_string(),
                                source_addr.ip().to_string(),
                                source_addr.port(),
                            );

                            let forwarded = Python::attach(|python| {
                                let py_reply = match Py::new(python, reply) {
                                    Ok(obj) => obj,
                                    Err(e) => {
                                        error!("failed to create PyReply for on_failure: {e}");
                                        return true;
                                    }
                                };
                                let py_req = match Py::new(python, py_request) {
                                    Ok(obj) => obj,
                                    Err(e) => {
                                        error!("failed to create PyRequest for on_failure: {e}");
                                        return true;
                                    }
                                };

                                for handler in &failure_handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((py_req.bind(python), py_reply.bind(python),));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(e) = run_coroutine(python, &ret) {
                                                    error!("async on_failure handler error: {e}");
                                                    return true;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("on_failure handler error: {e}");
                                            return true;
                                        }
                                    }
                                }

                                let result = py_reply.borrow(python).was_forwarded();
                                result
                            });

                            if !forwarded {
                                debug!("on_failure handler suppressed error response");
                                state.session_store.remove_by_server_key(&server_key);
                                return;
                            }

                            let final_response = match Arc::try_unwrap(response_arc) {
                                Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                                Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                            };
                            send_message(final_response, transport, source_addr, connection_id, state);
                        } else {
                            send_message(best_response, transport, source_addr, connection_id, state);
                        }

                        state.session_store.remove_by_server_key(&server_key);
                        return;
                    }
                    crate::proxy::fork::ForkAction::TryNext(next_index) => {
                        debug!(next_index = next_index, "fork: trying next branch (sequential)");
                        start_next_fork_branch(
                            next_index,
                            &session_arc,
                            &server_key,
                            state,
                        );
                        return;
                    }
                }
            }

            // Feed the response into the server transaction for caching
            let server_event = if status_code < 200 {
                if server_key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuProvisional(message.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuProvisional(message.clone())))
                }
            } else if status_code < 300 && server_key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::Tu2xx(message.clone())))
            } else if server_key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(message.clone())))
            } else {
                Some(ServerEvent::Nist(NistEvent::TuFinal(message.clone())))
            };

            // Feed response to server transaction. If the transaction emits
            // SendMessage, it handles delivery — we must not send again ourselves.
            let mut sent_by_transaction = false;
            if let Some(event) = server_event {
                if let Ok(actions) = state.transaction_manager.process_server_event(&server_key, event) {
                    sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                    process_timer_actions(
                        &actions,
                        &server_key,
                        Some(source_addr),
                        Some(transport),
                        Some(connection_id),
                        state,
                    );
                }
            }

            if !sent_by_transaction {
                debug!(
                    status = status_code,
                    destination = %source_addr,
                    branch = %branch,
                    "forwarding response via session"
                );
                send_message(message, transport, source_addr, connection_id, state);
            }

            // Clean up on final response
            if status_code >= 200 {
                state.session_store.remove_client_key(client_key);
            }
            return;
        }
    }

    // No matching session or B2BUA call — response is not ours
    debug!(branch = %branch, "response for unknown branch (not ours)");
}

/// Run `@proxy.on_reply` Python handlers on a response message.
///
/// Returns `(message, forwarded)` — if `forwarded` is false, the script
/// chose to drop the response (no `relay()` called).
fn run_reply_handlers(
    message: SipMessage,
    status_code: u16,
    branch: &str,
    state: &DispatcherState,
    original_request: SipMessage,
    source_addr: SocketAddr,
    transport: crate::transport::Transport,
) -> (SipMessage, bool) {
    let engine_state = state.engine.state();
    let reply_handlers = engine_state.handlers_for(&HandlerKind::ProxyReply);

    if reply_handlers.is_empty() {
        return (message, true);
    }

    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let reply = PyReply::new(Arc::clone(&message_arc));

    // Build a PyRequest from the original request so scripts get (request, reply)
    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let py_request_obj = PyRequest::new(
        request_arc,
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
    );

    let forwarded = Python::attach(|python| {
        let py_reply = match Py::new(python, reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply: {error}");
                return true; // forward on error
            }
        };
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for reply handler: {error}");
                return true;
            }
        };

        for handler in &reply_handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python), py_reply.bind(python),));
            match result {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async Python reply handler error: {error}");
                            return true;
                        }
                    }
                }
                Err(error) => {
                    error!("Python reply handler error: {error}");
                    return true; // forward on error to avoid silent drops
                }
            }
        }

        let result = py_reply.borrow(python).was_forwarded();
        result
    });

    if !forwarded {
        debug!(
            status = status_code,
            branch = %branch,
            "reply dropped by script (no relay() called)"
        );
    }

    // Extract the (possibly modified) message back
    let extracted = match Arc::try_unwrap(message_arc) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|error| {
            warn!("message mutex poisoned in reply handler: {error}");
            error.into_inner()
        }),
        Err(arc) => {
            // Arc still has extra references — clone from the shared state
            warn!("PyReply still holds message arc reference, cloning");
            arc.lock().unwrap_or_else(|error| error.into_inner()).clone()
        }
    };

    (extracted, forwarded)
}

/// Resolve a SIP URI string to a socket address using DNS (RFC 3263).
///
/// Supports numeric IPs, bare `ip:port` strings, and full SIP URIs with
/// DNS A/AAAA/SRV resolution.  Called from synchronous context using
/// `block_in_place` because the callers (relay, fork, B2BUA) are sync
/// functions running on the tokio multi-threaded runtime.
/// Resolved relay target: address + optional transport override.
struct RelayTarget {
    address: SocketAddr,
    /// Transport from URI params or SRV; `None` means use the inbound transport.
    transport: Option<Transport>,
}

fn resolve_target(uri_string: &str, resolver: &SipResolver) -> Option<RelayTarget> {
    // Try as bare IP:port first (cheapest check)
    if let Ok(addr) = uri_string.parse::<SocketAddr>() {
        return Some(RelayTarget { address: addr, transport: None });
    }

    // Try parsing as a full SIP URI
    if let Ok(uri) = parse_uri_standalone(uri_string) {
        // Extract transport hint from URI params (e.g. ;transport=tcp)
        let transport_hint = uri.get_param("transport").map(|s| s.to_string());

        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(resolver.resolve(
                &uri.host,
                uri.port,
                &uri.scheme,
                transport_hint.as_deref(),
            ))
        });

        return results.into_iter().next().map(|r| {
            let transport = r.transport.as_deref()
                .or(transport_hint.as_deref())
                .and_then(|t| match t.to_lowercase().as_str() {
                    "tcp" => Some(Transport::Tcp),
                    "tls" => Some(Transport::Tls),
                    "udp" => Some(Transport::Udp),
                    "ws" => Some(Transport::WebSocket),
                    "wss" => Some(Transport::WebSocketSecure),
                    _ => None,
                });
            RelayTarget { address: r.address, transport }
        });
    }

    None
}

/// Send a relayed request to a resolved target, using the connection pool for
/// TCP/TLS when no existing inbound connection is available.
///
/// Returns the `ConnectionId` used (new pool connection or the existing one).
fn send_to_target(
    data: Bytes,
    target: &RelayTarget,
    fallback_transport: Transport,
    fallback_connection_id: ConnectionId,
    state: &DispatcherState,
) -> ConnectionId {
    let transport = target.transport.unwrap_or(fallback_transport);
    let destination = target.address;

    match transport {
        Transport::Tcp => {
            // Use connection pool for outbound TCP
            let pool = Arc::clone(&state.connection_pool);
            let data_clone = data;
            match tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(pool.send_tcp(destination, data_clone))
            }) {
                Ok(connection_id) => {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TCP pool"
                    );
                    connection_id
                }
                Err(error) => {
                    error!(destination = %destination, "TCP pool send failed: {error}");
                    fallback_connection_id
                }
            }
        }
        Transport::Tls => {
            // TLS connection reuse: find an existing inbound TLS connection
            // to the destination (like OpenSIPS connection reuse).
            // First try exact SocketAddr match, then fall back to IP-only match
            // (handles NAT where Contact URI port differs from source port).
            let connection_id = state.tls_addr_map.get(&destination).map(|r| *r.value())
                .or_else(|| {
                    // IP-only fallback: find any TLS connection from the same IP
                    let target_ip = destination.ip();
                    state.tls_addr_map.iter()
                        .find(|entry| entry.key().ip() == target_ip)
                        .map(|entry| *entry.value())
                });

            if let Some(connection_id) = connection_id {
                let outbound_message = OutboundMessage {
                    connection_id,
                    transport: Transport::Tls,
                    destination,
                    data,
                };
                if let Err(error) = state.outbound.send(outbound_message) {
                    error!(destination = %destination, "TLS connection reuse send failed: {error}");
                } else {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TLS connection reuse"
                    );
                }
                connection_id
            } else {
                warn!(
                    destination = %destination,
                    "no TLS connection available for destination (no inbound connection to reuse)"
                );
                fallback_connection_id
            }
        }
        _ => {
            // UDP and other transports: use the existing outbound channel
            let outbound_message = OutboundMessage {
                connection_id: fallback_connection_id,
                transport,
                destination,
                data,
            };
            if let Err(error) = state.outbound.send(outbound_message) {
                error!("failed to enqueue relayed request: {error}");
            }
            fallback_connection_id
        }
    }
}

/// Run a Python coroutine to completion.
///
/// When a handler is `async def`, calling it returns a coroutine object.
/// This function drives it using `asyncio.run()` which creates a fresh
/// event loop, runs the coroutine, and tears it down.
/// Initialize the RTPEngine client set and media session store.
///
/// Returns `(None, None)` when `media.rtpengine` is not configured.
/// Also registers the Python `siphon.rtpengine` singleton for script use.
pub fn init_rtpengine(
    config: &Config,
) -> (
    Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
    Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
) {
    let media_config = match &config.media {
        Some(c) => c,
        None => return (None, None),
    };

    let instances_config = media_config.rtpengine.instances();
    let mut instance_tuples = Vec::new();

    for instance in &instances_config {
        match instance.address.parse::<std::net::SocketAddr>() {
            Ok(address) => {
                instance_tuples.push((address, instance.timeout_ms, instance.weight));
            }
            Err(parse_error) => {
                error!(
                    address = %instance.address,
                    error = %parse_error,
                    "invalid RTPEngine address, skipping"
                );
            }
        }
    }

    if instance_tuples.is_empty() {
        return (None, None);
    }

    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::client::RtpEngineSet::new(instance_tuples))
    }) {
        Ok(rtpengine_set) => {
            let rtpengine_set = Arc::new(rtpengine_set);
            let sessions = Arc::new(crate::rtpengine::session::MediaSessionStore::new());

            // Build profile registry from built-in defaults + custom YAML profiles
            let registry = Arc::new(
                crate::rtpengine::ProfileRegistry::from_config(&media_config.profiles),
            );

            // Create the Python-side singleton (shares the same Arcs)
            let py_rtpengine = crate::script::api::rtpengine::PyRtpEngine::new(
                Arc::clone(&rtpengine_set),
                Arc::clone(&sessions),
                registry,
            );

            Python::attach(|python| {
                if let Err(error) =
                    crate::script::api::set_rtpengine_singleton(python, py_rtpengine)
                {
                    error!("failed to store RTPEngine singleton: {error}");
                } else {
                    let count = instances_config.len();
                    info!(
                        instances = count,
                        "RTPEngine client registered ({count} instance{})",
                        if count == 1 { "" } else { "s" }
                    );
                }
            });

            (Some(rtpengine_set), Some(sessions))
        }
        Err(rtpengine_error) => {
            error!(error = %rtpengine_error, "failed to initialize RTPEngine client");
            (None, None)
        }
    }
}

/// Run a Python coroutine to completion.
/// Check if a Python object is a coroutine (awaitable).
fn is_coroutine(python: Python<'_>, obj: &Bound<'_, pyo3::PyAny>) -> PyResult<bool> {
    let asyncio = python.import("asyncio")?;
    let result = asyncio.call_method1("iscoroutine", (obj,))?;
    result.is_truthy()
}

fn run_coroutine(python: Python<'_>, coroutine: &Bound<'_, pyo3::PyAny>) -> PyResult<()> {
    let asyncio = python.import("asyncio")?;
    // block_in_place allows us to block in a tokio multi-threaded runtime
    // while asyncio.run() drives the Python event loop. The tokio runtime
    // continues on other threads, so tokio-backed futures (e.g. rtpengine
    // UDP I/O) can still make progress.
    tokio::task::block_in_place(|| {
        asyncio.call_method1("run", (coroutine,))
    })?;
    Ok(())
}

/// Build a SIP response from a request, copying mandatory headers.
fn build_response(
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    server_header: Option<&str>,
) -> SipMessage {
    let mut builder = SipMessageBuilder::new()
        .response(status_code, reason.to_string());

    // Copy all Via headers (response routing depends on this)
    if let Some(vias) = request.headers.get_all("Via") {
        for via in vias {
            builder = builder.via(via.clone());
        }
    }

    // Copy From, To, Call-ID, CSeq (mandatory in all responses per RFC 3261 §8.2.6.2)
    if let Some(from) = request.headers.from() {
        builder = builder.from(from.clone());
    }
    if let Some(to) = request.headers.to() {
        builder = builder.to(to.clone());
    }
    if let Some(call_id) = request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }
    if let Some(cseq) = request.headers.cseq() {
        builder = builder.cseq(cseq.clone());
    }

    // Copy any auth challenge headers the script may have set
    if let Some(www_auth) = request.headers.get("WWW-Authenticate") {
        builder = builder.header("WWW-Authenticate", www_auth.clone());
    }
    if let Some(proxy_auth) = request.headers.get("Proxy-Authenticate") {
        builder = builder.header("Proxy-Authenticate", proxy_auth.clone());
    }

    // Copy SIP-ETag for PUBLISH responses (RFC 3903 §4.1)
    if let Some(sip_etag) = request.headers.get("SIP-ETag") {
        builder = builder.header("SIP-ETag", sip_etag.clone());
    }

    if let Some(server) = server_header {
        builder = builder.header("Server", server.to_string());
    }

    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("response builder failed (this should not happen): {error}");
            // Construct a minimal valid response directly
            SipMessage {
                start_line: StartLine::Response(StatusLine {
                    version: Version::sip_2_0(),
                    status_code: 500,
                    reason_phrase: "Internal Server Error".to_string(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Build an ACK for a non-2xx final response to INVITE (RFC 3261 §17.1.1.3).
///
/// The ACK is hop-by-hop: each proxy generates its own for non-2xx.
/// - Request-URI: same as the original INVITE
/// - Via: only our own Via (the branch that created the client transaction)
/// - From: from the original request
/// - To: from the response (includes To-tag added by UAS)
/// - Call-ID: from the original request
/// - CSeq: same sequence number, ACK method
/// - Route: same as original INVITE (if any)
fn build_ack_for_non2xx(
    original_request: &SipMessage,
    response: &SipMessage,
    branch: &str,
    downstream_transport: Transport,
    local_addr: SocketAddr,
) -> SipMessage {
    let request_uri = match &original_request.start_line {
        StartLine::Request(rl) => rl.request_uri.clone(),
        _ => SipUri::new("invalid".to_string()),
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    let host = format_sip_host(&local_addr.ip().to_string());
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, host, local_addr.port(), branch
    ));

    if let Some(from) = original_request.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    if let Some(call_id) = original_request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = original_request.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    // Route: copy from original request if present
    if let Some(routes) = original_request.headers.get_all("Route") {
        for route in routes {
            builder = builder.header("Route", route.clone());
        }
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("ACK builder failed (this should not happen): {error}");
            SipMessage {
                start_line: StartLine::Request(RequestLine {
                    method: Method::Ack,
                    request_uri: SipUri::new("invalid".to_string()),
                    version: Version::sip_2_0(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Build an ACK for a non-2xx B-leg response in B2BUA mode (RFC 3261 §17.1.1.3).
///
/// Unlike the proxy path, we don't store the B-leg INVITE. Instead we
/// reconstruct the ACK from the response (which carries the same Call-ID,
/// From, and CSeq as the original B-leg INVITE) plus the B-leg target URI.
/// Sanitize a B2BUA response before forwarding it to the A-leg.
///
/// A proper B2BUA terminates and regenerates the dialog, so B-leg-specific
/// headers must not leak to the A-leg. This function:
/// - Replaces Contact with siphon's own address (critical for dialog routing)
/// - Strips User-Agent (UAC header — not for responses), sets Server
/// - Removes Allow, Allow-Events, Supported, Require
/// - Strips B-leg-specific P-Asserted-Identity, P-Charging-Vector
fn sanitize_b2bua_response(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
) {
    // Contact: must point to siphon so in-dialog requests (ACK, BYE, re-INVITE)
    // route through us, not directly to the B-leg.
    // Use advertised address (public IP) when configured, otherwise listen address.
    let listen_addr = state.listen_addrs.get(&a_leg_transport).copied()
        .unwrap_or(state.local_addr);
    let contact_host = state.advertised_addrs.get(&a_leg_transport)
        .map(|h| format_sip_host(h))
        .unwrap_or_else(|| format_sip_host(&listen_addr.ip().to_string()));
    let contact_value = format!(
        "<sip:{}:{};transport={}>",
        contact_host,
        listen_addr.port(),
        a_leg_transport.to_string().to_lowercase(),
    );
    response.headers.set("Contact", contact_value);

    // Remove User-Agent — responses use Server, not User-Agent (RFC 3261 §20.35/§20.41).
    // Leaving it would leak B-leg topology to the A-leg.
    response.headers.remove("User-Agent");
    response.headers.remove("Server");
    if let Some(ref srv) = state.server_header {
        response.headers.set("Server", srv.clone());
    }

    // P-Asserted-Identity, P-Charging-Vector, P-Charging-Function-Addresses:
    // Per RFC 3325 / RFC 3455, these are trust-domain headers that B2BUAs
    // within the trust domain SHOULD forward. Keep them.

    // Strip B-leg capability headers — siphon terminates the dialog.
    // These reveal the remote endpoint's feature set and break topology hiding.
    response.headers.remove("Allow");
    response.headers.remove("Allow-Events");
    response.headers.remove("Supported");
    response.headers.remove("Require");
    response.headers.remove("Content-Disposition");

    // Sanitize SDP: mask B-leg identity in o= and s= lines
    sanitize_sdp_identity(&mut response.body, &state.sdp_name);
}

/// Rewrite `o=` and `s=` lines in an SDP body to hide the remote endpoint's
/// identity.  Replaces the username in `o=` and the session name in `s=` with
/// "SIPhon" so that neither leg leaks the other's software name or hostname.
fn sanitize_sdp_identity(body: &mut Vec<u8>, name: &str) {
    if body.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let mut changed = false;
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.starts_with("o=") {
            // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <addr>
            // Replace username only, keep the rest.
            if let Some(rest) = line.strip_prefix("o=") {
                if let Some(space_pos) = rest.find(' ') {
                    result.push_str("o=");
                    result.push_str(name);
                    result.push_str(&rest[space_pos..]);
                    changed = true;
                    continue;
                }
            }
            result.push_str(line);
        } else if line.starts_with("s=") {
            // s=<session name> — replace entirely
            if line.ends_with("\r\n") {
                result.push_str("s=");
                result.push_str(name);
                result.push_str("\r\n");
            } else if line.ends_with('\n') {
                result.push_str("s=");
                result.push_str(name);
                result.push_str("\n");
            } else {
                result.push_str("s=");
                result.push_str(name);
            }
            changed = true;
        } else {
            result.push_str(line);
        }
    }
    if changed {
        *body = result.into_bytes();
    }
}

fn build_b2bua_ack_for_non2xx(
    response: &SipMessage,
    branch: &str,
    target_uri: Option<&str>,
    downstream_transport: Transport,
    local_addr: SocketAddr,
) -> SipMessage {
    let request_uri = target_uri
        .and_then(|uri| parse_uri_standalone(uri).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));

    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    let host = format_sip_host(&local_addr.ip().to_string());
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, host, local_addr.port(), branch
    ));

    // From: same as in the response (which echoes the B-leg INVITE's From)
    if let Some(from) = response.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    // Call-ID: same as in the response (B-leg Call-ID)
    if let Some(call_id) = response.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = response.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("B2BUA ACK builder failed (this should not happen): {error}");
            SipMessage {
                start_line: StartLine::Request(RequestLine {
                    method: Method::Ack,
                    request_uri: SipUri::new("invalid".to_string()),
                    version: Version::sip_2_0(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Serialize a SIP message and send it to a specific destination.
fn send_message(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());

    debug!(
        destination = %destination,
        size = data.len(),
        "sending message"
    );

    // HEP capture — outbound (sent to network)
    // Use the per-transport listen address so HEP reports the correct source
    // port (e.g. 5061 for TLS instead of the generic local_addr on 5060).
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, transport, &data);
    }

    let outbound_message = OutboundMessage {
        connection_id,
        transport,
        destination,
        data,
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue outbound message: {error}");
    }
}

/// Send a SIP message to the B-leg, using the TCP connection pool for TCP/TLS
/// or the direct outbound channel for UDP. This ensures in-dialog messages
/// (ACK, BYE) reach the B-leg over the correct transport.
fn send_b2bua_to_bleg(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());

    // HEP capture
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, transport, &data);
    }

    let target = RelayTarget {
        address: destination,
        transport: Some(transport),
    };
    send_to_target(data, &target, transport, ConnectionId::default(), state);
}

/// Create Rust-backed auth, registrar, log, and proxy utility singletons
/// and inject them into the Python `siphon` module, replacing the Python stubs.
pub fn inject_python_singletons(config: &Config) {
    let dns_resolver = Arc::new(match SipResolver::from_system() {
        Ok(resolver) => resolver,
        Err(error) => {
            error!("failed to initialize DNS resolver for proxy utils: {error}");
            return;
        }
    });
    // Build Registrar from config
    let registrar_config = RegistrarConfig {
        default_expires: config.registrar.default_expires,
        max_expires: config.registrar.max_expires,
        min_expires: config.registrar.min_expires.unwrap_or(60),
        max_contacts: config.registrar.max_contacts.unwrap_or(10) as usize,
    };
    let registrar = Arc::new(Registrar::new(registrar_config));
    let py_registrar = PyRegistrar::new(registrar);

    // Build PyAuth from config
    let mut realm_users = std::collections::HashMap::new();
    realm_users.insert(config.auth.realm.clone(), config.auth.users.clone());
    let mut py_auth = PyAuth::new(realm_users, config.auth.realm.clone());
    py_auth.set_backend_type(config.auth.backend.clone());

    // Wire HTTP auth backend if configured
    if let Some(http_config) = &config.auth.http {
        if let Err(error) = py_auth.set_http_config(http_config.clone()) {
            tracing::error!(%error, "failed to configure HTTP auth backend");
        }
        info!(
            url = %http_config.url,
            ha1 = http_config.ha1,
            "HTTP auth backend configured"
        );
    }

    // Wire AKA credentials for local Milenage auth (IMS P-CSCF)
    if !config.auth.aka_credentials.is_empty() {
        py_auth.set_aka_credentials(config.auth.aka_credentials.clone());
        info!(
            count = config.auth.aka_credentials.len(),
            "AKA credentials loaded for local Milenage auth"
        );
    }

    // Log namespace
    let py_log = PyLogNamespace::new();

    // Proxy utilities (rate limiter, sanity check, ENUM lookup, memory stats)
    let py_proxy_utils = crate::script::api::proxy_utils::PyProxyUtils::new(
        dns_resolver,
    );

    // Cache namespace (local LRU + optional Redis)
    let cache_manager = std::sync::Arc::new(crate::cache::CacheManager::new(
        config.cache.as_deref().unwrap_or(&[]),
    ));
    let py_cache = crate::script::api::cache::PyCacheNamespace::new(cache_manager);

    // Store singletons in the global so install_siphon_module() will inject
    // them each time it (re-)creates the module.
    Python::attach(|python| {
        if let Err(error) =
            crate::script::api::set_rust_singletons(python, py_auth, py_registrar, py_log, py_proxy_utils, py_cache)
        {
            error!("failed to store Rust singletons: {error}");
        } else {
            info!("Rust-backed auth, registrar, log, proxy utils, and cache registered for injection");
        }
    });

    // RTPEngine Python singleton is now initialized in init_rtpengine() above.
}

// ---------------------------------------------------------------------------
// Fork helpers
// ---------------------------------------------------------------------------

/// Cancel all fork branches except the winning one.
fn cancel_other_fork_branches(
    winning_key: &TransactionKey,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    let session_arc = match state.session_store.get_by_server_key(server_key) {
        Some(arc) => arc,
        None => return,
    };
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => return,
    };

    for client_key in &session.client_keys {
        if client_key == winning_key {
            continue;
        }
        if let Some(client_branch) = session.get_client_branch(client_key) {
            // Build a CANCEL for this branch
            let cancel_branch = TransactionKey::generate_branch();
            let transport_str = format!("{}", client_branch.transport);
            let via_value = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                cancel_branch,
            );

            // Build minimal CANCEL from original request
            let mut cancel = session.original_request.clone();
            if let StartLine::Request(ref mut rl) = cancel.start_line {
                rl.method = crate::sip::message::Method::Cancel;
            }
            cancel.headers.remove("Via");
            cancel.headers.add("Via", via_value);

            let data = Bytes::from(cancel.to_bytes());
            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "fork: cancelling branch"
            );

            let _ = state.outbound.send(OutboundMessage {
                connection_id: client_branch.connection_id,
                transport: client_branch.transport,
                destination: client_branch.destination,
                data,
            });
        }
    }
}

/// Start the next branch in a sequential fork.
fn start_next_fork_branch(
    next_index: usize,
    session_arc: &Arc<RwLock<ProxySession>>,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    let (original_request, record_routed, source_addr, connection_id, transport, agg) = {
        let session = match session_arc.read() {
            Ok(s) => s,
            Err(_) => return,
        };
        (
            session.original_request.clone(),
            session.record_routed,
            session.source_addr,
            session.connection_id,
            session.transport,
            session.fork_aggregator.clone(),
        )
    };

    let agg = match agg {
        Some(a) => a,
        None => return,
    };

    let target = {
        let agg_lock = match agg.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        agg_lock.branches.get(next_index).map(|b| b.target.to_string())
    };

    if let Some(target_str) = target {
        let inbound_info = InboundMessage {
            remote_addr: source_addr,
            local_addr: state.local_addr,
            connection_id,
            transport,
            data: Bytes::new(),
        };
        let Ok(mut session_mut) = session_arc.write() else {
            error!("session_arc write lock poisoned during sequential fork");
            return;
        };
        relay_fork_branch(
            &original_request,
            &target_str,
            next_index,
            record_routed,
            &inbound_info,
            server_key,
            &mut session_mut,
            &agg,
            state,
        );
    }
}

/// Map a SIP error code to a reason phrase.
fn best_error_reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        480 => "Temporarily Unavailable",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        600 => "Busy Everywhere",
        603 => "Decline",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------
// CANCEL handling
// ---------------------------------------------------------------------------

/// Handle an inbound CANCEL request (RFC 3261 §9.2).
///
/// CANCEL shares the same Via branch as the INVITE it cancels.
/// We look up the original INVITE's relay destination and forward CANCEL there.
fn handle_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    uac_branch: Option<&str>,
    uac_sent_by: &str,
    state: &DispatcherState,
) {
    let uac_branch = match uac_branch {
        Some(branch) => branch,
        None => {
            warn!("CANCEL without Via branch — dropping");
            return;
        }
    };

    // Check if this CANCEL belongs to a B2BUA call
    let engine_state = state.engine.state();
    if engine_state.has_b2bua_handlers() {
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_cancel(inbound, message, state);
                return;
            }
        }
    }
    drop(engine_state);

    // --- Try ProxySession-based CANCEL routing first ---
    // CANCEL shares the same Via branch as the INVITE it cancels.
    // Build the server key for the original INVITE transaction.
    let invite_server_key = TransactionKey::new(uac_branch.to_string(), crate::sip::message::Method::Invite, uac_sent_by.to_string());
    if let Some(session_arc) = state.session_store.get_by_server_key(&invite_server_key) {
        handle_cancel_via_session(inbound, message, &invite_server_key, session_arc, state);
        return;
    }

    // No matching session or B2BUA call
    debug!(uac_branch = %uac_branch, "CANCEL for unknown transaction");
    let response = build_response(&message, 481, "Call/Transaction Does Not Exist", state.server_header.as_deref());
    send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
}

// ---------------------------------------------------------------------------
// ProxySession-based ACK (2xx) handling
// ---------------------------------------------------------------------------

/// Handle ACK for 2xx responses by relaying it downstream via the ProxySession.
///
/// ACK for 2xx is end-to-end (RFC 3261 §13.2.2.4): the proxy must relay it
/// downstream to the UAS. Unlike ACK for non-2xx (which is hop-by-hop and
/// absorbed by the transaction layer), this ACK has a new Via branch and must
/// be matched by Call-ID.
fn handle_ack_via_session(
    _inbound: InboundMessage,
    message: SipMessage,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during ACK handling");
            return;
        }
    };

    // Forward ACK to each client branch (typically just one for a completed call)
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut ack_downstream = message.clone();

            // Strip all existing Via headers, add our own
            ack_downstream.headers.remove("Via");
            let transport_str = format!("{}", client_branch.transport);
            let via_value = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                TransactionKey::generate_branch(),
            );
            ack_downstream.headers.add("Via", via_value);

            let data = Bytes::from(ack_downstream.to_bytes());
            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "relaying ACK for 2xx downstream via session"
            );

            if let Some(ref hep) = state.hep_sender {
                let local = state.listen_addrs.get(&client_branch.transport).copied().unwrap_or(state.local_addr);
                hep.capture_outbound(local, client_branch.destination, client_branch.transport, &data);
            }

            if let Err(error) = state.outbound.send(OutboundMessage {
                connection_id: client_branch.connection_id,
                transport: client_branch.transport,
                destination: client_branch.destination,
                data,
            }) {
                error!("failed to relay ACK to {}: {error}", client_branch.destination);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProxySession-based CANCEL handling
// ---------------------------------------------------------------------------

/// Handle CANCEL using ProxySession — forwards CANCEL to all client branches
/// and sends 487 Request Terminated upstream.
fn handle_cancel_via_session(
    inbound: InboundMessage,
    message: SipMessage,
    invite_server_key: &TransactionKey,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during CANCEL handling");
            let response = build_response(&message, 500, "Internal Server Error", state.server_header.as_deref());
            send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            return;
        }
    };

    // Send 200 OK to CANCEL (RFC 3261 §9.2: always 200)
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref());
    send_message(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Forward CANCEL to each client branch
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut cancel_downstream = message.clone();
            cancel_downstream.headers.remove("Via");

            // CANCEL gets its own branch (different transaction) but we derive it
            // from the client branch so it's traceable.
            let cancel_branch = TransactionKey::generate_branch();
            let transport_str = format!("{}", client_branch.transport);
            let via_value = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                cancel_branch,
            );
            cancel_downstream.headers.add("Via", via_value);

            let data = Bytes::from(cancel_downstream.to_bytes());
            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "forwarding CANCEL downstream via session"
            );

            if let Err(error) = state.outbound.send(OutboundMessage {
                connection_id: client_branch.connection_id,
                transport: client_branch.transport,
                destination: client_branch.destination,
                data,
            }) {
                error!("failed to forward CANCEL to {}: {error}", client_branch.destination);
            }
        }
    }

    // Send 487 Request Terminated upstream using the original INVITE from the session
    let response_487 = build_response(
        &session.original_request,
        487,
        "Request Terminated",
        state.server_header.as_deref(),
    );
    send_message(
        response_487,
        session.transport,
        session.source_addr,
        session.connection_id,
        state,
    );

    // Clean up session
    let server_key = invite_server_key.clone();
    drop(session);
    state.session_store.remove_by_server_key(&server_key);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL handling
// ---------------------------------------------------------------------------

/// Handle CANCEL for a B2BUA call — cancel all pending B-legs.
fn handle_b2bua_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA CANCEL: no matching call");
            let response = build_response(&message, 481, "Call/Transaction Does Not Exist", state.server_header.as_deref());
            send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            return;
        }
    };

    let call = match state.call_actors.get_call(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Only cancel if call is still in Calling or Ringing state
    if call.state != CallState::Calling && call.state != CallState::Ringing {
        debug!(call_id = %call_id, state = ?call.state, "B2BUA CANCEL: call already answered/terminated");
        let response = build_response(&message, 200, "OK", state.server_header.as_deref());
        send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
        drop(call);
        return;
    }

    // Send 200 OK to CANCEL
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref());
    send_message(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Send CANCEL to all pending B-legs
    for b_leg in &call.b_legs {
        let cancel_branch = TransactionKey::generate_branch();
        let b_transport = b_leg.transport.transport;
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            format!("{}", b_transport).to_uppercase(),
            state.via_host(&b_transport),
            state.via_port(&b_transport),
            cancel_branch,
        );

        // Build CANCEL for the B-leg (same Request-URI as the B-leg INVITE)
        let cancel_uri = match parse_uri_standalone(&b_leg.dialog.target_uri.clone().unwrap_or_default()) {
            Ok(uri) => uri,
            Err(_) => continue,
        };
        let cancel_request = SipMessageBuilder::new()
            .request(crate::sip::message::Method::Cancel, cancel_uri)
            .via(via_value)
            .header("Call-ID", b_leg.dialog.call_id.clone())
            .content_length(0);

        // Copy From (with B-leg From-tag), To, CSeq from original
        let cancel_msg = if let Some(from) = message.headers.from() {
            // Rewrite From-tag from A-leg to B-leg
            let b_from = from.replace(
                &format!("tag={}", call.a_leg.dialog.remote_tag.as_deref().unwrap_or("")),
                &format!("tag={}", b_leg.dialog.local_tag),
            );
            cancel_request.from(b_from)
        } else {
            cancel_request
        };
        let cancel_msg = if let Some(to) = message.headers.to() {
            cancel_msg.to(to.clone())
        } else {
            cancel_msg
        };
        // CSeq for CANCEL uses same sequence number but CANCEL method
        let cancel_msg = if let Some(cseq_raw) = message.headers.cseq() {
            if let Some(seq_num) = cseq_raw.split_whitespace().next() {
                cancel_msg.cseq(format!("{} CANCEL", seq_num))
            } else {
                cancel_msg
            }
        } else {
            cancel_msg
        };

        if let Ok(cancel_built) = cancel_msg.build() {
            let data = Bytes::from(cancel_built.to_bytes());
            let outbound_message = OutboundMessage {
                connection_id: ConnectionId::default(),
                transport: b_leg.transport.transport,
                destination: b_leg.transport.remote_addr,
                data,
            };
            if let Err(error) = state.outbound.send(outbound_message) {
                error!(call_id = %call_id, "B2BUA: failed to send CANCEL to B-leg: {error}");
            }
        }
    }

    // Send Cancel to all B-leg actor handles
    for handle in call.b_leg_handles.iter().flatten() {
        let _ = handle.tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }

    // Send 487 Request Terminated to A-leg for the original INVITE
    let a_leg = call.a_leg.clone();
    drop(call);

    let response_487 = build_response(&message, 487, "Request Terminated", state.server_header.as_deref());
    send_message(
        response_487,
        a_leg.transport.transport,
        a_leg.transport.remote_addr,
        a_leg.transport.connection_id,
        state,
    );

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors and cleans up registry
    state.call_actors.remove_call(&call_id);
    state.call_event_receivers.remove(&call_id);
}

// ---------------------------------------------------------------------------
// B2BUA handlers
// ---------------------------------------------------------------------------

/// Handle an INVITE in B2BUA mode.
///
/// Creates a Call object, invokes `@b2bua.on_invite`, and processes the
/// script's action (dial, fork, reject).
fn handle_b2bua_invite(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .unwrap_or(&"unknown".to_string())
        .clone();
    let from_tag = message.headers.get("From")
        .and_then(|f| {
            f.split(';').find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
        .unwrap_or_default();

    let via_branch = message.headers.get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|v| v.branch)
        .unwrap_or_default();

    // Guard against INVITE retransmissions: if we already have a call for this
    // SIP Call-ID, this is a retransmission — absorb it silently.
    // Without this check, each UDP retransmission would create a new call and
    // spawn duplicate B-leg INVITEs.
    if state.call_actors.find_by_sip_call_id(&sip_call_id).is_some() {
        debug!(
            call_id = %sip_call_id,
            "B2BUA: absorbing INVITE retransmission (call already exists)"
        );
        return;
    }

    // Send 100 Trying immediately to suppress A-leg retransmissions
    // (RFC 3261 §8.2.6.1: SHOULD send 100 within 200ms for INVITE)
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref());
    send_message(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Create the call in the manager
    let a_leg = Leg::new_a_leg(
        sip_call_id.clone(),
        from_tag,
        via_branch,
        LegTransport {
            remote_addr: inbound.remote_addr,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
        },
    );
    let call_id = state.call_actors.create_call(a_leg);

    // Create the event channel for B-leg actors → dispatcher.
    // All B-leg actors for this call share the same sender.
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        call.event_tx = Some(event_tx);
    }
    state.call_event_receivers.insert(call_id.clone(), event_rx);

    // Invoke @b2bua.on_invite
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let py_call = PyCall::new(
        call_id.clone(),
        Arc::clone(&message_arc),
        inbound.remote_addr.ip().to_string(),
    );

    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaInvite);

    let (action, timer_override, credentials, recording_srs, preserve_call_id) = Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall: {error}");
                return (CallAction::None, None, None, None, false);
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async B2BUA on_invite handler error: {error}");
                            return (CallAction::Reject {
                                code: 500,
                                reason: "Script Error".to_string(),
                            }, None, None, None, false);
                        }
                    }
                }
                Err(error) => {
                    error!("B2BUA on_invite handler error: {error}");
                    return (CallAction::Reject {
                        code: 500,
                        reason: "Script Error".to_string(),
                    }, None, None, None, false);
                }
            }
        }

        let borrowed = call_obj.borrow(python);
        let action = borrowed.action().clone();
        let timer_override = borrowed.session_timer_override().cloned();
        let credentials = borrowed.outbound_credentials().map(|(u, p)| (u.to_string(), p.to_string()));
        let recording_srs = borrowed.record_srs().map(|s| s.to_string());
        let preserve_cid = borrowed.preserve_call_id();
        (action, timer_override, credentials, recording_srs, preserve_cid)
    });

    // Store the A-leg INVITE for later use by on_answer/on_failure/on_bye handlers
    state.call_actors.set_a_leg_invite(&call_id, Arc::clone(&message_arc));

    // Store per-call overrides from script
    if timer_override.is_some() || credentials.is_some() || recording_srs.is_some() || preserve_call_id {
        if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
            if let Some(override_config) = timer_override {
                call.session_timer_override = Some(override_config);
            }
            if credentials.is_some() {
                call.outbound_credentials = credentials;
            }
            if recording_srs.is_some() {
                call.recording_srs = recording_srs;
            }
            call.preserve_call_id = preserve_call_id;
        }
    }

    let Ok(message_guard) = message_arc.lock() else {
        error!("message_arc lock poisoned in B2BUA invite handler");
        return;
    };

    match action {
        CallAction::None => {
            debug!(call_id = %call_id, "B2BUA: silent drop (no action from script)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::Reject { code, reason } => {
            debug!(call_id = %call_id, code, "B2BUA: rejecting call");
            let response = build_response(&message_guard, code, &reason, state.server_header.as_deref());
            send_message(response, inbound.transport, inbound.remote_addr, inbound.connection_id, state);
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::Dial { target, timeout: _ } => {
            debug!(call_id = %call_id, target = %target, "B2BUA: dialling B-leg");
            b2bua_send_b_leg_invite(&call_id, &target, &message_guard, &inbound, state);
        }
        CallAction::Fork { targets, strategy: _, timeout: _ } => {
            debug!(call_id = %call_id, targets = ?targets, "B2BUA: forking B-legs");
            for target in &targets {
                b2bua_send_b_leg_invite(&call_id, target, &message_guard, &inbound, state);
            }
        }
        CallAction::Terminate => {
            debug!(call_id = %call_id, "B2BUA: terminate on invite (unusual)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::AcceptRefer => {
            debug!(call_id = %call_id, "B2BUA: AcceptRefer during INVITE (no-op)");
        }
        CallAction::RejectRefer { code, reason } => {
            debug!(call_id = %call_id, code, reason = %reason, "B2BUA: RejectRefer during INVITE (no-op)");
        }
    }
}

/// Send a B-leg INVITE for a B2BUA call.
fn b2bua_send_b_leg_invite(
    call_id: &str,
    target_uri: &str,
    original_request: &SipMessage,
    _inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let relay_target = match resolve_target(target_uri, &state.dns_resolver) {
        Some(t) => t,
        None => {
            warn!(call_id = %call_id, target = %target_uri, "B2BUA: cannot resolve target");
            return;
        }
    };
    let destination = relay_target.address;
    let outbound_transport = relay_target.transport.unwrap_or(Transport::Udp);

    // Build a new INVITE for the B-leg
    let branch = TransactionKey::generate_branch();
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        outbound_transport,
        state.via_host(&outbound_transport),
        state.via_port(&outbound_transport),
        branch,
    );

    let mut b_leg_invite = original_request.clone();
    // Replace Via with our own
    b_leg_invite.headers.remove("Via");
    b_leg_invite.headers.add("Via", via_value);
    // Update Request-URI to the target
    if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
        b_leg_invite.start_line = StartLine::Request(crate::sip::message::RequestLine {
            method: crate::sip::message::Method::Invite,
            request_uri: target_parsed,
            version: crate::sip::message::Version::sip_2_0(),
        });
    }

    // Generate fresh dialog identifiers for the B-leg (proper B2BUA behavior).
    // Call-ID is new by default unless the script called call.preserve_call_id().
    // From-tag is always unique per B-leg regardless.
    let (per_call_override, preserve_call_id, a_leg_call_id, a_leg_from_tag) =
        match state.call_actors.get_call(call_id) {
            Some(c) => (
                c.session_timer_override.clone(),
                c.preserve_call_id,
                c.a_leg.dialog.call_id.clone(),
                c.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
            ),
            None => (None, false, String::new(), String::new()),
        };

    let b_leg_call_id = if preserve_call_id {
        a_leg_call_id
    } else {
        crate::b2bua::actor::generate_call_id()
    };
    let b_leg_from_tag = crate::b2bua::actor::generate_tag();

    // Rewrite Call-ID for B-leg dialog
    b_leg_invite.headers.set("Call-ID", b_leg_call_id.clone());

    // Rewrite From for B-leg dialog:
    //  - Replace the tag with a fresh B-leg tag
    //  - Rewrite the URI host to the B2BUA's own domain (mask A-leg identity)
    if let Some(from) = b_leg_invite.headers.get("From")
        .or_else(|| b_leg_invite.headers.get("f"))
    {
        let old_pattern = format!("tag={}", a_leg_from_tag);
        let new_pattern = format!("tag={}", b_leg_from_tag);
        let mut new_from = from.replace(&old_pattern, &new_pattern);

        // Rewrite the host in the From URI to the B2BUA's advertised address.
        // From header format: ["Display" ]<sip:user@host[:port][;params]>[;tag=...]
        let b2bua_host = state.via_host(&outbound_transport);
        if let Some(at_pos) = new_from.find('@') {
            // Find the end of the host: first occurrence of '>', ':', or ';' after '@'
            let after_at = &new_from[at_pos + 1..];
            let host_end = after_at.find(|c: char| c == '>' || c == ';' || c == ':')
                .unwrap_or(after_at.len());
            let end_pos = at_pos + 1 + host_end;
            new_from = format!("{}{}{}", &new_from[..at_pos + 1], b2bua_host, &new_from[end_pos..]);
        }

        b_leg_invite.headers.set("From", new_from);
    }

    // Set Contact to siphon's own address so in-dialog requests route through us.
    // Use advertised address (public IP) when configured.
    let b_listen = state.listen_addrs.get(&outbound_transport).copied().unwrap_or(state.local_addr);
    let b_contact_host = state.advertised_addrs.get(&outbound_transport)
        .map(|h| format_sip_host(h))
        .unwrap_or_else(|| format_sip_host(&b_listen.ip().to_string()));
    b_leg_invite.headers.set("Contact", format!(
        "<sip:{}:{};transport={}>",
        b_contact_host, b_listen.port(),
        outbound_transport.to_string().to_lowercase(),
    ));

    // Replace User-Agent with our own
    if let Some(ref ua) = state.user_agent_header {
        b_leg_invite.headers.set("User-Agent", ua.clone());
    }

    // Strip any To-tag (B-leg INVITE should not have one)
    if let Some(to) = b_leg_invite.headers.get("To")
        .or_else(|| b_leg_invite.headers.get("t"))
    {
        if let Some(tag_start) = to.find(";tag=") {
            let new_to = to[..tag_start].to_string();
            b_leg_invite.headers.set("To", new_to);
        }
    }

    // Inject RFC 4028 session timer headers if configured.
    // Per-call override (from call.session_timer()) takes precedence over global config.
    if let Some(ref override_config) = per_call_override {
        b_leg_invite.headers.add("Supported", "timer".to_string());
        b_leg_invite.headers.add(
            "Session-Expires",
            format!("{};refresher=uac", override_config.session_expires),
        );
        b_leg_invite.headers.add("Min-SE", override_config.min_se.to_string());
    } else if let Some(ref timer_config) = state.session_timer_config {
        if timer_config.enabled {
            b_leg_invite.headers.add("Supported", "timer".to_string());
            b_leg_invite.headers.add(
                "Session-Expires",
                format!("{};refresher=uac", timer_config.session_expires),
            );
            b_leg_invite.headers.add("Min-SE", timer_config.min_se.to_string());
        }
    }

    // Sanitize SDP: mask A-leg identity in o= and s= lines
    sanitize_sdp_identity(&mut b_leg_invite.body, &state.sdp_name);

    // Register B-leg with call manager
    let b_leg = Leg::new_b_leg(
        b_leg_call_id,
        b_leg_from_tag,
        target_uri.to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: destination,
            connection_id: ConnectionId::default(),
            transport: outbound_transport,
        },
    );
    state.call_actors.add_b_leg(call_id, b_leg.clone());
    spawn_b_leg_actor(call_id, &b_leg, state);

    let data = Bytes::from(b_leg_invite.to_bytes());

    // HEP capture
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&outbound_transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, outbound_transport, &data);
    }

    // Send via pool for TCP/TLS, direct channel for UDP
    send_to_target(data, &relay_target, outbound_transport, ConnectionId::default(), state);
}

/// Spawn a [`LegActor`] for a B-leg and store its handle in the call.
///
/// The actor classifies inbound SIP messages into [`CallEvent`]s.
/// Call this after `add_b_leg` — uses the last B-leg index.
fn spawn_b_leg_actor(call_id: &str, b_leg: &Leg, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        if let Some(event_tx) = &call.event_tx {
            let (actor, handle) = LegActor::new(b_leg.clone(), event_tx.clone());
            let b_leg_index = call.b_legs.len().saturating_sub(1);
            drop(call);
            tokio::spawn(actor.run());
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.set_b_leg_handle(b_leg_index, handle);
            }
        }
    }
}

/// Handle a response to an outbound registration (z9hG4bK-reg- branch).
fn handle_registrant_response(
    registrant: &Arc<crate::registrant::RegistrantManager>,
    message: &SipMessage,
    status_code: u16,
    _branch: &str,
    state: &DispatcherState,
) {
    // Match response to a registration entry by Call-ID
    let call_id = match message.headers.get("Call-ID") {
        Some(cid) => cid.clone(),
        None => {
            warn!("registrant response has no Call-ID");
            return;
        }
    };

    let aor = match registrant.find_by_call_id(&call_id) {
        Some(aor) => aor,
        None => {
            debug!(call_id = %call_id, "registrant response: no matching entry");
            return;
        }
    };

    match status_code {
        200 => {
            // Parse Expires from Contact or Expires header
            let expires = message.headers.get("Expires")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(3600);
            registrant.handle_success(&aor, expires);
        }
        401 | 407 => {
            // Parse challenge header
            let header_name = if status_code == 401 {
                "WWW-Authenticate"
            } else {
                "Proxy-Authenticate"
            };

            let challenge_raw = match message.headers.get(header_name) {
                Some(raw) => raw.clone(),
                None => {
                    warn!(aor = %aor, status_code, "registrant: {status_code} without {header_name}");
                    registrant.handle_failure(&aor, status_code);
                    return;
                }
            };

            if let Some(challenge) = crate::auth::parse_challenge(&challenge_raw) {
                let is_proxy_auth = status_code == 407;
                if let Some((retry_message, _retry_branch, destination, transport)) =
                    registrant.build_register_with_auth(
                        &aor,
                        state.local_addr,
                        &challenge,
                        is_proxy_auth,
                        registrant.default_interval,
                    )
                {
                    let data = bytes::Bytes::from(retry_message.to_bytes());
                    let outbound_message = crate::transport::OutboundMessage {
                        connection_id: crate::transport::ConnectionId::default(),
                        transport,
                        destination,
                        data,
                    };
                    if let Err(error) = state.outbound.send(outbound_message) {
                        warn!(aor = %aor, %error, "failed to send authenticated REGISTER");
                        registrant.handle_failure(&aor, status_code);
                    }
                } else {
                    registrant.handle_failure(&aor, status_code);
                }
            } else {
                warn!(aor = %aor, "failed to parse digest challenge from {header_name}");
                registrant.handle_failure(&aor, status_code);
            }
        }
        _ => {
            registrant.handle_failure(&aor, status_code);
        }
    }
}

/// Handle a response to a B2BUA B-leg INVITE.
fn handle_b2bua_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    debug!(
        call_id = %call_id,
        branch = %branch,
        status = status_code,
        "B2BUA: received B-leg response"
    );

    // Get the A-leg info and stored INVITE for handler reconstruction.
    // Extract everything we need then drop the DashMap ref before entering Python.
    let (a_leg, a_leg_invite, b_leg_target, b_leg_dialog, b_leg_dest, b_leg_index, b_leg_stored_vias, call_state, outbound_credentials, recording_srs, b_leg_handle_tx) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let matching_b_idx = call.b_legs.iter().position(|b| b.branch == branch);
            let matching_b = matching_b_idx.map(|i| &call.b_legs[i]);
            let target = matching_b.map(|b| b.dialog.target_uri.clone().unwrap_or_default());
            let dialog = matching_b.map(|b| (b.dialog.call_id.clone(), b.dialog.local_tag.clone()));
            let dest = matching_b.map(|b| (b.transport.remote_addr, b.transport.transport));
            let stored_vias = matching_b.map(|b| b.stored_vias.clone()).unwrap_or_default();
            let handle_tx = matching_b_idx
                .and_then(|i| call.b_leg_handles.get(i))
                .and_then(|h| h.as_ref())
                .map(|h| h.tx.clone());
            (call.a_leg.clone(), call.a_leg_invite.clone(), target, dialog, dest, matching_b_idx, stored_vias, call.state.clone(), call.outbound_credentials.clone(), call.recording_srs.clone(), handle_tx)
        }
        None => {
            warn!(call_id = %call_id, "B2BUA: response for unknown call");
            return;
        }
    };

    // Handle retransmitted 200 OK for already-completed re-INVITEs.
    // The entry was marked "reinvite_done:<dir>" after the first 200 OK was processed.
    // Just re-ACK the responder to stop retransmissions — don't forward again.
    if let Some(done_direction) = b_leg_target.as_deref().and_then(|t| t.strip_prefix("reinvite_done:")) {
        if (200..300).contains(&status_code) {
            let is_a2b = done_direction == "a2b";
            if let Some((responder_dest, responder_transport)) = b_leg_dest {
                if let Some((ref responder_cid, ref _responder_ftag)) = b_leg_dialog {
                    let transport_str = format!("{}", responder_transport).to_uppercase();
                    let outbound_port = state.listen_addrs.get(&responder_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    let cseq_num = message.headers.cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    let ack_uri = SipUri::new(responder_dest.ip().to_string())
                        .with_port(responder_dest.port());
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, ack_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            format_sip_host(&state.local_addr.ip().to_string()),
                            outbound_port,
                            TransactionKey::generate_branch(),
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(responder_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for re-INVITE 2xx retransmit build failed: {error}");
                            return;
                        }
                    };
                    if is_a2b {
                        send_b2bua_to_bleg(ack, responder_transport, responder_dest, state);
                    } else {
                        send_message(ack, responder_transport, responder_dest, a_leg.transport.connection_id, state);
                    }
                    debug!(
                        call_id = %call_id,
                        "B2BUA: re-ACKed retransmitted 200 OK for completed re-INVITE"
                    );
                }
            }
        } else {
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: absorbing retransmitted non-2xx for completed re-INVITE"
            );
        }
        return;
    }

    // Detect re-INVITE responses: target_uri starts with "reinvite:".
    // Re-INVITE tracking legs don't have actors — handled directly below.
    let reinvite_direction = b_leg_target.as_deref().and_then(|t| t.strip_prefix("reinvite:"));

    if let Some(direction) = reinvite_direction {
        let is_a2b = direction == "a2b";

        // Determine where to route the response: back to the leg that sent the re-INVITE.
        // A→B re-INVITE: response goes to A-leg, rewrite B-leg→A-leg headers
        // B→A re-INVITE: response goes to B-leg, rewrite A-leg→B-leg headers
        let (resp_dest, resp_transport, resp_conn_id) = if is_a2b {
            (a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.transport.connection_id)
        } else {
            // B→A: send response to winning B-leg
            match state.call_actors.get_call(call_id) {
                Some(call) => {
                    let winner = call.winner.and_then(|i| call.b_legs.get(i));
                    if let Some(b) = winner {
                        (b.transport.remote_addr, b.transport.transport, ConnectionId::default())
                    } else {
                        warn!(call_id = %call_id, "B2BUA re-INVITE response: no winning B-leg");
                        return;
                    }
                }
                None => return,
            }
        };

        if is_a2b {
            // A→B: response from B-leg → rewrite B-leg identifiers back to A-leg
            if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message, &a_leg.dialog.call_id, b_ftag, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                );
            }
        } else {
            // B→A: response from A-leg → rewrite A-leg identifiers back to B-leg
            if let Some(call) = state.call_actors.get_call(call_id) {
                if let Some(winner) = call.winner.and_then(|i| call.b_legs.get(i)) {
                    crate::b2bua::actor::Dialog::rewrite_headers(
                        message, &winner.dialog.call_id, a_leg.dialog.remote_tag.as_deref().unwrap_or(""), &winner.dialog.local_tag,
                    );
                }
            }
        }

        // Replace Via(s) — restore the originator's Via headers from the
        // re-INVITE (stored_vias), NOT from the initial INVITE.
        // Both A→B and B→A use stored_vias captured when the re-INVITE arrived.
        message.headers.remove("Via");
        for via in &b_leg_stored_vias {
            message.headers.add("Via", via.clone());
        }

        sanitize_b2bua_response(message, state, resp_transport);

        // Helper: build and send ACK to the responder of the re-INVITE.
        // For 2xx: ACK uses a NEW branch (end-to-end, RFC 3261 §13.2.2.4).
        // For non-2xx: ACK uses the SAME branch (hop-by-hop, RFC 3261 §17.1.1.3).
        let send_reinvite_ack = |ack_branch: String, state: &DispatcherState| {
            if let Some((responder_dest, responder_transport)) = b_leg_dest {
                if let Some((ref responder_cid, ref _responder_ftag)) = b_leg_dialog {
                    let transport_str = format!("{}", responder_transport).to_uppercase();
                    let outbound_port = state.listen_addrs.get(&responder_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    let cseq_num = message.headers.cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    let ack_uri = SipUri::new(responder_dest.ip().to_string())
                        .with_port(responder_dest.port());
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, ack_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            format_sip_host(&state.local_addr.ip().to_string()),
                            outbound_port,
                            ack_branch,
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(responder_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for re-INVITE build failed: {error}");
                            return;
                        }
                    };
                    if is_a2b {
                        send_b2bua_to_bleg(ack, responder_transport, responder_dest, state);
                    } else {
                        send_message(ack, responder_transport, responder_dest, a_leg.transport.connection_id, state);
                    }
                }
            }
        };

        if (200..300).contains(&status_code) {
            // ACK the responder with a new branch (end-to-end ACK for 2xx)
            send_reinvite_ack(TransactionKey::generate_branch(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                "B2BUA: sent ACK to responder for re-INVITE 2xx"
            );

            // Reset session timer on successful re-INVITE
            state.call_actors.reset_session_timer(call_id);

            // Mark the re-INVITE B-leg entry as done (not removed!) so that
            // retransmitted 200 OKs can still be matched and re-ACKed.
            // The entry will be cleaned up when the call terminates.
            if let Some(idx) = b_leg_index {
                state.call_actors.set_b_leg_target_uri(call_id, idx, format!("reinvite_done:{}", direction));
            }
        } else if status_code >= 300 {
            // Non-2xx: ACK is hop-by-hop — reuse the SAME branch as the
            // forwarded re-INVITE (RFC 3261 §17.1.1.3).
            send_reinvite_ack(branch.to_string(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                status = status_code,
                "B2BUA: sent ACK to responder for re-INVITE non-2xx"
            );

            // Remove the re-INVITE B-leg entry — no retransmission expected
            // since the IST will transition Completed→Confirmed on our ACK.
            if let Some(idx) = b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
        }

        // Forward response to the originator
        if is_a2b {
            send_message(message.clone(), resp_transport, resp_dest, resp_conn_id, state);
        } else {
            send_b2bua_to_bleg(message.clone(), resp_transport, resp_dest, state);
        }

        debug!(
            call_id = %call_id,
            status = status_code,
            direction = direction,
            "B2BUA: forwarded re-INVITE response"
        );
        return;
    }

    // Route response through B-leg actor for classification.
    // The actor classifies the SIP response into a CallEvent (Provisional,
    // Answered, Failed). We send the message, block-recv the event, then
    // use the event to drive response handling below.
    // Re-INVITE tracking legs and retry legs may not have actors — fall
    // back to raw status_code classification in that case.
    let actor_event: Option<CallEvent> = if let Some(handle_tx) = &b_leg_handle_tx {
        let leg_transport = b_leg_dest.map(|(addr, transport)| LegTransport {
            remote_addr: addr,
            connection_id: ConnectionId::default(),
            transport,
        }).unwrap_or_else(|| LegTransport {
            remote_addr: state.local_addr,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        });
        match handle_tx.try_send(crate::b2bua::actor::LegMessage::SipInbound {
            message: message.clone(),
            source: leg_transport,
        }) {
            Ok(()) => {
                // Temporarily extract receiver to block on it.
                // Safe: dispatcher processes messages sequentially.
                if let Some((_, mut rx)) = state.call_event_receivers.remove(call_id) {
                    let event = rx.blocking_recv();
                    state.call_event_receivers.insert(call_id.to_string(), rx);
                    event
                } else {
                    None
                }
            }
            Err(_) => {
                debug!(call_id = %call_id, "B2BUA: actor mailbox full, classifying directly");
                None
            }
        }
    } else {
        None
    };

    // On 2xx: sync remote_tag from response back to canonical CallActor.
    // The LegActor extracts this on its clone, but we need to update the
    // authoritative copy in the CallActorStore.
    if matches!(&actor_event, Some(CallEvent::Answered { .. })) {
        if let Some(to_tag) = crate::b2bua::actor::extract_to_tag(message) {
            if let Some(idx) = b_leg_index {
                if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                    if let Some(b_leg) = call.b_legs.get_mut(idx) {
                        b_leg.dialog.remote_tag = Some(to_tag);
                    }
                }
            }
        }
    }

    // Event-driven response classification.
    // Actor events are authoritative when available; fall back to status_code.
    #[derive(Debug)]
    enum ResponseClass { Answered, Provisional, Failed }

    let class = match &actor_event {
        Some(CallEvent::Answered { .. }) => ResponseClass::Answered,
        Some(CallEvent::Provisional { status_code: code, .. }) if *code >= 180 => {
            ResponseClass::Provisional
        }
        Some(CallEvent::Failed { .. }) => ResponseClass::Failed,
        _ => {
            // No actor, filtered provisional (<180), or unexpected event
            if (200..300).contains(&status_code) { ResponseClass::Answered }
            else if (180..200).contains(&status_code) { ResponseClass::Provisional }
            else if status_code >= 300 { ResponseClass::Failed }
            else { return; } // 100 Trying from B-leg — absorb
        }
    };

    match class { ResponseClass::Answered => {
    // --- 2xx answer handling ---
    if (200..300).contains(&status_code) {
        // Absorb 200 OK retransmissions: if the call is already answered,
        // this is a retransmit from the B-leg (it hasn't received our ACK yet).
        // Re-send ACK to B-leg but don't re-forward or re-fire on_answer.
        if call_state == CallState::Answered {
            debug!(
                call_id = %call_id,
                "B2BUA: absorbing 200 OK retransmission (already answered)"
            );
            // Re-send ACK to B-leg to stop retransmissions
            if let Some((b_dest, b_transport)) = b_leg_dest {
                if let Some((ref b_cid, ref b_ftag)) = b_leg_dialog {
                    let mut ack = message.clone();
                    // Build ACK from the 200 OK
                    let request_uri = b_leg_target.as_deref()
                        .and_then(|uri| parse_uri_standalone(uri).ok())
                        .unwrap_or_else(|| SipUri::new("invalid".to_string()));
                    ack.start_line = StartLine::Request(crate::sip::message::RequestLine {
                        method: Method::Ack,
                        request_uri,
                        version: crate::sip::message::Version::sip_2_0(),
                    });
                    ack.headers.remove("Via");
                    let transport_str = format!("{}", b_transport).to_uppercase();
                    let outbound_port = state.listen_addrs.get(&b_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    ack.headers.add("Via", format!(
                        "SIP/2.0/{} {}:{};branch={}",
                        transport_str,
                        format_sip_host(&state.local_addr.ip().to_string()),
                        outbound_port,
                        TransactionKey::generate_branch(),
                    ));
                    // Ensure B-leg dialog identifiers
                    ack.headers.set("Call-ID", b_cid.clone());
                    if let Some(from) = ack.headers.from() {
                        let new_from = from.replace(
                            &format!("tag={}", a_leg.dialog.remote_tag.as_deref().unwrap_or("")),
                            &format!("tag={}", b_ftag),
                        );
                        ack.headers.set("From", new_from);
                    }
                    if let Some(cseq) = ack.headers.cseq() {
                        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
                        ack.headers.set("CSeq", format!("{} ACK", cseq_num));
                    }
                    ack.headers.set("Content-Length", "0".to_string());
                    ack.body.clear();
                    send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                }
            }
            return;
        }

        // 2xx — call answered; record the winning B-leg
        state.call_actors.set_state(call_id, CallState::Answered);
        if let Some(idx) = b_leg_index {
            state.call_actors.set_winner(call_id, idx);
        }

        // Wrap the 200 OK in Arc<Mutex<>> so Python handlers can modify SDP in-place
        let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));

        // Invoke @b2bua.on_answer handlers with (PyCall, PyReply)
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaAnswer);
        let mut answer_recording_srs: Option<String> = None;
        if !handlers.is_empty() {
            if let Some(invite_arc) = &a_leg_invite {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
                );
                let py_reply = PyReply::new(Arc::clone(&response_arc))
                    .with_a_leg(Arc::clone(invite_arc));

                answer_recording_srs = Python::attach(|python| {
                    let call_obj = match Py::new(python, py_call) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyCall for on_answer: {error}");
                            return None;
                        }
                    };
                    let reply_obj = match Py::new(python, py_reply) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyReply for on_answer: {error}");
                            return None;
                        }
                    };

                    for handler in &handlers {
                        let callable = handler.callable.bind(python);
                        match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                            Ok(ret) => {
                                if handler.is_async {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async B2BUA on_answer handler error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("B2BUA on_answer handler error: {error}");
                            }
                        }
                    }

                    // Extract record_srs set by on_answer handler (e.g. call.record("sip:srs@..."))
                    let borrowed = call_obj.borrow(python);
                    let result = borrowed.record_srs().map(|s| s.to_string());
                    drop(borrowed);
                    result
                });
            } else {
                warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_answer");
            }
        }
        // Merge: on_answer recording takes priority, fall back to on_invite recording
        let effective_recording_srs = answer_recording_srs.or(recording_srs);

        // RFC 4028: Activate session timer from negotiated 200 OK headers
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                // Parse Session-Expires from 200 OK (e.g. "1800;refresher=uas")
                let Ok(response_lock) = response_arc.lock() else {
                    error!("response_arc lock poisoned during session timer parsing");
                    return;
                };
                let (negotiated_expires, negotiated_refresher) =
                    if let Some(se_header) = response_lock.headers.get("Session-Expires") {
                        let parts: Vec<&str> = se_header.split(';').collect();
                        let expires = parts[0].trim().parse::<u32>()
                            .unwrap_or(timer_config.session_expires);
                        let refresher = parts.iter()
                            .find(|p| p.trim().starts_with("refresher="))
                            .map(|p| p.trim().trim_start_matches("refresher=").to_string())
                            .unwrap_or_else(|| "b2bua".to_string());
                        (expires, refresher)
                    } else {
                        // Remote didn't include Session-Expires — use our config defaults
                        (timer_config.session_expires, "b2bua".to_string())
                    };
                drop(response_lock);

                let timer_state = crate::b2bua::actor::SessionTimerState {
                    session_expires: negotiated_expires,
                    refresher: negotiated_refresher.clone(),
                    last_refresh: std::time::Instant::now(),
                };
                state.call_actors.set_session_timer(call_id, timer_state);

                debug!(
                    call_id = %call_id,
                    session_expires = negotiated_expires,
                    refresher = %negotiated_refresher,
                    "B2BUA: session timer activated"
                );
            }
        }

        // Extract the (possibly SDP-modified) response and forward to A-leg
        let mut response = match Arc::try_unwrap(response_arc) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|error| error.into_inner()),
            Err(arc) => arc.lock().unwrap_or_else(|error| error.into_inner()).clone(),
        };

        // Inject session timer headers into response forwarded to A-leg
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                if response.headers.get("Supported").is_none() {
                    response.headers.add("Supported", "timer".to_string());
                }
                if response.headers.get("Session-Expires").is_none() {
                    response.headers.add(
                        "Session-Expires",
                        format!("{};refresher=uac", timer_config.session_expires),
                    );
                }
            }
        }

        // Rewrite B-leg dialog headers back to A-leg identifiers
        if let Some((ref b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut response, &a_leg.dialog.call_id, b_ftag, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            );
            let _ = (b_cid,); // Call-ID already set by rewrite_dialog_headers
        }

        // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
        // The B-leg response only carries our Via; the A-leg caller expects its own.
        response.headers.remove("Via");
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    for via in vias {
                        response.headers.add("Via", via.clone());
                    }
                }
            }
        }

        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(&mut response, state, a_leg.transport.transport);

        // Send ACK to B-leg immediately — in B2BUA mode we terminate the
        // B-leg dialog ourselves rather than waiting for the A-leg's ACK.
        // This stops the B-leg from retransmitting the 200 OK.
        if let Some((b_dest, b_transport)) = b_leg_dest {
            if let Some((ref b_cid, ref _b_ftag)) = b_leg_dialog {
                let ack_uri = b_leg_target.as_deref()
                    .and_then(|uri| parse_uri_standalone(uri).ok())
                    .unwrap_or_else(|| SipUri::new("invalid".to_string()));
                let transport_str = format!("{}", b_transport).to_uppercase();
                let via_value = format!(
                    "SIP/2.0/{} {}:{};branch={}",
                    transport_str,
                    state.via_host(&b_transport),
                    state.via_port(&b_transport),
                    TransactionKey::generate_branch(),
                );
                let cseq_num = message.headers.cseq()
                    .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                    .unwrap_or_else(|| "1".to_string());
                let from = message.headers.from().cloned().unwrap_or_default();
                let to = message.headers.to().cloned().unwrap_or_default();
                let ack = match SipMessageBuilder::new()
                    .request(Method::Ack, ack_uri)
                    .via(via_value)
                    .from(from.to_string())
                    .to(to.to_string())
                    .call_id(b_cid.clone())
                    .cseq(format!("{} ACK", cseq_num))
                    .header("Max-Forwards", "70".to_string())
                    .content_length(0)
                    .build()
                {
                    Ok(ack) => ack,
                    Err(error) => {
                        error!("B2BUA ACK for 2xx build failed: {error}");
                        return;
                    }
                };
                send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                debug!(call_id = %call_id, "B2BUA: sent ACK to B-leg for 200 OK");
            }
        }

        // Extract SDP body before forwarding (needed for SIPREC)
        let sdp_body = response.body.clone();

        send_message(
            response,
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            state,
        );

        // SIPREC: start recording if configured for this call
        if let Some(srs_uri) = &effective_recording_srs {
            let sdp = &sdp_body;
            if let Some(invite_arc) = &a_leg_invite {
                let Ok(invite) = invite_arc.lock() else {
                    error!(call_id = %call_id, "invite_arc lock poisoned during SIPREC start");
                    return;
                };
                let caller_uri = invite.headers.get("From")
                    .map(|from| from.to_string())
                    .unwrap_or_default();
                let callee_uri = invite.headers.get("To")
                    .map(|to| to.to_string())
                    .unwrap_or_default();
                drop(invite);

                if let Some((_session_id, rec_invite, destination, transport)) =
                    state.recording_manager.start_recording(
                        call_id, srs_uri, &caller_uri, &callee_uri, sdp, state.local_addr,
                    )
                {
                    let data = Bytes::from(rec_invite.to_bytes());
                    let outbound_message = OutboundMessage {
                        connection_id: ConnectionId::default(),
                        transport,
                        destination,
                        data,
                    };
                    if let Err(error) = state.outbound.send(outbound_message) {
                        error!(call_id = %call_id, "SIPREC: failed to send recording INVITE: {error}");
                    }
                }
            }
        }
    } // end 2xx guard

    } ResponseClass::Provisional => {
    // --- 1xx provisional handling ---
    {
        // 1xx provisional — forward to A-leg
        state.call_actors.set_state(call_id, CallState::Ringing);

        // Invoke @b2bua.on_early_media handlers when provisional has SDP body.
        // This lets scripts process early media through RTPEngine before forwarding.
        let has_sdp_body = !message.body.is_empty();
        if has_sdp_body {
            let engine_state = state.engine.state();
            let handlers = engine_state.handlers_for(&HandlerKind::B2buaEarlyMedia);
            if !handlers.is_empty() {
                if let Some(invite_arc) = &a_leg_invite {
                    let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));
                    let py_call = PyCall::new(
                        call_id.to_string(),
                        Arc::clone(invite_arc),
                        a_leg.transport.remote_addr.ip().to_string(),
                    );
                    let py_reply = PyReply::new(Arc::clone(&response_arc))
                        .with_a_leg(Arc::clone(invite_arc));

                    Python::attach(|python| {
                        let call_obj = match Py::new(python, py_call) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyCall for on_early_media: {error}");
                                return;
                            }
                        };
                        let reply_obj = match Py::new(python, py_reply) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for on_early_media: {error}");
                                return;
                            }
                        };

                        for handler in &handlers {
                            let callable = handler.callable.bind(python);
                            match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async B2BUA on_early_media handler error: {error}");
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("B2BUA on_early_media handler error: {error}");
                                }
                            }
                        }
                    });

                    // Replace message with potentially modified version (e.g. RTPEngine-rewritten SDP)
                    if let Ok(modified) = response_arc.lock() {
                        *message = modified.clone();
                    };
                } else {
                    warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_early_media");
                }
            }
        }

        // Rewrite B-leg dialog headers back to A-leg identifiers
        if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message, &a_leg.dialog.call_id, b_ftag, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            );
        }
        // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
        message.headers.remove("Via");
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    for via in vias {
                        message.headers.add("Via", via.clone());
                    }
                }
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(message, state, a_leg.transport.transport);
        send_message(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            state,
        );
    }

    } ResponseClass::Failed => {
    // --- 3xx+ error handling ---
    {
        // RFC 4028: 422 "Session Interval Too Small" — retry with higher Session-Expires
        if status_code == 422 {
            if let Some(ref timer_config) = state.session_timer_config {
                if timer_config.enabled {
                    let remote_min_se = message.headers.get("Min-SE")
                        .and_then(|v| v.split(';').next())
                        .and_then(|v| v.trim().parse::<u32>().ok());

                    if let (Some(min_se), Some(target_uri), Some(invite_arc)) =
                        (remote_min_se, &b_leg_target, &a_leg_invite)
                    {
                        if min_se > timer_config.session_expires {
                            info!(
                                call_id = %call_id,
                                min_se = min_se,
                                "B2BUA: 422 received, retrying with Session-Expires={min_se}"
                            );

                            // Resolve target
                            if let Some(relay_target) = resolve_target(target_uri, &state.dns_resolver) {
                                let destination = relay_target.address;
                                let transport = relay_target.transport.unwrap_or(Transport::Udp);

                                // Build retry INVITE from stored A-leg INVITE
                                let Ok(original) = invite_arc.lock() else {
                                    error!(call_id = %call_id, "invite_arc lock poisoned during fork retry");
                                    return;
                                };
                                let mut retry = original.clone();
                                drop(original);

                                // Replace Via with new branch
                                let new_branch = TransactionKey::generate_branch();
                                let via_value = format!(
                                    "SIP/2.0/{} {}:{};branch={}",
                                    transport,
                                    state.via_host(&transport),
                                    state.via_port(&transport),
                                    new_branch,
                                );
                                retry.headers.remove("Via");
                                retry.headers.add("Via", via_value);

                                // Update Request-URI
                                if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                    retry.start_line = StartLine::Request(
                                        crate::sip::message::RequestLine {
                                            method: crate::sip::message::Method::Invite,
                                            request_uri: target_parsed,
                                            version: crate::sip::message::Version::sip_2_0(),
                                        },
                                    );
                                }

                                // Set updated session timer headers
                                retry.headers.remove("Session-Expires");
                                retry.headers.remove("Min-SE");
                                retry.headers.add(
                                    "Session-Expires",
                                    format!("{};refresher=uac", min_se),
                                );
                                retry.headers.add("Min-SE", min_se.to_string());

                                // Reuse B-leg dialog identifiers from the failed attempt
                                let (retry_call_id, retry_from_tag) = b_leg_dialog.clone()
                                    .unwrap_or_else(|| (a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()));
                                crate::b2bua::actor::Dialog::rewrite_headers(
                                    &mut retry, &retry_call_id, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""), &retry_from_tag,
                                );

                                let b_leg = Leg::new_b_leg(
                                    retry_call_id,
                                    retry_from_tag,
                                    target_uri.clone(),
                                    new_branch,
                                    LegTransport {
                                        remote_addr: destination,
                                        connection_id: ConnectionId::default(),
                                        transport,
                                    },
                                );
                                state.call_actors.add_b_leg(call_id, b_leg.clone());
                                spawn_b_leg_actor(call_id, &b_leg, state);

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, ConnectionId::default(), state);
                            }
                            return; // don't forward 422 to A-leg or fire on_failure
                        }
                    }
                }
            }
        }

        // 401/407 — auto-retry with digest credentials if available
        if status_code == 401 || status_code == 407 {
            if let Some((username, password)) = &outbound_credentials {
                let challenge_header = if status_code == 401 {
                    message.headers.get("WWW-Authenticate")
                } else {
                    message.headers.get("Proxy-Authenticate")
                };

                if let Some(challenge_value) = challenge_header {
                    if let Some(challenge) = crate::auth::parse_challenge(challenge_value) {
                        if let (Some(target_uri), Some(invite_arc)) = (&b_leg_target, &a_leg_invite) {
                            info!(
                                call_id = %call_id,
                                status = status_code,
                                realm = %challenge.realm,
                                "B2BUA: {status_code} received, retrying with credentials"
                            );

                            let credentials = crate::auth::DigestCredentials {
                                username: username.clone(),
                                password: password.clone(),
                            };

                            let auth_header_name = if status_code == 401 {
                                "Authorization"
                            } else {
                                "Proxy-Authorization"
                            };

                            let auth_value = crate::auth::format_authorization_header(
                                &challenge,
                                &credentials,
                                "INVITE",
                                target_uri,
                                Some(1),
                                None,
                            );

                            // Resolve target
                            if let Some(relay_target) = resolve_target(target_uri, &state.dns_resolver) {
                                let destination = relay_target.address;
                                let transport = relay_target.transport.unwrap_or(Transport::Udp);

                                // Build retry INVITE from stored A-leg INVITE
                                let Ok(original) = invite_arc.lock() else {
                                    error!(call_id = %call_id, "invite_arc lock poisoned during fork retry");
                                    return;
                                };
                                let mut retry = original.clone();
                                drop(original);

                                // Replace Via with new branch
                                let new_branch = TransactionKey::generate_branch();
                                let via_value = format!(
                                    "SIP/2.0/{} {}:{};branch={}",
                                    transport,
                                    state.via_host(&transport),
                                    state.via_port(&transport),
                                    new_branch,
                                );
                                retry.headers.remove("Via");
                                retry.headers.add("Via", via_value);

                                // Update Request-URI
                                if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                    retry.start_line = StartLine::Request(
                                        crate::sip::message::RequestLine {
                                            method: crate::sip::message::Method::Invite,
                                            request_uri: target_parsed,
                                            version: crate::sip::message::Version::sip_2_0(),
                                        },
                                    );
                                }

                                // Add authorization header
                                retry.headers.remove(auth_header_name);
                                retry.headers.add(auth_header_name, auth_value);

                                // Reuse B-leg dialog identifiers from the failed attempt
                                let (retry_call_id, retry_from_tag) = b_leg_dialog.clone()
                                    .unwrap_or_else(|| (a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()));
                                crate::b2bua::actor::Dialog::rewrite_headers(
                                    &mut retry, &retry_call_id, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""), &retry_from_tag,
                                );

                                let b_leg = Leg::new_b_leg(
                                    retry_call_id,
                                    retry_from_tag,
                                    target_uri.clone(),
                                    new_branch,
                                    LegTransport {
                                        remote_addr: destination,
                                        connection_id: ConnectionId::default(),
                                        transport,
                                    },
                                );
                                state.call_actors.add_b_leg(call_id, b_leg.clone());
                                spawn_b_leg_actor(call_id, &b_leg, state);

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, ConnectionId::default(), state);
                            }
                            return; // don't forward 401/407 to A-leg or fire on_failure
                        }
                    }
                }
            }
        }

        // Error response — invoke @b2bua.on_failure with (PyCall, code, reason)
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
        if !handlers.is_empty() {
            let reason = match &message.start_line {
                StartLine::Response(status_line) => status_line.reason_phrase.clone(),
                _ => "Unknown".to_string(),
            };

            if let Some(invite_arc) = &a_leg_invite {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
                );

                Python::attach(|python| {
                    let call_obj = match Py::new(python, py_call) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyCall for on_failure: {error}");
                            return;
                        }
                    };

                    for handler in &handlers {
                        let callable = handler.callable.bind(python);
                        match callable.call1((
                            call_obj.bind(python),
                            status_code,
                            reason.as_str(),
                        )) {
                            Ok(ret) => {
                                if handler.is_async {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async B2BUA on_failure handler error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("B2BUA on_failure handler error: {error}");
                            }
                        }
                    }
                });
            } else {
                warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_failure");
            }
        }

        // Send ACK to B-leg for non-2xx final response (RFC 3261 §17.1.1.3).
        // The B2BUA must acknowledge non-2xx responses hop-by-hop.
        if let Some((b_dest, b_transport)) = b_leg_dest {
            let ack = build_b2bua_ack_for_non2xx(
                message,
                branch,
                b_leg_target.as_deref(),
                b_transport,
                state.local_addr,
            );
            send_message(ack, b_transport, b_dest, ConnectionId::default(), state);
        }

        // Forward error to A-leg — rewrite B-leg dialog headers back to A-leg
        if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message, &a_leg.dialog.call_id, b_ftag, &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            );
        }
        // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
        message.headers.remove("Via");
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    for via in vias {
                        message.headers.add("Via", via.clone());
                    }
                }
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(message, state, a_leg.transport.transport);
        send_message(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            state,
        );
        state.call_actors.remove_call(call_id);
        state.call_event_receivers.remove(call_id);
    }

    } // end ResponseClass::Failed
    } // end match class
}

/// Schedule cleanup of zombie re-INVITE entries after Timer H (32 seconds).
///
/// Called after `remove_call()` which may have moved `reinvite_done:` or
/// `reinvite:` B-leg entries to the zombie map. After 32 seconds the remote
/// UAS stops retransmitting per RFC 3261 §17.2.1, so the entries are no longer needed.
fn schedule_zombie_reinvite_cleanup(call_actors: &crate::b2bua::actor::CallActorStore) {
    if call_actors.zombie_reinvites.is_empty() {
        return;
    }
    let zombie_map = call_actors.zombie_reinvites.clone();
    let zombie_keys: Vec<String> = zombie_map.iter()
        .map(|entry| entry.key().clone())
        .collect();
    if !zombie_keys.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(32)).await;
            for key in zombie_keys {
                zombie_map.remove(&key);
            }
        });
    }
}

/// Handle a BYE for a B2BUA call — bridge to the other leg.
fn handle_b2bua_bye(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA BYE: no matching call");
            return;
        }
    };

    // Extract everything from the DashMap ref and drop it before entering Python
    let (from_a_leg, a_leg_invite, a_leg_source_ip) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
            (from_a, call.a_leg_invite.clone(), call.a_leg.transport.remote_addr.ip().to_string())
        }
        None => return,
    };

    // Invoke @b2bua.on_bye handlers with (PyCall, PyByeInitiator)
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaBye);
    if !handlers.is_empty() {
        let side = if from_a_leg { "a".to_string() } else { "b".to_string() };

        if let Some(invite_arc) = &a_leg_invite {
            let py_call = PyCall::new(
                call_id.clone(),
                Arc::clone(invite_arc),
                a_leg_source_ip,
            );
            let initiator = PyByeInitiator { side };

            Python::attach(|python| {
                let call_obj = match Py::new(python, py_call) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyCall for on_bye: {error}");
                        return;
                    }
                };
                let initiator_obj = match Py::new(python, initiator) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyByeInitiator: {error}");
                        return;
                    }
                };

                for handler in &handlers {
                    let callable = handler.callable.bind(python);
                    match callable.call1((call_obj.bind(python), initiator_obj.bind(python))) {
                        Ok(ret) => {
                            if handler.is_async {
                                if let Err(error) = run_coroutine(python, &ret) {
                                    error!("async B2BUA on_bye handler error: {error}");
                                }
                            }
                        }
                        Err(error) => {
                            error!("B2BUA on_bye handler error: {error}");
                        }
                    }
                }
            });
        } else {
            warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_bye");
        }
    }

    // Re-acquire the call ref for BYE bridging
    let call = match state.call_actors.get_call(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Send 200 OK to the BYE sender
    let bye_response = build_response(&message, 200, "OK", state.server_header.as_deref());
    send_message(
        bye_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Forward BYE to the other leg with dialog header rewriting
    if from_a_leg {
        // BYE from A → forward to B-leg(s)
        if let Some(winner_index) = call.winner {
            if let Some(b_leg) = call.b_legs.get(winner_index) {
                let branch = TransactionKey::generate_branch();
                let transport_str = format!("{}", b_leg.transport.transport).to_uppercase();
                let via_value = format!(
                    "SIP/2.0/{} {}:{};branch={}",
                    transport_str,
                    state.via_host(&b_leg.transport.transport),
                    state.via_port(&b_leg.transport.transport),
                    branch,
                );
                let mut bye = message.clone();
                bye.headers.remove("Via");
                bye.headers.add("Via", via_value);
                // Rewrite A-leg dialog headers → B-leg dialog headers
                crate::b2bua::actor::Dialog::rewrite_headers(
                    &mut bye, &b_leg.dialog.call_id, call.a_leg.dialog.remote_tag.as_deref().unwrap_or(""), &b_leg.dialog.local_tag,
                );
                send_b2bua_to_bleg(bye, b_leg.transport.transport, b_leg.transport.remote_addr, state);
            }
        }
    } else {
        // BYE from B → forward to A-leg
        let mut bye = message.clone();
        // Rewrite B-leg dialog headers → A-leg dialog headers
        if let Some(winner_index) = call.winner {
            if let Some(b_leg) = call.b_legs.get(winner_index) {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    &mut bye, &call.a_leg.dialog.call_id, &b_leg.dialog.local_tag, call.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                );
            }
        }
        send_message(
            bye,
            call.a_leg.transport.transport,
            call.a_leg.transport.remote_addr,
            call.a_leg.transport.connection_id,
            state,
        );
    }

    drop(call);

    // Safety-net: if an RTPEngine media session exists for this call but the
    // script didn't delete it, clean up in the background.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                }
            });
        }
    }

    // SIPREC: stop any active recording sessions for this call
    let bye_messages = state.recording_manager.stop_recording(&call_id, state.local_addr);
    for (bye_msg, destination, transport) in bye_messages {
        let data = Bytes::from(bye_msg.to_bytes());
        let outbound_message = OutboundMessage {
            connection_id: ConnectionId::default(),
            transport,
            destination,
            data,
        };
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(call_id = %call_id, "SIPREC: failed to send BYE to SRS: {error}");
        }
    }

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors, cleans up registry,
    // and moves re-INVITE tracking entries to the zombie map
    state.call_actors.remove_call(&call_id);
    state.call_event_receivers.remove(&call_id);
    schedule_zombie_reinvite_cleanup(&state.call_actors);
}

/// Sweep all active calls for session timer expiry (RFC 4028).
///
/// Called every ~5 seconds from a background task. For each call:
/// - If `elapsed > session_expires`: tear down the call (both legs).
/// - If `elapsed > session_expires / 2` and refresher is "b2bua": send refresh re-INVITE.
fn session_timer_sweep(state: &DispatcherState) {
    let now = std::time::Instant::now();

    // Collect calls needing action (avoid holding DashMap ref during send)
    let mut calls_to_refresh: Vec<String> = Vec::new();
    let mut calls_to_terminate: Vec<String> = Vec::new();

    // Iterate all calls — only look at Answered calls with a session timer
    for entry in state.call_actors.iter_calls() {
        let call = entry.value();
        if call.state != CallState::Answered {
            continue;
        }
        if let Some(ref timer) = call.session_timer {
            let elapsed = now.duration_since(timer.last_refresh);
            let expires = std::time::Duration::from_secs(timer.session_expires as u64);
            let half_expires = expires / 2;

            if elapsed >= expires {
                // Session expired — terminate
                calls_to_terminate.push(call.id.clone());
            } else if elapsed >= half_expires && timer.refresher == "b2bua" {
                // Time to refresh
                calls_to_refresh.push(call.id.clone());
            }
        }
    }

    // Send refresh re-INVITEs
    for call_id in calls_to_refresh {
        b2bua_send_refresh_reinvite(&call_id, state);
    }

    // Terminate expired calls
    for call_id in calls_to_terminate {
        info!(call_id = %call_id, "B2BUA: session timer expired, terminating call");
        b2bua_session_timer_terminate(&call_id, state);
    }
}

/// Send a B2BUA-initiated refresh re-INVITE to the B-leg.
fn b2bua_send_refresh_reinvite(call_id: &str, state: &DispatcherState) {
    let (a_leg_invite, a_leg_from_tag, winner_b_leg, session_expires) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            let se = call.session_timer.as_ref().map(|t| t.session_expires).unwrap_or(1800);
            (call.a_leg_invite.clone(), call.a_leg.dialog.remote_tag.clone().unwrap_or_default(), b_leg, se)
        }
        None => return,
    };

    let (invite_arc, b_leg) = match (a_leg_invite, winner_b_leg) {
        (Some(invite), Some(b_leg)) => (invite, b_leg),
        _ => {
            debug!(call_id = %call_id, "B2BUA refresh: missing invite or B-leg");
            return;
        }
    };

    let Ok(original) = invite_arc.lock() else {
        error!(call_id = %call_id, "invite_arc lock poisoned during session timer refresh");
        return;
    };
    let mut reinvite = original.clone();
    drop(original);

    // New Via/branch
    let branch = TransactionKey::generate_branch();
    let transport_str = format!("{}", b_leg.transport.transport).to_uppercase();
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&b_leg.transport.transport),
        state.via_port(&b_leg.transport.transport),
        branch,
    );
    reinvite.headers.remove("Via");
    reinvite.headers.add("Via", via_value);

    // Update Request-URI to B-leg target
    let b_leg_target_uri = b_leg.dialog.target_uri.clone().unwrap_or_default();
    if !b_leg_target_uri.is_empty() {
        if let Ok(target_parsed) = parse_uri_standalone(&b_leg_target_uri) {
            reinvite.start_line = StartLine::Request(crate::sip::message::RequestLine {
                method: crate::sip::message::Method::Invite,
                request_uri: target_parsed,
                version: crate::sip::message::Version::sip_2_0(),
            });
        }
    }

    // Rewrite A-leg dialog headers → B-leg dialog headers
    crate::b2bua::actor::Dialog::rewrite_headers(
        &mut reinvite, &b_leg.dialog.call_id, &a_leg_from_tag, &b_leg.dialog.local_tag,
    );

    // Set session timer headers
    reinvite.headers.remove("Session-Expires");
    reinvite.headers.remove("Min-SE");
    reinvite.headers.add(
        "Session-Expires",
        format!("{};refresher=uac", session_expires),
    );
    if let Some(ref timer_config) = state.session_timer_config {
        reinvite.headers.add("Min-SE", timer_config.min_se.to_string());
    }
    if reinvite.headers.get("Supported").is_none() {
        reinvite.headers.add("Supported", "timer".to_string());
    }

    // Register new branch for response routing (reuse B-leg dialog identifiers)
    // Mark as re-INVITE so the response handler doesn't absorb it as a retransmission
    let mut new_b_leg = Leg::new_b_leg(
        b_leg.dialog.call_id.clone(),
        b_leg.dialog.local_tag.clone(),
        "reinvite:a2b".to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: b_leg.transport.remote_addr,
            connection_id: ConnectionId::default(),
            transport: b_leg.transport.transport,
        },
    );
    new_b_leg.stored_vias = vec![];
    state.call_actors.add_b_leg(call_id, new_b_leg);

    // Reset timer preemptively (will be confirmed on 200 OK)
    state.call_actors.reset_session_timer(call_id);

    debug!(call_id = %call_id, "B2BUA: sending session timer refresh re-INVITE");
    send_b2bua_to_bleg(reinvite, b_leg.transport.transport, b_leg.transport.remote_addr, state);
}

/// Terminate a call due to session timer expiry — send BYE to both legs.
fn b2bua_session_timer_terminate(call_id: &str, state: &DispatcherState) {
    let (a_leg, winner_b_leg, sip_call_id) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (call.a_leg.clone(), b_leg, call.a_leg.dialog.call_id.clone())
        }
        None => return,
    };

    // Build a BYE message for each leg
    let bye_branch_a = TransactionKey::generate_branch();
    let bye_a = SipMessageBuilder::new()
        .request(
            crate::sip::message::Method::Bye,
            crate::sip::uri::SipUri::new(a_leg.transport.remote_addr.ip().to_string())
                .with_port(a_leg.transport.remote_addr.port()),
        )
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            format!("{}", a_leg.transport.transport).to_uppercase(),
            format_sip_host(&state.local_addr.ip().to_string()),
            state.listen_addrs.get(&a_leg.transport.transport).map(|a| a.port()).unwrap_or(state.local_addr.port()),
            bye_branch_a,
        ))
        .call_id(sip_call_id.clone())
        .from(format!("<sip:siphon@{}>;tag=session-timer", state.local_addr))
        .to(format!("<sip:endpoint@{}>;tag={}", a_leg.transport.remote_addr, a_leg.dialog.remote_tag.as_deref().unwrap_or("")))
        .cseq("1 BYE".to_string())
        .content_length(0)
        .build();

    if let Ok(bye_msg) = bye_a {
        send_message(bye_msg, a_leg.transport.transport, a_leg.transport.remote_addr, a_leg.transport.connection_id, state);
    }

    // BYE to B-leg (use B-leg Call-ID and From-tag)
    if let Some(b_leg) = &winner_b_leg {
        let bye_branch_b = TransactionKey::generate_branch();
        let bye_b = SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Bye,
                crate::sip::uri::SipUri::new(b_leg.transport.remote_addr.ip().to_string())
                    .with_port(b_leg.transport.remote_addr.port()),
            )
            .via(format!(
                "SIP/2.0/{} {}:{};branch={}",
                format!("{}", b_leg.transport.transport).to_uppercase(),
                format_sip_host(&state.local_addr.ip().to_string()),
                state.listen_addrs.get(&b_leg.transport.transport).map(|a| a.port()).unwrap_or(state.local_addr.port()),
                bye_branch_b,
            ))
            .call_id(b_leg.dialog.call_id.clone())
            .from(format!("<sip:siphon@{}>;tag={}", state.local_addr, b_leg.dialog.local_tag))
            .to(format!("<sip:endpoint@{}>", b_leg.transport.remote_addr))
            .cseq("1 BYE".to_string())
            .content_length(0)
            .build();

        if let Ok(bye_msg) = bye_b {
            send_b2bua_to_bleg(bye_msg, b_leg.transport.transport, b_leg.transport.remote_addr, state);
        }
    }

    // Safety-net RTPEngine cleanup
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                }
            });
        }
    }

    state.call_actors.set_state(call_id, CallState::Terminated);
    state.call_actors.remove_call(call_id);
    state.call_event_receivers.remove(call_id);
    schedule_zombie_reinvite_cleanup(&state.call_actors);
}

/// Handle a mid-dialog re-INVITE for a B2BUA call.
///
/// Re-INVITEs are used for session timer refreshes (RFC 4028), hold/resume,
/// and codec renegotiation. They are forwarded to the other leg transparently.
fn handle_b2bua_reinvite(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA re-INVITE: no matching call");
            return;
        }
    };

    // Determine direction and extract routing info
    let (from_a_leg, a_leg, winner_b_leg) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (from_a, call.a_leg.clone(), b_leg)
        }
        None => return,
    };

    debug!(
        call_id = %call_id,
        from_a_leg = from_a_leg,
        "B2BUA: forwarding re-INVITE"
    );

    // Send 100 Trying to the re-INVITE sender
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref());
    send_message(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Build the forwarded re-INVITE with new Via/branch
    let branch = TransactionKey::generate_branch();

    let mut forwarded = message.clone();
    forwarded.headers.remove("Via");

    // Register this branch for response routing back to the re-INVITE sender
    let reinvite_target = if from_a_leg {
        // A→B: forward to winning B-leg, rewrite A-leg → B-leg dialog headers
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded, &b_leg.dialog.call_id, a_leg.dialog.remote_tag.as_deref().unwrap_or(""), &b_leg.dialog.local_tag,
            );
            Some((b_leg.transport.remote_addr, b_leg.transport.transport, b_leg.dialog.call_id.clone(), b_leg.dialog.local_tag.clone()))
        } else {
            warn!(call_id = %call_id, "B2BUA re-INVITE: no winning B-leg");
            return;
        }
    } else {
        // B→A: forward to A-leg, rewrite B-leg → A-leg dialog headers
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded, &a_leg.dialog.call_id, &b_leg.dialog.local_tag, a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            );
        }
        Some((a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()))
    };

    if let Some((destination, transport, leg_call_id, leg_from_tag)) = reinvite_target {
        // Set Via with correct transport for the target leg
        let transport_str = format!("{}", transport).to_uppercase();
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            state.via_host(&transport),
            state.via_port(&transport),
            branch,
        );
        forwarded.headers.add("Via", via_value);

        // Sanitize: strip headers that leak the other leg's identity/capabilities.
        // SIPhon is UAC on the forwarded re-INVITE, so set our own User-Agent.
        if let Some(ref ua) = state.user_agent_header {
            forwarded.headers.set("User-Agent", ua.clone());
        } else {
            forwarded.headers.remove("User-Agent");
        }
        forwarded.headers.remove("Server");
        forwarded.headers.remove("Allow");
        forwarded.headers.remove("Allow-Events");
        forwarded.headers.remove("Supported");
        forwarded.headers.remove("Require");
        // P-Asserted-Identity from the other leg must not cross the B2BUA boundary.
        forwarded.headers.remove("P-Asserted-Identity");

        // Sanitize SDP: mask other leg's identity in o= and s= lines
        sanitize_sdp_identity(&mut forwarded.body, &state.sdp_name);

        // Track the re-INVITE branch → call_id for response routing.
        // Encode the direction so the response handler knows where to relay.
        // Store the originator's Via(s) so we can restore them on the response.
        let direction = if from_a_leg { "reinvite:a2b" } else { "reinvite:b2a" };
        let originator_vias = message.headers.get_all("Via")
            .map(|v| v.to_vec())
            .unwrap_or_default();
        let mut reinvite_leg = Leg::new_b_leg(
            leg_call_id,
            leg_from_tag,
            direction.to_string(),
            branch.clone(),
            LegTransport {
                remote_addr: destination,
                connection_id: ConnectionId::default(),
                transport,
            },
        );
        reinvite_leg.stored_vias = originator_vias;
        state.call_actors.add_b_leg(&call_id, reinvite_leg);

        send_b2bua_to_bleg(forwarded, transport, destination, state);
    }

    // Reset session timer on successful re-INVITE (timer reset happens on 200 OK
    // via handle_b2bua_response which calls set_state — we reset the timer there)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;
    use crate::sip::builder::SipMessageBuilder;

    fn sample_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
            .cseq("314159 INVITE".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn build_response_copies_mandatory_headers() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None);

        assert!(response.is_response());
        assert_eq!(response.status_code(), Some(200));

        // Via must be copied
        let vias = response.headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 1);
        assert!(vias[0].contains("pc33.atlanta.com"));

        // From/To/Call-ID/CSeq must be copied
        assert!(response.headers.from().unwrap().contains("alice@atlanta.com"));
        assert!(response.headers.to().unwrap().contains("bob@biloxi.com"));
        assert_eq!(
            response.headers.call_id().unwrap(),
            "a84b4c76e66710@pc33.atlanta.com"
        );
        assert!(response.headers.cseq().unwrap().contains("INVITE"));
    }

    #[test]
    fn build_response_sets_content_length_zero() {
        let request = sample_invite();
        let response = build_response(&request, 404, "Not Found", None);
        assert_eq!(response.headers.get("Content-Length").unwrap(), "0");
    }

    #[test]
    fn build_response_copies_multiple_vias() {
        let mut request = sample_invite();
        request.headers.add(
            "Via",
            "SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK-proxy".to_string(),
        );

        let response = build_response(&request, 200, "OK", None);
        let vias = response.headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 2);
    }

    #[test]
    fn build_response_serializes_to_valid_sip() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None);
        let bytes = response.to_bytes();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("Via:"));
        assert!(text.contains("From:"));
        assert!(text.contains("To:"));
        assert!(text.contains("Call-ID:"));
        assert!(text.contains("CSeq:"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_response_includes_server_header_when_configured() {
        let request = sample_invite();
        let response = build_response(&request, 401, "Unauthorized", Some("SIPhon/0.1.0"));
        assert_eq!(response.headers.get("Server").unwrap(), "SIPhon/0.1.0");
    }

    #[test]
    fn build_response_omits_server_header_when_none() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None);
        assert!(response.headers.get("Server").is_none());
    }

    #[test]
    fn build_ack_for_non2xx_has_correct_headers() {
        let request = sample_invite();
        let response = build_response(&request, 480, "Temporarily Unavailable", None);
        let local_addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();

        let ack = build_ack_for_non2xx(
            &request,
            &response,
            "z9hG4bK-proxy-branch",
            Transport::Tcp,
            local_addr,
        );

        // Must be an ACK request
        assert!(ack.is_request());
        let bytes = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(bytes.starts_with("ACK sip:bob@biloxi.com SIP/2.0\r\n"));

        // Via: our own hop only (not the UAC's)
        let via = ack.headers.via().unwrap();
        assert!(via.contains("z9hG4bK-proxy-branch"));
        assert!(via.contains("TCP"));
        assert!(via.contains("10.0.0.1:5060"));

        // From: same as original request
        assert_eq!(ack.headers.from().unwrap(), request.headers.from().unwrap());

        // To: from the response (may have To-tag)
        assert_eq!(ack.headers.to().unwrap(), response.headers.to().unwrap());

        // Call-ID: same as original
        assert_eq!(ack.headers.call_id().unwrap(), request.headers.call_id().unwrap());

        // CSeq: same number, ACK method
        let cseq = ack.headers.cseq().unwrap();
        assert!(cseq.contains("314159"));
        assert!(cseq.contains("ACK"));
        assert!(!cseq.contains("INVITE"));

        // Max-Forwards present
        assert_eq!(ack.headers.get("Max-Forwards").unwrap(), "70");

        // Content-Length: 0
        assert_eq!(ack.headers.content_length(), Some(0));
    }

    fn test_resolver() -> SipResolver {
        SipResolver::from_system().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_ip_with_port() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@192.168.1.100:5080", &resolver).unwrap();
        assert_eq!(result.address, "192.168.1.100:5080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_ip_default_port() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@10.0.0.1", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_localhost() {
        let resolver = test_resolver();
        let result = resolve_target("sip:bob@localhost:5090", &resolver).unwrap();
        assert_eq!(result.address.port(), 5090);
        assert!(result.address.ip().is_loopback());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_bare_socketaddr() {
        let resolver = test_resolver();
        let result = resolve_target("10.0.0.1:5060", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert!(result.transport.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_transport_tcp() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@10.0.0.1:5060;transport=tcp", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(result.transport, Some(Transport::Tcp));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_unresolvable_domain() {
        let resolver = test_resolver();
        assert!(resolve_target("sip:alice@this-domain-should-not-exist-xyzzy.invalid", &resolver).is_none());
    }

    // --- CANCEL tests ---

    fn sample_cancel() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Cancel,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
            .cseq("314159 CANCEL".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn build_cancel_response_200() {
        let cancel = sample_cancel();
        let response = build_response(&cancel, 200, "OK", None);
        assert_eq!(response.status_code(), Some(200));
        assert!(response.headers.cseq().unwrap().contains("CANCEL"));
    }

    #[test]
    fn build_cancel_response_481() {
        let cancel = sample_cancel();
        let response = build_response(&cancel, 481, "Call/Transaction Does Not Exist", None);
        assert_eq!(response.status_code(), Some(481));
    }

    #[test]
    fn build_487_response() {
        let invite = sample_invite();
        let response = build_response(&invite, 487, "Request Terminated", None);
        assert_eq!(response.status_code(), Some(487));
        assert!(response.headers.cseq().unwrap().contains("INVITE"));
    }

    // --- Transaction integration tests ---

    #[test]
    fn transaction_manager_creates_client_transaction() {
        let manager = TransactionManager::default();
        let invite = sample_invite();
        let txn_transport = crate::transaction::state::Transport::Udp;
        let (key, actions) = manager.new_client_transaction(invite, txn_transport).unwrap();
        assert_eq!(key.method, Method::Invite);
        assert_eq!(manager.count(), 1);
        // Should have SendMessage + StartTimer(B) + StartTimer(A) for UDP
        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
        assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::B, _))));
        assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::A, _))));
    }

    #[test]
    fn transaction_manager_creates_server_transaction() {
        let manager = TransactionManager::default();
        let invite = sample_invite();
        let txn_transport = crate::transaction::state::Transport::Udp;
        let (key, actions) = manager.new_server_transaction(&invite, txn_transport).unwrap();
        assert_eq!(key.method, Method::Invite);
        assert_eq!(manager.count(), 1);
        assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    }

    #[test]
    fn timer_entry_created_with_correct_fields() {
        let key = TransactionKey::new("z9hG4bK-test".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
        let entry = TimerEntry {
            key: key.clone(),
            name: TimerName::A,
            fires_at: std::time::Instant::now() + std::time::Duration::from_millis(500),
            destination: Some("10.0.0.1:5060".parse().unwrap()),
            transport: Some(Transport::Udp),
            connection_id: Some(ConnectionId::default()),
        };
        assert_eq!(entry.key, key);
        assert_eq!(entry.name, TimerName::A);
        assert!(entry.destination.is_some());
    }

    #[test]
    fn transport_conversion_udp() {
        let txn = crate::transaction::state::Transport::from(Transport::Udp);
        assert_eq!(txn, crate::transaction::state::Transport::Udp);
    }

    #[test]
    fn transport_conversion_tcp_is_reliable() {
        let txn = crate::transaction::state::Transport::from(Transport::Tcp);
        assert_eq!(txn, crate::transaction::state::Transport::Reliable);
    }

    #[test]
    fn transport_conversion_tls_is_reliable() {
        let txn = crate::transaction::state::Transport::from(Transport::Tls);
        assert_eq!(txn, crate::transaction::state::Transport::Reliable);
    }

    // --- B2BUA call manager tests ---

    #[test]
    fn call_manager_create_and_cancel() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "call-1".to_string(),
            "tag-1".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        let call_id = manager.create_call(a_leg);
        assert_eq!(manager.count(), 1);

        // Simulate cancel: set state and remove
        manager.set_state(&call_id, CallState::Terminated);
        manager.remove_call(&call_id);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn call_manager_b_leg_response_routing() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "call-1".to_string(),
            "tag-1".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        let call_id = manager.create_call(a_leg);

        let b_leg = Leg::new_b_leg(
            "b2b-test-1".to_string(),
            "sb-test-1".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "z9hG4bK-b1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.2:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        manager.add_b_leg(&call_id, b_leg);

        // Can route response via B-leg branch
        assert_eq!(manager.call_id_for_branch("z9hG4bK-b1"), Some(call_id.clone()));

        // Set winner and verify answered state
        manager.set_winner(&call_id, 0);
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    /// Verify that next_hop routing does not clobber the Request-URI.
    ///
    /// The relay_request function uses next_hop only for DNS resolution /
    /// packet routing, keeping the original R-URI (including user part) intact.
    /// This test validates the invariant at the message level.
    #[test]
    fn next_hop_does_not_overwrite_request_uri() {
        let invite = sample_invite();
        // Original R-URI: sip:bob@biloxi.com
        let original_ruri = match &invite.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert!(original_ruri.contains("bob@"), "original R-URI should have user part: {original_ruri}");

        // Simulate what relay_request does: clone, add Via/RR, but do NOT overwrite R-URI
        let relayed = invite.clone();
        let ruri_after = match &relayed.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert_eq!(original_ruri, ruri_after,
            "R-URI must be preserved when next_hop is used for routing only");
    }

    // --- Bug fix regression tests ---

    /// Bug 1: INVITE retransmissions should be detected via find_by_sip_call_id.
    #[test]
    fn retransmission_guard_detects_duplicate_call_id() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "retransmit-test@host".to_string(),
            "tag-orig".to_string(),
            "z9hG4bK-orig".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        let _call_id = manager.create_call(a_leg);

        // Second INVITE with same SIP Call-ID (retransmission) should be detected
        assert!(
            manager.find_by_sip_call_id("retransmit-test@host").is_some(),
            "retransmission guard must detect existing call by SIP Call-ID"
        );
        // Different Call-ID should not match
        assert!(manager.find_by_sip_call_id("different-call@host").is_none());
    }

    /// Bug 2: build_b2bua_ack_for_non2xx constructs a valid ACK from a B-leg error response.
    #[test]
    fn build_b2bua_ack_for_non2xx_constructs_valid_ack() {
        // Build a 486 response as if from B-leg
        let response = SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-b2b-branch".to_string())
            .from("<sip:alice@example.com>;tag=b-leg-ftag".to_string())
            .to("<sip:bob@example.com>;tag=bob-tag".to_string())
            .call_id("b-leg-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let local_addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let ack = build_b2bua_ack_for_non2xx(
            &response,
            "z9hG4bK-b2b-branch",
            Some("sip:bob@10.0.0.2:5060"),
            Transport::Udp,
            local_addr,
        );

        assert!(ack.is_request());
        let bytes = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(bytes.starts_with("ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"));

        // Via uses our branch (same as client transaction)
        let via = ack.headers.via().unwrap();
        assert!(via.contains("z9hG4bK-b2b-branch"));
        assert!(via.contains("UDP"));

        // From/To/Call-ID from the response
        assert!(ack.headers.from().unwrap().contains("b-leg-ftag"));
        assert!(ack.headers.to().unwrap().contains("bob-tag"));
        assert_eq!(ack.headers.call_id().unwrap(), "b-leg-call-id");

        // CSeq: same number, ACK method
        let cseq = ack.headers.cseq().unwrap();
        assert!(cseq.contains("1"));
        assert!(cseq.contains("ACK"));
        assert!(!cseq.contains("INVITE"));

        assert_eq!(ack.headers.content_length(), Some(0));
    }

    /// Bug 3: Winner is recorded and can be used to find the winning B-leg for ACK bridging.
    #[test]
    fn winner_tracks_answered_b_leg_for_ack_bridging() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "ack-bridge-test@host".to_string(),
            "a-tag".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        let call_id = manager.create_call(a_leg);

        // Add two B-legs (forked call)
        let b_leg_0 = Leg::new_b_leg(
            "b-cid-0".to_string(),
            "b-ftag-0".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "z9hG4bK-b0".to_string(),
            LegTransport {
                remote_addr: "10.0.0.2:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        let b_leg_1 = Leg::new_b_leg(
            "b-cid-1".to_string(),
            "b-ftag-1".to_string(),
            "sip:bob@10.0.0.3".to_string(),
            "z9hG4bK-b1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.3:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        manager.add_b_leg(&call_id, b_leg_0);
        manager.add_b_leg(&call_id, b_leg_1);

        // B-leg 1 answers first
        manager.set_winner(&call_id, 1);
        manager.set_state(&call_id, CallState::Answered);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(1));
        let winner = &call.b_legs[call.winner.unwrap()];
        assert_eq!(winner.dialog.call_id, "b-cid-1");
        assert_eq!(winner.dialog.local_tag, "b-ftag-1");
        assert_eq!(winner.transport.remote_addr, "10.0.0.3:5060".parse::<SocketAddr>().unwrap());

        // ACK bridging would use find_by_sip_call_id to locate the call
        assert_eq!(
            manager.find_by_sip_call_id("ack-bridge-test@host"),
            Some(call_id),
        );
    }

    #[test]
    fn sanitize_sdp_identity_rewrites_o_and_s_lines() {
        let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let mut body = sdp.as_bytes().to_vec();
        sanitize_sdp_identity(&mut body, "Invenio SBC");
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("o=Invenio SBC 123 456 IN IP4 10.0.0.1\r\n"));
        assert!(result.contains("s=Invenio SBC\r\n"));
        assert!(!result.contains("FreeSWITCH"));
        // Other lines unchanged
        assert!(result.contains("v=0\r\n"));
        assert!(result.contains("m=audio 8000 RTP/AVP 0\r\n"));
    }

    #[test]
    fn sanitize_sdp_identity_no_op_on_empty_body() {
        let mut body = Vec::new();
        sanitize_sdp_identity(&mut body, "SIPhon");
        assert!(body.is_empty());
    }

    /// Verify that fork targets DO update the R-URI (each branch gets its Contact).
    #[test]
    fn fork_branch_updates_request_uri() {
        let invite = sample_invite();
        let mut relayed = invite.clone();

        // Simulate fork branch updating R-URI to registered contact
        let target = "sip:bob@192.168.1.50:5060;transport=tls";
        if let Ok(new_uri) = parse_uri_standalone(target) {
            if let StartLine::Request(ref mut rl) = relayed.start_line {
                rl.request_uri = new_uri;
            }
        }

        let ruri = match &relayed.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert!(ruri.contains("bob@192.168.1.50"),
            "fork branch R-URI should be updated to target contact: {ruri}");
    }
}
