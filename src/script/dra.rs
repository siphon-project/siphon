//! Diameter Routing Agent (DRA) server bootstrap and dispatch.
//!
//! Wires the server-mode pieces (Phases 0–5) into a running agent:
//!   - connects each tenant's backend `servers` as outbound clients (so pools
//!     can reach them);
//!   - binds the inbound TCP/SCTP listeners and runs the staged
//!     [`ServerHandshake`] (ACL + Origin-Host gates + `@on_inbound_cer`) on
//!     each accepted connection;
//!   - dispatches every inbound request to `@diameter.on_request` on its own
//!     task (bounded by a global semaphore so a slow backend can't exhaust
//!     resources), then ships the returned answer back over the inbound
//!     connection.
//!
//! Per-request concurrency is the key difference from the client-mode
//! `dispatcher.rs` loop, which awaits each handler serially: a DRA relay can
//! block for the backend RTT, so serial dispatch would head-of-line-block
//! every tenant.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn};

use crate::config::DiameterConfig;
use crate::diameter::auth::{AclMatch, OriginHostPolicy, SourceIpAcl};
use crate::diameter::codec::{Avp, DiameterMsg};
use crate::diameter::dictionary;
use crate::diameter::peer::{self, DiameterPeer, IncomingRequest, PeerConfig};
use crate::diameter::server::{CerDecision, ServerHandshake, ServerIdentity};
use crate::diameter::transport::DiameterListener;
use crate::diameter::{forward, DiameterClient, DiameterManager};
use crate::script::api::diameter_server::{PyDiameterAnswer, PyDiameterRequest, PyInboundPeer};
use crate::script::engine::{run_coroutine_value, HandlerKind, ScriptEngine};

/// Global cap on concurrently in-flight inbound requests being relayed.
const MAX_INFLIGHT: usize = 512;

/// Per-tenant advertised identity, indexed by tenant name.
type TenantIdentities = Arc<HashMap<String, (String, String)>>;

/// Bootstrap the DRA / server NF: connect backends, dial any outbound serving
/// connections (`connect_to`), and bind the inbound listeners. Runs whenever
/// `diameter.listen` is set OR any tenant has `connect_to` peers.
pub fn spawn(
    config: &DiameterConfig,
    manager: Arc<DiameterManager>,
    engine: Arc<ScriptEngine>,
    product_name: &str,
    product_version: &str,
) {
    let has_connect_to = config.tenants.values().any(|t| !t.connect_to.is_empty());
    if config.listen.is_none() && !has_connect_to {
        return;
    }

    let semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT));

    // Tenant identities + connect backend servers (DRA relay targets) +
    // outbound serving connections (e.g. HSS → DRA).
    let mut identities: HashMap<String, (String, String)> = HashMap::new();
    for (tenant_name, tenant) in &config.tenants {
        let identity = (
            tenant.identity.origin_host.clone(),
            tenant.identity.origin_realm.clone(),
        );
        identities.insert(tenant_name.clone(), identity.clone());
        for server in &tenant.servers {
            spawn_backend_connection(
                tenant,
                server,
                Arc::clone(&manager),
                product_name,
                product_version,
            );
        }
        for upstream in &tenant.connect_to {
            spawn_serving_connection(
                tenant_name.clone(),
                identity.clone(),
                upstream.clone(),
                Arc::clone(&engine),
                Arc::clone(&semaphore),
                product_name,
                product_version,
            );
        }
    }
    let identities: TenantIdentities = Arc::new(identities);

    // No inbound listener (e.g. a pure HSS that only dials out) → done.
    let Some(listen) = config.listen.clone() else {
        return;
    };

    // Build the two auth gates from every tenant's client list.
    let mut acl = SourceIpAcl::new();
    let mut origin_policy = OriginHostPolicy::new();
    for (tenant_name, tenant) in &config.tenants {
        for client in &tenant.clients {
            for cidr in &client.allowed_ips {
                if let Err(error) = acl.add_str(cidr, tenant_name, &client.name) {
                    warn!(%error, tenant = %tenant_name, peer = %client.name, "DRA: bad allowed_ips entry");
                }
            }
            if let Some(expected) = &client.expected_origin_host {
                origin_policy.set(&client.name, expected);
            }
        }
    }

    // Default identity for error/reject CEAs (before a tenant is chosen):
    // top-level origin if set, else the first tenant's identity.
    let (default_origin_host, default_origin_realm) = if !config.origin_host.is_empty() {
        (config.origin_host.clone(), config.origin_realm.clone())
    } else {
        identities
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| ("dra.localdomain".to_string(), "localdomain".to_string()))
    };

    let handshake = Arc::new(ServerHandshake {
        acl: Arc::new(acl),
        origin_policy: Arc::new(origin_policy),
        identity: ServerIdentity {
            default_origin_host,
            default_origin_realm,
            local_ip: std::net::Ipv4Addr::UNSPECIFIED,
            product_name: config
                .product_name
                .clone()
                .unwrap_or_else(|| product_name.to_string()),
            firmware_revision: peer::version_to_firmware_revision(product_version),
            watchdog_interval: config.watchdog_interval,
            application_ids: vec![],
        },
    });

    if let Some(tcp_addr) = listen.tcp {
        spawn_listener(
            tcp_addr,
            "tcp",
            Arc::clone(&handshake),
            Arc::clone(&engine),
            Arc::clone(&semaphore),
            Arc::clone(&identities),
        );
    }
    if let Some(sctp_addr) = listen.sctp {
        spawn_listener(
            sctp_addr,
            "sctp",
            Arc::clone(&handshake),
            Arc::clone(&engine),
            Arc::clone(&semaphore),
            Arc::clone(&identities),
        );
    }
}

/// Connect one backend server as an outbound client, reconnecting on drop.
/// Supports both TCP and SCTP transports.
fn spawn_backend_connection(
    tenant: &crate::config::DiameterTenant,
    server: &crate::config::DiameterServerEntry,
    manager: Arc<DiameterManager>,
    product_name: &str,
    product_version: &str,
) {
    let transport = server.transport.clone();
    let config = PeerConfig {
        host: server.host.clone(),
        port: server.port,
        origin_host: tenant.identity.origin_host.clone(),
        origin_realm: tenant.identity.origin_realm.clone(),
        destination_host: None,
        destination_realm: tenant.identity.origin_realm.clone(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: vec![],
        watchdog_interval: 30,
        reconnect_delay: 5,
        product_name: product_name.to_string(),
        firmware_revision: peer::version_to_firmware_revision(product_version),
    };
    let name = server.name.clone();
    tokio::spawn(async move {
        loop {
            match peer::connect_with_transport(config.clone(), &transport).await {
                Ok((connected, mut incoming_rx)) => {
                    let client = Arc::new(DiameterClient::new(Arc::clone(&connected)));
                    manager.register(name.clone(), client);
                    info!(peer = %name, "DRA backend connected");
                    // Drain backend-initiated requests (none expected for a
                    // pure relay target); answers correlate via send_request.
                    while incoming_rx.recv().await.is_some() {}
                    warn!(peer = %name, "DRA backend disconnected, reconnecting");
                }
                Err(error) => {
                    warn!(peer = %name, %error, "DRA backend connect failed, retrying in 5s");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Dial an outbound connection and **serve** the inbound requests it carries
/// via `@diameter.on_request` — the HSS-dials-DRA case. siphon sends the CER
/// with the tenant identity; reconnects on drop. Per-request dispatch is
/// bounded by the same global semaphore as the listener path.
#[allow(clippy::too_many_arguments)]
fn spawn_serving_connection(
    tenant_name: String,
    identity: (String, String),
    entry: crate::config::DiameterServerEntry,
    engine: Arc<ScriptEngine>,
    semaphore: Arc<Semaphore>,
    product_name: &str,
    product_version: &str,
) {
    let (origin_host, origin_realm) = identity;
    let config = PeerConfig {
        host: entry.host.clone(),
        port: entry.port,
        origin_host: origin_host.clone(),
        origin_realm: origin_realm.clone(),
        destination_host: None,
        destination_realm: origin_realm.clone(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: vec![],
        watchdog_interval: 30,
        reconnect_delay: 5,
        product_name: product_name.to_string(),
        firmware_revision: peer::version_to_firmware_revision(product_version),
    };
    let transport = entry.transport.clone();
    let peer_info = PyInboundPeer {
        name: entry.name.clone(),
        tenant: tenant_name.clone(),
        addr: format!("{}:{}", entry.host, entry.port),
        transport: transport.clone(),
    };

    tokio::spawn(async move {
        loop {
            match peer::connect_with_transport(config.clone(), &transport).await {
                Ok((connected, mut incoming_rx)) => {
                    info!(
                        peer = %entry.name,
                        tenant = %tenant_name,
                        "DRA: outbound serving connection established (inbound requests → on_request)"
                    );
                    while let Some(incoming) = incoming_rx.recv().await {
                        let engine = Arc::clone(&engine);
                        let semaphore = Arc::clone(&semaphore);
                        let inbound_peer = Arc::clone(&connected);
                        let peer_info = peer_info.clone();
                        let origin_host = origin_host.clone();
                        let origin_realm = origin_realm.clone();
                        tokio::spawn(async move {
                            let _permit = match semaphore.acquire_owned().await {
                                Ok(permit) => permit,
                                Err(_) => return,
                            };
                            dispatch_request(
                                engine,
                                inbound_peer,
                                incoming,
                                peer_info,
                                origin_host,
                                origin_realm,
                            )
                            .await;
                        });
                    }
                    warn!(peer = %entry.name, "DRA: outbound serving connection dropped, reconnecting");
                }
                Err(error) => {
                    warn!(peer = %entry.name, %error, "DRA: outbound serving connect failed, retrying in 5s");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Bind one listener (TCP or SCTP) and accept connections forever.
fn spawn_listener(
    addr: String,
    transport: &'static str,
    handshake: Arc<ServerHandshake>,
    engine: Arc<ScriptEngine>,
    semaphore: Arc<Semaphore>,
    identities: TenantIdentities,
) {
    tokio::spawn(async move {
        let listener = match transport {
            "sctp" => match addr.parse::<SocketAddr>() {
                Ok(socket_addr) => DiameterListener::bind_sctp(socket_addr),
                Err(error) => {
                    warn!(%addr, %error, "DRA: bad SCTP listen address");
                    return;
                }
            },
            _ => DiameterListener::bind_tcp(&addr).await,
        };
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                warn!(%addr, %transport, %error, "DRA: failed to bind listener");
                return;
            }
        };
        info!(%addr, %transport, "DRA listening");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let handshake = Arc::clone(&handshake);
                    let engine = Arc::clone(&engine);
                    let semaphore = Arc::clone(&semaphore);
                    let identities = Arc::clone(&identities);
                    tokio::spawn(async move {
                        serve_connection(
                            stream, peer_addr, transport, handshake, engine, semaphore, identities,
                        )
                        .await;
                    });
                }
                Err(error) => {
                    warn!(%addr, %transport, %error, "DRA: accept error");
                    return;
                }
            }
        }
    });
}

/// Run the handshake on one accepted connection and, on success, consume its
/// inbound requests.
async fn serve_connection(
    stream: crate::diameter::transport::DiameterStream,
    peer_addr: SocketAddr,
    transport: &'static str,
    handshake: Arc<ServerHandshake>,
    engine: Arc<ScriptEngine>,
    semaphore: Arc<Semaphore>,
    identities: TenantIdentities,
) {
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingRequest>(256);

    // The CER identity resolver: invoke @on_inbound_cer, else the tenant's
    // configured identity.
    let resolver_engine = Arc::clone(&engine);
    let resolver_identities = Arc::clone(&identities);
    let resolve = move |acl_match: &AclMatch, asserted: &str| -> CerDecision {
        resolve_cer_identity(&resolver_engine, &resolver_identities, acl_match, asserted, peer_addr)
    };

    let (admitted_peer, acl_match) = match handshake
        .run(stream, peer_addr, incoming_tx, resolve)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            warn!(%peer_addr, %transport, %error, "DRA: handshake rejected");
            return;
        }
    };

    let dra_origin_host = admitted_peer.config().origin_host.clone();
    let dra_origin_realm = admitted_peer.config().origin_realm.clone();
    let peer_info = PyInboundPeer {
        name: acl_match.peer.clone(),
        tenant: acl_match.tenant.clone(),
        addr: peer_addr.to_string(),
        transport: transport.to_string(),
    };

    while let Some(incoming) = incoming_rx.recv().await {
        let engine = Arc::clone(&engine);
        let semaphore = Arc::clone(&semaphore);
        let inbound_peer = Arc::clone(&admitted_peer);
        let peer_info = peer_info.clone();
        let dra_origin_host = dra_origin_host.clone();
        let dra_origin_realm = dra_origin_realm.clone();
        tokio::spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            dispatch_request(
                engine,
                inbound_peer,
                incoming,
                peer_info,
                dra_origin_host,
                dra_origin_realm,
            )
            .await;
        });
    }
}

/// Resolve the CEA identity for an authenticated peer via `@on_inbound_cer`,
/// falling back to the tenant's configured identity when no handler exists.
fn resolve_cer_identity(
    engine: &Arc<ScriptEngine>,
    identities: &TenantIdentities,
    acl_match: &AclMatch,
    asserted: &str,
    peer_addr: SocketAddr,
) -> CerDecision {
    let fallback = || match identities.get(&acl_match.tenant) {
        Some((origin_host, origin_realm)) => CerDecision::Accept {
            origin_host: origin_host.clone(),
            origin_realm: origin_realm.clone(),
        },
        None => CerDecision::Reject(dictionary::DIAMETER_UNKNOWN_PEER),
    };

    pyo3::Python::attach(|python| {
        let state = engine.state();
        let handlers = state.handlers_for(&HandlerKind::DiameterOnInboundCer);
        let Some(handler) = handlers.first() else {
            return fallback();
        };
        let call = handler.callable.bind(python).call1((
            peer_addr.ip().to_string(),
            acl_match.peer.as_str(),
            asserted,
        ));
        let returned = match call {
            Ok(value) => {
                if handler.is_async {
                    match run_coroutine_value(python, &value) {
                        Ok(resolved) => resolved.into_bound(python),
                        Err(error) => {
                            warn!(%error, "DRA: async on_inbound_cer failed");
                            return fallback();
                        }
                    }
                } else {
                    value
                }
            }
            Err(error) => {
                warn!(%error, "DRA: on_inbound_cer failed");
                return fallback();
            }
        };
        if returned.is_none() {
            return CerDecision::Reject(dictionary::DIAMETER_UNKNOWN_PEER);
        }
        match returned.extract::<(String, String)>() {
            Ok((origin_host, origin_realm)) => CerDecision::Accept {
                origin_host,
                origin_realm,
            },
            Err(_) => {
                warn!("DRA: on_inbound_cer must return (origin_host, origin_realm) or None");
                fallback()
            }
        }
    })
}

/// Dispatch a single inbound request to `@diameter.on_request`, ship the
/// answer back, then fire `@diameter.on_request_completed`.
///
/// Shared by the DRA listener, outbound serving connections, AND the legacy
/// `diameter.peers` inbound path (dispatcher.rs) — one inbound model for every
/// connection type and every application.
pub(crate) async fn dispatch_request(
    engine: Arc<ScriptEngine>,
    inbound_peer: Arc<DiameterPeer>,
    incoming: IncomingRequest,
    peer_info: PyInboundPeer,
    dra_origin_host: String,
    dra_origin_realm: String,
) {
    let start = Instant::now();

    // Build the answer (and keep the Py request/answer for the completed hook)
    // inside spawn_blocking — Python work must hold the GIL on a blocking
    // thread, and `forward_to` awaits the backend via the async pool.
    let engine_for_handler = Arc::clone(&engine);
    let join = crate::script::py_executor::try_run(move || -> AnswerOutcome {
        pyo3::Python::attach(|python| {
            build_answer_via_handler(
                python,
                &engine_for_handler,
                &incoming,
                &peer_info,
                &dra_origin_host,
                &dra_origin_realm,
            )
        })
    })
    .await;

    let outcome = match join {
        Ok(outcome) => outcome,
        Err(_panic) => {
            warn!("DRA: dispatch task panicked");
            return;
        }
    };

    if let Err(error) = inbound_peer.send_response(outcome.wire).await {
        warn!(%error, "DRA: failed to send answer upstream");
    }

    // Post-answer hook (best-effort).
    let latency_us = start.elapsed().as_micros() as u64;
    if let (Some(request_py), Some(answer_py)) = (outcome.request_py, outcome.answer_py) {
        let engine = Arc::clone(&engine);
        let _ = crate::script::py_executor::run(move || {
            pyo3::Python::attach(|python| {
                let state = engine.state();
                for handler in state.handlers_for(&HandlerKind::DiameterOnRequestCompleted) {
                    let call = handler.callable.bind(python).call1((
                        request_py.bind(python),
                        answer_py.bind(python),
                        latency_us,
                    ));
                    match call {
                        Ok(value) if handler.is_async => {
                            if let Err(error) = run_coroutine_value(python, &value) {
                                warn!(%error, "DRA: async on_request_completed failed");
                            }
                        }
                        Ok(_) => {}
                        Err(error) => warn!(%error, "DRA: on_request_completed failed"),
                    }
                }
            });
        })
        .await;
    }
}

/// The answer bytes plus optional Py handles for the completed hook.
struct AnswerOutcome {
    wire: Vec<u8>,
    request_py: Option<Py<PyDiameterRequest>>,
    answer_py: Option<Py<PyDiameterAnswer>>,
}

/// Invoke `@diameter.on_request` and produce the answer wire bytes. Falls back
/// to DIAMETER_UNABLE_TO_DELIVER (3002) when the handler returns `None`, and
/// DIAMETER_INVALID_AVP_LENGTH (5014) when the inbound message is malformed.
fn build_answer_via_handler(
    python: Python<'_>,
    engine: &Arc<ScriptEngine>,
    incoming: &IncomingRequest,
    peer_info: &PyInboundPeer,
    dra_origin_host: &str,
    dra_origin_realm: &str,
) -> AnswerOutcome {
    // Parse the inbound request into the lossless tree.
    let request_msg = match DiameterMsg::from_wire(&incoming.raw) {
        Ok(msg) => msg,
        Err(error) => {
            warn!(%error, "DRA: malformed inbound request");
            let stub = stub_message(incoming);
            let answer = forward::build_answer(
                &stub,
                dra_origin_host,
                dra_origin_realm,
                dictionary::DIAMETER_INVALID_AVP_LENGTH,
                Some("malformed request"),
            );
            return AnswerOutcome {
                wire: answer.to_wire(),
                request_py: None,
                answer_py: None,
            };
        }
    };

    let state = engine.state();
    let handlers = state.handlers_for(&HandlerKind::DiameterOnRequest);
    let no_route_answer = || {
        forward::build_answer(
            &request_msg,
            dra_origin_host,
            dra_origin_realm,
            dictionary::DIAMETER_UNABLE_TO_DELIVER,
            Some("no on_request handler"),
        )
    };

    let Some(handler) = handlers.first() else {
        let answer = no_route_answer();
        return AnswerOutcome {
            wire: answer.to_wire(),
            request_py: None,
            answer_py: None,
        };
    };

    // Build the PyDiameterRequest and hand it to the script.
    let request = PyDiameterRequest::new(
        request_msg.clone(),
        peer_info.clone(),
        dra_origin_host.to_string(),
        dra_origin_realm.to_string(),
    );
    let request_py = match Py::new(python, request) {
        Ok(handle) => handle,
        Err(error) => {
            warn!(%error, "DRA: failed to build request object");
            let answer = no_route_answer();
            return AnswerOutcome {
                wire: answer.to_wire(),
                request_py: None,
                answer_py: None,
            };
        }
    };

    let result = handler.callable.bind(python).call1((request_py.bind(python),));
    let resolved = match result {
        Ok(value) => {
            if handler.is_async {
                match run_coroutine_value(python, &value) {
                    Ok(resolved) => resolved.into_bound(python),
                    Err(error) => {
                        warn!(%error, "DRA: async on_request handler failed");
                        let answer = no_route_answer();
                        return AnswerOutcome {
                            wire: answer.to_wire(),
                            request_py: Some(request_py),
                            answer_py: None,
                        };
                    }
                }
            } else {
                value
            }
        }
        Err(error) => {
            warn!(%error, "DRA: on_request handler raised");
            let answer = no_route_answer();
            return AnswerOutcome {
                wire: answer.to_wire(),
                request_py: Some(request_py),
                answer_py: None,
            };
        }
    };

    // None → 3002; otherwise expect a DiameterAnswer.
    let answer_py: Py<PyDiameterAnswer> = if resolved.is_none() {
        let answer = no_route_answer();
        match Py::new(python, PyDiameterAnswer::from_msg(answer)) {
            Ok(handle) => handle,
            Err(_) => {
                return AnswerOutcome {
                    wire: no_route_answer().to_wire(),
                    request_py: Some(request_py),
                    answer_py: None,
                }
            }
        }
    } else {
        match resolved.downcast::<PyDiameterAnswer>() {
            Ok(answer_bound) => answer_bound.clone().unbind(),
            Err(_) => {
                warn!("DRA: on_request must return a DiameterAnswer or None");
                match Py::new(python, PyDiameterAnswer::from_msg(no_route_answer())) {
                    Ok(handle) => handle,
                    Err(_) => {
                        return AnswerOutcome {
                            wire: no_route_answer().to_wire(),
                            request_py: Some(request_py),
                            answer_py: None,
                        }
                    }
                }
            }
        }
    };

    let wire = match answer_py.borrow(python).to_wire() {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%error, "DRA: failed to serialize answer");
            no_route_answer().to_wire()
        }
    };

    AnswerOutcome {
        wire,
        request_py: Some(request_py),
        answer_py: Some(answer_py),
    }
}

/// Minimal tree carrying just the header fields of a malformed inbound request,
/// so an error answer can echo its command/app/hbh/e2e.
fn stub_message(incoming: &IncomingRequest) -> DiameterMsg {
    DiameterMsg {
        flags: crate::diameter::codec::FLAG_REQUEST | crate::diameter::codec::FLAG_PROXIABLE,
        command_code: incoming.command_code,
        application_id: incoming.application_id,
        hop_by_hop: incoming.hop_by_hop,
        end_to_end: incoming.end_to_end,
        avps: vec![Avp::utf8(dictionary::avp::SESSION_ID, 0, "")],
    }
}
