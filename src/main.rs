use std::sync::Arc;

use clap::Parser;
use siphon::config::Config;
use siphon::dispatcher;
use siphon::hep::HepSender;
use siphon::gateway::DispatcherManager;
use siphon::script::engine::{ScriptEngine, spawn_file_watcher};
use siphon::transport;
use siphon::uac::UacSender;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "siphon", about = "SIPhon — high-performance SIP proxy, B2BUA and IMS platform")]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "siphon.yaml")]
    config: String,
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS operations
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = Arc::new(Config::from_file(&cli.config).unwrap_or_else(|error| {
        eprintln!("Failed to load {}: {error}", cli.config);
        std::process::exit(1);
    }));

    info!(
        "SIPhon starting — script: {}, domain: {:?}",
        config.script.path,
        config.domain.local
    );

    // --- Inject Rust singletons before script loads ---
    // The script does `from siphon import auth, registrar, log, rtpengine` at import time,
    // so the Rust-backed objects must be in place before the script executes.
    pyo3::Python::initialize();
    dispatcher::inject_python_singletons(&config);
    let pre_rtpengine = dispatcher::init_rtpengine(&config);

    // --- Restore registrar contacts from backend (if configured) ---
    init_registrar_backend(&config).await;

    // --- Gateway dispatcher (create manager + inject singleton before script loads) ---
    let gateway_manager = if let Some(ref gateway_config) = config.gateway {
        use siphon::gateway::{Algorithm, Destination, DispatcherGroup, ProbeConfig};

        let manager = Arc::new(DispatcherManager::new());

        for group_config in &gateway_config.groups {
            let algorithm = Algorithm::from_str(&group_config.algorithm)
                .unwrap_or_else(|| {
                    warn!(
                        algorithm = %group_config.algorithm,
                        group = %group_config.name,
                        "unknown algorithm, defaulting to weighted"
                    );
                    Algorithm::Weighted
                });

            let mut destinations = Vec::new();
            for dest_config in &group_config.destinations {
                let address = match dest_config.address.parse::<std::net::SocketAddr>() {
                    Ok(addr) => addr,
                    Err(parse_error) => {
                        error!(
                            address = %dest_config.address,
                            error = %parse_error,
                            "invalid gateway destination address, skipping"
                        );
                        continue;
                    }
                };
                let transport_type = match dest_config.transport.as_str() {
                    "tcp" => transport::Transport::Tcp,
                    "tls" => transport::Transport::Tls,
                    _ => transport::Transport::Udp,
                };
                destinations.push(
                    Destination::new(
                        dest_config.uri.clone(),
                        address,
                        transport_type,
                        dest_config.weight,
                        dest_config.priority,
                    )
                    .with_attrs(dest_config.attrs.clone()),
                );
            }

            let probe = ProbeConfig {
                enabled: group_config.probe.enabled,
                interval: std::time::Duration::from_secs(group_config.probe.interval_secs as u64),
                failure_threshold: group_config.probe.failure_threshold,
            };

            manager.add_group(
                DispatcherGroup::new(group_config.name.clone(), algorithm, destinations)
                    .with_probe_config(probe),
            );
        }

        // Inject gateway Python API before script loads
        pyo3::Python::attach(|python| {
            let py_gateway = siphon::script::api::gateway::PyGateway::new(Arc::clone(&manager));
            if let Err(error) = siphon::script::api::set_gateway_singleton(python, py_gateway) {
                error!("failed to store gateway singleton: {error}");
            } else {
                info!("gateway registered for injection");
            }
        });

        Some(manager)
    } else {
        None
    };

    // --- CDR singleton (inject before script loads; writer task spawned later) ---
    if config.cdr.is_some() {
        pyo3::Python::attach(|python| {
            let py_cdr = siphon::script::api::cdr::PyCdrNamespace::new();
            if let Err(error) = siphon::script::api::set_cdr_singleton(python, py_cdr) {
                error!("failed to store CDR singleton: {error}");
            } else {
                info!("CDR namespace registered for injection");
            }
        });
    }

    // --- Presence singleton (inject before script loads) ---
    let presence_store = Arc::new(siphon::presence::PresenceStore::new());
    pyo3::Python::attach(|python| {
        let py_presence = siphon::script::api::presence::PyPresence::new(Arc::clone(&presence_store));
        if let Err(error) = siphon::script::api::set_presence_singleton(python, py_presence) {
            error!("failed to store presence singleton: {error}");
        } else {
            info!("presence namespace registered for injection");
        }
    });

    // --- LI singleton (inject before script loads; tasks spawned later) ---
    let li_state: Option<(siphon::li::LiManager, tokio::sync::mpsc::Receiver<siphon::li::IriEvent>, tokio::sync::mpsc::Receiver<siphon::li::AuditEntry>)> =
        if let Some(ref li_config) = config.lawful_intercept {
            if li_config.enabled {
                let channel_size = li_config.x2.as_ref()
                    .map(|x2| x2.channel_size)
                    .unwrap_or(10_000);
                let (li_manager, iri_rx, audit_rx) =
                    siphon::li::LiManager::new(li_config.clone(), channel_size);

                // Inject Python singleton (LiManager is Clone)
                let py_li_manager = li_manager.clone();
                pyo3::Python::attach(|python| {
                    let py_li = siphon::script::api::li::PyLiNamespace::new(py_li_manager);
                    if let Err(error) = siphon::script::api::set_li_singleton(python, py_li) {
                        error!("failed to store LI singleton: {error}");
                    } else {
                        info!("lawful intercept namespace registered for injection");
                    }
                });

                Some((li_manager, iri_rx, audit_rx))
            } else {
                None
            }
        } else {
            None
        };

    // --- Diameter singleton (inject before script loads; peers connected later) ---
    let diameter_manager: Option<Arc<siphon::diameter::DiameterManager>> =
        if config.diameter.is_some() {
            let manager = Arc::new(siphon::diameter::DiameterManager::new());

            pyo3::Python::attach(|python| {
                let py_diameter = siphon::script::api::diameter::PyDiameter::new(Arc::clone(&manager));
                if let Err(error) = siphon::script::api::set_diameter_singleton(python, py_diameter) {
                    warn!("failed to set Diameter Python singleton: {error}");
                } else {
                    info!("Diameter namespace registered for injection");
                }
            });

            Some(manager)
        } else {
            None
        };

    // Wire Diameter manager into PyAuth for IMS digest (require_ims_digest)
    if let Some(ref manager) = diameter_manager {
        pyo3::Python::attach(|python| {
            siphon::script::api::wire_auth_diameter_manager(python, Arc::clone(manager));
            info!("Diameter manager wired into auth namespace for IMS digest");
        });
    }

    // --- Script engine ---
    let engine = Arc::new(
        ScriptEngine::new(&config.script).unwrap_or_else(|error| {
            eprintln!("Failed to load script: {error}");
            std::process::exit(1);
        }),
    );

    // Start file watcher for hot-reload
    spawn_file_watcher(Arc::clone(&engine));

    // --- Initialize metrics ---
    siphon::metrics::init();

    // --- Build transport ACL from security config ---
    let transport_acl = {
        use siphon::transport::acl::TransportAcl;

        if let Some(ref sec) = config.security {
            // Start APIBAN poller if configured
            let apiban_set = if let Some(ref apiban_config) = sec.apiban {
                let client = siphon::apiban::ApiBanClient::new(apiban_config);
                let banned = client.banned();
                client.start();
                info!("APIBAN blocklist poller started");
                Some(banned)
            } else {
                None
            };

            let acl = if let Some(banned) = apiban_set {
                TransportAcl::with_apiban(vec![], vec![], banned)
            } else {
                TransportAcl::new(vec![], vec![])
            };
            Arc::new(acl)
        } else {
            Arc::new(TransportAcl::new(vec![], vec![]))
        }
    };

    // --- Transport channels ---
    // Single inbound channel: all transports → dispatcher.
    // Per-transport outbound channels: dispatcher routes by transport type.
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (udp_outbound_tx, udp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
    let (tcp_outbound_tx, tcp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
    let (tls_outbound_tx, tls_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
    let (ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
    let (wss_outbound_tx, wss_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
    let (sctp_outbound_tx, sctp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();

    // Build a routing map: Transport → sender
    let outbound_senders = Arc::new(transport::OutboundRouter {
        udp: udp_outbound_tx,
        tcp: tcp_outbound_tx,
        tls: tls_outbound_tx,
        ws: ws_outbound_tx,
        wss: wss_outbound_tx,
        sctp: sctp_outbound_tx,
    });

    // --- Start UDP listeners ---
    let mut first_listen_addr: Option<std::net::SocketAddr> = None;
    let mut listen_addrs = std::collections::HashMap::new();
    for addr_str in &config.listen.udp {
        let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
            eprintln!("Invalid UDP listen address '{addr_str}': {error}");
            std::process::exit(1);
        });
        if first_listen_addr.is_none() {
            first_listen_addr = Some(addr);
        }
        listen_addrs.entry(transport::Transport::Udp).or_insert(addr);
        info!(addr = %addr, "starting UDP transport");
        transport::udp::listen(addr, inbound_tx.clone(), udp_outbound_rx.clone(), Arc::clone(&transport_acl)).await;
    }

    // --- Start TCP listeners ---
    let tcp_connection_map = Arc::new(dashmap::DashMap::new());
    for addr_str in &config.listen.tcp {
        let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
            eprintln!("Invalid TCP listen address '{addr_str}': {error}");
            std::process::exit(1);
        });
        if first_listen_addr.is_none() {
            first_listen_addr = Some(addr);
        }
        listen_addrs.entry(transport::Transport::Tcp).or_insert(addr);
        info!(addr = %addr, "starting TCP transport");
        transport::tcp::listen(addr, inbound_tx.clone(), tcp_outbound_rx.clone(), Arc::clone(&tcp_connection_map), Arc::clone(&transport_acl)).await;
    }

    // --- Start TLS listeners ---
    let tls_addr_map: Arc<dashmap::DashMap<std::net::SocketAddr, transport::ConnectionId>> =
        Arc::new(dashmap::DashMap::new());
    if let Some(ref tls_config) = config.tls {
        let tls_connection_map = Arc::new(dashmap::DashMap::new());
        for addr_str in &config.listen.tls {
            let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
                eprintln!("Invalid TLS listen address '{addr_str}': {error}");
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Tls).or_insert(addr);
            info!(addr = %addr, "starting TLS transport");
            transport::tls::listen(addr, tls_config, inbound_tx.clone(), tls_outbound_rx.clone(), Arc::clone(&tls_connection_map), Arc::clone(&transport_acl), Arc::clone(&tls_addr_map)).await;
        }
    }

    // --- Start WebSocket listeners ---
    let ws_connection_map = Arc::new(dashmap::DashMap::new());
    for addr_str in &config.listen.ws {
        let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
            eprintln!("Invalid WS listen address '{addr_str}': {error}");
            std::process::exit(1);
        });
        if first_listen_addr.is_none() {
            first_listen_addr = Some(addr);
        }
        listen_addrs.entry(transport::Transport::WebSocket).or_insert(addr);
        info!(addr = %addr, "starting WS transport");
        transport::ws::listen(addr, inbound_tx.clone(), ws_outbound_rx.clone(), Arc::clone(&ws_connection_map), Arc::clone(&transport_acl)).await;
    }

    // --- Start WSS listeners ---
    if let Some(ref tls_config) = config.tls {
        let wss_connection_map = Arc::new(dashmap::DashMap::new());
        for addr_str in &config.listen.wss {
            let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
                eprintln!("Invalid WSS listen address '{addr_str}': {error}");
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::WebSocketSecure).or_insert(addr);
            info!(addr = %addr, "starting WSS transport");
            transport::ws::listen_secure(addr, tls_config, inbound_tx.clone(), wss_outbound_rx.clone(), Arc::clone(&wss_connection_map), Arc::clone(&transport_acl)).await;
        }
    }

    // --- Start SCTP listeners ---
    let sctp_connection_map = Arc::new(dashmap::DashMap::new());
    for addr_str in &config.listen.sctp {
        let addr: std::net::SocketAddr = addr_str.parse().unwrap_or_else(|error| {
            eprintln!("Invalid SCTP listen address '{addr_str}': {error}");
            std::process::exit(1);
        });
        if first_listen_addr.is_none() {
            first_listen_addr = Some(addr);
        }
        listen_addrs.entry(transport::Transport::Sctp).or_insert(addr);
        info!(addr = %addr, "starting SCTP transport");
        transport::sctp::listen(addr, inbound_tx.clone(), sctp_outbound_rx.clone(), Arc::clone(&sctp_connection_map), Arc::clone(&transport_acl)).await;
    }

    let local_addr = first_listen_addr.unwrap_or_else(|| {
        eprintln!("No listen addresses configured");
        std::process::exit(1);
    });

    // --- Create outbound TCP connection pool ---
    let connection_pool = Arc::new(transport::pool::ConnectionPool::new(
        Arc::clone(&tcp_connection_map),
        inbound_tx.clone(),
        local_addr,
    ));

    // Drop our copy of senders — workers hold their own clones
    drop(inbound_tx);

    // --- Initialize HEP capture (if configured) ---
    let hep_sender = if let Some(ref tracing_config) = config.tracing {
        if let Some(ref hep_config) = tracing_config.hep {
            match HepSender::new(hep_config).await {
                Ok(sender) => Some(Arc::new(sender)),
                Err(error) => {
                    warn!("HEP capture disabled: {error}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // --- Prometheus metrics endpoint (if configured) ---
    if let Some(ref metrics_config) = config.metrics {
        if let Some(ref prom_config) = metrics_config.prometheus {
            let listen_addr: std::net::SocketAddr = prom_config.listen.parse().unwrap_or_else(|error| {
                eprintln!("Invalid metrics listen address '{}': {error}", prom_config.listen);
                std::process::exit(1);
            });
            let path = prom_config.path.clone();
            tokio::spawn(async move {
                use axum::{routing::get, Router};
                let app = Router::new().route(&path, get(|| async {
                    siphon::metrics::encode_metrics()
                }));
                info!(addr = %listen_addr, path = %path, "Prometheus metrics endpoint started");
                if let Err(error) = axum::serve(
                    tokio::net::TcpListener::bind(listen_addr).await.unwrap(),
                    app,
                ).await {
                    error!("metrics HTTP server failed: {error}");
                }
            });
        }
    }

    // --- UAC sender (for keepalive & health probes) ---
    let uac_sender = Arc::new(UacSender::new(Arc::clone(&outbound_senders), local_addr));

    // Wire UAC sender into proxy.send_request() Python API
    {
        let dns_resolver = Arc::new(
            siphon::dns::SipResolver::from_system()
                .expect("failed to initialize DNS resolver for proxy.send_request()"),
        );
        siphon::script::api::proxy_utils::set_uac_sender(
            Arc::clone(&uac_sender),
            dns_resolver,
        );
    }

    // --- Gateway health probers (manager was created earlier, before script load) ---
    if let Some(ref manager) = gateway_manager {
        siphon::gateway::spawn_health_probers(
            Arc::clone(manager),
            Arc::clone(&uac_sender),
        );
    }

    // --- CDR writer (if configured; singleton was injected earlier) ---
    if let Some(ref cdr_yaml) = config.cdr {
        let cdr_config = cdr_yaml.to_cdr_config();
        if let Some(receiver) = siphon::cdr::init(&cdr_config) {
            let writer_config = cdr_config.clone();
            tokio::spawn(siphon::cdr::writer_task(receiver, writer_config));
            info!("CDR writer started (backend: {})", cdr_yaml.backend);
        }
    }

    // --- Diameter peers (connect to peers; manager + singleton were created earlier) ---
    if let Some(ref diameter_config) = config.diameter {
        if let Some(ref manager) = diameter_manager {
            for peer_entry in &diameter_config.peers {
                let peer_config = diameter_config.to_peer_config(peer_entry);
                match siphon::diameter::peer::connect(peer_config).await {
                    Ok((peer, _incoming_rx)) => {
                        let client = Arc::new(siphon::diameter::DiameterClient::new(peer));
                        manager.register(peer_entry.name.clone(), client);
                        info!(peer = %peer_entry.name, "Diameter peer connected");
                    }
                    Err(error) => {
                        warn!(peer = %peer_entry.name, %error, "failed to connect Diameter peer");
                    }
                }
            }
        }
    }

    // --- Outbound registration (if configured) ---
    let registrant_manager: Option<Arc<siphon::registrant::RegistrantManager>> =
        if let Some(ref registrant_config) = config.registrant {
            use siphon::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager};

            let manager = Arc::new(RegistrantManager::new(
                registrant_config.default_interval,
                std::time::Duration::from_secs(registrant_config.retry_interval),
                std::time::Duration::from_secs(registrant_config.max_retry_interval),
            ));

            for entry_config in &registrant_config.entries {
                let registrar_host = entry_config.registrar
                    .strip_prefix("sip:")
                    .or_else(|| entry_config.registrar.strip_prefix("sips:"))
                    .unwrap_or(&entry_config.registrar);

                let destination: std::net::SocketAddr = registrar_host
                    .parse()
                    .unwrap_or_else(|_| {
                        format!("{registrar_host}:5060")
                            .parse()
                            .unwrap_or_else(|_| "0.0.0.0:5060".parse().unwrap())
                    });

                let transport_type = match entry_config.transport.as_str() {
                    "tcp" => transport::Transport::Tcp,
                    "tls" => transport::Transport::Tls,
                    _ => transport::Transport::Udp,
                };

                let entry = RegistrantEntry::new(
                    entry_config.aor.clone(),
                    entry_config.registrar.clone(),
                    destination,
                    transport_type,
                    RegistrantCredentials {
                        username: entry_config.user.clone(),
                        password: entry_config.password.clone(),
                        realm: entry_config.realm.clone(),
                    },
                    entry_config.interval.unwrap_or(registrant_config.default_interval),
                    entry_config.contact.clone(),
                );
                manager.add(entry);
            }

            info!(
                count = registrant_config.entries.len(),
                "outbound registrations configured"
            );

            // Spawn background registration loop
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let loop_manager = Arc::clone(&manager);
            let loop_outbound = Arc::clone(&outbound_senders);
            tokio::spawn(async move {
                siphon::registrant::registration_loop(
                    loop_manager,
                    loop_outbound,
                    local_addr,
                    shutdown_rx,
                ).await;
            });

            // Store shutdown sender so we can signal de-registration on Ctrl+C
            // (For now it will be dropped when main exits, which also triggers shutdown.)
            let _ = shutdown_tx;

            // Inject registration Python API
            let py_manager = Arc::clone(&manager);
            pyo3::Python::attach(|python| {
                let py_registration = siphon::script::api::registrant::PyRegistration::new(
                    py_manager,
                    local_addr,
                );
                if let Err(error) = siphon::script::api::set_registration_singleton(python, py_registration) {
                    error!("failed to store registration singleton: {error}");
                } else {
                    info!("registration namespace registered for injection");
                }
            });

            Some(manager)
        } else {
            None
        };

    // --- LI tasks (manager + singleton were created earlier; spawn async tasks now) ---
    if let Some((_li_manager, iri_rx, audit_rx)) = li_state {
        let li_config = config.lawful_intercept.as_ref().unwrap();

        // Spawn X2 IRI delivery task if configured
        if let Some(ref x2_config) = li_config.x2 {
            let x2_arc = std::sync::Arc::new(x2_config.clone());
            tokio::spawn(siphon::li::x2::delivery_task(iri_rx, x2_arc));
            info!("X2 IRI delivery task started");
        } else {
            // Drain the channel so senders don't block
            tokio::spawn(async move {
                let mut receiver = iri_rx;
                while receiver.recv().await.is_some() {}
            });
        }

        // Spawn X3 media capture task if configured
        if let Some(ref x3_config) = li_config.x3 {
            match siphon::li::x3::X3Manager::new(x3_config) {
                Ok(x3_manager) => {
                    let listen_address = x3_config.listen_udp.clone();
                    tokio::spawn(async move {
                        if let Err(error) = siphon::li::x3::receive_and_forward_task(
                            &listen_address, x3_manager,
                        ).await {
                            error!("X3 receive task failed: {error}");
                        }
                    });
                    info!("X3 media capture task started");
                }
                Err(error) => {
                    error!("failed to create X3 manager: {error}");
                }
            }
        }

        // Spawn audit log writer task
        let audit_log_path = li_config.audit_log.clone();
        tokio::spawn(async move {
            let mut receiver = audit_rx;
            let mut file = if let Some(ref path) = audit_log_path {
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                {
                    Ok(file) => Some(file),
                    Err(error) => {
                        error!("failed to open LI audit log {path}: {error}");
                        None
                    }
                }
            } else {
                None
            };

            use tokio::io::AsyncWriteExt;
            while let Some(entry) = receiver.recv().await {
                if let Some(ref mut file) = file {
                    let line = format!(
                        "{:?} {:?} liid={} {}\n",
                        entry.timestamp,
                        entry.operation,
                        entry.liid.as_deref().unwrap_or("-"),
                        entry.detail,
                    );
                    let _ = file.write_all(line.as_bytes()).await;
                }
            }
        });
    }

    // --- IPsec SA manager (if configured) ---
    let ipsec_manager = if config.ipsec.is_some() {
        let manager = Arc::new(siphon::ipsec::IpsecManager::new());
        info!(
            active = manager.active_count(),
            "IPsec SA manager initialized (SAs created on REGISTER)"
        );
        Some(manager)
    } else {
        None
    };

    // --- iFC evaluation engine (if configured) ---
    if let Some(ref isc_config) = config.isc {
        let xml = if let Some(ref path) = isc_config.ifc_xml_path {
            match std::fs::read_to_string(path) {
                Ok(contents) => Some(contents),
                Err(error) => {
                    error!("failed to read iFC XML from {path}: {error}");
                    None
                }
            }
        } else {
            isc_config.ifc_xml.clone()
        };

        if let Some(xml) = xml {
            match siphon::ifc::parse_service_profile(&xml) {
                Ok(ifcs) => {
                    info!(count = ifcs.len(), "iFC rules loaded");
                }
                Err(error) => {
                    error!("failed to parse iFC XML: {error}");
                }
            }
        }
    }

    // --- SBI client (if configured) ---
    if let Some(ref sbi_config) = config.sbi {
        let sbi_internal_config = sbi_config.to_sbi_config();
        let _sbi_manager = siphon::sbi::SbiManager::new(sbi_internal_config);
        info!("SBI client initialized");
        if let Some(ref nrf_url) = sbi_config.nrf_url {
            info!(nrf_url = %nrf_url, "NRF discovery endpoint configured");
        }
    }

    // --- NAT keepalive (if configured) ---
    if let Some(ref nat_config) = config.nat {
        if let Some(ref keepalive_config) = nat_config.keepalive {
            // Get the registrar from inject_python_singletons — it was already created.
            // For keepalive we need a separate Registrar reference. We'll create one
            // from config (it's a lightweight DashMap wrapper).
            let registrar_config = siphon::registrar::RegistrarConfig {
                default_expires: config.registrar.default_expires,
                max_expires: config.registrar.max_expires,
                min_expires: config.registrar.min_expires.unwrap_or(60),
                max_contacts: config.registrar.max_contacts.unwrap_or(10) as usize,
            };
            let registrar = Arc::new(siphon::registrar::Registrar::new(registrar_config));
            siphon::nat::spawn_keepalive(
                keepalive_config.clone(),
                registrar,
                Arc::clone(&uac_sender),
            );
        }
    }

    // --- Start dispatcher ---
    let dispatcher_handle = tokio::spawn(dispatcher::run(
        inbound_rx,
        outbound_senders,
        Arc::clone(&engine),
        Arc::clone(&config),
        local_addr,
        listen_addrs,
        hep_sender,
        uac_sender,
        connection_pool,
        pre_rtpengine,
        registrant_manager,
        ipsec_manager,
        config.ipsec.clone(),
        tls_addr_map,
    ));

    info!("SIPhon ready — press Ctrl+C to stop");

    // Wait for shutdown signal (SIGINT or SIGTERM)
    siphon::shutdown::wait_for_signal().await;

    info!("shutting down...");

    // Abort the dispatcher (stops accepting new SIP messages).
    dispatcher_handle.abort();
    let _ = dispatcher_handle.await;

    // The tokio runtime has many background tasks (transport workers, timers,
    // file watchers, etc.) that have no shutdown signal yet.  Rather than
    // hanging while the runtime waits for them, exit the process immediately.
    std::process::exit(0);
}

/// Create the registrar backend (Redis/Postgres), restore persisted contacts
/// into the in-memory registrar, and set up write-through persistence.
async fn init_registrar_backend(config: &Config) {
    use siphon::config::RegistrarBackendType;
    use siphon::registrar::backend;
    use siphon::script::api::registrar_arc;

    let registrar = match registrar_arc() {
        Some(r) => r,
        None => return,
    };

    match config.registrar.backend {
        RegistrarBackendType::Redis => {
            let redis_config = match &config.registrar.redis {
                Some(cfg) => backend::RedisBackendConfig {
                    url: cfg.url.clone(),
                    urls: Vec::new(),
                    key_prefix: cfg.key_prefix.clone(),
                    shard_count: 0,
                    ttl_slack_secs: cfg.ttl_slack_secs as u64,
                },
                None => {
                    error!("registrar backend is redis but no redis config provided");
                    return;
                }
            };
            match backend::RedisBackend::connect(redis_config).await {
                Ok(redis_backend) => {
                    match backend::restore_from_backend(&redis_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            info!(aors, contacts, "restored contacts from Redis backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Redis backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(redis_backend));
                }
                Err(err) => {
                    error!(%err, "failed to connect to Redis registrar backend");
                }
            }
        }
        RegistrarBackendType::Postgres => {
            let pg_config = match &config.registrar.postgres {
                Some(cfg) => backend::PostgresBackendConfig {
                    url: cfg.url.clone(),
                    urls: Vec::new(),
                    table: cfg.table.clone(),
                    shard_count: 0,
                },
                None => {
                    error!("registrar backend is postgres but no postgres config provided");
                    return;
                }
            };
            match backend::PostgresBackend::connect(pg_config).await {
                Ok(pg_backend) => {
                    match backend::restore_from_backend(&pg_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            info!(aors, contacts, "restored contacts from Postgres backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Postgres backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(pg_backend));
                }
                Err(err) => {
                    error!(%err, "failed to connect to Postgres registrar backend");
                }
            }
        }
        RegistrarBackendType::Memory | RegistrarBackendType::Python => {
            // No persistence backend — nothing to restore.
        }
    }
}
