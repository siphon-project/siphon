//! `SiphonServer` — public builder API for embedding siphon as a library.
//!
//! Consumers create their own `main()`, optionally embed a Python script
//! with `include_str!()`, and call `SiphonServer::builder().run()`.

use std::sync::Arc;

use tracing::{error, info, warn};

use crate::config::Config;
use crate::hep::HepSender;
use crate::gateway::DispatcherManager;
use crate::script::engine::{ScriptEngine, spawn_file_watcher};
use crate::transport;
use crate::uac::UacSender;
use crate::{dispatcher, shutdown};

/// Builder for running a siphon server instance.
///
/// # Examples
///
/// ```rust,no_run
/// use siphon::SiphonServer;
///
/// SiphonServer::builder()
///     .config_path("siphon.yaml")
///     .embedded_script(include_str!("../scripts/proxy_default.py"))
///     .run();
/// ```
pub struct SiphonServer {
    config_path: Option<String>,
    config_string: Option<String>,
    embedded_script: Option<&'static str>,
}

impl SiphonServer {
    /// Create a new builder with no configuration set.
    pub fn builder() -> Self {
        Self {
            config_path: None,
            config_string: None,
            embedded_script: None,
        }
    }

    /// Set the path to the YAML configuration file.
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_owned());
        self
    }

    /// Provide the YAML configuration as an in-memory string.
    /// This takes priority over `config_path`.
    pub fn config_string(mut self, yaml: &str) -> Self {
        self.config_string = Some(yaml.to_owned());
        self
    }

    /// Embed a Python script source into the binary.
    /// When set, the script is loaded from this string instead of from disk.
    /// Hot-reload is automatically disabled for embedded scripts.
    pub fn embedded_script(mut self, source: &'static str) -> Self {
        self.embedded_script = Some(source);
        self
    }

    /// Run the siphon server. This blocks until shutdown (SIGINT/SIGTERM).
    ///
    /// Creates its own tokio runtime, so callers do not need `#[tokio::main]`.
    pub fn run(self) {
        // Install rustls crypto provider before any TLS operations
        if tokio_rustls::rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            eprintln!("Failed to install rustls CryptoProvider");
            std::process::exit(1);
        }

        let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|error| {
            eprintln!("Failed to create tokio runtime: {error}");
            std::process::exit(1);
        });

        runtime.block_on(self.run_async());
    }

    /// Async entry point — all the real work happens here.
    async fn run_async(self) {
        // --- Load configuration ---
        let config = if let Some(ref yaml) = self.config_string {
            Arc::new(Config::from_str(yaml).unwrap_or_else(|error| {
                eprintln!("Failed to parse config: {error}");
                std::process::exit(1);
            }))
        } else {
            let path = self.config_path.as_deref().unwrap_or("siphon.yaml");
            Arc::new(Config::from_file(path).unwrap_or_else(|error| {
                eprintln!("Failed to load {path}: {error}");
                std::process::exit(1);
            }))
        };

        // --- Initialise structured logging ---
        let _log_guard = init_logging(&config.log);

        let script_desc = if self.embedded_script.is_some() {
            "<embedded>".to_owned()
        } else {
            config.script.path.clone()
        };

        info!(
            "SIPhon v{} starting — script: {}, domain: {:?}",
            env!("CARGO_PKG_VERSION"),
            script_desc,
            config.domain.local
        );

        // --- Inject Rust singletons before script loads ---
        pyo3::Python::initialize();
        dispatcher::inject_python_singletons(&config);
        let pre_rtpengine = dispatcher::init_rtpengine(&config);

        // --- Restore registrar contacts from backend (if configured) ---
        init_registrar_backend(&config).await;

        // --- Gateway dispatcher ---
        let gateway_manager = init_gateway(&config);

        // --- CDR singleton ---
        if config.cdr.is_some() {
            pyo3::Python::attach(|python| {
                let py_cdr = crate::script::api::cdr::PyCdrNamespace::new();
                if let Err(error) = crate::script::api::set_cdr_singleton(python, py_cdr) {
                    error!("failed to store CDR singleton: {error}");
                } else {
                    info!("CDR namespace registered for injection");
                }
            });
        }

        // --- Presence singleton ---
        let presence_store = Arc::new(crate::presence::PresenceStore::new());
        pyo3::Python::attach(|python| {
            let py_presence = crate::script::api::presence::PyPresence::new(Arc::clone(&presence_store));
            if let Err(error) = crate::script::api::set_presence_singleton(python, py_presence) {
                error!("failed to store presence singleton: {error}");
            } else {
                info!("presence namespace registered for injection");
            }
        });

        // --- LI singleton ---
        let li_state = init_li(&config);

        // --- Diameter singleton ---
        let diameter_manager = init_diameter(&config);

        // Wire Diameter manager into PyAuth for IMS digest
        if let Some(ref manager) = diameter_manager {
            pyo3::Python::attach(|python| {
                crate::script::api::wire_auth_diameter_manager(python, Arc::clone(manager));
                info!("Diameter manager wired into auth namespace for IMS digest");
            });
        }

        // --- Script engine ---
        let engine = if let Some(source) = self.embedded_script {
            Arc::new(ScriptEngine::new_embedded(source).unwrap_or_else(|error| {
                eprintln!("Failed to load embedded script: {error}");
                std::process::exit(1);
            }))
        } else {
            Arc::new(ScriptEngine::new(&config.script).unwrap_or_else(|error| {
                eprintln!("Failed to load script: {error}");
                std::process::exit(1);
            }))
        };

        // Start file watcher for hot-reload (no-op for embedded scripts)
        spawn_file_watcher(Arc::clone(&engine));

        // Start any @timer.every() handlers registered in the script.
        engine.restart_timers();

        // --- Initialize metrics ---
        if let Err(error) = crate::metrics::init() {
            error!("Failed to initialize metrics: {error}");
        }

        // --- Build transport ACL ---
        let transport_acl = build_transport_acl(&config);

        // --- Transport channels ---
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (udp_outbound_tx, udp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (tcp_outbound_tx, tcp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (tls_outbound_tx, tls_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (wss_outbound_tx, wss_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (sctp_outbound_tx, sctp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();

        let outbound_senders = Arc::new(transport::OutboundRouter {
            udp: udp_outbound_tx,
            tcp: tcp_outbound_tx,
            tls: tls_outbound_tx,
            ws: ws_outbound_tx,
            wss: wss_outbound_tx,
            sctp: sctp_outbound_tx,
        });

        // --- Start transport listeners ---
        let mut first_listen_addr: Option<std::net::SocketAddr> = None;
        let mut listen_addrs = std::collections::HashMap::new();
        let mut advertised_addrs: std::collections::HashMap<transport::Transport, String> = std::collections::HashMap::new();

        // UDP
        for entry in &config.listen.udp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid UDP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Udp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Udp).or_insert_with(|| adv.to_string());
            }
            info!(addr = %addr, "starting UDP transport");
            transport::udp::listen(addr, inbound_tx.clone(), udp_outbound_rx.clone(), Arc::clone(&transport_acl)).await;
        }

        // TCP
        let tcp_connection_map = Arc::new(dashmap::DashMap::new());
        for entry in &config.listen.tcp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid TCP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Tcp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Tcp).or_insert_with(|| adv.to_string());
            }
            info!(addr = %addr, "starting TCP transport");
            transport::tcp::listen(addr, inbound_tx.clone(), tcp_outbound_rx.clone(), Arc::clone(&tcp_connection_map), Arc::clone(&transport_acl)).await;
        }

        // TLS
        let tls_addr_map: Arc<dashmap::DashMap<std::net::SocketAddr, transport::ConnectionId>> =
            Arc::new(dashmap::DashMap::new());
        let tls_connection_map: Arc<dashmap::DashMap<transport::ConnectionId, tokio::sync::mpsc::Sender<bytes::Bytes>>> =
            Arc::new(dashmap::DashMap::new());
        if let Some(ref tls_config) = config.tls {
            for entry in &config.listen.tls {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid TLS listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs.entry(transport::Transport::Tls).or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs.entry(transport::Transport::Tls).or_insert_with(|| adv.to_string());
                }
                info!(addr = %addr, "starting TLS transport");
                transport::tls::listen(addr, tls_config, inbound_tx.clone(), tls_outbound_rx.clone(), Arc::clone(&tls_connection_map), Arc::clone(&transport_acl), Arc::clone(&tls_addr_map)).await;
            }
        }

        // WebSocket
        let ws_connection_map = Arc::new(dashmap::DashMap::new());
        for entry in &config.listen.ws {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid WS listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::WebSocket).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::WebSocket).or_insert_with(|| adv.to_string());
            }
            info!(addr = %addr, "starting WS transport");
            transport::ws::listen(addr, inbound_tx.clone(), ws_outbound_rx.clone(), Arc::clone(&ws_connection_map), Arc::clone(&transport_acl)).await;
        }

        // WSS
        if let Some(ref tls_config) = config.tls {
            let wss_connection_map = Arc::new(dashmap::DashMap::new());
            for entry in &config.listen.wss {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid WSS listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs.entry(transport::Transport::WebSocketSecure).or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs.entry(transport::Transport::WebSocketSecure).or_insert_with(|| adv.to_string());
                }
                info!(addr = %addr, "starting WSS transport");
                transport::ws::listen_secure(addr, tls_config, inbound_tx.clone(), wss_outbound_rx.clone(), Arc::clone(&wss_connection_map), Arc::clone(&transport_acl)).await;
            }
        }

        // SCTP
        let sctp_connection_map = Arc::new(dashmap::DashMap::new());
        for entry in &config.listen.sctp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid SCTP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Sctp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Sctp).or_insert_with(|| adv.to_string());
            }
            info!(addr = %addr, "starting SCTP transport");
            transport::sctp::listen(addr, inbound_tx.clone(), sctp_outbound_rx.clone(), Arc::clone(&sctp_connection_map), Arc::clone(&transport_acl)).await;
        }

        let local_addr = first_listen_addr.unwrap_or_else(|| {
            eprintln!("No listen addresses configured");
            std::process::exit(1);
        });

        // --- Connection pool ---
        let connection_pool = Arc::new(transport::pool::ConnectionPool::new(
            Arc::clone(&tcp_connection_map),
            inbound_tx.clone(),
            local_addr,
        ));

        drop(inbound_tx);

        // --- HEP capture ---
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

        // --- Prometheus metrics endpoint ---
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
                        crate::metrics::encode_metrics()
                    }));
                    info!(addr = %listen_addr, path = %path, "Prometheus metrics endpoint started");
                    match tokio::net::TcpListener::bind(listen_addr).await {
                        Ok(listener) => {
                            if let Err(error) = axum::serve(listener, app).await {
                                error!("metrics HTTP server failed: {error}");
                            }
                        }
                        Err(error) => {
                            error!(addr = %listen_addr, "failed to bind metrics listener: {error}");
                        }
                    }
                });
            }
        }

        // --- UAC sender ---
        let uac_sender = Arc::new(UacSender::new(Arc::clone(&outbound_senders), local_addr));

        // Wire UAC sender into proxy.send_request() Python API
        {
            let dns_resolver = Arc::new(match crate::dns::SipResolver::from_system() {
                Ok(resolver) => resolver,
                Err(error) => {
                    error!("failed to initialize DNS resolver for proxy.send_request(): {error}");
                    std::process::exit(1);
                }
            });
            crate::script::api::proxy_utils::set_uac_sender(
                Arc::clone(&uac_sender),
                dns_resolver,
            );
        }

        // --- Gateway health probers ---
        if let Some(ref manager) = gateway_manager {
            crate::gateway::spawn_health_probers(
                Arc::clone(manager),
                Arc::clone(&uac_sender),
            );
        }

        // --- CDR writer ---
        if let Some(ref cdr_yaml) = config.cdr {
            let cdr_config = cdr_yaml.to_cdr_config();
            if let Some(receiver) = crate::cdr::init(&cdr_config) {
                let writer_config = cdr_config.clone();
                tokio::spawn(crate::cdr::writer_task(receiver, writer_config));
                info!("CDR writer started (backend: {})", cdr_yaml.backend);
            }
        }

        // --- Diameter peers ---
        if let Some(ref diameter_config) = config.diameter {
            if let Some(ref manager) = diameter_manager {
                for peer_entry in &diameter_config.peers {
                    let peer_config = diameter_config.to_peer_config(peer_entry);
                    match crate::diameter::peer::connect(peer_config).await {
                        Ok((peer, _incoming_rx)) => {
                            let client = Arc::new(crate::diameter::DiameterClient::new(peer));
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

        // --- Outbound registration ---
        let registrant_manager = init_registrant(&config, &outbound_senders, local_addr);

        // --- LI tasks ---
        spawn_li_tasks(li_state, &config);

        // --- IPsec SA manager ---
        let ipsec_manager = if config.ipsec.is_some() {
            let manager = Arc::new(crate::ipsec::IpsecManager::new());
            info!(
                active = manager.active_count(),
                "IPsec SA manager initialized (SAs created on REGISTER)"
            );
            Some(manager)
        } else {
            None
        };

        // --- iFC evaluation engine ---
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
                match crate::ifc::parse_service_profile(&xml) {
                    Ok(ifcs) => {
                        info!(count = ifcs.len(), "iFC rules loaded");
                    }
                    Err(error) => {
                        error!("failed to parse iFC XML: {error}");
                    }
                }
            }
        }

        // --- SBI client ---
        if let Some(ref sbi_config) = config.sbi {
            let sbi_internal_config = sbi_config.to_sbi_config();
            let _sbi_manager = crate::sbi::SbiManager::new(sbi_internal_config);
            info!("SBI client initialized");
            if let Some(ref nrf_url) = sbi_config.nrf_url {
                info!(nrf_url = %nrf_url, "NRF discovery endpoint configured");
            }
        }

        // --- NAT keepalive ---
        if let Some(ref nat_config) = config.nat {
            if let Some(ref keepalive_config) = nat_config.keepalive {
                if let Some(registrar) = crate::script::api::registrar_arc() {
                    crate::nat::spawn_keepalive(
                        keepalive_config.clone(),
                        Arc::clone(registrar),
                        Arc::clone(&uac_sender),
                    );
                }
            }
        }

        // --- CRLF keepalive ---
        let crlf_pong_tracker = if let Some(ref nat_config) = config.nat {
            if let Some(ref crlf_config) = nat_config.crlf_keepalive {
                let tracker = Arc::new(transport::crlf_keepalive::CrlfPongTracker::new());
                transport::crlf_keepalive::spawn(
                    crlf_config.clone(),
                    vec![
                        Arc::clone(&tcp_connection_map),
                        Arc::clone(&tls_connection_map),
                    ],
                    Arc::clone(&tracker),
                );
                Some(tracker)
            } else {
                None
            }
        } else {
            None
        };

        // Subscribe to registrar events
        let registrar_event_rx = crate::script::api::registrar_arc()
            .map(|r| r.subscribe_events());

        // --- Start dispatcher ---
        let dispatcher_handle = tokio::spawn(dispatcher::run(
            inbound_rx,
            outbound_senders,
            Arc::clone(&engine),
            Arc::clone(&config),
            local_addr,
            listen_addrs,
            advertised_addrs,
            hep_sender,
            uac_sender,
            connection_pool,
            pre_rtpengine,
            registrant_manager,
            ipsec_manager,
            config.ipsec.clone(),
            tls_addr_map,
            crlf_pong_tracker,
            registrar_event_rx,
        ));

        // Evict connection-oriented contacts restored from the backend
        if let Some(registrar) = crate::script::api::registrar_arc() {
            let evicted = registrar.evict_connection_oriented();
            if evicted > 0 {
                info!(evicted, "evicted connection-oriented contacts after restart");
            }
        }

        info!("SIPhon ready — press Ctrl+C to stop");

        // Wait for shutdown signal (SIGINT or SIGTERM)
        shutdown::wait_for_signal().await;

        info!("shutting down...");

        dispatcher_handle.abort();
        let _ = dispatcher_handle.await;

        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------
// Helper functions extracted from main.rs
// ---------------------------------------------------------------------------

fn init_logging(
    log_config: &crate::config::LogConfig,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use crate::config::{LogFormat, LogLevel};
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let level = match log_config.level {
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            };
            tracing_subscriber::EnvFilter::new(level)
        });

    let is_json = log_config.format == LogFormat::Json;

    let console_layer = if is_json {
        tracing_subscriber::fmt::layer()
            .json()
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .boxed()
    };

    let (file_layer, guard) = if let Some(ref path) = log_config.file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|error| {
                eprintln!("Failed to open log file {path}: {error}");
                std::process::exit(1);
            });
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let layer = if is_json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        };

        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}

async fn init_registrar_backend(config: &Config) {
    use crate::config::RegistrarBackendType;
    use crate::registrar::backend;
    use crate::script::api::registrar_arc;

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
        RegistrarBackendType::Memory | RegistrarBackendType::Python => {}
    }
}

fn init_gateway(config: &Config) -> Option<Arc<DispatcherManager>> {
    use crate::gateway::{Algorithm, Destination, DispatcherGroup, ProbeConfig};

    let gateway_config = config.gateway.as_ref()?;

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
        let py_gateway = crate::script::api::gateway::PyGateway::new(Arc::clone(&manager));
        if let Err(error) = crate::script::api::set_gateway_singleton(python, py_gateway) {
            error!("failed to store gateway singleton: {error}");
        } else {
            info!("gateway registered for injection");
        }
    });

    Some(manager)
}

type LiState = (
    crate::li::LiManager,
    tokio::sync::mpsc::Receiver<crate::li::IriEvent>,
    tokio::sync::mpsc::Receiver<crate::li::AuditEntry>,
);

fn init_li(config: &Config) -> Option<LiState> {
    let li_config = config.lawful_intercept.as_ref()?;
    if !li_config.enabled {
        return None;
    }

    let channel_size = li_config.x2.as_ref()
        .map(|x2| x2.channel_size)
        .unwrap_or(10_000);
    let (li_manager, iri_rx, audit_rx) =
        crate::li::LiManager::new(li_config.clone(), channel_size);

    let py_li_manager = li_manager.clone();
    pyo3::Python::attach(|python| {
        let py_li = crate::script::api::li::PyLiNamespace::new(py_li_manager);
        if let Err(error) = crate::script::api::set_li_singleton(python, py_li) {
            error!("failed to store LI singleton: {error}");
        } else {
            info!("lawful intercept namespace registered for injection");
        }
    });

    Some((li_manager, iri_rx, audit_rx))
}

fn init_diameter(config: &Config) -> Option<Arc<crate::diameter::DiameterManager>> {
    config.diameter.as_ref()?;

    let manager = Arc::new(crate::diameter::DiameterManager::new());

    pyo3::Python::attach(|python| {
        let py_diameter = crate::script::api::diameter::PyDiameter::new(Arc::clone(&manager));
        if let Err(error) = crate::script::api::set_diameter_singleton(python, py_diameter) {
            warn!("failed to set Diameter Python singleton: {error}");
        } else {
            info!("Diameter namespace registered for injection");
        }
    });

    Some(manager)
}

fn init_registrant(
    config: &Config,
    outbound_senders: &Arc<transport::OutboundRouter>,
    local_addr: std::net::SocketAddr,
) -> Option<Arc<crate::registrant::RegistrantManager>> {
    use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager};

    let registrant_config = config.registrant.as_ref()?;

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
            .or_else(|_| format!("{registrar_host}:5060").parse())
            .unwrap_or_else(|_: std::net::AddrParseError| {
                warn!(host = %registrar_host, "invalid registrant host, falling back to 0.0.0.0:5060");
                std::net::SocketAddr::from(([0, 0, 0, 0], 5060))
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
    let loop_outbound = Arc::clone(outbound_senders);
    tokio::spawn(async move {
        crate::registrant::registration_loop(
            loop_manager,
            loop_outbound,
            local_addr,
            shutdown_rx,
        ).await;
    });

    let _ = shutdown_tx;

    // Inject registration Python API
    let py_manager = Arc::clone(&manager);
    pyo3::Python::attach(|python| {
        let py_registration = crate::script::api::registrant::PyRegistration::new(
            py_manager,
            local_addr,
        );
        if let Err(error) = crate::script::api::set_registration_singleton(python, py_registration) {
            error!("failed to store registration singleton: {error}");
        } else {
            info!("registration namespace registered for injection");
        }
    });

    Some(manager)
}

fn spawn_li_tasks(
    li_state: Option<LiState>,
    config: &Config,
) {
    let (_, iri_rx, audit_rx) = match li_state {
        Some(state) => state,
        None => return,
    };

    let li_config = match config.lawful_intercept.as_ref() {
        Some(cfg) => cfg,
        None => {
            error!("lawful_intercept config missing despite LI state being initialized");
            return;
        }
    };

    // Spawn X2 IRI delivery task
    if let Some(ref x2_config) = li_config.x2 {
        let x2_arc = Arc::new(x2_config.clone());
        tokio::spawn(crate::li::x2::delivery_task(iri_rx, x2_arc));
        info!("X2 IRI delivery task started");
    } else {
        tokio::spawn(async move {
            let mut receiver = iri_rx;
            while receiver.recv().await.is_some() {}
        });
    }

    // Spawn X3 media capture task
    if let Some(ref x3_config) = li_config.x3 {
        match crate::li::x3::X3Manager::new(x3_config) {
            Ok(x3_manager) => {
                let listen_address = x3_config.listen_udp.clone();
                tokio::spawn(async move {
                    if let Err(error) = crate::li::x3::receive_and_forward_task(
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

    // Spawn audit log writer
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

fn build_transport_acl(config: &Config) -> Arc<transport::acl::TransportAcl> {
    use transport::acl::TransportAcl;

    if let Some(ref sec) = config.security {
        let apiban_set = if let Some(ref apiban_config) = sec.apiban {
            match crate::apiban::ApiBanClient::new(apiban_config) {
                Ok(client) => {
                    let banned = client.banned();
                    client.start();
                    info!("APIBAN blocklist poller started");
                    Some(banned)
                }
                Err(error) => {
                    error!("Failed to create APIBAN client: {error}");
                    None
                }
            }
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
}
