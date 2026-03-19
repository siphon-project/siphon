//! NAT keepalive — periodic OPTIONS pings to registered contacts.
//!
//! When `nat.keepalive.enabled` is true, a background task iterates
//! all registered contacts that have a `source_addr`, sends OPTIONS
//! pings, and deregisters contacts that fail to respond after
//! `failure_threshold` consecutive failures.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::config::NatKeepaliveConfig;
use crate::registrar::Registrar;
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, Transport};
use crate::uac::UacSender;

/// Tracks consecutive failure count per contact.
struct FailureTracker {
    /// Key: "aor|contact_uri" → consecutive failure count.
    failures: DashMap<String, u32>,
}

impl FailureTracker {
    fn new() -> Self {
        Self {
            failures: DashMap::new(),
        }
    }

    fn record_success(&self, key: &str) {
        self.failures.remove(key);
    }

    fn record_failure(&self, key: &str) -> u32 {
        let mut entry = self.failures.entry(key.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    fn remove(&self, key: &str) {
        self.failures.remove(key);
    }
}

/// Spawn the NAT keepalive background task.
///
/// Periodically sends OPTIONS pings to all registered contacts that
/// have a `source_addr`. Contacts that fail to respond after
/// `failure_threshold` consecutive pings are deregistered.
pub fn spawn_keepalive(
    config: NatKeepaliveConfig,
    registrar: Arc<Registrar>,
    uac_sender: Arc<UacSender>,
    tls_addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
) {
    if !config.enabled {
        info!("NAT keepalive disabled");
        return;
    }

    let interval = Duration::from_secs(config.interval_secs as u64);
    let threshold = config.failure_threshold;

    // Collect all local listen IPs so we can skip contacts that point
    // to siphon itself (e.g. registrant self-contacts).
    let local_ips: std::collections::HashSet<std::net::IpAddr> = listen_addrs
        .values()
        .map(|addr| addr.ip())
        .collect();

    info!(
        interval_secs = config.interval_secs,
        failure_threshold = threshold,
        "NAT keepalive started"
    );

    tokio::spawn(async move {
        let tracker = FailureTracker::new();
        let mut tick = tokio::time::interval(interval);

        loop {
            tick.tick().await;
            ping_all_contacts(&registrar, &uac_sender, &tls_addr_map, &tracker, threshold, &local_ips).await;
        }
    });
}

/// Look up a TLS connection ID from the addr_map (exact match, then IP-only fallback).
fn lookup_tls_connection(
    tls_addr_map: &DashMap<SocketAddr, ConnectionId>,
    addr: SocketAddr,
) -> Option<ConnectionId> {
    tls_addr_map.get(&addr).map(|r| *r.value())
}

/// Send OPTIONS pings to all registered contacts with a source address.
async fn ping_all_contacts(
    registrar: &Registrar,
    uac_sender: &UacSender,
    tls_addr_map: &DashMap<SocketAddr, ConnectionId>,
    tracker: &FailureTracker,
    threshold: u32,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) {
    let contacts = registrar.all_contacts();
    let nat_count = contacts.iter().filter(|(_, c)| c.source_addr.is_some()).count();
    debug!(total = contacts.len(), nat = nat_count, "keepalive sweep");

    for (aor, contact) in contacts {
        let source_addr = match contact.source_addr {
            Some(addr) => addr,
            None => continue,
        };

        // Skip contacts whose URI host resolves to one of siphon's own
        // listen addresses.  These are registrant self-contacts (siphon
        // registered itself upstream), not remote clients behind NAT.
        let contact_host_ip = contact.uri.host.parse::<std::net::IpAddr>().ok();
        if let Some(ip) = contact_host_ip {
            if local_ips.contains(&ip) {
                debug!(aor = %aor, contact = %contact.uri, "skipping self-contact (local listen address)");
                continue;
            }
        }


        let contact_uri_string = contact.uri.to_string();
        let tracker_key = format!("{aor}|{contact_uri_string}");

        let transport = contact
            .source_transport
            .as_deref()
            .and_then(|t| match t {
                "udp" => Some(Transport::Udp),
                "tcp" => Some(Transport::Tcp),
                "tls" => Some(Transport::Tls),
                "ws" => Some(Transport::WebSocket),
                "wss" => Some(Transport::WebSocketSecure),
                _ => None,
            })
            .unwrap_or(Transport::Udp);

        let request_uri = SipUri::new(source_addr.ip().to_string())
            .with_port(source_addr.port());

        // For TLS: send OPTIONS on the existing connection (connection reuse).
        // The UacSender would create a new outbound connection, which won't work
        // for NAT'd TLS clients. Instead, look up the connection in tls_addr_map
        // and send directly on it.
        if transport == Transport::Tls {
            if let Some(connection_id) = lookup_tls_connection(tls_addr_map, source_addr) {
                let receiver = uac_sender.send_options_on_connection(
                    source_addr, transport, request_uri, connection_id,
                );
                let result = tokio::time::timeout(Duration::from_secs(5), receiver).await;
                match result {
                    Ok(Ok(crate::uac::UacResult::Response(response))) => {
                        let status = response.status_code().unwrap_or(0);
                        debug!(aor = %aor, contact = %contact_uri_string, status, "keepalive response (TLS reuse)");
                        tracker.record_success(&tracker_key);
                    }
                    _ => {
                        record_keepalive_failure(registrar, tracker, &aor, &contact_uri_string, &tracker_key, threshold);
                    }
                }
            } else {
                // No TLS connection available — connection is dead
                record_keepalive_failure(registrar, tracker, &aor, &contact_uri_string, &tracker_key, threshold);
            }
            continue;
        }

        // Non-TLS: use the UAC sender as before (creates outbound connection)
        let receiver = uac_sender.send_options(source_addr, transport, request_uri);

        // Wait for response with a 5-second timeout
        let result = tokio::time::timeout(Duration::from_secs(5), receiver).await;

        match result {
            Ok(Ok(crate::uac::UacResult::Response(response))) => {
                let status = response.status_code().unwrap_or(0);
                debug!(aor = %aor, contact = %contact_uri_string, status, "keepalive response");
                tracker.record_success(&tracker_key);
            }
            _ => {
                record_keepalive_failure(registrar, tracker, &aor, &contact_uri_string, &tracker_key, threshold);
            }
        }
    }
}

fn record_keepalive_failure(
    registrar: &Registrar,
    tracker: &FailureTracker,
    aor: &str,
    contact_uri_string: &str,
    tracker_key: &str,
    threshold: u32,
) {
    let count = tracker.record_failure(tracker_key);
    warn!(aor = %aor, contact = %contact_uri_string, failures = count, "keepalive failed");
    if count >= threshold {
        warn!(aor = %aor, contact = %contact_uri_string, "deregistering unresponsive contact after {count} failures");
        registrar.remove_contact(aor, contact_uri_string);
        tracker.remove(tracker_key);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::RegistrarConfig;
    use crate::transport::{OutboundMessage, OutboundRouter};
    use std::net::SocketAddr;

    fn make_registrar() -> Arc<Registrar> {
        Arc::new(Registrar::new(RegistrarConfig::default()))
    }

    fn make_uac_sender() -> (Arc<UacSender>, Vec<flume::Receiver<OutboundMessage>>) {
        let (udp_tx, udp_rx) = flume::unbounded();
        let (tcp_tx, tcp_rx) = flume::unbounded();
        let (tls_tx, tls_rx) = flume::unbounded();
        let (ws_tx, ws_rx) = flume::unbounded();
        let (wss_tx, wss_rx) = flume::unbounded();
        let (sctp_tx, sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });

        let sender = Arc::new(UacSender::new(router, "127.0.0.1:5060".parse().unwrap(), std::collections::HashMap::new(), std::collections::HashMap::new(), None, None, None));
        (sender, vec![udp_rx, tcp_rx, tls_rx, ws_rx, wss_rx, sctp_rx])
    }

    #[test]
    fn failure_tracker_records_and_clears() {
        let tracker = FailureTracker::new();
        let key = "sip:alice@example.com|sip:alice@10.0.0.1";

        assert_eq!(tracker.record_failure(key), 1);
        assert_eq!(tracker.record_failure(key), 2);
        assert_eq!(tracker.record_failure(key), 3);

        tracker.record_success(key);
        // After success, counter resets
        assert_eq!(tracker.record_failure(key), 1);
    }

    #[tokio::test]
    async fn ping_deregisters_after_threshold() {
        let registrar = make_registrar();
        let (uac_sender, _rxs) = make_uac_sender();
        let tls_addr_map = Arc::new(DashMap::new());

        let source: SocketAddr = "192.168.1.100:50000".parse().unwrap();

        registrar
            .save_with_source(
                "sip:alice@example.com",
                SipUri::new("192.168.1.100".to_string()).with_user("alice".to_string()),
                3600, 1.0, "c1".into(), 1,
                Some(source), None,
            )
            .unwrap();

        assert!(registrar.is_registered("sip:alice@example.com"));

        let tracker = FailureTracker::new();

        // Simulate 3 rounds of pinging (threshold=3) — no response means timeout
        // Each call to ping_all_contacts will send OPTIONS and wait 5s for response,
        // which will timeout since nobody is answering.
        // Use threshold=1 to avoid long test.
        let local_ips = std::collections::HashSet::new();
        ping_all_contacts(&registrar, &uac_sender, &tls_addr_map, &tracker, 1, &local_ips).await;

        // After 1 failure with threshold=1, contact should be removed
        assert!(!registrar.is_registered("sip:alice@example.com"));
    }

    #[tokio::test]
    async fn ping_skips_contacts_without_source_addr() {
        let registrar = make_registrar();
        let (uac_sender, _rxs) = make_uac_sender();
        let tls_addr_map = Arc::new(DashMap::new());

        // Contact without source_addr
        registrar
            .save(
                "sip:alice@example.com",
                SipUri::new("10.0.0.1".to_string()).with_user("alice".to_string()),
                3600, 1.0, "c1".into(), 1,
            )
            .unwrap();

        let tracker = FailureTracker::new();
        let local_ips = std::collections::HashSet::new();
        ping_all_contacts(&registrar, &uac_sender, &tls_addr_map, &tracker, 1, &local_ips).await;

        // Contact should still be registered — it was skipped
        assert!(registrar.is_registered("sip:alice@example.com"));
    }
}
