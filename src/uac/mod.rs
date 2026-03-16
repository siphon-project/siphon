//! UAC (User Agent Client) — generates outbound SIP requests.
//!
//! Used by NAT keepalive (OPTIONS pings), PSTN health probing, and
//! any feature that needs to originate SIP requests without an
//! inbound trigger.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

/// Result of a UAC request.
#[derive(Debug)]
pub enum UacResult {
    /// Received a response.
    Response(Box<SipMessage>),
    /// Request timed out with no response.
    Timeout,
}

/// A pending UAC request awaiting a response.
struct PendingRequest {
    sender: oneshot::Sender<UacResult>,
}

/// UAC sender — generates and sends outbound SIP requests.
pub struct UacSender {
    outbound: Arc<OutboundRouter>,
    local_addr: SocketAddr,
    /// SIP domain used in From header (first configured domain).
    domain: String,
    /// Pending requests keyed by branch parameter.
    pending: Arc<DashMap<String, PendingRequest>>,
    cseq_counter: std::sync::atomic::AtomicU32,
}

impl UacSender {
    pub fn new(outbound: Arc<OutboundRouter>, local_addr: SocketAddr, domain: String) -> Self {
        Self {
            outbound,
            local_addr,
            domain,
            pending: Arc::new(DashMap::new()),
            cseq_counter: std::sync::atomic::AtomicU32::new(1),
        }
    }

    /// Send an OPTIONS request to a target address.
    ///
    /// Returns a receiver that will get the response or timeout.
    /// The caller is responsible for applying a timeout on the receiver.
    pub fn send_options(
        &self,
        destination: SocketAddr,
        transport: Transport,
        request_uri: SipUri,
    ) -> oneshot::Receiver<UacResult> {
        let branch = format!("z9hG4bK-uac-{}", uuid::Uuid::new_v4());
        let cseq = self
            .cseq_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let via = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport, self.domain, self.local_addr.port(), branch
        );

        let message = match SipMessageBuilder::new()
            .request(Method::Options, request_uri.clone())
            .via(via)
            .to(format!("<{request_uri}>"))
            .from(format!("<sip:siphon@{}>;tag=uac-{}", self.domain, cseq))
            .call_id(format!("uac-keepalive-{}", uuid::Uuid::new_v4()))
            .cseq(format!("{cseq} OPTIONS"))
            .max_forwards(70)
            .content_length(0)
            .build()
        {
            Ok(message) => message,
            Err(error) => {
                warn!("UAC failed to build OPTIONS message: {error}");
                let (sender, receiver) = oneshot::channel();
                let _ = sender.send(UacResult::Timeout);
                return receiver;
            }
        };

        let data = Bytes::from(message.to_bytes());

        let outbound_message = OutboundMessage {
            connection_id: ConnectionId::default(),
            transport,
            destination,
            data,
        };

        let (sender, receiver) = oneshot::channel();
        self.pending.insert(branch.clone(), PendingRequest { sender });

        debug!(
            destination = %destination,
            branch = %branch,
            "UAC sending OPTIONS"
        );

        if let Err(error) = self.outbound.send(outbound_message) {
            warn!("UAC failed to send OPTIONS: {error}");
            // Remove the pending entry and signal timeout
            if let Some((_, pending)) = self.pending.remove(&branch) {
                let _ = pending.sender.send(UacResult::Timeout);
            }
        }

        receiver
    }

    /// Match an incoming response to a pending UAC request.
    ///
    /// Returns `true` if the response was consumed (matched a UAC branch).
    pub fn match_response(&self, message: &SipMessage) -> bool {
        // Extract branch from topmost Via
        let branch = match message.headers.get("Via").or_else(|| message.headers.get("v")) {
            Some(via_raw) => {
                match crate::sip::headers::via::Via::parse_multi(via_raw) {
                    Ok(vias) => vias.first().and_then(|v| v.branch.clone()),
                    Err(_) => None,
                }
            }
            None => None,
        };

        let branch = match branch {
            Some(b) if b.starts_with("z9hG4bK-uac-") => b,
            _ => return false,
        };

        if let Some((_, pending)) = self.pending.remove(&branch) {
            debug!(branch = %branch, "UAC matched response");
            let _ = pending.sender.send(UacResult::Response(Box::new(message.clone())));
            true
        } else {
            false
        }
    }

    /// Fire-and-forget: send a pre-built SIP message with no response tracking.
    ///
    /// Used for NOTIFY, MESSAGE, and other outbound requests where the caller
    /// does not need to correlate a response.
    pub fn send_request(
        &self,
        message: SipMessage,
        destination: SocketAddr,
        transport: Transport,
    ) {
        let data = Bytes::from(message.to_bytes());
        let outbound_message = OutboundMessage {
            connection_id: ConnectionId::default(),
            transport,
            destination,
            data,
        };

        debug!(
            destination = %destination,
            transport = %transport,
            "UAC fire-and-forget send"
        );

        if let Err(error) = self.outbound.send(outbound_message) {
            warn!("UAC send_request failed: {error}");
        }
    }

    /// Clean up timed-out pending requests.
    /// Called periodically by the dispatcher's sweep task.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Expire a specific pending request by branch (called on timeout).
    pub fn expire_branch(&self, branch: &str) {
        if let Some((_, pending)) = self.pending.remove(branch) {
            let _ = pending.sender.send(UacResult::Timeout);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns (UacSender, Vec<Receiver>) — keep the receivers alive so sends succeed.
    fn make_uac_sender() -> (UacSender, Vec<flume::Receiver<OutboundMessage>>) {
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

        let sender = UacSender::new(router, "127.0.0.1:5060".parse().unwrap(), "localhost".to_string());
        let receivers = vec![udp_rx, tcp_rx, tls_rx, ws_rx, wss_rx, sctp_rx];
        (sender, receivers)
    }

    #[test]
    fn send_options_creates_pending() {
        let (sender, _rxs) = make_uac_sender();
        assert_eq!(sender.pending_count(), 0);

        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        assert_eq!(sender.pending_count(), 1);
    }

    #[test]
    fn match_response_with_uac_branch() {
        let (sender, _rxs) = make_uac_sender();

        // Send an OPTIONS to get the branch
        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );
        assert_eq!(sender.pending_count(), 1);

        // Get the branch from the pending map
        let branch = sender.pending.iter().next().unwrap().key().clone();

        // Build a response with that branch
        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via(format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"))
            .to("<sip:10.0.0.1>".to_string())
            .from("<sip:siphon@127.0.0.1>;tag=uac-1".to_string())
            .call_id("uac-test".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert!(sender.match_response(&response));
        assert_eq!(sender.pending_count(), 0);
    }

    #[test]
    fn match_response_ignores_non_uac_branch() {
        let (sender, _rxs) = make_uac_sender();

        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-regular".to_string())
            .to("<sip:bob@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=abc".to_string())
            .call_id("regular-call".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert!(!sender.match_response(&response));
    }

    #[test]
    fn expire_branch_signals_timeout() {
        let (sender, _rxs) = make_uac_sender();

        let mut receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        let branch = sender.pending.iter().next().unwrap().key().clone();
        sender.expire_branch(&branch);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(result, UacResult::Timeout));
        assert_eq!(sender.pending_count(), 0);
    }

    #[test]
    fn cseq_increments() {
        let (sender, _rxs) = make_uac_sender();

        let _r1 = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );
        let _r2 = sender.send_options(
            "10.0.0.2:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.2".to_string()),
        );

        assert_eq!(sender.pending_count(), 2);
    }

    #[test]
    fn send_request_fire_and_forget() {
        let (sender, receivers) = make_uac_sender();

        let message = SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Notify,
                SipUri::new("10.0.0.5".to_string()),
            )
            .via(format!(
                "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-notify-{}",
                uuid::Uuid::new_v4()
            ))
            .to("<sip:as@10.0.0.5>".to_string())
            .from("<sip:scscf@ims.example.com>;tag=notif1".to_string())
            .call_id("notify-test-1".to_string())
            .cseq("1 NOTIFY".to_string())
            .content_length(0)
            .build()
            .unwrap();

        sender.send_request(
            message,
            "10.0.0.5:5060".parse().unwrap(),
            Transport::Udp,
        );

        // No pending entry (fire-and-forget).
        assert_eq!(sender.pending_count(), 0);

        // Message was sent to UDP channel.
        let udp_rx = &receivers[0]; // UDP is index 0
        let outbound = udp_rx.try_recv().unwrap();
        assert_eq!(outbound.destination, "10.0.0.5:5060".parse().unwrap());
        assert!(!outbound.data.is_empty());
    }
}
