//! X3 CC Delivery — media content capture via RTPEngine + encapsulation.
//!
//! When an intercepted call requires CC (Content of Communication) delivery:
//! 1. Tell RTPEngine to start recording, mirroring RTP to a local UDP port
//! 2. Receive mirrored RTP packets on the local UDP socket
//! 3. Encapsulate in ETSI CC-PDU (TS 102 232-1) or forward raw
//! 4. Deliver to the mediation device's X3 collector
//!
//! Each intercepted call gets its own forwarding entry (LIID + correlation ID).

use super::asn1;
use crate::config::LiX3Config;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Active media capture session for one intercepted call.
#[derive(Debug, Clone)]
pub struct CaptureSession {
    /// LIID for this intercept.
    pub liid: String,
    /// Correlation ID (Call-ID for SIP).
    pub correlation_id: String,
    /// RTPEngine's source address for mirrored RTP (used to demux packets).
    pub rtpengine_source: Option<SocketAddr>,
}

/// Encapsulation format for X3 delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encapsulation {
    /// ETSI TS 102 232 CC-PDU (ASN.1/BER envelope around IP packet).
    Etsi,
    /// Raw IP/RTP packets forwarded as-is.
    RawIp,
}

impl Encapsulation {
    pub fn parse(value: &str) -> Self {
        match value {
            "raw_ip" | "raw" => Self::RawIp,
            _ => Self::Etsi,
        }
    }
}

/// X3 media capture manager.
///
/// Manages active capture sessions and the UDP receive/forward loop.
#[derive(Clone)]
pub struct X3Manager {
    /// Active capture sessions keyed by correlation ID (Call-ID).
    sessions: Arc<DashMap<String, CaptureSession>>,
    /// X3 delivery target address.
    delivery_address: SocketAddr,
    /// Encapsulation format.
    encapsulation: Encapsulation,
}

impl X3Manager {
    /// Create a new X3 manager.
    pub fn new(config: &LiX3Config) -> Result<Self, String> {
        let delivery_address: SocketAddr = config.delivery_address.parse()
            .map_err(|error| format!("invalid X3 delivery address: {error}"))?;

        Ok(Self {
            sessions: Arc::new(DashMap::new()),
            delivery_address,
            encapsulation: Encapsulation::parse(&config.encapsulation),
        })
    }

    /// Start media capture for an intercepted call.
    ///
    /// In a full implementation this would send `start recording` to RTPEngine.
    /// For now, registers the session so incoming mirrored RTP can be forwarded.
    pub fn start_capture(
        &self,
        liid: &str,
        correlation_id: &str,
        rtpengine_source: Option<SocketAddr>,
    ) {
        let session = CaptureSession {
            liid: liid.to_string(),
            correlation_id: correlation_id.to_string(),
            rtpengine_source,
        };

        info!(
            liid = %liid,
            correlation_id = %correlation_id,
            "X3: media capture started"
        );

        self.sessions.insert(correlation_id.to_string(), session);
    }

    /// Stop media capture for an intercepted call.
    ///
    /// In a full implementation this would send `stop recording` to RTPEngine.
    pub fn stop_capture(&self, correlation_id: &str) -> Option<CaptureSession> {
        let removed = self.sessions.remove(correlation_id).map(|(_, session)| session);

        if let Some(ref session) = removed {
            info!(
                liid = %session.liid,
                correlation_id = %correlation_id,
                "X3: media capture stopped"
            );
        }

        removed
    }

    /// Check if there's an active capture for this correlation ID.
    pub fn is_capturing(&self, correlation_id: &str) -> bool {
        self.sessions.contains_key(correlation_id)
    }

    /// Get the session for a correlation ID.
    pub fn get_session(&self, correlation_id: &str) -> Option<CaptureSession> {
        self.sessions.get(correlation_id).map(|entry| entry.clone())
    }

    /// Number of active capture sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Encapsulate an RTP packet for X3 delivery.
    pub fn encapsulate(
        &self,
        liid: &str,
        correlation_id: &str,
        rtp_payload: &[u8],
    ) -> Vec<u8> {
        match self.encapsulation {
            Encapsulation::Etsi => {
                asn1::encode_cc_pdu(liid, correlation_id, SystemTime::now(), rtp_payload)
            }
            Encapsulation::RawIp => {
                // Forward raw — just the RTP packet as-is
                rtp_payload.to_vec()
            }
        }
    }

    /// Get the delivery address.
    pub fn delivery_address(&self) -> SocketAddr {
        self.delivery_address
    }
}

/// Background task that receives mirrored RTP from RTPEngine and forwards to mediation.
///
/// Binds a local UDP socket, receives packets, looks up the capture session,
/// encapsulates, and forwards to the X3 delivery address.
pub async fn receive_and_forward_task(
    listen_address: &str,
    manager: X3Manager,
) -> Result<(), String> {
    let socket = UdpSocket::bind(listen_address).await
        .map_err(|error| format!("X3: failed to bind UDP socket on {listen_address}: {error}"))?;

    let local_address = socket.local_addr()
        .map_err(|error| format!("X3: failed to get local address: {error}"))?;

    info!(address = %local_address, "X3 UDP receiver started");

    // Create a separate socket for forwarding to mediation
    let forward_socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|error| format!("X3: failed to bind forward socket: {error}"))?;

    let mut buffer = vec![0u8; 65536]; // max UDP packet size

    loop {
        let (length, source_address) = match socket.recv_from(&mut buffer).await {
            Ok(result) => result,
            Err(error) => {
                warn!(error = %error, "X3: UDP receive error");
                continue;
            }
        };

        let packet = &buffer[..length];

        // Find the capture session that matches this source
        // In production, RTPEngine tags packets with a cookie or we match by source addr.
        // For now, iterate sessions to find one matching the source.
        let session = find_session_by_source(&manager, source_address);

        if let Some(session) = session {
            let encapsulated = manager.encapsulate(
                &session.liid,
                &session.correlation_id,
                packet,
            );

            match forward_socket.send_to(&encapsulated, manager.delivery_address()).await {
                Ok(_) => {
                    debug!(
                        liid = %session.liid,
                        bytes = encapsulated.len(),
                        "X3: CC packet forwarded"
                    );
                }
                Err(error) => {
                    warn!(
                        liid = %session.liid,
                        error = %error,
                        "X3: failed to forward CC packet"
                    );
                }
            }
        }
        // Packets not matching any session are silently dropped
    }
}

/// Find a capture session matching the given source address.
fn find_session_by_source(manager: &X3Manager, source: SocketAddr) -> Option<CaptureSession> {
    for entry in manager.sessions.iter() {
        if let Some(expected_source) = entry.value().rtpengine_source {
            if expected_source == source {
                return Some(entry.value().clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LiX3Config {
        LiX3Config {
            listen_udp: "127.0.0.1:0".to_string(),
            delivery_address: "127.0.0.1:19999".to_string(),
            transport: "udp".to_string(),
            encapsulation: "etsi".to_string(),
        }
    }

    #[test]
    fn create_x3_manager() {
        let manager = X3Manager::new(&test_config()).unwrap();
        assert_eq!(manager.active_sessions(), 0);
        assert_eq!(manager.encapsulation, Encapsulation::Etsi);
    }

    #[test]
    fn start_and_stop_capture() {
        let manager = X3Manager::new(&test_config()).unwrap();

        manager.start_capture("LI-001", "call-123@example.com", None);
        assert!(manager.is_capturing("call-123@example.com"));
        assert_eq!(manager.active_sessions(), 1);

        let session = manager.stop_capture("call-123@example.com").unwrap();
        assert_eq!(session.liid, "LI-001");
        assert!(!manager.is_capturing("call-123@example.com"));
        assert_eq!(manager.active_sessions(), 0);
    }

    #[test]
    fn stop_nonexistent_returns_none() {
        let manager = X3Manager::new(&test_config()).unwrap();
        assert!(manager.stop_capture("nonexistent").is_none());
    }

    #[test]
    fn encapsulate_etsi_produces_valid_cc_pdu() {
        let manager = X3Manager::new(&test_config()).unwrap();
        let rtp_payload = vec![0x80, 0x00, 0x01, 0x02, 0x03];

        let encapsulated = manager.encapsulate("LI-001", "call-123", &rtp_payload);

        // Should be a valid PS-PDU with type CC
        let (version, pdu_type, _) = asn1::decode_ps_pdu(&encapsulated).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 2); // CC
    }

    #[test]
    fn encapsulate_raw_ip_passes_through() {
        let mut config = test_config();
        config.encapsulation = "raw_ip".to_string();
        let manager = X3Manager::new(&config).unwrap();

        let rtp_payload = vec![0x80, 0x00, 0x01, 0x02, 0x03];
        let encapsulated = manager.encapsulate("LI-001", "call-123", &rtp_payload);

        // Raw mode: output == input
        assert_eq!(encapsulated, rtp_payload);
    }

    #[test]
    fn encapsulation_from_str() {
        assert_eq!(Encapsulation::parse("etsi"), Encapsulation::Etsi);
        assert_eq!(Encapsulation::parse("raw_ip"), Encapsulation::RawIp);
        assert_eq!(Encapsulation::parse("raw"), Encapsulation::RawIp);
        assert_eq!(Encapsulation::parse("unknown"), Encapsulation::Etsi); // default
    }

    #[test]
    fn multiple_concurrent_sessions() {
        let manager = X3Manager::new(&test_config()).unwrap();

        manager.start_capture("LI-001", "call-1@example.com", None);
        manager.start_capture("LI-002", "call-2@example.com", None);
        manager.start_capture("LI-003", "call-3@example.com", None);

        assert_eq!(manager.active_sessions(), 3);

        manager.stop_capture("call-2@example.com");
        assert_eq!(manager.active_sessions(), 2);
        assert!(manager.is_capturing("call-1@example.com"));
        assert!(!manager.is_capturing("call-2@example.com"));
        assert!(manager.is_capturing("call-3@example.com"));
    }

    #[test]
    fn get_session_returns_correct_data() {
        let manager = X3Manager::new(&test_config()).unwrap();
        let source: SocketAddr = "10.0.0.1:20000".parse().unwrap();

        manager.start_capture("LI-001", "call-123", Some(source));

        let session = manager.get_session("call-123").unwrap();
        assert_eq!(session.liid, "LI-001");
        assert_eq!(session.rtpengine_source.unwrap(), source);
    }
}
