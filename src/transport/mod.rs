/// Transport layer — UDP, TCP, TLS, WebSocket, WSS, SCTP.
/// Each transport sends inbound SIP messages to the core via a channel
/// and receives outbound messages via a per-connection sender.
pub mod udp;
pub mod tcp;
pub mod tls;
pub mod ws;
pub mod sctp;
pub mod pool;
pub mod rate_limit;
pub mod acl;
pub mod flow;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use socket2::SockRef;
use tracing::warn;

/// Global monotonic counter for assigning connection-oriented connection IDs.
/// Shared across TCP and TLS listeners so IDs are globally unique.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_connection_id() -> ConnectionId {
    ConnectionId(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed))
}

/// Default idle timeout for connection-oriented transports (TCP/TLS/WS/WSS).
/// Connections with no activity for this duration are closed to prevent
/// zombie connections from accumulating (especially behind NAT).
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Apply TCP_NODELAY and SO_KEEPALIVE to an accepted TCP socket.
/// Called after `TcpListener::accept()` for TCP, TLS, WS, and WSS connections.
pub fn configure_tcp_socket(socket: &tokio::net::TcpStream) {
    let sock_ref = SockRef::from(socket);

    // Disable Nagle — SIP is request-response, every message should go immediately.
    if let Err(error) = sock_ref.set_tcp_nodelay(true) {
        warn!("failed to set TCP_NODELAY: {}", error);
    }

    // Enable SO_KEEPALIVE to detect dead connections behind NAT/firewalls.
    if let Err(error) = sock_ref.set_keepalive(true) {
        warn!("failed to set SO_KEEPALIVE: {}", error);
    }

    // Tune keepalive intervals: probe after 60s idle, every 10s, 3 retries.
    // Total detection time: 60 + 10*3 = 90 seconds.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        if let Err(error) = sock_ref.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(10))
                .with_retries(3),
        ) {
            warn!("failed to set TCP keepalive params: {}", error);
        }
    }
}

/// Uniquely identifies a transport connection.
/// For UDP: hashed from (local_addr, remote_addr).
/// For TCP/TLS: monotonic counter assigned at accept().
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(pub u64);

/// An inbound SIP datagram or stream segment, including routing metadata.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub connection_id: ConnectionId,
    pub transport: Transport,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub data: Bytes,
}

/// Transport protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    WebSocket,
    WebSocketSecure,
    Sctp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Udp => write!(formatter, "UDP"),
            Transport::Tcp => write!(formatter, "TCP"),
            Transport::Tls => write!(formatter, "TLS"),
            Transport::WebSocket => write!(formatter, "WS"),
            Transport::WebSocketSecure => write!(formatter, "WSS"),
            Transport::Sctp => write!(formatter, "SCTP"),
        }
    }
}

/// A message to be sent outbound on a specific connection.
#[derive(Debug)]
pub struct OutboundMessage {
    pub connection_id: ConnectionId,
    pub transport: Transport,
    pub destination: SocketAddr,
    pub data: Bytes,
}

/// Routes outbound messages to the correct transport channel.
pub struct OutboundRouter {
    pub udp: flume::Sender<OutboundMessage>,
    pub tcp: flume::Sender<OutboundMessage>,
    pub tls: flume::Sender<OutboundMessage>,
    pub ws: flume::Sender<OutboundMessage>,
    pub wss: flume::Sender<OutboundMessage>,
    pub sctp: flume::Sender<OutboundMessage>,
}

impl OutboundRouter {
    pub fn send(&self, message: OutboundMessage) -> Result<(), flume::SendError<OutboundMessage>> {
        match message.transport {
            Transport::Udp => self.udp.send(message),
            Transport::Tcp => self.tcp.send(message),
            Transport::Tls => self.tls.send(message),
            Transport::WebSocket => self.ws.send(message),
            Transport::WebSocketSecure => self.wss.send(message),
            Transport::Sctp => self.sctp.send(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configure_tcp_socket_sets_nodelay_and_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });

        let (server_socket, _) = listener.accept().await.unwrap();
        let client_socket = connect_task.await.unwrap();

        // Apply our configuration
        configure_tcp_socket(&server_socket);
        configure_tcp_socket(&client_socket);

        // Verify TCP_NODELAY is set
        assert!(server_socket.nodelay().unwrap(), "server TCP_NODELAY should be true");
        assert!(client_socket.nodelay().unwrap(), "client TCP_NODELAY should be true");

        // Verify SO_KEEPALIVE is set via socket2
        let server_ref = SockRef::from(&server_socket);
        assert!(server_ref.keepalive().unwrap(), "server SO_KEEPALIVE should be true");
    }

    #[test]
    fn transport_display_udp() {
        assert_eq!(Transport::Udp.to_string(), "UDP");
    }

    #[test]
    fn transport_display_tcp() {
        assert_eq!(Transport::Tcp.to_string(), "TCP");
    }

    #[test]
    fn transport_display_tls() {
        assert_eq!(Transport::Tls.to_string(), "TLS");
    }

    #[test]
    fn transport_display_websocket() {
        assert_eq!(Transport::WebSocket.to_string(), "WS");
    }

    #[test]
    fn transport_display_wss() {
        assert_eq!(Transport::WebSocketSecure.to_string(), "WSS");
    }

    #[test]
    fn transport_display_sctp() {
        assert_eq!(Transport::Sctp.to_string(), "SCTP");
    }

    #[test]
    fn transport_variants_are_distinct() {
        assert_ne!(Transport::Udp, Transport::Tcp);
        assert_ne!(Transport::Tcp, Transport::Tls);
        assert_ne!(Transport::Tls, Transport::WebSocket);
        assert_ne!(Transport::WebSocket, Transport::WebSocketSecure);
        assert_ne!(Transport::WebSocketSecure, Transport::Sctp);
        assert_ne!(Transport::Udp, Transport::Sctp);
    }

    #[test]
    fn transport_clone() {
        let original = Transport::Tls;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn connection_id_equality() {
        assert_eq!(ConnectionId(42), ConnectionId(42));
        assert_ne!(ConnectionId(1), ConnectionId(2));
    }

    #[test]
    fn connection_id_hash_works() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ConnectionId(1));
        set.insert(ConnectionId(2));
        set.insert(ConnectionId(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn connection_id_debug() {
        let id = ConnectionId(12345);
        let debug = format!("{:?}", id);
        assert!(debug.contains("12345"));
    }

    #[test]
    fn inbound_message_construction() {
        let message = InboundMessage {
            connection_id: ConnectionId(1),
            transport: Transport::Udp,
            local_addr: "127.0.0.1:5060".parse().unwrap(),
            remote_addr: "192.168.1.1:50000".parse().unwrap(),
            data: Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n"),
        };
        assert_eq!(message.connection_id, ConnectionId(1));
        assert_eq!(message.transport, Transport::Udp);
        assert_eq!(message.local_addr.port(), 5060);
        assert_eq!(message.remote_addr.port(), 50000);
        assert!(!message.data.is_empty());
    }

    #[test]
    fn outbound_message_construction() {
        let message = OutboundMessage {
            connection_id: ConnectionId(99),
            transport: Transport::Udp,
            destination: "10.0.0.1:5060".parse().unwrap(),
            data: Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"),
        };
        assert_eq!(message.connection_id, ConnectionId(99));
        assert_eq!(message.transport, Transport::Udp);
        assert_eq!(message.destination.port(), 5060);
    }
}
