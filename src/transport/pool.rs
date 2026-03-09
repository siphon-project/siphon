//! Outbound TCP/TLS connection pool.
//!
//! When the proxy needs to relay a SIP message to a remote server over TCP/TLS,
//! it needs an established connection to that destination. This pool creates and
//! reuses connections, keyed by `(SocketAddr, Transport)`.
//!
//! Architecture:
//!   - Pool stores `mpsc::Sender<Bytes>` per destination (same pattern as inbound connections)
//!   - Each pooled connection has a read task that feeds responses back to the inbound channel
//!   - Idle connections are closed after `CONNECTION_IDLE_TIMEOUT`
//!   - Connections are removed on error and recreated on next use

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::transport::{
    ConnectionId, InboundMessage, Transport, CONNECTION_IDLE_TIMEOUT,
    configure_tcp_socket, next_connection_id,
};

/// Key for a pooled connection: destination address + transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PoolKey {
    destination: SocketAddr,
    transport: Transport,
}

/// A pooled outbound connection.
struct PoolEntry {
    connection_id: ConnectionId,
    sender: mpsc::Sender<Bytes>,
}

/// Connection pool for outbound TCP/TLS connections.
pub struct ConnectionPool {
    connections: Arc<DashMap<PoolKey, PoolEntry>>,
    /// Shared connection map (same one used by inbound connections).
    /// Pooled connections are also registered here so responses can be
    /// routed back via the same connection_id.
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    /// Channel to feed inbound responses back to the dispatcher.
    inbound_tx: flume::Sender<InboundMessage>,
    /// Local address to use as source in InboundMessage.
    local_addr: SocketAddr,
}

impl ConnectionPool {
    pub fn new(
        connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
        inbound_tx: flume::Sender<InboundMessage>,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            connection_map,
            inbound_tx,
            local_addr,
        }
    }

    /// Send data to a destination, creating or reusing a pooled TCP connection.
    ///
    /// Returns the `ConnectionId` used (so responses can be correlated).
    pub async fn send_tcp(
        &self,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        let key = PoolKey {
            destination,
            transport: Transport::Tcp,
        };

        // Try existing connection first
        if let Some(entry) = self.connections.get(&key) {
            if !entry.sender.is_closed()
                && entry.sender.send(data.clone()).await.is_ok()
            {
                return Ok(entry.connection_id);
            }
            // Connection dead — remove and create new
            drop(entry);
            self.connections.remove(&key);
        }

        // Create new connection, binding to the local listening address so
        // outbound connections originate from the well-known SIP port (e.g. :5060)
        // rather than a random ephemeral port. TCP identifies connections by the
        // full 4-tuple so multiple outbound connections from the same local port
        // to different destinations are fine.
        let socket = if destination.is_ipv6() {
            tokio::net::TcpSocket::new_v6()?
        } else {
            tokio::net::TcpSocket::new_v4()?
        };
        socket.set_reuseaddr(true)?;
        #[cfg(unix)]
        socket.set_reuseport(true)?;
        socket.bind(self.local_addr)?;
        let stream = socket.connect(destination).await?;
        configure_tcp_socket(&stream);

        let connection_id = next_connection_id();
        let local_addr = stream.local_addr().unwrap_or(self.local_addr);
        let (mut reader, mut writer) = stream.into_split();

        // Per-connection write channel
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);

        // Register in the shared connection map so the outbound distributor
        // can route responses back on this connection.
        self.connection_map.insert(connection_id, write_tx.clone());

        debug!(
            destination = %destination,
            connection_id = ?connection_id,
            "pool: opened outbound TCP connection"
        );

        // Read task — responses from the remote server come back here
        let inbound_tx = self.inbound_tx.clone();
        let conn_map = self.connection_map.clone();
        let connections = self.connections.clone();
        let key_for_cleanup = key;
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65536);
            loop {
                match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut buffer)).await
                {
                    Ok(Ok(0)) => {
                        info!("pool: TCP connection {:?} to {} closed by peer", connection_id, destination);
                        break;
                    }
                    Ok(Ok(size)) => {
                        let response_data = Bytes::copy_from_slice(&buffer[..size]);
                        let message = InboundMessage {
                            connection_id,
                            transport: Transport::Tcp,
                            local_addr,
                            remote_addr: destination,
                            data: response_data,
                        };
                        if let Err(error) = inbound_tx.send_async(message).await {
                            error!("pool: inbound enqueue failed: {}", error);
                            break;
                        }
                    }
                    Ok(Err(error)) => {
                        warn!("pool: TCP read error on {:?}: {}", connection_id, error);
                        break;
                    }
                    Err(_) => {
                        info!(
                            "pool: TCP connection {:?} idle timeout ({}s)",
                            connection_id,
                            CONNECTION_IDLE_TIMEOUT.as_secs()
                        );
                        break;
                    }
                }
            }
            conn_map.remove(&connection_id);
            connections.remove(&key_for_cleanup);
        });

        // Write task
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if let Err(error) = writer.write_all(&data).await {
                    warn!("pool: TCP write error on {:?}: {}", connection_id, error);
                    break;
                }
            }
        });

        // Send the initial data
        if write_tx.send(data).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pooled connection closed immediately",
            ));
        }

        // Store in pool
        self.connections.insert(
            key,
            PoolEntry {
                connection_id,
                sender: write_tx,
            },
        );

        Ok(connection_id)
    }

    /// Number of active pooled connections.
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_connects_and_sends() {
        // Start a TCP server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let size = socket.read(&mut buffer).await.unwrap();
            let received = String::from_utf8_lossy(&buffer[..size]).to_string();
            // Echo back a response
            socket.write_all(b"SIP/2.0 200 OK\r\n\r\n").await.unwrap();
            received
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map.clone(),
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
        );

        // Send via pool
        let data = Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n");
        let connection_id = pool.send_tcp(server_addr, data).await.unwrap();
        assert_ne!(connection_id, ConnectionId::default());
        assert_eq!(pool.active_connections(), 1);

        // Verify server received the data
        let received = server_task.await.unwrap();
        assert!(received.contains("INVITE"));

        // Verify response comes back via inbound channel
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timeout waiting for response")
        .expect("channel closed");

        assert_eq!(response.connection_id, connection_id);
        assert_eq!(response.transport, Transport::Tcp);
        let response_text = String::from_utf8_lossy(&response.data);
        assert!(response_text.contains("200 OK"));
    }

    #[tokio::test]
    async fn pool_reuses_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts one connection, reads two messages
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            // Read first message
            let _ = socket.read(&mut buffer).await.unwrap();
            // Read second message
            let _ = socket.read(&mut buffer).await.unwrap();
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
        );

        let id1 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 1"))
            .await
            .unwrap();
        let id2 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 2"))
            .await
            .unwrap();

        // Same connection reused
        assert_eq!(id1, id2);
        assert_eq!(pool.active_connections(), 1);
    }

    #[tokio::test]
    async fn pool_reconnects_on_dead_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts first connection, reads one message, then closes
        let listener_arc = Arc::new(tokio::sync::Mutex::new(listener));
        let listener_clone = listener_arc.clone();
        tokio::spawn(async move {
            let listener = listener_clone.lock().await;
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            drop(socket); // close connection
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
        );

        let id1 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 1"))
            .await
            .unwrap();

        // Wait for the server to close the connection
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Accept second connection on server side
        let listener_clone2 = listener_arc.clone();
        tokio::spawn(async move {
            let listener = listener_clone2.lock().await;
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
        });

        let id2 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 2"))
            .await
            .unwrap();

        // Different connection (reconnected)
        assert_ne!(id1, id2);
    }
}
