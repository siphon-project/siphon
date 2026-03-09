//! TCP transport with per-connection response routing.
//!
//! Each accepted connection gets a unique `ConnectionId` and a
//! `mpsc::Sender<Bytes>` stored in a `DashMap`. When the core wants to
//! send a response, it looks up the connection ID and sends to that sender.
//!
//! This fixes the broken "broadcast to all TCP connections" bug in the
//! original prototype.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport, CONNECTION_IDLE_TIMEOUT, configure_tcp_socket, next_connection_id};

/// Spawn a TCP listener. For each accepted connection a task is spawned that:
///   1. Reads inbound SIP messages and sends them to `inbound_tx`
///   2. Receives outbound messages from its per-connection channel and writes them
///
/// The `connection_map` maps ConnectionId → per-connection outbound sender.
/// The outbound dispatcher (in the core) looks up the connection ID and routes
/// responses to the right connection.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
) {
    // Spawn a task that distributes outbound messages to per-connection senders.
    let connection_map_clone = connection_map.clone();
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map_clone.get(&outbound.connection_id) {
                if let Err(e) = sender.send(outbound.data).await {
                    warn!("TCP outbound send failed for connection {:?}: {}", outbound.connection_id, e);
                }
            } else {
                warn!("TCP outbound: connection {:?} not found (may have closed)", outbound.connection_id);
            }
        }
    });

    tokio::spawn(async move {
        let listener = TcpListener::bind(local_addr)
            .await
            .expect("failed to bind TCP listener");
        info!("TCP listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((socket, remote_addr)) => {
                    let connection_id = next_connection_id();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();

                    configure_tcp_socket(&socket);
                    debug!("TCP accepted {} as {:?}", remote_addr, connection_id);

                    tokio::spawn(async move {
                        let local_addr = socket.local_addr().unwrap_or(local_addr);
                        let (mut reader, mut writer) = socket.into_split();

                        // Per-connection outbound channel
                        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
                        connection_map.insert(connection_id, outbound_tx);

                        // Read task with idle timeout
                        let inbound_tx_clone = inbound_tx.clone();
                        let read_task = tokio::spawn(async move {
                            let mut buffer = BytesMut::zeroed(65536);
                            loop {
                                match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut buffer)).await {
                                    Ok(Ok(0)) => {
                                        debug!("TCP connection {:?} closed by peer", connection_id);
                                        break;
                                    }
                                    Ok(Ok(size)) => {
                                        let data = Bytes::copy_from_slice(&buffer[..size]);
                                        let message = InboundMessage {
                                            connection_id,
                                            transport: Transport::Tcp,
                                            local_addr,
                                            remote_addr,
                                            data,
                                        };
                                        if let Err(e) = inbound_tx_clone.send_async(message).await {
                                            error!("TCP inbound enqueue failed: {}", e);
                                            break;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        warn!("TCP read error on {:?}: {}", connection_id, e);
                                        break;
                                    }
                                    Err(_) => {
                                        debug!("TCP connection {:?} idle timeout ({}s)", connection_id, CONNECTION_IDLE_TIMEOUT.as_secs());
                                        break;
                                    }
                                }
                            }
                        });

                        // Write task
                        let write_task = tokio::spawn(async move {
                            while let Some(data) = outbound_rx.recv().await {
                                if let Err(e) = writer.write_all(&data).await {
                                    warn!("TCP write error on {:?}: {}", connection_id, e);
                                    break;
                                }
                            }
                        });

                        // Wait for either half to close, then clean up.
                        tokio::select! {
                            _ = read_task => {}
                            _ = write_task => {}
                        }

                        connection_map.remove(&connection_id);
                        debug!("TCP connection {:?} cleaned up", connection_id);
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn connection_ids_are_unique() {
        let id1 = next_connection_id();
        let id2 = next_connection_id();
        let id3 = next_connection_id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn connection_map_routes_to_correct_connection() {
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        let conn_a = ConnectionId(100);
        let conn_b = ConnectionId(200);

        let (tx_a, mut rx_a) = mpsc::channel::<Bytes>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<Bytes>(4);

        connection_map.insert(conn_a, tx_a);
        connection_map.insert(conn_b, tx_b);

        // Send to conn_a
        let data_a = Bytes::from_static(b"SIP/2.0 200 OK for A\r\n\r\n");
        connection_map.get(&conn_a).unwrap().send(data_a.clone()).await.unwrap();

        // Send to conn_b
        let data_b = Bytes::from_static(b"SIP/2.0 200 OK for B\r\n\r\n");
        connection_map.get(&conn_b).unwrap().send(data_b.clone()).await.unwrap();

        // Verify A gets A's message
        let received_a = rx_a.recv().await.unwrap();
        assert_eq!(received_a, data_a);

        // Verify B gets B's message
        let received_b = rx_b.recv().await.unwrap();
        assert_eq!(received_b, data_b);

        // Verify A does NOT have B's message
        assert!(rx_a.try_recv().is_err());
    }

    #[tokio::test]
    async fn removed_connection_returns_none() {
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let conn = ConnectionId(999);
        let (tx, _rx) = mpsc::channel::<Bytes>(4);
        connection_map.insert(conn, tx);
        connection_map.remove(&conn);
        assert!(connection_map.get(&conn).is_none());
    }
}
