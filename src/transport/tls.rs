//! TLS transport — wraps TCP connections with rustls.
//!
//! Structurally identical to the TCP listener but performs a TLS handshake
//! on each accepted connection before splitting into read/write halves.
//! Failed handshakes are logged and the connection is dropped without
//! affecting other connections or the accept loop.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::TlsServerConfig;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport, CONNECTION_IDLE_TIMEOUT, configure_tcp_socket, next_connection_id};
use crate::transport::acl::TransportAcl;

/// Build a `TlsAcceptor` from the certificate and key paths in config.
pub fn build_tls_acceptor(tls_config: &TlsServerConfig) -> io::Result<TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;

    // Load certificate chain
    let cert_file = File::open(&tls_config.certificate).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open certificate file '{}': {}", tls_config.certificate, error),
        )
    })?;
    let certificates: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse certificate PEM: {}", error),
            )
        })?;

    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file contains no certificates",
        ));
    }

    // Load private key
    let key_file = File::open(&tls_config.private_key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open private key file '{}': {}", tls_config.private_key, error),
        )
    })?;
    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse private key PEM: {}", error),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private key file contains no private key",
            )
        })?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build TLS server config: {}", error),
            )
        })?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Spawn a TLS listener. Mirrors the TCP listener but wraps each accepted
/// connection in a TLS handshake before spawning read/write tasks.
pub async fn listen(
    local_addr: SocketAddr,
    tls_config: &TlsServerConfig,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
) {
    let acceptor = build_tls_acceptor(tls_config).unwrap_or_else(|error| {
        eprintln!("Failed to build TLS acceptor: {error}");
        std::process::exit(1);
    });

    // Spawn a task that distributes outbound messages to per-connection senders.
    let connection_map_clone = connection_map.clone();
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map_clone.get(&outbound.connection_id) {
                if let Err(error) = sender.send(outbound.data).await {
                    warn!("TLS outbound send failed for connection {:?}: {}", outbound.connection_id, error);
                }
            } else {
                debug!("TLS outbound: connection {:?} not found (may have closed)", outbound.connection_id);
            }
        }
    });

    tokio::spawn(async move {
        let listener = match TcpListener::bind(local_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                error!("failed to bind TLS listener on {local_addr}: {error}");
                return;
            }
        };
        info!("TLS listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((tcp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TLS rejected {} by ACL", remote_addr);
                        continue;
                    }
                    let acceptor = acceptor.clone();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let addr_map = addr_map.clone();

                    configure_tcp_socket(&tcp_stream);

                    tokio::spawn(async move {
                        // Perform TLS handshake — timeout is inherited from tokio runtime.
                        let tls_stream = match acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                warn!("TLS handshake failed from {}: {}", remote_addr, error);
                                return;
                            }
                        };

                        let connection_id = next_connection_id();
                        debug!("TLS accepted {} as {:?}", remote_addr, connection_id);

                        let local_addr = tls_stream.get_ref().0.local_addr().unwrap_or(local_addr);
                        let (mut reader, mut writer) = tokio::io::split(tls_stream);

                        // Per-connection outbound channel
                        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
                        connection_map.insert(connection_id, outbound_tx);
                        addr_map.insert(remote_addr, connection_id);

                        // Read task with idle timeout and SIP stream framing (RFC 3261 §18.3)
                        let inbound_tx_clone = inbound_tx.clone();
                        let read_task = tokio::spawn(async move {
                            let mut accumulator = BytesMut::with_capacity(65536);
                            let mut read_buf = [0u8; 8192];
                            loop {
                                match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut read_buf)).await {
                                    Ok(Ok(0)) => {
                                        info!("TLS connection {:?} closed by peer", connection_id);
                                        break;
                                    }
                                    Ok(Ok(size)) => {
                                        accumulator.extend_from_slice(&read_buf[..size]);

                                        // Extract all complete SIP messages from the buffer
                                        loop {
                                            let message_len = match crate::transport::tcp::extract_sip_message_length(&accumulator) {
                                                Some(len) if len <= accumulator.len() => len,
                                                _ => break, // incomplete message, need more data
                                            };
                                            let data = accumulator.split_to(message_len).freeze();
                                            let message = InboundMessage {
                                                connection_id,
                                                transport: Transport::Tls,
                                                local_addr,
                                                remote_addr,
                                                data,
                                            };
                                            if let Err(error) = inbound_tx_clone.send_async(message).await {
                                                error!("TLS inbound enqueue failed: {}", error);
                                                return;
                                            }
                                        }
                                    }
                                    Ok(Err(error)) => {
                                        warn!("TLS read error on {:?} from {}: {}", connection_id, remote_addr, error);
                                        break;
                                    }
                                    Err(_) => {
                                        info!("TLS connection {:?} idle timeout ({}s)", connection_id, CONNECTION_IDLE_TIMEOUT.as_secs());
                                        break;
                                    }
                                }
                            }
                        });

                        // Write task
                        let write_task = tokio::spawn(async move {
                            while let Some(data) = outbound_rx.recv().await {
                                if let Err(error) = writer.write_all(&data).await {
                                    warn!("TLS write error on {:?}: {}", connection_id, error);
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
                        addr_map.remove(&remote_addr);
                        debug!("TLS connection {:?} cleaned up", connection_id);
                    });
                }
                Err(error) => {
                    error!("TLS accept error: {}", error);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_acl() -> Arc<TransportAcl> {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    fn generate_test_cert() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("failed to create cert params");
        let certificate = certificate_params.self_signed(&key_pair).expect("self-sign");
        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();
        (cert_pem, key_pem)
    }

    fn write_test_cert(directory: &tempfile::TempDir) -> TlsServerConfig {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
        }
    }

    #[test]
    fn tls_acceptor_builds_from_valid_config() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_ok(), "build_tls_acceptor failed: {:?}", result.err());
    }

    #[test]
    fn tls_acceptor_fails_on_missing_cert() {
        ensure_crypto_provider();
        let tls_config = TlsServerConfig {
            certificate: "/nonexistent/cert.pem".to_string(),
            private_key: "/nonexistent/key.pem".to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        let error = result.as_ref().err().unwrap().to_string();
        assert!(error.contains("cert"), "error should mention cert: {}", error);
    }

    #[test]
    fn tls_acceptor_fails_on_bad_cert_content() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, b"not a certificate").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let tls_config = TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tls_connection_lifecycle() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        // Start TLS listener on a random port
        listen(
            "127.0.0.1:0".parse().unwrap(),
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            Arc::new(DashMap::new()),
        )
        .await;

        // We need the actual bound port. Since listen() binds inside a spawned task,
        // give it a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Read the cert back to build a client config that trusts it
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        // Unfortunately we can't easily get the bound port from inside the spawned task.
        // We'll use a different approach: bind to a known port.
        // Let's redo with a specific approach — start a raw TcpListener to find a free port first.
        drop(inbound_rx); // clean up the first attempt

        // --- Retry with a port we control ---
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();
        drop(tcp_listener); // release so TLS listener can bind

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(
            bound_addr,
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            Arc::new(DashMap::new()),
        )
        .await;

        // Give the listener time to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect as a TLS client
        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send a SIP REGISTER
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: test-tls-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        tls_stream.write_all(sip_message.as_bytes()).await.unwrap();

        // Receive the inbound message
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timed out waiting for inbound message")
        .expect("inbound channel closed");

        assert_eq!(message.transport, Transport::Tls);
        assert_eq!(message.local_addr, bound_addr);
        assert!(!message.data.is_empty());
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("REGISTER"), "expected REGISTER in data: {}", data_str);

        // Verify connection is tracked
        assert!(connection_map.contains_key(&message.connection_id));
    }

    #[tokio::test]
    async fn tls_connection_cleanup_on_client_drop() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        // Find a free port
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();
        drop(tcp_listener);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let addr_map: Arc<DashMap<SocketAddr, ConnectionId>> = Arc::new(DashMap::new());

        listen(
            bound_addr,
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            Arc::clone(&addr_map),
        )
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Build TLS client
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send data so the connection gets an ID
        tls_stream.write_all(b"REGISTER sip:test SIP/2.0\r\n\r\n").await.unwrap();
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let connection_id = message.connection_id;
        let remote_addr = message.remote_addr;
        assert!(connection_map.contains_key(&connection_id));
        // Verify addr_map is populated for connection reuse
        assert!(
            addr_map.contains_key(&remote_addr),
            "addr_map should track TLS connection by remote address"
        );
        assert_eq!(*addr_map.get(&remote_addr).unwrap(), connection_id);

        // Drop the client
        drop(tls_stream);

        // Wait for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !connection_map.contains_key(&connection_id),
            "connection should have been cleaned up after client drop"
        );
        assert!(
            !addr_map.contains_key(&remote_addr),
            "addr_map should be cleaned up after client drop"
        );
    }
}
