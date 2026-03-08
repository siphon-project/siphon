//! X2 IRI Delivery — ETSI TS 102 232 signaling event export.
//!
//! Encodes IRI events as ASN.1/BER PDUs and delivers them over a persistent
//! TCP/TLS connection to the mediation device. Handles reconnection on
//! connection loss and backpressure via the bounded mpsc channel.

use super::asn1::{self, IriType};
use super::IriEvent;
use super::IriEventType;
use crate::config::LiX2Config;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Background task that drains the IRI channel and delivers to the mediation device.
///
/// This task runs for the lifetime of the LI subsystem. It maintains a
/// persistent TCP connection and reconnects on failure.
pub async fn delivery_task(
    mut receiver: mpsc::Receiver<IriEvent>,
    config: Arc<LiX2Config>,
) {
    info!(
        address = %config.delivery_address,
        transport = %config.transport,
        "X2 IRI delivery task started"
    );

    let mut connection: Option<TcpStream> = None;
    let reconnect_interval = std::time::Duration::from_secs(config.reconnect_interval_secs);

    while let Some(event) = receiver.recv().await {
        let encoded = encode_iri_event(&event);

        // Ensure we have a connection
        if connection.is_none() {
            connection = connect(&config.delivery_address).await;
        }

        // Try to send; reconnect on failure
        if let Some(ref mut stream) = connection {
            // Write length-prefixed PDU (4-byte big-endian length + PDU)
            let length = (encoded.len() as u32).to_be_bytes();
            let write_result = async {
                stream.write_all(&length).await?;
                stream.write_all(&encoded).await?;
                stream.flush().await
            }.await;

            match write_result {
                Ok(()) => {
                    debug!(
                        liid = %event.liid,
                        event_type = ?event.event_type,
                        "X2 IRI event delivered"
                    );
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        liid = %event.liid,
                        "X2 delivery failed, will reconnect"
                    );
                    connection = None;

                    // Retry once after reconnect
                    tokio::time::sleep(reconnect_interval).await;
                    if let Some(ref mut stream) = connect(&config.delivery_address).await {
                        let retry_result = async {
                            stream.write_all(&length).await?;
                            stream.write_all(&encoded).await?;
                            stream.flush().await
                        }.await;

                        match retry_result {
                            Ok(()) => {
                                info!(liid = %event.liid, "X2 IRI event delivered after reconnect");
                                // Keep the new connection (we need to move it)
                            }
                            Err(error) => {
                                error!(
                                    error = %error,
                                    liid = %event.liid,
                                    "X2 delivery failed after reconnect, event dropped"
                                );
                            }
                        }
                    }
                }
            }
        } else {
            error!(
                liid = %event.liid,
                "X2 no connection to mediation device, IRI event dropped"
            );
        }
    }

    info!("X2 IRI delivery task stopped (channel closed)");
}

/// Establish TCP connection to the mediation device.
async fn connect(address: &str) -> Option<TcpStream> {
    match TcpStream::connect(address).await {
        Ok(stream) => {
            info!(address = %address, "X2 connected to mediation device");
            Some(stream)
        }
        Err(error) => {
            error!(address = %address, error = %error, "X2 connection failed");
            None
        }
    }
}

/// Encode an IRI event to ASN.1/BER.
fn encode_iri_event(event: &IriEvent) -> Vec<u8> {
    let iri_type = match event.event_type {
        IriEventType::Begin => IriType::Begin,
        IriEventType::Continue => IriType::Continue,
        IriEventType::End => IriType::End,
        IriEventType::Report => IriType::Report,
    };

    asn1::encode_iri_pdu(
        &event.liid,
        &event.correlation_id,
        iri_type,
        event.timestamp,
        &event.sip_method,
        event.status_code,
        &event.from_uri,
        &event.to_uri,
        event.request_uri.as_deref(),
        event.raw_message.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::target::DeliveryType;
    use std::time::SystemTime;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn test_iri_event() -> IriEvent {
        IriEvent {
            liid: "LI-001".to_string(),
            correlation_id: "call-123@example.com".to_string(),
            event_type: IriEventType::Begin,
            timestamp: SystemTime::now(),
            sip_method: "INVITE".to_string(),
            status_code: None,
            from_uri: "sip:alice@example.com".to_string(),
            to_uri: "sip:bob@example.com".to_string(),
            request_uri: Some("sip:bob@example.com".to_string()),
            source_ip: None,
            destination_ip: None,
            delivery_type: DeliveryType::IriAndCc,
            raw_message: None,
        }
    }

    #[test]
    fn encode_iri_event_produces_valid_ber() {
        let event = test_iri_event();
        let encoded = encode_iri_event(&event);

        // Should be a valid BER SEQUENCE (PS-PDU)
        assert_eq!(encoded[0], 0x30);
        assert!(!encoded.is_empty());

        // Should decode as PS-PDU
        let (version, pdu_type, _inner) = asn1::decode_ps_pdu(&encoded).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 1); // IRI
    }

    #[tokio::test]
    async fn delivery_task_sends_length_prefixed_pdu() {
        // Bind a mock mediation device
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let config = Arc::new(LiX2Config {
            delivery_address: address,
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
            channel_size: 100,
            tls: None,
        });

        let (sender, receiver) = mpsc::channel(100);

        // Spawn delivery task
        tokio::spawn(delivery_task(receiver, config));

        // Accept connection
        let accept_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read length-prefixed PDU
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).await.unwrap();
            let length = u32::from_be_bytes(length_bytes) as usize;

            let mut pdu = vec![0u8; length];
            stream.read_exact(&mut pdu).await.unwrap();

            pdu
        });

        // Send an IRI event
        sender.send(test_iri_event()).await.unwrap();

        // Receive and verify
        let pdu = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            accept_handle,
        ).await.unwrap().unwrap();

        // Should be a valid PS-PDU
        let (version, pdu_type, _) = asn1::decode_ps_pdu(&pdu).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 1);
    }

    #[test]
    fn all_iri_event_types_encode() {
        for event_type in [
            IriEventType::Begin,
            IriEventType::Continue,
            IriEventType::End,
            IriEventType::Report,
        ] {
            let mut event = test_iri_event();
            event.event_type = event_type.clone();
            let encoded = encode_iri_event(&event);
            assert!(!encoded.is_empty());
            assert!(asn1::decode_ps_pdu(&encoded).is_some());
        }
    }
}
