//! RTPEngine NG protocol UDP client.
//!
//! Sends bencode-encoded commands to RTPEngine and correlates responses
//! using a random cookie prefix.  A background receiver task dispatches
//! responses to waiting callers via oneshot channels.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{debug, error, trace, warn};

use super::bencode::{self, BencodeValue};
use super::error::RtpEngineError;
use super::profile::NgFlags;

/// Async client for the RTPEngine NG control protocol.
pub struct RtpEngineClient {
    /// Local UDP socket bound to an ephemeral port.
    socket: Arc<UdpSocket>,
    /// RTPEngine NG control address.
    address: SocketAddr,
    /// Pending requests awaiting responses, keyed by cookie.
    pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>>,
    /// Response timeout in milliseconds.
    timeout_ms: u64,
}

impl RtpEngineClient {
    /// Create a new client and spawn the background receiver task.
    pub async fn new(address: SocketAddr, timeout_ms: u64) -> Result<Self, RtpEngineError> {
        // Bind to an ephemeral port (0 = OS-assigned).
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(socket);
        let pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>> =
            Arc::new(DashMap::new());

        // Spawn background receiver.
        {
            let socket = Arc::clone(&socket);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                receiver_loop(socket, pending).await;
            });
        }

        Ok(Self {
            socket,
            address,
            pending,
            timeout_ms,
        })
    }

    /// Send an `offer` command with SDP, returning the rewritten SDP.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send an `answer` command with SDP, returning the rewritten SDP.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("answer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send a `delete` command to tear down a media session.
    pub async fn delete(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("delete")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `query` command to get session statistics.
    pub async fn query(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<BencodeValue, RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("query")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];

        self.send_command(BencodeValue::dict(pairs)).await
    }

    /// Send a `subscribe request` command for SIPREC media forking.
    ///
    /// Creates a subscription on an existing call's media, returning SDP
    /// for the recording leg. Used to fork RTP to a Session Recording Server.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("subscribe request")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
        ];
        if let Some(sdp_bytes) = sdp {
            pairs.push(("sdp", BencodeValue::String(sdp_bytes.to_vec())));
        }
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send a `subscribe answer` command to complete SIPREC media subscription.
    ///
    /// Returns the rewritten SDP if RTPEngine includes one, or an empty vec
    /// if the command succeeded without returning SDP (which is valid for
    /// subscribe answer — unlike offer/answer, the response may omit SDP).
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("subscribe answer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;

        // subscribe answer may or may not return SDP — both are valid.
        Ok(response
            .dict_get_bytes("sdp")
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default())
    }

    /// Send an `unsubscribe` command to stop SIPREC media forking.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("unsubscribe")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `ping` command — health check.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("ping")),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        let result = response
            .dict_get_str("result")
            .ok_or_else(|| RtpEngineError::Protocol("ping response missing 'result'".to_string()))?;

        if result == "pong" {
            Ok(())
        } else {
            Err(RtpEngineError::Protocol(format!(
                "expected 'pong', got '{result}'"
            )))
        }
    }

    /// Send a bencode command and wait for the response.
    async fn send_command(
        &self,
        command: BencodeValue,
    ) -> Result<BencodeValue, RtpEngineError> {
        let cookie = generate_cookie();
        let encoded = bencode::encode(&command);

        // Build the wire message: "<cookie> <bencode>"
        let mut message = Vec::with_capacity(cookie.len() + 1 + encoded.len());
        message.extend_from_slice(cookie.as_bytes());
        message.push(b' ');
        message.extend_from_slice(&encoded);

        // Register the pending request before sending.
        let (sender, receiver) = oneshot::channel();
        self.pending.insert(cookie.clone(), sender);

        trace!(cookie = %cookie, address = %self.address, "sending NG command");

        // Send the UDP packet.
        self.socket.send_to(&message, self.address).await?;

        // Wait for the response with timeout.
        let timeout_duration = std::time::Duration::from_millis(self.timeout_ms);
        match tokio::time::timeout(timeout_duration, receiver).await {
            Ok(Ok(response)) => {
                debug!(cookie = %cookie, "received NG response");
                Ok(response)
            }
            Ok(Err(_)) => {
                // Sender was dropped (receiver task crashed or cleaned up).
                Err(RtpEngineError::Protocol(
                    "response channel closed unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                // Timeout — clean up the pending entry.
                self.pending.remove(&cookie);
                Err(RtpEngineError::Timeout {
                    timeout_ms: self.timeout_ms,
                })
            }
        }
    }

    /// Extract the rewritten SDP from an NG response, checking for errors.
    fn extract_sdp_response(&self, response: &BencodeValue) -> Result<Vec<u8>, RtpEngineError> {
        self.check_result(response)?;

        response
            .dict_get_bytes("sdp")
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                RtpEngineError::Protocol("response missing 'sdp' field".to_string())
            })
    }

    /// Check the `result` field of a response for errors.
    fn check_result(&self, response: &BencodeValue) -> Result<(), RtpEngineError> {
        let result = response
            .dict_get_str("result")
            .ok_or_else(|| {
                RtpEngineError::Protocol("response missing 'result' field".to_string())
            })?;

        if result == "ok" {
            Ok(())
        } else {
            let reason = response
                .dict_get_str("error-reason")
                .unwrap_or(result);
            Err(RtpEngineError::EngineError(reason.to_string()))
        }
    }
}

/// Generate a random cookie string for request/response correlation.
fn generate_cookie() -> String {
    // Use UUID v4, take the first 8 hex chars (no dashes).
    let uuid = uuid::Uuid::new_v4();
    uuid.simple().to_string()[..8].to_string()
}

/// Background receiver loop — reads UDP responses and dispatches to waiters.
async fn receiver_loop(
    socket: Arc<UdpSocket>,
    pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>>,
) {
    let mut buffer = BytesMut::zeroed(65535);

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((size, source)) => {
                let data = &buffer[..size];
                trace!(size, source = %source, "received NG response packet");

                // Split on the first space: cookie + bencode payload.
                let space_position = match data.iter().position(|&byte| byte == b' ') {
                    Some(position) => position,
                    None => {
                        warn!("NG response missing space separator, ignoring");
                        continue;
                    }
                };

                let cookie = match std::str::from_utf8(&data[..space_position]) {
                    Ok(cookie) => cookie.to_string(),
                    Err(_) => {
                        warn!("NG response cookie is not valid UTF-8, ignoring");
                        continue;
                    }
                };

                let payload = &data[space_position + 1..];
                match bencode::decode_full_dict(payload) {
                    Ok(value) => {
                        if let Some((_, sender)) = pending.remove(&cookie) {
                            let _ = sender.send(value);
                        } else {
                            debug!(cookie = %cookie, "no pending request for cookie (stale or duplicate)");
                        }
                    }
                    Err(error) => {
                        warn!(cookie = %cookie, error = %error, "failed to decode NG response");
                    }
                }
            }
            Err(error) => {
                error!(error = %error, "NG receiver socket error");
                // Brief pause before retrying to avoid busy-loop on persistent errors.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-instance set with weighted round-robin
// ---------------------------------------------------------------------------

/// A set of RTPEngine instances with weighted round-robin selection.
///
/// Call-ID affinity: once a call-id is assigned to an instance (via `offer`),
/// subsequent commands for that call-id go to the same instance.
pub struct RtpEngineSet {
    clients: Vec<RtpEngineClient>,
    /// Cumulative weights for weighted selection.
    cumulative_weights: Vec<u32>,
    total_weight: u32,
    /// Atomic counter for round-robin.
    counter: std::sync::atomic::AtomicU64,
    /// Call-ID → client index affinity.
    affinity: DashMap<String, usize>,
}

impl RtpEngineSet {
    /// Create a set from multiple address/timeout/weight triples.
    pub async fn new(
        instances: Vec<(SocketAddr, u64, u32)>,
    ) -> Result<Self, RtpEngineError> {
        if instances.is_empty() {
            return Err(RtpEngineError::Protocol(
                "at least one RTPEngine instance is required".to_string(),
            ));
        }

        let mut clients = Vec::with_capacity(instances.len());
        let mut cumulative_weights = Vec::with_capacity(instances.len());
        let mut running_total = 0u32;

        for (address, timeout_ms, weight) in &instances {
            clients.push(RtpEngineClient::new(*address, *timeout_ms).await?);
            running_total += weight;
            cumulative_weights.push(running_total);
        }

        Ok(Self {
            clients,
            cumulative_weights,
            total_weight: running_total,
            counter: std::sync::atomic::AtomicU64::new(0),
            affinity: DashMap::new(),
        })
    }

    /// Select a client by call-id affinity or weighted round-robin.
    fn select(&self, call_id: &str) -> &RtpEngineClient {
        if self.clients.len() == 1 {
            return &self.clients[0];
        }

        // Check affinity first.
        if let Some(index) = self.affinity.get(call_id) {
            return &self.clients[*index];
        }

        // Weighted round-robin: increment counter, mod by total weight,
        // then find the first cumulative weight that exceeds the value.
        let tick = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cw| position < cw)
            .unwrap_or(0);

        &self.clients[index]
    }

    /// Record call-id affinity after the first command.
    fn bind_affinity(&self, call_id: &str) {
        if self.clients.len() <= 1 {
            return;
        }
        if !self.affinity.contains_key(call_id) {
            // Find which client we'd select and bind it.
            if let Some(index) = self.affinity.get(call_id) {
                let _ = index; // already bound by another thread
            } else {
                let tick = self
                    .counter
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .wrapping_sub(1); // last used tick
                let position = (tick % self.total_weight as u64) as u32;
                let index = self
                    .cumulative_weights
                    .iter()
                    .position(|&cw| position < cw)
                    .unwrap_or(0);
                self.affinity.insert(call_id.to_string(), index);
            }
        }
    }

    /// Send an `offer` command, binding call-id affinity to the selected instance.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        let result = client.offer(call_id, from_tag, sdp, flags).await?;
        self.bind_affinity(call_id);
        Ok(result)
    }

    /// Send an `answer` command to the affinity-bound instance.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.answer(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send a `delete` command and remove affinity.
    pub async fn delete(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        let result = client.delete(call_id, from_tag).await;
        self.affinity.remove(call_id);
        result
    }

    /// Send a `query` command to the affinity-bound instance.
    pub async fn query(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<BencodeValue, RtpEngineError> {
        let client = self.select(call_id);
        client.query(call_id, from_tag).await
    }

    /// Send a `subscribe request` command to the affinity-bound instance.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.subscribe_request(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send a `subscribe answer` command to the affinity-bound instance.
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.subscribe_answer(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send an `unsubscribe` command to the affinity-bound instance.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.unsubscribe(call_id, from_tag, to_tag).await
    }

    /// Ping all instances. Returns Ok only if all respond.
    pub async fn ping_all(&self) -> Result<(), RtpEngineError> {
        for client in &self.clients {
            client.ping().await?;
        }
        Ok(())
    }

    /// Ping any one instance (the first healthy one). For quick health checks.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        if let Some(client) = self.clients.first() {
            client.ping().await
        } else {
            Err(RtpEngineError::Protocol("no RTPEngine instances".to_string()))
        }
    }

    /// Number of active call-id affinities.
    pub fn active_sessions(&self) -> usize {
        self.affinity.len()
    }

    /// Number of configured instances.
    pub fn instance_count(&self) -> usize {
        self.clients.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_format() {
        let cookie = generate_cookie();
        assert_eq!(cookie.len(), 8);
        assert!(cookie.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cookie_uniqueness() {
        let cookies: Vec<String> = (0..100).map(|_| generate_cookie()).collect();
        let unique: std::collections::HashSet<&String> = cookies.iter().collect();
        // With 8 hex chars (32 bits), collision in 100 samples is astronomically unlikely.
        assert_eq!(unique.len(), cookies.len());
    }

    #[tokio::test]
    async fn ping_roundtrip_with_mock() {
        // Spawn a mock RTPEngine that responds to ping with pong.
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                // Extract cookie.
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                // Build pong response.
                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("pong")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);

                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn offer_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let rewritten_sdp = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 203.0.113.1\r\n",
            "s=-\r\n",
            "c=IN IP4 203.0.113.1\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
        );

        let rewritten_sdp_clone = rewritten_sdp.to_string();
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                // Verify the command is an offer.
                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("offer"));
                assert_eq!(command.dict_get_str("call-id"), Some("test-call-1"));
                assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));

                // Build response with rewritten SDP.
                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string(&rewritten_sdp_clone)),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);

                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

        let original_sdp = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 8000 RTP/AVP 0\r\n",
        );

        let flags = NgFlags::default();
        let result = client
            .offer("test-call-1", "tag-a", original_sdp.as_bytes(), &flags)
            .await
            .unwrap();

        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.contains("203.0.113.1"));
        assert!(result_str.contains("30000"));
    }

    #[tokio::test]
    async fn answer_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("answer"));
                assert_eq!(command.dict_get_str("to-tag"), Some("tag-b"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\n")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let flags = NgFlags::default();
        let result = client
            .answer("call-1", "tag-a", "tag-b", b"v=0\r\nc=IN IP4 10.0.0.1\r\n", &flags)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&result).unwrap().contains("203.0.113.1"));
    }

    #[tokio::test]
    async fn delete_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("delete"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.delete("call-1", "tag-a").await.unwrap();
    }

    #[tokio::test]
    async fn timeout_on_no_response() {
        // Bind a socket but never respond.
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        // Keep the socket alive so the send doesn't fail with "connection refused".
        let _keep_alive = mock_socket;

        let client = RtpEngineClient::new(mock_addr, 100).await.unwrap();
        let result = client.ping().await;
        assert!(matches!(result, Err(RtpEngineError::Timeout { .. })));
    }

    #[tokio::test]
    async fn engine_error_response() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("error")),
                    ("error-reason", BencodeValue::string("session not found")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let result = client.delete("call-1", "tag-a").await;
        assert!(matches!(result, Err(RtpEngineError::EngineError(_))));
        assert!(result.unwrap_err().to_string().contains("session not found"));
    }

    // -- RtpEngineSet tests --

    /// Helper: spawn a mock RTPEngine that responds to all commands with "ok".
    async fn spawn_mock_rtpengine() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((size, source)) => {
                        let data = &buffer[..size];
                        let space = data.iter().position(|&b| b == b' ').unwrap();
                        let cookie = std::str::from_utf8(&data[..space]).unwrap().to_string();

                        let payload = &data[space + 1..];
                        let command = bencode::decode_full_dict(payload).unwrap();
                        let cmd_name = command.dict_get_str("command").unwrap_or("unknown");

                        let response = if cmd_name == "ping" {
                            BencodeValue::dict(vec![
                                ("result", BencodeValue::string("pong")),
                            ])
                        } else {
                            let mut pairs = vec![
                                ("result", BencodeValue::string("ok")),
                            ];
                            if cmd_name == "offer" || cmd_name == "answer" || cmd_name == "subscribe request" || cmd_name == "subscribe answer" {
                                pairs.push(("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\n")));
                            }
                            BencodeValue::dict(pairs)
                        };

                        let encoded = bencode::encode(&response);
                        let mut reply = Vec::new();
                        reply.extend_from_slice(cookie.as_bytes());
                        reply.push(b' ');
                        reply.extend_from_slice(&encoded);
                        let _ = socket.send_to(&reply, source).await;
                    }
                    Err(_) => break,
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn set_single_instance() {
        let addr = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![(addr, 2000, 1)]).await.unwrap();
        assert_eq!(set.instance_count(), 1);
        set.ping().await.unwrap();
    }

    #[tokio::test]
    async fn set_multiple_instances_ping_all() {
        let addr1 = spawn_mock_rtpengine().await;
        let addr2 = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![
            (addr1, 2000, 1),
            (addr2, 2000, 1),
        ]).await.unwrap();
        assert_eq!(set.instance_count(), 2);
        set.ping_all().await.unwrap();
    }

    #[tokio::test]
    async fn set_call_id_affinity() {
        let addr1 = spawn_mock_rtpengine().await;
        let addr2 = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![
            (addr1, 2000, 1),
            (addr2, 2000, 1),
        ]).await.unwrap();

        let flags = NgFlags::default();

        // First offer binds affinity.
        set.offer("call-abc", "tag-a", b"v=0\r\n", &flags).await.unwrap();
        assert_eq!(set.active_sessions(), 1);

        // Answer goes to the same instance (affinity).
        set.answer("call-abc", "tag-a", "tag-b", b"v=0\r\n", &flags).await.unwrap();
        assert_eq!(set.active_sessions(), 1);

        // Delete removes affinity.
        set.delete("call-abc", "tag-a").await.unwrap();
        assert_eq!(set.active_sessions(), 0);
    }

    #[tokio::test]
    async fn set_empty_instances_rejected() {
        let result = RtpEngineSet::new(vec![]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subscribe_request_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("subscribe request"));
                assert_eq!(command.dict_get_str("call-id"), Some("call-1"));
                assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));
                assert_eq!(command.dict_get_str("to-tag"), Some("tag-b"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\nm=audio 40000 RTP/AVP 0\r\n")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let flags = NgFlags::default();
        let result = client
            .subscribe_request("call-1", "tag-a", "tag-b", None, &flags)
            .await
            .unwrap();
        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.contains("203.0.113.1"));
        assert!(result_str.contains("40000"));
    }

    #[tokio::test]
    async fn unsubscribe_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("unsubscribe"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.unsubscribe("call-1", "tag-a", "tag-b").await.unwrap();
    }

    #[tokio::test]
    async fn set_subscribe_uses_affinity() {
        let addr = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![(addr, 2000, 1)]).await.unwrap();
        let flags = NgFlags::default();

        // First offer to bind affinity.
        set.offer("call-sub", "tag-a", b"v=0\r\n", &flags).await.unwrap();

        // subscribe_request uses the same instance via affinity.
        let result = set
            .subscribe_request("call-sub", "tag-a", "tag-b", None, &flags)
            .await
            .unwrap();
        assert!(!result.is_empty());
    }
}
