//! SIPREC — SIP-based Recording (RFC 7866).
//!
//! Manages recording sessions that fork media to a Session Recording Server (SRS).
//! When a B2BUA call is recorded, SIPhon sends an INVITE to the SRS with:
//! - Part 1: SDP (a=recvonly, mirroring the main call's media)
//! - Part 2: RFC 7866 recording metadata XML

pub mod metadata;
pub mod multipart;

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::Transport;

/// Fallback destination when SRS URI cannot be parsed to a socket address.
const FALLBACK_DESTINATION: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
    5060,
);

/// State of a recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// INVITE sent to SRS, waiting for response.
    Pending,
    /// SRS answered (200 OK), recording active.
    Active,
    /// BYE sent to SRS, recording stopped.
    Stopped,
    /// Recording failed (SRS rejected or error).
    Failed,
}

impl fmt::Display for RecordingState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(formatter, "pending"),
            Self::Active => write!(formatter, "active"),
            Self::Stopped => write!(formatter, "stopped"),
            Self::Failed => write!(formatter, "failed"),
        }
    }
}

/// A single recording session.
#[derive(Debug)]
pub struct RecordingSession {
    /// Recording session ID (UUID).
    pub session_id: String,
    /// The B2BUA call ID this recording belongs to.
    pub call_id: String,
    /// SRS URI (e.g. "sip:srs@recorder.example.com").
    pub srs_uri: String,
    /// Current state.
    pub state: RecordingState,
    /// SIP Call-ID for the recording INVITE dialog.
    pub sip_call_id: String,
    /// Branch used for the recording INVITE.
    pub branch: String,
    /// CSeq counter for this recording dialog.
    pub cseq: AtomicU32,
    /// From-tag for this recording dialog.
    pub from_tag: String,
    /// To-tag from the SRS 200 OK (set after answer).
    pub to_tag: Option<String>,
}

/// Manages all active recording sessions.
#[derive(Debug)]
pub struct RecordingManager {
    /// session_id -> RecordingSession
    sessions: DashMap<String, RecordingSession>,
    /// call_id -> list of session_ids (a call can have multiple recordings)
    call_sessions: DashMap<String, Vec<String>>,
    /// branch -> session_id (for routing SRS responses)
    branch_to_session: DashMap<String, String>,
    /// CSeq counter for recording INVITEs.
    cseq_counter: AtomicU32,
}

impl Default for RecordingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            call_sessions: DashMap::new(),
            branch_to_session: DashMap::new(),
            cseq_counter: AtomicU32::new(1),
        }
    }

    /// Start recording a call by sending INVITE to SRS.
    ///
    /// Returns the recording session ID and the SIP message to send.
    pub fn start_recording(
        &self,
        call_id: &str,
        srs_uri: &str,
        caller_uri: &str,
        callee_uri: &str,
        sdp: &[u8],
        local_addr: SocketAddr,
    ) -> Option<(String, SipMessage, SocketAddr, Transport)> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let sip_call_id = format!("siprec-{}", uuid::Uuid::new_v4());
        let branch = format!("z9hG4bK-rec-{}", uuid::Uuid::new_v4());
        let from_tag = format!("rec-{}", &session_id[..8]);
        let cseq = self.cseq_counter.fetch_add(1, Ordering::Relaxed);

        // Parse SRS URI to get destination — strip scheme and user part
        let srs_host_part = srs_uri
            .strip_prefix("sip:")
            .or_else(|| srs_uri.strip_prefix("sips:"))
            .unwrap_or(srs_uri);
        // Strip user@ if present (e.g. "srs@10.0.0.5:5060" -> "10.0.0.5:5060")
        let srs_host = if let Some(at_pos) = srs_host_part.find('@') {
            &srs_host_part[at_pos + 1..]
        } else {
            srs_host_part
        };

        let destination: SocketAddr = srs_host
            .parse()
            .or_else(|_| format!("{srs_host}:5060").parse())
            .unwrap_or(FALLBACK_DESTINATION);

        // Build recording metadata XML
        let metadata_xml = metadata::build_recording_metadata(
            &session_id,
            caller_uri,
            callee_uri,
        );

        // Build recvonly SDP from the call's SDP
        let recording_sdp = build_recording_sdp(sdp, local_addr);

        // Build multipart/mixed body
        let boundary = format!("srec-{}", &session_id[..8]);
        let multipart_body = build_multipart_body(&boundary, &recording_sdp, &metadata_xml);

        let request_uri = SipUri::new(srs_host.to_string());
        let via = format!("SIP/2.0/UDP {};branch={}", local_addr, branch);

        let message = SipMessageBuilder::new()
            .request(Method::Invite, request_uri)
            .via(via)
            .from(format!("<sip:recorder@{}>;tag={}", local_addr.ip(), from_tag))
            .to(format!("<{srs_uri}>"))
            .call_id(sip_call_id.clone())
            .cseq(format!("{cseq} INVITE"))
            .header("Contact", format!("<sip:recorder@{local_addr}>"))
            .header("Content-Type", format!("multipart/mixed;boundary={boundary}"))
            .header("Require", "siprec".to_string())
            .max_forwards(70)
            .body(multipart_body)
            .build();

        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(call_id = %call_id, %error, "failed to build recording INVITE");
                return None;
            }
        };

        let session = RecordingSession {
            session_id: session_id.clone(),
            call_id: call_id.to_string(),
            srs_uri: srs_uri.to_string(),
            state: RecordingState::Pending,
            sip_call_id,
            branch: branch.clone(),
            cseq: AtomicU32::new(cseq + 1),
            from_tag,
            to_tag: None,
        };

        self.sessions.insert(session_id.clone(), session);
        self.call_sessions
            .entry(call_id.to_string())
            .or_default()
            .push(session_id.clone());
        self.branch_to_session.insert(branch, session_id.clone());

        info!(
            call_id = %call_id,
            session_id = %session_id,
            srs = %srs_uri,
            "SIPREC: starting recording"
        );

        Some((session_id, message, destination, Transport::Udp))
    }

    /// Handle a 200 OK from the SRS — recording is now active.
    pub fn handle_success(&self, session_id: &str, to_tag: Option<String>) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.state = RecordingState::Active;
            session.to_tag = to_tag;
            info!(
                session_id = %session_id,
                call_id = %session.call_id,
                "SIPREC: recording active"
            );
        }
    }

    /// Handle a failure from the SRS.
    pub fn handle_failure(&self, session_id: &str, status_code: u16) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.state = RecordingState::Failed;
            warn!(
                session_id = %session_id,
                call_id = %session.call_id,
                status_code,
                "SIPREC: recording failed"
            );
        }
    }

    /// Stop recording a call by sending BYE to SRS.
    ///
    /// Returns a list of BYE messages to send.
    pub fn stop_recording(
        &self,
        call_id: &str,
        local_addr: SocketAddr,
    ) -> Vec<(SipMessage, SocketAddr, Transport)> {
        let session_ids = match self.call_sessions.get(call_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let mut bye_messages = Vec::new();

        for session_id in &session_ids {
            if let Some(mut session) = self.sessions.get_mut(session_id) {
                if session.state != RecordingState::Active {
                    continue;
                }

                session.state = RecordingState::Stopped;
                let cseq = session.cseq.fetch_add(1, Ordering::Relaxed);

                let srs_host_part = session.srs_uri
                    .strip_prefix("sip:")
                    .or_else(|| session.srs_uri.strip_prefix("sips:"))
                    .unwrap_or(&session.srs_uri);
                let srs_host = if let Some(at_pos) = srs_host_part.find('@') {
                    &srs_host_part[at_pos + 1..]
                } else {
                    srs_host_part
                };

                let destination: SocketAddr = srs_host
                    .parse()
                    .or_else(|_| format!("{srs_host}:5060").parse())
                    .unwrap_or(FALLBACK_DESTINATION);

                let request_uri = SipUri::new(srs_host.to_string());
                let branch = format!("z9hG4bK-rec-bye-{}", uuid::Uuid::new_v4());
                let via = format!("SIP/2.0/UDP {};branch={}", local_addr, branch);

                let mut to_value = format!("<{}>", session.srs_uri);
                if let Some(ref to_tag) = session.to_tag {
                    to_value.push_str(&format!(";tag={to_tag}"));
                }

                if let Ok(bye) = SipMessageBuilder::new()
                    .request(Method::Bye, request_uri)
                    .via(via)
                    .from(format!("<sip:recorder@{}>;tag={}", local_addr.ip(), session.from_tag))
                    .to(to_value)
                    .call_id(session.sip_call_id.clone())
                    .cseq(format!("{cseq} BYE"))
                    .max_forwards(70)
                    .content_length(0)
                    .build()
                {
                    bye_messages.push((bye, destination, Transport::Udp));
                    debug!(
                        session_id = %session_id,
                        "SIPREC: sending BYE to SRS"
                    );
                }
            }
        }

        // Clean up
        self.call_sessions.remove(call_id);
        for session_id in &session_ids {
            self.branch_to_session.retain(|_, value| value != session_id);
            self.sessions.remove(session_id);
        }

        bye_messages
    }

    /// Look up a recording session by branch (for routing SRS responses).
    pub fn session_for_branch(&self, branch: &str) -> Option<String> {
        self.branch_to_session.get(branch).map(|value| value.clone())
    }

    /// Check if a call has any active recording sessions.
    pub fn is_recording(&self, call_id: &str) -> bool {
        self.call_sessions.get(call_id)
            .map(|ids| {
                ids.iter().any(|id| {
                    self.sessions.get(id)
                        .map(|session| session.state == RecordingState::Active || session.state == RecordingState::Pending)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Number of active recording sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.iter()
            .filter(|session| session.state == RecordingState::Active)
            .count()
    }
}

/// Build a recvonly SDP from the call's SDP.
///
/// Rewrites the SDP to be recvonly (the SRS receives but does not send).
fn build_recording_sdp(original_sdp: &[u8], local_addr: SocketAddr) -> Vec<u8> {
    let sdp_str = String::from_utf8_lossy(original_sdp);

    // Simple SDP rewriting: replace sendrecv/sendonly with recvonly
    let mut result = String::new();
    for line in sdp_str.lines() {
        if line.starts_with("a=sendrecv") || line.starts_with("a=sendonly") {
            result.push_str("a=recvonly\r\n");
        } else if line.starts_with("o=") {
            // Replace origin address with our address
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() >= 6 {
                result.push_str(&format!(
                    "{} {} {} IN IP4 {}\r\n",
                    parts[0], parts[1], parts[2], local_addr.ip()
                ));
            } else {
                result.push_str(line);
                result.push_str("\r\n");
            }
        } else if line.starts_with("c=IN IP4 ") {
            // Replace connection address with our address
            result.push_str(&format!("c=IN IP4 {}\r\n", local_addr.ip()));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    result.into_bytes()
}

/// Build a multipart/mixed body with SDP and recording metadata XML.
fn build_multipart_body(boundary: &str, sdp: &[u8], metadata_xml: &str) -> Vec<u8> {
    let mut body = Vec::new();

    // SDP part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    body.extend_from_slice(sdp);
    if !sdp.ends_with(b"\r\n") {
        body.extend_from_slice(b"\r\n");
    }

    // Metadata XML part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/rs-metadata+xml\r\n\r\n");
    body.extend_from_slice(metadata_xml.as_bytes());
    if !metadata_xml.ends_with("\r\n") {
        body.extend_from_slice(b"\r\n");
    }

    // Closing boundary
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    body
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_state_display() {
        assert_eq!(RecordingState::Pending.to_string(), "pending");
        assert_eq!(RecordingState::Active.to_string(), "active");
        assert_eq!(RecordingState::Stopped.to_string(), "stopped");
        assert_eq!(RecordingState::Failed.to_string(), "failed");
    }

    #[test]
    fn recording_manager_new_is_empty() {
        let manager = RecordingManager::new();
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.is_recording("call-1"));
    }

    #[test]
    fn start_recording_creates_session() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let result = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        );

        assert!(result.is_some());
        let (session_id, message, destination, transport) = result.unwrap();

        assert!(manager.is_recording("call-1"));
        assert_eq!(destination, "10.0.0.5:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Udp);

        // Verify the INVITE message
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("INVITE"));
        assert!(raw.contains("Require: siprec"));
        assert!(raw.contains("multipart/mixed"));
        assert!(raw.contains("application/sdp"));
        assert!(raw.contains("application/rs-metadata+xml"));
        assert!(raw.contains("a=recvonly"));

        // Verify session is in pending state
        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Pending);
    }

    #[test]
    fn handle_success_activates_session() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        manager.handle_success(&session_id, Some("srs-tag-1".to_string()));

        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Active);
        assert_eq!(session.to_tag.as_deref(), Some("srs-tag-1"));
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn handle_failure_marks_failed() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        manager.handle_failure(&session_id, 503);

        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Failed);
    }

    #[test]
    fn stop_recording_sends_bye() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        manager.handle_success(&session_id, Some("srs-tag-1".to_string()));
        assert_eq!(manager.active_count(), 1);

        let bye_messages = manager.stop_recording("call-1", "10.0.0.1:5060".parse().unwrap());
        assert_eq!(bye_messages.len(), 1);

        let (bye, _destination, _transport) = &bye_messages[0];
        let bytes = bye.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("BYE"));
        assert!(raw.contains("srs-tag-1"));

        // Session should be cleaned up
        assert!(!manager.is_recording("call-1"));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn stop_recording_no_op_for_non_active() {
        let manager = RecordingManager::new();
        let bye_messages = manager.stop_recording("no-such-call", "10.0.0.1:5060".parse().unwrap());
        assert!(bye_messages.is_empty());
    }

    #[test]
    fn session_for_branch_routing() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, message, _, _) = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        // Extract branch from the message
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        let branch = raw.lines()
            .find(|line| line.starts_with("Via:"))
            .and_then(|line| line.split("branch=").nth(1))
            .map(|branch_value| branch_value.split(';').next().unwrap_or(branch_value).trim())
            .unwrap();

        assert_eq!(manager.session_for_branch(branch), Some(session_id));
        assert!(manager.session_for_branch("z9hG4bK-other").is_none());
    }

    #[test]
    fn build_recording_sdp_rewrites_sendrecv() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );
        let result = build_recording_sdp(sdp.as_bytes(), "10.0.0.2:5060".parse().unwrap());
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("a=recvonly"));
        assert!(!result_str.contains("a=sendrecv"));
    }

    #[test]
    fn build_recording_sdp_rewrites_connection_address() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );
        let result = build_recording_sdp(sdp.as_bytes(), "10.0.0.2:5060".parse().unwrap());
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("c=IN IP4 10.0.0.2"));
        assert!(!result_str.contains("c=IN IP4 10.0.0.1"));
    }

    #[test]
    fn build_multipart_body_structure() {
        let sdp = b"v=0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let xml = "<recording xmlns='urn:ietf:params:xml:ns:recording:1'/>";
        let body = build_multipart_body("test-boundary", sdp, xml);
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("--test-boundary\r\n"));
        assert!(body_str.contains("Content-Type: application/sdp"));
        assert!(body_str.contains("Content-Type: application/rs-metadata+xml"));
        assert!(body_str.contains("--test-boundary--\r\n"));
    }

    #[test]
    fn multiple_recordings_per_call() {
        let manager = RecordingManager::new();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id_1, _, _, _) = manager.start_recording(
            "call-1",
            "sip:srs1@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        let (session_id_2, _, _, _) = manager.start_recording(
            "call-1",
            "sip:srs2@10.0.0.6:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
        ).unwrap();

        assert_ne!(session_id_1, session_id_2);
        assert!(manager.is_recording("call-1"));

        // Activate both
        manager.handle_success(&session_id_1, Some("tag-1".to_string()));
        manager.handle_success(&session_id_2, Some("tag-2".to_string()));
        assert_eq!(manager.active_count(), 2);

        // Stop all recordings for the call
        let bye_messages = manager.stop_recording("call-1", "10.0.0.1:5060".parse().unwrap());
        assert_eq!(bye_messages.len(), 2);
        assert_eq!(manager.active_count(), 0);
    }
}
