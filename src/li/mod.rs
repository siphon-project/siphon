//! Lawful Intercept — ETSI X1/X2/X3 + SIPREC (RFC 7866).
//!
//! This module implements the three ETSI LI interfaces:
//!
//! - **X1** (TS 103 221-1): Administration — provision/modify/deactivate intercept targets
//! - **X2** (TS 102 232-5): IRI delivery — real-time signaling events (ASN.1/BER over TCP/TLS)
//! - **X3** (TS 102 232-1): CC delivery — media content via RTPEngine recording + encapsulation
//! - **SIPREC** (RFC 7866): SIP-based media recording to an SRS
//!
//! # Architecture
//!
//! The LI manager holds:
//! - A [`TargetStore`] of active intercept targets (provisioned via X1)
//! - An X2 sender channel for IRI events
//! - An X3 handler for media capture control
//! - An audit logger for compliance
//!
//! The dispatcher calls [`LiManager::check_message`] on every SIP message.
//! If the message matches an active target, IRI events are emitted to X2
//! and (for IRI+CC targets) media capture is triggered via X3/SIPREC.

pub mod target;
pub mod asn1;
pub mod x1;
pub mod x2;
pub mod x3;
pub mod siprec;

use crate::config::LawfulInterceptConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use target::{DeliveryType, InterceptTarget, TargetStore};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

/// IRI event types per ETSI TS 102 232-5 §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IriEventType {
    /// Session/call initiation (INVITE received).
    Begin,
    /// Call progress (1xx provisional, re-INVITE).
    Continue,
    /// Session termination (BYE, CANCEL, error response).
    End,
    /// Standalone event (REGISTER, MESSAGE, SUBSCRIBE, etc.).
    Report,
}

/// An IRI (Intercept Related Information) event to be delivered via X2.
#[derive(Debug, Clone)]
pub struct IriEvent {
    /// LIID of the matching intercept target.
    pub liid: String,
    /// Correlation identifier (typically Call-ID for call correlation).
    pub correlation_id: String,
    /// Event type.
    pub event_type: IriEventType,
    /// Timestamp of the event.
    pub timestamp: SystemTime,
    /// SIP method (INVITE, BYE, REGISTER, etc.).
    pub sip_method: String,
    /// SIP status code (for responses), None for requests.
    pub status_code: Option<u16>,
    /// From URI.
    pub from_uri: String,
    /// To URI.
    pub to_uri: String,
    /// Request-URI (for requests).
    pub request_uri: Option<String>,
    /// Source IP of the SIP message.
    pub source_ip: Option<IpAddr>,
    /// Destination IP of the SIP message.
    pub destination_ip: Option<IpAddr>,
    /// The delivery type for this target (determines if X3 is also needed).
    pub delivery_type: DeliveryType,
    /// Raw SIP message bytes (included in IRI for full signaling capture).
    pub raw_message: Option<Vec<u8>>,
}

/// Audit log entry — every X1 operation and intercept match is recorded.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: SystemTime,
    pub operation: AuditOperation,
    pub liid: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub enum AuditOperation {
    /// X1: Target activated.
    TargetActivated,
    /// X1: Target modified.
    TargetModified,
    /// X1: Target deactivated.
    TargetDeactivated,
    /// X1: Target listing requested.
    TargetListed,
    /// Message matched an intercept target.
    InterceptMatch,
    /// X2: IRI event delivered.
    IriDelivered,
    /// X3: Media capture started.
    MediaCaptureStarted,
    /// X3: Media capture stopped.
    MediaCaptureStopped,
    /// System: LI subsystem started.
    SystemStarted,
    /// System: LI subsystem stopped.
    SystemStopped,
}

/// Central LI manager — holds target store, X2 sender, audit logger.
#[derive(Clone)]
pub struct LiManager {
    /// Active intercept targets.
    targets: Arc<TargetStore>,
    /// Channel to X2 delivery task.
    iri_sender: mpsc::Sender<IriEvent>,
    /// Audit log sender.
    audit_sender: mpsc::Sender<AuditEntry>,
    /// Configuration snapshot.
    config: Arc<LawfulInterceptConfig>,
}

impl LiManager {
    /// Initialize the LI subsystem from configuration.
    ///
    /// Returns the manager and background task receivers that must be spawned.
    pub fn new(
        config: LawfulInterceptConfig,
        iri_channel_size: usize,
    ) -> (Self, mpsc::Receiver<IriEvent>, mpsc::Receiver<AuditEntry>) {
        let (iri_sender, iri_receiver) = mpsc::channel(iri_channel_size);
        let (audit_sender, audit_receiver) = mpsc::channel(10_000);

        let manager = Self {
            targets: Arc::new(TargetStore::new()),
            iri_sender,
            audit_sender,
            config: Arc::new(config),
        };

        // Log startup
        let _ = manager.audit_sender.try_send(AuditEntry {
            timestamp: SystemTime::now(),
            operation: AuditOperation::SystemStarted,
            liid: None,
            detail: "LI subsystem initialized".to_string(),
        });

        info!("lawful intercept subsystem initialized");

        (manager, iri_receiver, audit_receiver)
    }

    /// Check a SIP message against active intercept targets.
    ///
    /// Called by the dispatcher on every inbound/outbound SIP message.
    /// Returns the list of matching targets (empty if no match).
    pub fn check_message(
        &self,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<InterceptTarget> {
        if !self.config.enabled {
            return Vec::new();
        }

        self.targets.match_message(request_uri, from_uri, to_uri, source_ip)
    }

    /// Emit an IRI event for X2 delivery (non-blocking).
    pub fn emit_iri(&self, event: IriEvent) {
        if let Err(error) = self.iri_sender.try_send(event) {
            match error {
                mpsc::error::TrySendError::Full(event) => {
                    warn!(liid = %event.liid, "X2 IRI channel full, dropping event");
                }
                mpsc::error::TrySendError::Closed(event) => {
                    error!(liid = %event.liid, "X2 IRI channel closed");
                }
            }
        }
    }

    /// Record an audit entry (non-blocking).
    pub fn audit(&self, operation: AuditOperation, liid: Option<&str>, detail: String) {
        let entry = AuditEntry {
            timestamp: SystemTime::now(),
            operation,
            liid: liid.map(String::from),
            detail,
        };
        if self.audit_sender.try_send(entry).is_err() {
            error!("audit log channel full or closed — compliance violation");
        }
    }

    /// Get a reference to the target store (used by X1 endpoints).
    pub fn targets(&self) -> &TargetStore {
        &self.targets
    }

    /// Get the configuration.
    pub fn config(&self) -> &LawfulInterceptConfig {
        &self.config
    }

    /// Whether the LI subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

impl std::fmt::Debug for LiManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("LiManager")
            .field("enabled", &self.config.enabled)
            .field("active_targets", &self.targets.count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use target::TargetIdentity;

    fn test_config() -> LawfulInterceptConfig {
        LawfulInterceptConfig {
            enabled: true,
            audit_log: Some("/tmp/li-audit-test.log".to_string()),
            x1: None,
            x2: None,
            x3: None,
            siprec: None,
        }
    }

    #[test]
    fn manager_creation() {
        let (manager, _iri_receiver, _audit_receiver) = LiManager::new(test_config(), 100);
        assert!(manager.is_enabled());
        assert_eq!(manager.targets().count(), 0);
    }

    #[test]
    fn check_message_returns_empty_when_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let (manager, _iri_receiver, _audit_receiver) = LiManager::new(config, 100);

        // Add a target that would match
        manager.targets().activate(InterceptTarget {
            liid: "LI-001".to_string(),
            target_identity: TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            delivery_type: DeliveryType::IriOnly,
            active: true,
            activated_at: SystemTime::now(),
            warrant_ref: None,
            mediation_id: None,
        });

        // Should return empty because disabled
        let matches = manager.check_message(
            None,
            Some("sip:alice@example.com"),
            None,
            None,
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn check_message_matches_when_enabled() {
        let (manager, _iri_receiver, _audit_receiver) = LiManager::new(test_config(), 100);
        manager.targets().activate(InterceptTarget {
            liid: "LI-001".to_string(),
            target_identity: TargetIdentity::SipUri("sip:alice@example.com".to_string()),
            delivery_type: DeliveryType::IriAndCc,
            active: true,
            activated_at: SystemTime::now(),
            warrant_ref: None,
            mediation_id: None,
        });

        let matches = manager.check_message(
            None,
            Some("sip:alice@example.com"),
            None,
            None,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].delivery_type, DeliveryType::IriAndCc);
    }

    #[tokio::test]
    async fn emit_iri_delivers_to_channel() {
        let (manager, mut iri_receiver, _audit_receiver) = LiManager::new(test_config(), 100);

        manager.emit_iri(IriEvent {
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
        });

        let event = iri_receiver.recv().await.unwrap();
        assert_eq!(event.liid, "LI-001");
        assert_eq!(event.event_type, IriEventType::Begin);
        assert_eq!(event.sip_method, "INVITE");
    }

    #[tokio::test]
    async fn audit_entries_delivered() {
        let (manager, _iri_receiver, mut audit_receiver) = LiManager::new(test_config(), 100);

        // Drain the SystemStarted entry from new()
        let startup_entry = audit_receiver.recv().await.unwrap();
        assert!(matches!(startup_entry.operation, AuditOperation::SystemStarted));

        manager.audit(
            AuditOperation::TargetActivated,
            Some("LI-001"),
            "Target activated: sip:alice@example.com".to_string(),
        );

        let entry = audit_receiver.recv().await.unwrap();
        assert!(matches!(entry.operation, AuditOperation::TargetActivated));
        assert_eq!(entry.liid.unwrap(), "LI-001");
    }
}
