//! RFC 3680 Registration Event — `application/reginfo+xml` body generation.
//!
//! Generates registration information documents for the `reg` event package.
//! Used by the S-CSCF to notify Application Servers about registration state
//! changes via SUBSCRIBE/NOTIFY (3GPP TS 24.229).
//!
//! XML is generated as formatted strings following the same pattern as
//! `presence/pidf.rs` — no external XML crate needed.

use std::fmt;

use super::Contact;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Document state: `"full"` (complete snapshot) or `"partial"` (delta update).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReginfoState {
    Full,
    Partial,
}

impl fmt::Display for ReginfoState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReginfoState::Full => write!(formatter, "full"),
            ReginfoState::Partial => write!(formatter, "partial"),
        }
    }
}

/// Per-AoR registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Initial registration (not yet confirmed).
    Init,
    /// At least one active contact binding.
    Active,
    /// All contacts expired or deregistered.
    Terminated,
}

impl fmt::Display for RegistrationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationState::Init => write!(formatter, "init"),
            RegistrationState::Active => write!(formatter, "active"),
            RegistrationState::Terminated => write!(formatter, "terminated"),
        }
    }
}

/// Per-contact binding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    Active,
    Terminated,
}

impl fmt::Display for ContactState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactState::Active => write!(formatter, "active"),
            ContactState::Terminated => write!(formatter, "terminated"),
        }
    }
}

/// What happened to the contact (RFC 3680 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactEvent {
    Registered,
    Created,
    Refreshed,
    Shortened,
    Deactivated,
    Expired,
    Unregistered,
    Rejected,
    Probation,
}

impl fmt::Display for ContactEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ContactEvent::Registered => "registered",
            ContactEvent::Created => "created",
            ContactEvent::Refreshed => "refreshed",
            ContactEvent::Shortened => "shortened",
            ContactEvent::Deactivated => "deactivated",
            ContactEvent::Expired => "expired",
            ContactEvent::Unregistered => "unregistered",
            ContactEvent::Rejected => "rejected",
            ContactEvent::Probation => "probation",
        };
        write!(formatter, "{}", label)
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A single contact binding within a registration.
#[derive(Debug, Clone)]
pub struct ReginfoContact {
    /// Contact URI (e.g. `sip:alice@10.0.0.1:5060`).
    pub uri: String,
    /// Binding state.
    pub state: ContactState,
    /// What event triggered this state.
    pub event: ContactEvent,
    /// Remaining expires in seconds (None for terminated contacts).
    pub expires: Option<u64>,
    /// Quality value (0.0–1.0).
    pub q: Option<f32>,
}

/// A single AoR registration entry.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Address of Record (e.g. `sip:alice@ims.example.com`).
    pub aor: String,
    /// Unique registration ID (stable across NOTIFYs for the same AoR).
    pub id: String,
    /// Registration state.
    pub state: RegistrationState,
    /// Contact bindings.
    pub contacts: Vec<ReginfoContact>,
}

/// A complete reginfo document (RFC 3680 §5).
#[derive(Debug, Clone)]
pub struct ReginfoBody {
    /// Monotonically increasing document version.
    pub version: u32,
    /// `"full"` (complete snapshot) or `"partial"` (delta).
    pub state: ReginfoState,
    /// Registrations in this document.
    pub registrations: Vec<Registration>,
}

impl ReginfoBody {
    /// MIME content type for this document.
    pub fn content_type() -> &'static str {
        "application/reginfo+xml"
    }

    /// Serialize to RFC 3680 reginfo XML.
    pub fn to_xml(&self) -> String {
        let mut output = String::with_capacity(512);
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str(&format!(
            "<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"{}\" state=\"{}\">\n",
            self.version, self.state,
        ));

        for registration in &self.registrations {
            output.push_str(&format!(
                "  <registration aor=\"{}\" id=\"{}\" state=\"{}\">\n",
                xml_escape(&registration.aor),
                xml_escape(&registration.id),
                registration.state,
            ));

            for contact in &registration.contacts {
                output.push_str(&format!(
                    "    <contact id=\"c-{}\" state=\"{}\" event=\"{}\"",
                    xml_escape(&contact.uri),
                    contact.state,
                    contact.event,
                ));
                if let Some(expires) = contact.expires {
                    output.push_str(&format!(" expires=\"{expires}\""));
                }
                if let Some(q) = contact.q {
                    output.push_str(&format!(" q=\"{q:.1}\""));
                }
                output.push_str(">\n");
                output.push_str(&format!(
                    "      <uri>{}</uri>\n",
                    xml_escape(&contact.uri),
                ));
                output.push_str("    </contact>\n");
            }

            output.push_str("  </registration>\n");
        }

        output.push_str("</reginfo>\n");
        output
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a full-state reginfo document from current registrar contacts.
///
/// If `contacts` is empty, the registration is marked as terminated.
pub fn build_full_reginfo(aor: &str, contacts: &[Contact], version: u32) -> ReginfoBody {
    let registration_state = if contacts.is_empty() {
        RegistrationState::Terminated
    } else {
        RegistrationState::Active
    };

    let reginfo_contacts: Vec<ReginfoContact> = contacts
        .iter()
        .filter(|contact| !contact.is_expired())
        .map(|contact| ReginfoContact {
            uri: contact.uri.to_string(),
            state: ContactState::Active,
            event: ContactEvent::Registered,
            expires: Some(contact.remaining_seconds()),
            q: Some(contact.q),
        })
        .collect();

    // Generate a stable registration ID from the AoR.
    let id = format!("reg-{:x}", hash_aor(aor));

    ReginfoBody {
        version,
        state: ReginfoState::Full,
        registrations: vec![Registration {
            aor: aor.to_string(),
            id,
            state: registration_state,
            contacts: reginfo_contacts,
        }],
    }
}

/// Simple hash for generating stable registration IDs.
fn hash_aor(aor: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in aor.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

/// Escape XML special characters.
fn xml_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::sip::uri::SipUri;

    fn make_contact(uri_str: &str, expires_secs: u64) -> Contact {
        let mut uri = SipUri::new("10.0.0.1".to_string());
        uri.user = Some("alice".to_string());
        uri.port = Some(5060);
        let _ = uri_str;
        Contact {
            uri,
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: Duration::from_secs(expires_secs),
            call_id: "test-call-id".to_string(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
        }
    }

    #[test]
    fn content_type() {
        assert_eq!(ReginfoBody::content_type(), "application/reginfo+xml");
    }

    #[test]
    fn full_reginfo_with_active_contacts() {
        let contacts = vec![make_contact("sip:alice@10.0.0.1:5060", 3600)];
        let body = build_full_reginfo("sip:alice@ims.example.com", &contacts, 0);

        assert_eq!(body.version, 0);
        assert_eq!(body.state, ReginfoState::Full);
        assert_eq!(body.registrations.len(), 1);
        assert_eq!(body.registrations[0].state, RegistrationState::Active);
        assert_eq!(body.registrations[0].contacts.len(), 1);
        assert_eq!(body.registrations[0].contacts[0].state, ContactState::Active);
        assert_eq!(body.registrations[0].contacts[0].event, ContactEvent::Registered);

        let xml = body.to_xml();
        assert!(xml.contains("application/reginfo+xml") == false); // content type is separate
        assert!(xml.contains("urn:ietf:params:xml:ns:reginfo"));
        assert!(xml.contains("version=\"0\""));
        assert!(xml.contains("state=\"full\""));
        assert!(xml.contains("sip:alice@ims.example.com"));
        assert!(xml.contains("state=\"active\""));
        assert!(xml.contains("event=\"registered\""));
        assert!(xml.contains("<uri>"));
    }

    #[test]
    fn full_reginfo_no_contacts_is_terminated() {
        let body = build_full_reginfo("sip:bob@ims.example.com", &[], 5);

        assert_eq!(body.registrations[0].state, RegistrationState::Terminated);
        assert!(body.registrations[0].contacts.is_empty());

        let xml = body.to_xml();
        assert!(xml.contains("state=\"terminated\""));
        assert!(xml.contains("version=\"5\""));
    }

    #[test]
    fn xml_escapes_special_characters() {
        let body = ReginfoBody {
            version: 0,
            state: ReginfoState::Full,
            registrations: vec![Registration {
                aor: "sip:alice&bob@example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![],
            }],
        };
        let xml = body.to_xml();
        assert!(xml.contains("alice&amp;bob"));
    }

    #[test]
    fn reginfo_states_display() {
        assert_eq!(ReginfoState::Full.to_string(), "full");
        assert_eq!(ReginfoState::Partial.to_string(), "partial");
        assert_eq!(RegistrationState::Active.to_string(), "active");
        assert_eq!(RegistrationState::Terminated.to_string(), "terminated");
        assert_eq!(RegistrationState::Init.to_string(), "init");
        assert_eq!(ContactState::Active.to_string(), "active");
        assert_eq!(ContactState::Terminated.to_string(), "terminated");
        assert_eq!(ContactEvent::Registered.to_string(), "registered");
        assert_eq!(ContactEvent::Expired.to_string(), "expired");
        assert_eq!(ContactEvent::Unregistered.to_string(), "unregistered");
    }

    #[test]
    fn stable_registration_id() {
        let body1 = build_full_reginfo("sip:alice@ims.example.com", &[], 0);
        let body2 = build_full_reginfo("sip:alice@ims.example.com", &[], 1);
        // Same AoR should produce same registration ID.
        assert_eq!(body1.registrations[0].id, body2.registrations[0].id);

        // Different AoR should produce different registration ID.
        let body3 = build_full_reginfo("sip:bob@ims.example.com", &[], 0);
        assert_ne!(body1.registrations[0].id, body3.registrations[0].id);
    }

    #[test]
    fn contact_with_q_and_expires() {
        let contact = ReginfoContact {
            uri: "sip:alice@10.0.0.1:5060".to_string(),
            state: ContactState::Active,
            event: ContactEvent::Refreshed,
            expires: Some(1800),
            q: Some(0.5),
        };
        let body = ReginfoBody {
            version: 2,
            state: ReginfoState::Partial,
            registrations: vec![Registration {
                aor: "sip:alice@example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![contact],
            }],
        };
        let xml = body.to_xml();
        assert!(xml.contains("expires=\"1800\""));
        assert!(xml.contains("q=\"0.5\""));
        assert!(xml.contains("event=\"refreshed\""));
        assert!(xml.contains("state=\"partial\""));
    }
}
