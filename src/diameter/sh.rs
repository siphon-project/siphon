//! Sh Diameter interface per 3GPP TS 29.328/329.
//!
//! Provides typed request parsing and answer building for the Sh interface
//! between Application Servers (AS) and the HSS:
//!   - UDR/UDA: user data queries
//!   - PUR/PUA: profile updates
//!   - SNR/SNA: notification subscriptions
//!   - PNR/PNA: push notifications from HSS

use crate::diameter::codec::*;
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::IncomingRequest;

/// Data-Reference values per TS 29.328 section 7.6.
pub mod data_reference {
    pub const REPOSITORY_DATA: u32 = 0;
    pub const IMS_PUBLIC_IDENTITY: u32 = 10;
    pub const IMS_USER_STATE: u32 = 11;
    pub const S_CSCF_NAME: u32 = 12;
    pub const INITIAL_FILTER_CRITERIA: u32 = 13;
    pub const LOCATION_INFO: u32 = 14;
    pub const USER_STATE: u32 = 15;
    pub const CHARGING_INFO: u32 = 16;
    pub const MSISDN: u32 = 17;
    pub const PSI_ACTIVATION: u32 = 18;
    pub const DSAI: u32 = 19;
    pub const SERVICE_LEVEL_TRACE: u32 = 21;
    pub const IP_ADDRESS_SECURE_BINDING: u32 = 22;
}

/// Subscription request type for SNR.
pub mod subscription_type {
    pub const SUBSCRIBE: u32 = 0;
    pub const UNSUBSCRIBE: u32 = 1;
}

// ── AVP extraction helpers ─────────────────────────────────────────────────

fn mandatory_string(avps: &serde_json::Value, key: &str) -> Option<String> {
    avps.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn extract_public_identity(avps: &serde_json::Value) -> Option<String> {
    avps.get("User-Identity")
        .and_then(|ui| ui.get("Public-Identity"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn collect_data_references(avps: &serde_json::Value) -> Option<Vec<u32>> {
    match avps.get("Data-Reference") {
        Some(serde_json::Value::Array(items)) => {
            let refs: Vec<u32> = items
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect();
            if refs.is_empty() { None } else { Some(refs) }
        }
        Some(single) => single.as_u64().map(|n| vec![n as u32]),
        None => None,
    }
}

fn decode_octet_string_xml(avps: &serde_json::Value, key: &str) -> Option<String> {
    avps.get(key)
        .and_then(|v| v.as_str())
        .and_then(crate::diameter::codec::hex::decode)
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

// ── Sh Answer Builder ──────────────────────────────────────────────────────

/// Fluent builder for constructing Sh answer messages.
struct ShAnswerBuilder {
    avp_payload: Vec<u8>,
    command: u32,
    hbh: u32,
    e2e: u32,
    is_request: bool,
}

impl ShAnswerBuilder {
    fn new(command: u32, hbh: u32, e2e: u32) -> Self {
        Self {
            avp_payload: Vec::new(),
            command,
            hbh,
            e2e,
            is_request: false,
        }
    }

    fn request(mut self) -> Self {
        self.is_request = true;
        self
    }

    fn session(mut self, session_id: &str) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        self
    }

    fn origin(mut self, host: &str, realm: &str) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, host));
        self.avp_payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, realm));
        self
    }

    fn destination(mut self, host: &str, realm: &str) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
        self.avp_payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, realm));
        self
    }

    fn result_code(mut self, code: u32) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, code));
        self
    }

    fn experimental_result(mut self, vendor: u32, code: u32) -> Self {
        let mut children = Vec::new();
        children.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, vendor));
        children.extend_from_slice(&encode_avp_u32(avp::EXPERIMENTAL_RESULT_CODE, code));
        self.avp_payload.extend_from_slice(&encode_avp(
            avp::EXPERIMENTAL_RESULT,
            AVP_FLAG_MANDATORY,
            &children,
        ));
        self
    }

    fn no_state(mut self) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        self
    }

    fn sh_app(mut self) -> Self {
        self.avp_payload.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::SH_APP_ID,
        ));
        self
    }

    fn user_data_xml(mut self, xml: &str) -> Self {
        self.avp_payload.extend_from_slice(&encode_avp_octet_3gpp(
            avp::USER_DATA_SH,
            xml.as_bytes(),
        ));
        self
    }

    fn user_identity(mut self, public_id: &str) -> Self {
        let inner = encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_id);
        self.avp_payload.extend_from_slice(&encode_avp_grouped_3gpp(avp::USER_IDENTITY, &inner));
        self
    }

    fn encode(self) -> Vec<u8> {
        let flags = if self.is_request {
            FLAG_REQUEST | FLAG_PROXIABLE
        } else {
            FLAG_PROXIABLE
        };
        encode_diameter_message(flags, self.command, dictionary::SH_APP_ID, self.hbh, self.e2e, &self.avp_payload)
    }
}

// ── UDR / UDA ──────────────────────────────────────────────────────────────

/// Parsed User-Data-Request from an Application Server.
#[derive(Debug, Clone)]
pub struct UserDataQuery {
    pub session_id: String,
    pub requesting_host: String,
    pub requesting_realm: String,
    pub identity: String,
    pub references: Vec<u32>,
    pub service_indication: Option<String>,
}

/// Parse an incoming User-Data-Request.
pub fn parse_user_data_request(incoming: &IncomingRequest) -> Option<UserDataQuery> {
    let avps = &incoming.avps;

    Some(UserDataQuery {
        session_id: mandatory_string(avps, "Session-Id")?,
        requesting_host: mandatory_string(avps, "Origin-Host")?,
        requesting_realm: mandatory_string(avps, "Origin-Realm")?,
        identity: extract_public_identity(avps)?,
        references: collect_data_references(avps)?,
        service_indication: mandatory_string(avps, "Service-Indication"),
    })
}

/// Build a successful UDA with user data XML payload.
pub fn build_user_data_answer(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    xml_payload: &str,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    ShAnswerBuilder::new(dictionary::CMD_SH_USER_DATA, hbh, e2e)
        .session(session_id)
        .result_code(dictionary::DIAMETER_SUCCESS)
        .origin(origin_host, origin_realm)
        .no_state()
        .sh_app()
        .user_data_xml(xml_payload)
        .encode()
}

/// Build a UDA error with an Experimental-Result code.
pub fn build_user_data_error(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    error_code: u32,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    ShAnswerBuilder::new(dictionary::CMD_SH_USER_DATA, hbh, e2e)
        .session(session_id)
        .origin(origin_host, origin_realm)
        .no_state()
        .sh_app()
        .experimental_result(dictionary::VENDOR_3GPP, error_code)
        .encode()
}

// ── PUR / PUA ──────────────────────────────────────────────────────────────

/// Parsed Profile-Update-Request from an AS.
#[derive(Debug, Clone)]
pub struct ProfileUpdateData {
    pub session_id: String,
    pub requesting_host: String,
    pub requesting_realm: String,
    pub identity: String,
    pub reference: u32,
    pub xml_payload: Option<String>,
}

/// Parse an incoming Profile-Update-Request (Sh).
pub fn parse_profile_update(incoming: &IncomingRequest) -> Option<ProfileUpdateData> {
    let avps = &incoming.avps;

    let reference = avps
        .get("Data-Reference")
        .and_then(|v| v.as_u64())? as u32;

    Some(ProfileUpdateData {
        session_id: mandatory_string(avps, "Session-Id")?,
        requesting_host: mandatory_string(avps, "Origin-Host")?,
        requesting_realm: mandatory_string(avps, "Origin-Realm")?,
        identity: extract_public_identity(avps)?,
        reference,
        xml_payload: decode_octet_string_xml(avps, "User-Data-Sh"),
    })
}

/// Build a successful PUA response.
pub fn build_profile_update_answer(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    ShAnswerBuilder::new(dictionary::CMD_SH_PROFILE_UPDATE, hbh, e2e)
        .session(session_id)
        .result_code(dictionary::DIAMETER_SUCCESS)
        .origin(origin_host, origin_realm)
        .no_state()
        .sh_app()
        .encode()
}

// ── SNR / SNA ──────────────────────────────────────────────────────────────

/// Parsed Subscribe-Notifications-Request from an AS.
#[derive(Debug, Clone)]
pub struct NotificationSubscription {
    pub session_id: String,
    pub requesting_host: String,
    pub requesting_realm: String,
    pub identity: String,
    pub references: Vec<u32>,
    pub action: u32,
    pub service_indication: Option<String>,
}

/// Parse an incoming Subscribe-Notifications-Request.
pub fn parse_notification_subscribe(incoming: &IncomingRequest) -> Option<NotificationSubscription> {
    let avps = &incoming.avps;

    let action = avps
        .get("Subs-Req-Type")
        .and_then(|v| v.as_u64())? as u32;

    Some(NotificationSubscription {
        session_id: mandatory_string(avps, "Session-Id")?,
        requesting_host: mandatory_string(avps, "Origin-Host")?,
        requesting_realm: mandatory_string(avps, "Origin-Realm")?,
        identity: extract_public_identity(avps)?,
        references: collect_data_references(avps)?,
        action,
        service_indication: mandatory_string(avps, "Service-Indication"),
    })
}

/// Build a successful SNA response.
pub fn build_notification_subscribe_answer(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    ShAnswerBuilder::new(dictionary::CMD_SH_SUBSCRIBE_NOTIFICATIONS, hbh, e2e)
        .session(session_id)
        .result_code(dictionary::DIAMETER_SUCCESS)
        .origin(origin_host, origin_realm)
        .no_state()
        .sh_app()
        .encode()
}

// ── PNR (Push-Notification-Request) ────────────────────────────────────────

/// Build a Push-Notification-Request (HSS → AS).
#[allow(clippy::too_many_arguments)]
pub fn build_push_notification(
    origin_host: &str,
    origin_realm: &str,
    target_host: &str,
    target_realm: &str,
    session_id: &str,
    identity: &str,
    xml_payload: &str,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    ShAnswerBuilder::new(dictionary::CMD_SH_PUSH_NOTIFICATION, hbh, e2e)
        .request()
        .session(session_id)
        .origin(origin_host, origin_realm)
        .destination(target_host, target_realm)
        .no_state()
        .sh_app()
        .user_identity(identity)
        .user_data_xml(xml_payload)
        .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_udr_message() -> Vec<u8> {
        let identity_inner = encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:subscriber@ims.mnc001.mcc001.3gppnetwork.org");
        let user_identity = encode_avp_grouped_3gpp(avp::USER_IDENTITY, &identity_inner);

        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "sh;001011234567890;42"));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "telephony-as.ims.mnc001.mcc001.3gppnetwork.org"));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.mnc001.mcc001.3gppnetwork.org"));
        payload.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        payload.extend_from_slice(&user_identity);
        payload.extend_from_slice(&encode_avp_u32_3gpp(avp::DATA_REFERENCE, data_reference::IMS_USER_STATE));
        payload.extend_from_slice(&encode_avp_u32_3gpp(avp::DATA_REFERENCE, data_reference::S_CSCF_NAME));

        encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_SH_USER_DATA,
            dictionary::SH_APP_ID,
            10, 20,
            &payload,
        )
    }

    #[test]
    fn parse_user_data_request_extracts_fields() {
        let raw = create_udr_message();
        let decoded = decode_diameter(&raw).unwrap();

        let incoming = IncomingRequest {
            command_code: decoded.command_code,
            application_id: decoded.application_id,
            hop_by_hop: decoded.hop_by_hop,
            end_to_end: decoded.end_to_end,
            avps: decoded.avps,
            raw,
        };

        let query = parse_user_data_request(&incoming).expect("valid UDR");
        assert_eq!(query.session_id, "sh;001011234567890;42");
        assert_eq!(query.requesting_host, "telephony-as.ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(query.identity, "sip:subscriber@ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(query.references.len(), 2);
        assert!(query.references.contains(&data_reference::IMS_USER_STATE));
        assert!(query.references.contains(&data_reference::S_CSCF_NAME));
        assert!(query.service_indication.is_none());
    }

    #[test]
    fn user_data_answer_roundtrip() {
        let xml = "<Sh-Data><IMSPublicIdentity>sip:test@ims.example.net</IMSPublicIdentity></Sh-Data>";
        let wire = build_user_data_answer(
            "hss.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "sh;001011234567890;42",
            xml, 10, 20,
        );

        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_SH_USER_DATA);
        assert_eq!(decoded.application_id, dictionary::SH_APP_ID);
        assert_eq!(decoded.avps.get("Result-Code").and_then(|v| v.as_u64()), Some(2001));
        assert_eq!(decoded.avps.get("Session-Id").and_then(|v| v.as_str()), Some("sh;001011234567890;42"));

        // Verify XML payload survives encode/decode
        let xml_hex = decoded.avps.get("User-Data-Sh").and_then(|v| v.as_str()).unwrap();
        let xml_bytes = crate::diameter::codec::hex::decode(xml_hex).unwrap();
        assert_eq!(String::from_utf8(xml_bytes).unwrap(), xml);
    }

    #[test]
    fn user_data_error_has_experimental_result() {
        let wire = build_user_data_error(
            "hss.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "sh;err;1",
            5001, 5, 6,
        );

        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert!(decoded.avps.get("Result-Code").is_none());
        let exp = decoded.avps.get("Experimental-Result").expect("must have Experimental-Result");
        assert_eq!(exp.get("Experimental-Result-Code").and_then(|v| v.as_u64()), Some(5001));
    }

    #[test]
    fn push_notification_carries_identity_and_data() {
        let xml = "<Sh-Data><IMSUserState>REGISTERED</IMSUserState></Sh-Data>";
        let wire = build_push_notification(
            "hss.ims.example.net",
            "ims.example.net",
            "telephony-as.ims.example.net",
            "ims.example.net",
            "sh;pnr;99",
            "sip:user@ims.example.net",
            xml, 30, 40,
        );

        let decoded = decode_diameter(&wire).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_SH_PUSH_NOTIFICATION);

        let identity = decoded.avps
            .get("User-Identity")
            .and_then(|ui| ui.get("Public-Identity"))
            .and_then(|v| v.as_str());
        assert_eq!(identity, Some("sip:user@ims.example.net"));
    }

    #[test]
    fn profile_update_answer_is_valid() {
        let wire = build_profile_update_answer(
            "hss.ims.example.net",
            "ims.example.net",
            "sh;pur;5",
            7, 8,
        );

        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_SH_PROFILE_UPDATE);
        assert_eq!(decoded.avps.get("Result-Code").and_then(|v| v.as_u64()), Some(2001));
    }

    #[test]
    fn notification_subscribe_answer_is_valid() {
        let wire = build_notification_subscribe_answer(
            "hss.ims.example.net",
            "ims.example.net",
            "sh;snr;12",
            11, 22,
        );

        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_SH_SUBSCRIBE_NOTIFICATIONS);
        assert_eq!(decoded.avps.get("Result-Code").and_then(|v| v.as_u64()), Some(2001));
    }
}
