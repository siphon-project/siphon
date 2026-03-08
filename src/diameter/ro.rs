//! Ro Diameter interface per 3GPP TS 32.299 / RFC 4006.
//!
//! Online charging for IMS sessions between the CTF (S-CSCF/P-CSCF/AS)
//! and the OCS (Online Charging System):
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | CCR/CCA | 272 | CTF → OCS | Credit control (INITIAL/UPDATE/TERMINATION/EVENT) |

use std::sync::Arc;

use tracing::info;

use crate::diameter::codec::*;
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::DiameterPeer;

// ── CC-Request-Type (RFC 4006 §8.3) ────────────────────────────────────

/// Credit-Control request type per RFC 4006 table 8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CcRequestType {
    Initial = 1,
    Update = 2,
    Termination = 3,
    Event = 4,
}

impl CcRequestType {
    fn as_u32(self) -> u32 {
        self as u32
    }

    fn label(self) -> &'static str {
        match self {
            CcRequestType::Initial => "INITIAL",
            CcRequestType::Update => "UPDATE",
            CcRequestType::Termination => "TERMINATION",
            CcRequestType::Event => "EVENT",
        }
    }
}

// ── Subscription-Id-Type (RFC 4006 §8.47) ──────────────────────────────

/// Identifies how the subscriber is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SubscriberIdKind {
    EndUserE164 = 0,
    EndUserImsi = 1,
    EndUserSipUri = 2,
    EndUserNai = 3,
    EndUserPrivate = 4,
}

impl SubscriberIdKind {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Role-of-Node (TS 32.299 §7.2.174) ──────────────────────────────────

/// IMS node role for charging purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NodeRole {
    OriginatingRole = 0,
    TerminatingRole = 1,
    ProxyRole = 2,
    BcfRole = 3,
}

impl NodeRole {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Node-Functionality (TS 32.299 §7.2.126) ────────────────────────────

/// IMS node functionality for charging correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NodeFunctionality {
    SCscf = 0,
    PCscf = 1,
    ICscf = 2,
    Mrfc = 3,
    Mgcf = 4,
    Bgcf = 5,
    ApplicationServer = 6,
    Ibcf = 7,
    SCscfRestore = 8,
    Ecscf = 9,
    Atcf = 10,
}

impl NodeFunctionality {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Subscriber identity ─────────────────────────────────────────────────

/// Subscriber identification for charging (Subscription-Id AVP).
#[derive(Debug, Clone)]
pub struct SubscriberId {
    pub kind: SubscriberIdKind,
    pub data: String,
}

impl SubscriberId {
    /// E.164 MSISDN subscriber.
    pub fn msisdn(number: &str) -> Self {
        Self {
            kind: SubscriberIdKind::EndUserE164,
            data: number.to_string(),
        }
    }

    /// IMSI subscriber.
    pub fn imsi(value: &str) -> Self {
        Self {
            kind: SubscriberIdKind::EndUserImsi,
            data: value.to_string(),
        }
    }

    /// SIP URI subscriber.
    pub fn sip_uri(uri: &str) -> Self {
        Self {
            kind: SubscriberIdKind::EndUserSipUri,
            data: uri.to_string(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_avp_u32(avp::SUBSCRIPTION_ID_TYPE, self.kind.as_u32()));
        inner.extend_from_slice(&encode_avp_utf8(avp::SUBSCRIPTION_ID_DATA, &self.data));
        encode_avp_grouped(avp::SUBSCRIPTION_ID, &inner)
    }
}

// ── Service units ───────────────────────────────────────────────────────

/// Requested, granted, or used service units for credit control.
#[derive(Debug, Clone, Default)]
pub struct ServiceUnit {
    pub time_seconds: Option<u32>,
    pub total_octets: Option<u64>,
    pub input_octets: Option<u64>,
    pub output_octets: Option<u64>,
}

impl ServiceUnit {
    fn encode_as(&self, wrapper_code: u32) -> Vec<u8> {
        let mut inner = Vec::new();
        if let Some(t) = self.time_seconds {
            inner.extend_from_slice(&encode_avp_u32(avp::CC_TIME, t));
        }
        if let Some(v) = self.total_octets {
            inner.extend_from_slice(&encode_avp_u64(avp::CC_TOTAL_OCTETS, v));
        }
        if let Some(v) = self.input_octets {
            inner.extend_from_slice(&encode_avp_u64(avp::CC_INPUT_OCTETS, v));
        }
        if let Some(v) = self.output_octets {
            inner.extend_from_slice(&encode_avp_u64(avp::CC_OUTPUT_OCTETS, v));
        }
        encode_avp_grouped(wrapper_code, &inner)
    }
}

// ── IMS charging information ────────────────────────────────────────────

/// IMS-specific charging data carried in Service-Information → IMS-Information.
///
/// Per TS 32.299 §7.2.71, this is the primary charging context for IMS sessions.
#[derive(Debug, Clone, Default)]
pub struct ImsChargingData {
    pub calling_party: Option<String>,
    pub called_party: Option<String>,
    pub sip_method: Option<String>,
    pub event: Option<String>,
    pub role_of_node: Option<NodeRole>,
    pub node_functionality: Option<NodeFunctionality>,
    pub ims_charging_identifier: Option<String>,
    pub cause_code: Option<i32>,
}

impl ImsChargingData {
    fn encode_ims_information(&self) -> Vec<u8> {
        let mut ims_inner = Vec::new();

        // Event-Type grouped AVP
        if self.sip_method.is_some() || self.event.is_some() {
            let mut event_children = Vec::new();
            if let Some(ref method) = self.sip_method {
                event_children.extend_from_slice(&encode_avp_utf8_3gpp(
                    avp::SIP_METHOD_CHARGING,
                    method,
                ));
            }
            if let Some(ref event) = self.event {
                event_children.extend_from_slice(&encode_avp_utf8_3gpp(avp::EVENT, event));
            }
            ims_inner.extend_from_slice(&encode_avp_grouped_3gpp(
                avp::EVENT_TYPE,
                &event_children,
            ));
        }

        if let Some(role) = self.role_of_node {
            ims_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::ROLE_OF_NODE, role.as_u32()));
        }
        if let Some(func) = self.node_functionality {
            ims_inner.extend_from_slice(&encode_avp_u32_3gpp(
                avp::NODE_FUNCTIONALITY,
                func.as_u32(),
            ));
        }
        if let Some(ref caller) = self.calling_party {
            ims_inner.extend_from_slice(&encode_avp_utf8_3gpp(
                avp::CALLING_PARTY_ADDRESS,
                caller,
            ));
        }
        if let Some(ref callee) = self.called_party {
            ims_inner.extend_from_slice(&encode_avp_utf8_3gpp(
                avp::CALLED_PARTY_ADDRESS,
                callee,
            ));
        }
        if let Some(ref icid) = self.ims_charging_identifier {
            ims_inner.extend_from_slice(&encode_avp_utf8_3gpp(
                avp::IMS_CHARGING_IDENTIFIER,
                icid,
            ));
        }
        if let Some(cause) = self.cause_code {
            ims_inner.extend_from_slice(&encode_avp_i32_3gpp(avp::CAUSE_CODE, cause));
        }

        ims_inner
    }

    /// Encode the full Service-Information → IMS-Information grouped AVP chain.
    pub fn encode_service_information(&self) -> Vec<u8> {
        let ims_info = self.encode_ims_information();
        let ims_grouped = encode_avp_grouped_3gpp(avp::IMS_INFORMATION, &ims_info);
        encode_avp_grouped_3gpp(avp::SERVICE_INFORMATION, &ims_grouped)
    }
}

// ── Credit-Control Answer (parsed) ──────────────────────────────────────

/// Parsed Credit-Control-Answer from the OCS.
#[derive(Debug, Clone)]
pub struct CreditControlAnswer {
    pub result_code: u32,
    pub request_type: Option<u32>,
    pub request_number: Option<u32>,
    pub granted_time: Option<u32>,
    pub granted_total_octets: Option<u64>,
    pub validity_time: Option<u32>,
}

impl CreditControlAnswer {
    pub fn is_success(&self) -> bool {
        self.result_code == dictionary::DIAMETER_SUCCESS
    }
}

fn parse_cca(avps: &serde_json::Value) -> CreditControlAnswer {
    let granted = avps.get("Granted-Service-Unit");
    CreditControlAnswer {
        result_code: avps
            .get("Result-Code")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        request_type: avps
            .get("CC-Request-Type")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        request_number: avps
            .get("CC-Request-Number")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        granted_time: granted
            .and_then(|g| g.get("CC-Time"))
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        granted_total_octets: granted
            .and_then(|g| g.get("CC-Total-Octets"))
            .and_then(|v| v.as_u64()),
        validity_time: avps
            .get("Validity-Time")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
    }
}

// ── CCR sender ──────────────────────────────────────────────────────────

/// Full set of parameters for a Credit-Control-Request.
pub struct CreditControlParams<'a> {
    pub request_type: CcRequestType,
    pub request_number: u32,
    pub subscriber: &'a SubscriberId,
    pub ims_data: Option<&'a ImsChargingData>,
    pub requested_units: Option<&'a ServiceUnit>,
    pub used_units: Option<&'a ServiceUnit>,
    pub rating_group: Option<u32>,
    pub service_identifier: Option<u32>,
}

/// Send a Credit-Control-Request to the OCS.
///
/// Per TS 32.299 §6.4.2, the CTF sends CCR at session start (INITIAL),
/// during the session (UPDATE), at session end (TERMINATION), or for
/// one-time events (EVENT).
pub async fn send_ccr(
    peer: &Arc<DiameterPeer>,
    params: &CreditControlParams<'_>,
) -> Result<CreditControlAnswer, String> {
    let config = peer.config();
    let hbh = peer.next_hbh();
    let e2e = peer.next_e2e();
    let session_id = peer.new_session_id();

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
    payload.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, dictionary::RO_APP_ID));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
    if let Some(ref host) = config.destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }

    payload.extend_from_slice(&encode_avp_u32(
        avp::CC_REQUEST_TYPE,
        params.request_type.as_u32(),
    ));
    payload.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_NUMBER, params.request_number));

    // Subscription-Id
    payload.extend_from_slice(&params.subscriber.encode());

    // Requested-Service-Unit
    if let Some(rsu) = params.requested_units {
        payload.extend_from_slice(&rsu.encode_as(avp::REQUESTED_SERVICE_UNIT));
    }

    // Used-Service-Unit
    if let Some(usu) = params.used_units {
        payload.extend_from_slice(&usu.encode_as(avp::USED_SERVICE_UNIT));
    }

    // Multiple-Services-Credit-Control wrapper for Rating-Group/Service-Identifier
    if params.rating_group.is_some() || params.service_identifier.is_some() {
        let mut mscc = Vec::new();
        if let Some(rg) = params.rating_group {
            mscc.extend_from_slice(&encode_avp_u32(avp::RATING_GROUP, rg));
        }
        if let Some(si) = params.service_identifier {
            mscc.extend_from_slice(&encode_avp_u32(avp::SERVICE_IDENTIFIER, si));
        }
        if let Some(rsu) = params.requested_units {
            mscc.extend_from_slice(&rsu.encode_as(avp::REQUESTED_SERVICE_UNIT));
        }
        payload.extend_from_slice(&encode_avp_grouped_3gpp(
            avp::MULTIPLE_SERVICES_CREDIT_CONTROL,
            &mscc,
        ));
    }

    // Service-Information → IMS-Information
    if let Some(ims) = params.ims_data {
        payload.extend_from_slice(&ims.encode_service_information());
    }

    let wire = encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_CREDIT_CONTROL,
        dictionary::RO_APP_ID,
        hbh,
        e2e,
        &payload,
    );

    info!(
        session = %session_id,
        request_type = %params.request_type.label(),
        "Ro: sending CCR"
    );
    let answer = peer.send_request(wire).await?;

    Ok(parse_cca(&answer.avps))
}

/// Send CCR-Initial (start of charging session).
pub async fn send_ccr_initial(
    peer: &Arc<DiameterPeer>,
    subscriber: &SubscriberId,
    ims_data: Option<&ImsChargingData>,
    requested_units: Option<&ServiceUnit>,
) -> Result<CreditControlAnswer, String> {
    send_ccr(
        peer,
        &CreditControlParams {
            request_type: CcRequestType::Initial,
            request_number: 0,
            subscriber,
            ims_data,
            requested_units,
            used_units: None,
            rating_group: None,
            service_identifier: None,
        },
    )
    .await
}

/// Send CCR-Termination (end of charging session).
pub async fn send_ccr_termination(
    peer: &Arc<DiameterPeer>,
    subscriber: &SubscriberId,
    request_number: u32,
    ims_data: Option<&ImsChargingData>,
    used_units: Option<&ServiceUnit>,
) -> Result<CreditControlAnswer, String> {
    send_ccr(
        peer,
        &CreditControlParams {
            request_type: CcRequestType::Termination,
            request_number,
            subscriber,
            ims_data,
            requested_units: None,
            used_units,
            rating_group: None,
            service_identifier: None,
        },
    )
    .await
}

/// Send CCR-Event (one-shot event charging, e.g., registration or MESSAGE).
pub async fn send_ccr_event(
    peer: &Arc<DiameterPeer>,
    subscriber: &SubscriberId,
    ims_data: Option<&ImsChargingData>,
) -> Result<CreditControlAnswer, String> {
    send_ccr(
        peer,
        &CreditControlParams {
            request_type: CcRequestType::Event,
            request_number: 0,
            subscriber,
            ims_data,
            requested_units: None,
            used_units: None,
            rating_group: None,
            service_identifier: None,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 3GPP enum compliance (RFC 4006 + TS 32.299) ─────────────────────

    #[test]
    fn cc_request_type_rfc4006_values() {
        assert_eq!(CcRequestType::Initial.as_u32(), 1);
        assert_eq!(CcRequestType::Update.as_u32(), 2);
        assert_eq!(CcRequestType::Termination.as_u32(), 3);
        assert_eq!(CcRequestType::Event.as_u32(), 4);
    }

    #[test]
    fn cc_request_type_labels() {
        assert_eq!(CcRequestType::Initial.label(), "INITIAL");
        assert_eq!(CcRequestType::Update.label(), "UPDATE");
        assert_eq!(CcRequestType::Termination.label(), "TERMINATION");
        assert_eq!(CcRequestType::Event.label(), "EVENT");
    }

    #[test]
    fn subscriber_id_kind_rfc4006_values() {
        assert_eq!(SubscriberIdKind::EndUserE164.as_u32(), 0);
        assert_eq!(SubscriberIdKind::EndUserImsi.as_u32(), 1);
        assert_eq!(SubscriberIdKind::EndUserSipUri.as_u32(), 2);
        assert_eq!(SubscriberIdKind::EndUserNai.as_u32(), 3);
        assert_eq!(SubscriberIdKind::EndUserPrivate.as_u32(), 4);
    }

    #[test]
    fn node_role_ts32299_values() {
        assert_eq!(NodeRole::OriginatingRole.as_u32(), 0);
        assert_eq!(NodeRole::TerminatingRole.as_u32(), 1);
        assert_eq!(NodeRole::ProxyRole.as_u32(), 2);
        assert_eq!(NodeRole::BcfRole.as_u32(), 3);
    }

    #[test]
    fn node_functionality_ts32299_values() {
        assert_eq!(NodeFunctionality::SCscf.as_u32(), 0);
        assert_eq!(NodeFunctionality::PCscf.as_u32(), 1);
        assert_eq!(NodeFunctionality::ICscf.as_u32(), 2);
        assert_eq!(NodeFunctionality::Mrfc.as_u32(), 3);
        assert_eq!(NodeFunctionality::Mgcf.as_u32(), 4);
        assert_eq!(NodeFunctionality::Bgcf.as_u32(), 5);
        assert_eq!(NodeFunctionality::ApplicationServer.as_u32(), 6);
        assert_eq!(NodeFunctionality::Ibcf.as_u32(), 7);
        assert_eq!(NodeFunctionality::Ecscf.as_u32(), 9);
        assert_eq!(NodeFunctionality::Atcf.as_u32(), 10);
    }

    // ── Subscriber identity encoding ────────────────────────────────────

    #[test]
    fn subscriber_msisdn_encoding_roundtrip() {
        let sub = SubscriberId::msisdn("+15551234567");
        let encoded = sub.encode();
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::SUBSCRIPTION_ID);
        // Decode the grouped AVP to verify children
        let wire = build_ccr_wire_for_test(CcRequestType::Event, 0, &sub, None, None, None);
        let decoded = decode_diameter(&wire).unwrap();
        let sub_id = decoded.avps.get("Subscription-Id").unwrap();
        assert_eq!(sub_id.get("Subscription-Id-Type").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(sub_id.get("Subscription-Id-Data").and_then(|v| v.as_str()), Some("+15551234567"));
    }

    #[test]
    fn subscriber_imsi_encoding() {
        let sub = SubscriberId::imsi("001011234567890");
        assert_eq!(sub.kind, SubscriberIdKind::EndUserImsi);
        assert_eq!(sub.data, "001011234567890");
    }

    #[test]
    fn subscriber_sip_uri_encoding() {
        let sub = SubscriberId::sip_uri("sip:alice@ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(sub.kind, SubscriberIdKind::EndUserSipUri);
    }

    // ── Service unit encoding ───────────────────────────────────────────

    #[test]
    fn requested_service_unit_encoding() {
        let rsu = ServiceUnit {
            time_seconds: Some(3600),
            total_octets: Some(10_000_000),
            input_octets: None,
            output_octets: None,
        };
        let encoded = rsu.encode_as(avp::REQUESTED_SERVICE_UNIT);
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::REQUESTED_SERVICE_UNIT);
    }

    #[test]
    fn used_service_unit_encoding() {
        let usu = ServiceUnit {
            time_seconds: Some(120),
            total_octets: None,
            input_octets: Some(50000),
            output_octets: Some(80000),
        };
        let encoded = usu.encode_as(avp::USED_SERVICE_UNIT);
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::USED_SERVICE_UNIT);
    }

    #[test]
    fn empty_service_unit_encoding() {
        let empty = ServiceUnit::default();
        let encoded = empty.encode_as(avp::GRANTED_SERVICE_UNIT);
        // Even empty, it should have a valid grouped AVP header
        assert!(!encoded.is_empty());
    }

    // ── IMS charging data encoding (TS 32.299 §7.2.71) ─────────────────

    #[test]
    fn ims_charging_invite_originating() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            event: None,
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-001011234567890-1709734800".into()),
            cause_code: None,
        };
        let encoded = data.encode_service_information();
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::SERVICE_INFORMATION);
        // Service-Information must be substantial with nested IMS-Information
        assert!(encoded.len() > 100);
    }

    #[test]
    fn ims_charging_bye_with_cause_code() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("BYE".into()),
            event: None,
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-bye-test".into()),
            cause_code: Some(0), // Normal call clearing
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn ims_charging_with_event_type() {
        let data = ImsChargingData {
            calling_party: None,
            called_party: None,
            sip_method: None,
            event: Some("reg".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::PCscf),
            ims_charging_identifier: None,
            cause_code: None,
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn ims_charging_minimal() {
        let data = ImsChargingData::default();
        let encoded = data.encode_service_information();
        // Even with no fields, the nested grouped structure is present
        assert!(!encoded.is_empty());
    }

    // ── CCA parsing ─────────────────────────────────────────────────────

    #[test]
    fn cca_initial_success_with_grant() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "CC-Request-Type": 1,
            "CC-Request-Number": 0,
            "Granted-Service-Unit": {
                "CC-Time": 3600,
                "CC-Total-Octets": 10000000
            },
            "Validity-Time": 1800
        });
        let answer = parse_cca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.request_type, Some(1));
        assert_eq!(answer.request_number, Some(0));
        assert_eq!(answer.granted_time, Some(3600));
        assert_eq!(answer.granted_total_octets, Some(10_000_000));
        assert_eq!(answer.validity_time, Some(1800));
    }

    #[test]
    fn cca_credit_limit_reached() {
        let json = serde_json::json!({
            "Result-Code": 4012,
            "CC-Request-Type": 2,
            "CC-Request-Number": 5
        });
        let answer = parse_cca(&json);
        assert!(!answer.is_success());
        assert_eq!(answer.result_code, 4012);
        assert_eq!(answer.request_type, Some(2));
        assert!(answer.granted_time.is_none());
        assert!(answer.granted_total_octets.is_none());
    }

    #[test]
    fn cca_termination_no_grant() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "CC-Request-Type": 3,
            "CC-Request-Number": 10
        });
        let answer = parse_cca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.request_type, Some(3));
        assert!(answer.granted_time.is_none());
    }

    #[test]
    fn cca_minimal_response() {
        let json = serde_json::json!({"Result-Code": 2001});
        let answer = parse_cca(&json);
        assert!(answer.is_success());
        assert!(answer.request_type.is_none());
        assert!(answer.validity_time.is_none());
    }

    // ── CCR wire-format roundtrip ───────────────────────────────────────

    /// Helper: build a CCR on the wire for testing (bypasses peer).
    fn build_ccr_wire_for_test(
        request_type: CcRequestType,
        request_number: u32,
        subscriber: &SubscriberId,
        ims_data: Option<&ImsChargingData>,
        requested_units: Option<&ServiceUnit>,
        used_units: Option<&ServiceUnit>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "ro;test;sess;1"));
        payload.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, dictionary::RO_APP_ID));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.mnc001.mcc001.3gppnetwork.org"));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.mnc001.mcc001.3gppnetwork.org"));
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, "ims.mnc001.mcc001.3gppnetwork.org"));
        payload.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_TYPE, request_type.as_u32()));
        payload.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_NUMBER, request_number));
        payload.extend_from_slice(&subscriber.encode());
        if let Some(rsu) = requested_units {
            payload.extend_from_slice(&rsu.encode_as(avp::REQUESTED_SERVICE_UNIT));
        }
        if let Some(usu) = used_units {
            payload.extend_from_slice(&usu.encode_as(avp::USED_SERVICE_UNIT));
        }
        if let Some(ims) = ims_data {
            payload.extend_from_slice(&ims.encode_service_information());
        }
        encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_CREDIT_CONTROL,
            dictionary::RO_APP_ID,
            1, 2,
            &payload,
        )
    }

    #[test]
    fn ccr_initial_wire_roundtrip() {
        let sub = SubscriberId::msisdn("+15551234567");
        let rsu = ServiceUnit { time_seconds: Some(3600), ..Default::default() };
        let ims = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-roundtrip-001".into()),
            ..Default::default()
        };

        let wire = build_ccr_wire_for_test(
            CcRequestType::Initial, 0, &sub, Some(&ims), Some(&rsu), None,
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_CREDIT_CONTROL);
        assert_eq!(decoded.application_id, dictionary::RO_APP_ID);
        assert_eq!(decoded.avps.get("Session-Id").and_then(|v| v.as_str()), Some("ro;test;sess;1"));
        assert_eq!(decoded.avps.get("CC-Request-Type").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(decoded.avps.get("CC-Request-Number").and_then(|v| v.as_u64()), Some(0));

        // Verify nested Service-Information → IMS-Information
        let svc_info = decoded.avps.get("Service-Information").unwrap();
        let ims_info = svc_info.get("IMS-Information").unwrap();
        assert!(ims_info.get("Calling-Party-Address").is_some());
        assert!(ims_info.get("Called-Party-Address").is_some());
        assert!(ims_info.get("IMS-Charging-Identifier").is_some());
    }

    #[test]
    fn ccr_termination_wire_roundtrip() {
        let sub = SubscriberId::imsi("001011234567890");
        let usu = ServiceUnit {
            time_seconds: Some(120),
            input_octets: Some(50000),
            output_octets: Some(80000),
            ..Default::default()
        };

        let wire = build_ccr_wire_for_test(
            CcRequestType::Termination, 5, &sub, None, None, Some(&usu),
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(decoded.avps.get("CC-Request-Type").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(decoded.avps.get("CC-Request-Number").and_then(|v| v.as_u64()), Some(5));
    }

    #[test]
    fn ccr_event_wire_roundtrip() {
        let sub = SubscriberId::sip_uri("sip:alice@ims.mnc001.mcc001.3gppnetwork.org");
        let wire = build_ccr_wire_for_test(CcRequestType::Event, 0, &sub, None, None, None);
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(decoded.avps.get("CC-Request-Type").and_then(|v| v.as_u64()), Some(4));
        let sub_id = decoded.avps.get("Subscription-Id").unwrap();
        assert_eq!(sub_id.get("Subscription-Id-Type").and_then(|v| v.as_u64()), Some(2));
    }

    // ── App ID and command code compliance ──────────────────────────────

    #[test]
    fn ro_app_id_is_rfc4006() {
        // Ro uses Auth-Application-Id = 4 (Credit-Control per RFC 4006)
        assert_eq!(dictionary::RO_APP_ID, 4);
    }

    #[test]
    fn ro_command_code_rfc4006() {
        assert_eq!(dictionary::CMD_CREDIT_CONTROL, 272);
    }
}
