//! Rf Diameter interface per 3GPP TS 32.299.
//!
//! Offline charging for IMS sessions between the CTF (S-CSCF/P-CSCF/AS)
//! and the CDF (Charging Data Function):
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | ACR/ACA | 271 | CTF → CDF | Accounting record (START/INTERIM/STOP/EVENT) |
//!
//! Rf uses the base Diameter accounting application (Acct-Application-Id = 3)
//! with 3GPP IMS-specific AVPs in the Service-Information grouped AVP.

use std::sync::Arc;

use tracing::info;

use crate::diameter::codec::*;
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::DiameterPeer;
use crate::diameter::ro::ImsChargingData;

// ── Accounting-Record-Type (RFC 6733 §9.8.1) ───────────────────────────

/// Accounting record type per RFC 6733 table 9.8.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AccountingRecordType {
    EventRecord = 1,
    StartRecord = 2,
    InterimRecord = 3,
    StopRecord = 4,
}

impl AccountingRecordType {
    fn as_u32(self) -> u32 {
        self as u32
    }

    fn label(self) -> &'static str {
        match self {
            AccountingRecordType::EventRecord => "EVENT",
            AccountingRecordType::StartRecord => "START",
            AccountingRecordType::InterimRecord => "INTERIM",
            AccountingRecordType::StopRecord => "STOP",
        }
    }
}

// ── Accounting Answer (parsed) ──────────────────────────────────────────

/// Parsed Accounting-Answer from the CDF.
#[derive(Debug, Clone)]
pub struct AccountingAnswer {
    pub result_code: u32,
    pub record_type: Option<u32>,
    pub record_number: Option<u32>,
    pub session_id: Option<String>,
}

impl AccountingAnswer {
    pub fn is_success(&self) -> bool {
        self.result_code == dictionary::DIAMETER_SUCCESS
    }
}

fn parse_aca(avps: &serde_json::Value) -> AccountingAnswer {
    AccountingAnswer {
        result_code: avps
            .get("Result-Code")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        record_type: avps
            .get("Accounting-Record-Type")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        record_number: avps
            .get("Accounting-Record-Number")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        session_id: avps
            .get("Session-Id")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

// ── ACR parameters ──────────────────────────────────────────────────────

/// Full set of parameters for an Accounting-Request.
pub struct AccountingParams<'a> {
    pub record_type: AccountingRecordType,
    pub record_number: u32,
    pub session_id: Option<&'a str>,
    pub ims_data: Option<&'a ImsChargingData>,
}

// ── ACR sender ──────────────────────────────────────────────────────────

/// Send an Accounting-Request to the CDF.
///
/// Per TS 32.299 §6.3.2, the CTF generates ACRs at session boundaries
/// (START/STOP) and optionally mid-session (INTERIM). EVENT records
/// are used for one-shot transactions (e.g., MESSAGE, REGISTER).
pub async fn send_acr(
    peer: &Arc<DiameterPeer>,
    params: &AccountingParams<'_>,
) -> Result<AccountingAnswer, String> {
    let config = peer.config();
    let hbh = peer.next_hbh();
    let e2e = peer.next_e2e();

    // Use provided session_id for continuity, or generate a new one
    let owned_session;
    let session_id = match params.session_id {
        Some(id) => id,
        None => {
            owned_session = peer.new_session_id();
            &owned_session
        }
    };

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
    if let Some(ref host) = config.destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }

    // Acct-Application-Id = 3 (Rf uses base accounting, not Vendor-Specific-Application-Id)
    payload.extend_from_slice(&encode_avp_u32(avp::ACCT_APPLICATION_ID, dictionary::RF_APP_ID));

    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_TYPE,
        params.record_type.as_u32(),
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_NUMBER,
        params.record_number,
    ));

    // Service-Information → IMS-Information (shared with Ro)
    if let Some(ims) = params.ims_data {
        payload.extend_from_slice(&ims.encode_service_information());
    }

    let wire = encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_ACCOUNTING,
        dictionary::RF_APP_ID,
        hbh,
        e2e,
        &payload,
    );

    info!(
        session = %session_id,
        record_type = %params.record_type.label(),
        record_number = params.record_number,
        "Rf: sending ACR"
    );
    let answer = peer.send_request(wire).await?;

    Ok(parse_aca(&answer.avps))
}

/// Send ACR-START (begin accounting session).
pub async fn send_acr_start(
    peer: &Arc<DiameterPeer>,
    ims_data: Option<&ImsChargingData>,
) -> Result<AccountingAnswer, String> {
    send_acr(
        peer,
        &AccountingParams {
            record_type: AccountingRecordType::StartRecord,
            record_number: 0,
            session_id: None,
            ims_data,
        },
    )
    .await
}

/// Send ACR-INTERIM (mid-session accounting update).
pub async fn send_acr_interim(
    peer: &Arc<DiameterPeer>,
    session_id: &str,
    record_number: u32,
    ims_data: Option<&ImsChargingData>,
) -> Result<AccountingAnswer, String> {
    send_acr(
        peer,
        &AccountingParams {
            record_type: AccountingRecordType::InterimRecord,
            record_number,
            session_id: Some(session_id),
            ims_data,
        },
    )
    .await
}

/// Send ACR-STOP (end accounting session).
pub async fn send_acr_stop(
    peer: &Arc<DiameterPeer>,
    session_id: &str,
    record_number: u32,
    ims_data: Option<&ImsChargingData>,
) -> Result<AccountingAnswer, String> {
    send_acr(
        peer,
        &AccountingParams {
            record_type: AccountingRecordType::StopRecord,
            record_number,
            session_id: Some(session_id),
            ims_data,
        },
    )
    .await
}

/// Send ACR-EVENT (one-shot accounting, e.g., SIP MESSAGE or REGISTER).
pub async fn send_acr_event(
    peer: &Arc<DiameterPeer>,
    ims_data: Option<&ImsChargingData>,
) -> Result<AccountingAnswer, String> {
    send_acr(
        peer,
        &AccountingParams {
            record_type: AccountingRecordType::EventRecord,
            record_number: 0,
            session_id: None,
            ims_data,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::ro::{ImsChargingData, NodeFunctionality, NodeRole};

    // ── Accounting-Record-Type compliance (RFC 6733 §9.8.1) ─────────────

    #[test]
    fn accounting_record_type_rfc6733_values() {
        assert_eq!(AccountingRecordType::EventRecord.as_u32(), 1);
        assert_eq!(AccountingRecordType::StartRecord.as_u32(), 2);
        assert_eq!(AccountingRecordType::InterimRecord.as_u32(), 3);
        assert_eq!(AccountingRecordType::StopRecord.as_u32(), 4);
    }

    #[test]
    fn accounting_record_type_labels() {
        assert_eq!(AccountingRecordType::EventRecord.label(), "EVENT");
        assert_eq!(AccountingRecordType::StartRecord.label(), "START");
        assert_eq!(AccountingRecordType::InterimRecord.label(), "INTERIM");
        assert_eq!(AccountingRecordType::StopRecord.label(), "STOP");
    }

    // ── ACA parsing ────────────────────────────────────────────────────

    #[test]
    fn aca_start_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 2,
            "Accounting-Record-Number": 0,
            "Session-Id": "cdf.ims.mnc001.mcc001.3gppnetwork.org;sess;42"
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(2));
        assert_eq!(answer.record_number, Some(0));
        assert_eq!(
            answer.session_id.as_deref(),
            Some("cdf.ims.mnc001.mcc001.3gppnetwork.org;sess;42")
        );
    }

    #[test]
    fn aca_interim_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 3,
            "Accounting-Record-Number": 5
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(3));
        assert_eq!(answer.record_number, Some(5));
        assert!(answer.session_id.is_none());
    }

    #[test]
    fn aca_stop_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 4,
            "Accounting-Record-Number": 10
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(4));
        assert_eq!(answer.record_number, Some(10));
    }

    #[test]
    fn aca_event_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 1,
            "Accounting-Record-Number": 0
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(1));
    }

    #[test]
    fn aca_out_of_space() {
        // DIAMETER_OUT_OF_SPACE (4002) — CDF cannot store more records
        let json = serde_json::json!({
            "Result-Code": 4002,
            "Accounting-Record-Type": 2,
            "Accounting-Record-Number": 0
        });
        let answer = parse_aca(&json);
        assert!(!answer.is_success());
        assert_eq!(answer.result_code, 4002);
    }

    #[test]
    fn aca_unknown_session() {
        // DIAMETER_UNKNOWN_SESSION_ID (5002) — CDF lost the session
        let json = serde_json::json!({
            "Result-Code": 5002,
            "Accounting-Record-Type": 3,
            "Accounting-Record-Number": 3
        });
        let answer = parse_aca(&json);
        assert!(!answer.is_success());
        assert_eq!(answer.result_code, 5002);
    }

    #[test]
    fn aca_minimal_response() {
        let json = serde_json::json!({"Result-Code": 2001});
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert!(answer.record_type.is_none());
        assert!(answer.record_number.is_none());
        assert!(answer.session_id.is_none());
    }

    #[test]
    fn aca_missing_result_code_defaults_to_zero() {
        let json = serde_json::json!({});
        let answer = parse_aca(&json);
        assert_eq!(answer.result_code, 0);
        assert!(!answer.is_success());
    }

    // ── IMS charging data shared with Ro ────────────────────────────────

    #[test]
    fn ims_data_invite_originating() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            event: None,
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-rf-test-001".into()),
            cause_code: Some(0),
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
        // Outer AVP code must be Service-Information (873)
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::SERVICE_INFORMATION);
        // Substantial payload with nested IMS-Information
        assert!(encoded.len() > 100);
    }

    #[test]
    fn ims_data_register_event_pcscf() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: None,
            sip_method: Some("REGISTER".into()),
            event: None,
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::PCscf),
            ims_charging_identifier: None,
            cause_code: None,
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn ims_data_minimal_empty() {
        let data = ImsChargingData::default();
        let encoded = data.encode_service_information();
        // Even with no fields, the nested grouped structure is present
        assert!(!encoded.is_empty());
    }

    // ── ACR wire-format roundtrip ──────────────────────────────────────

    /// Helper: build an ACR on the wire for testing (bypasses peer).
    fn build_acr_wire_for_test(
        record_type: AccountingRecordType,
        record_number: u32,
        session_id: &str,
        ims_data: Option<&ImsChargingData>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        payload.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_HOST,
            "scscf.ims.mnc001.mcc001.3gppnetwork.org",
        ));
        payload.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        payload.extend_from_slice(&encode_avp_utf8(
            avp::DESTINATION_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        payload.extend_from_slice(&encode_avp_u32(
            avp::ACCT_APPLICATION_ID,
            dictionary::RF_APP_ID,
        ));
        payload.extend_from_slice(&encode_avp_u32(
            avp::ACCOUNTING_RECORD_TYPE,
            record_type.as_u32(),
        ));
        payload.extend_from_slice(&encode_avp_u32(
            avp::ACCOUNTING_RECORD_NUMBER,
            record_number,
        ));
        if let Some(ims) = ims_data {
            payload.extend_from_slice(&ims.encode_service_information());
        }
        encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1,
            2,
            &payload,
        )
    }

    #[test]
    fn acr_start_wire_roundtrip() {
        let ims = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-rf-roundtrip-001".into()),
            ..Default::default()
        };

        let wire = build_acr_wire_for_test(
            AccountingRecordType::StartRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            Some(&ims),
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_ACCOUNTING);
        assert_eq!(decoded.application_id, dictionary::RF_APP_ID);
        assert_eq!(
            decoded.avps.get("Session-Id").and_then(|v| v.as_str()),
            Some("cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1")
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(2) // START
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            decoded
                .avps
                .get("Acct-Application-Id")
                .and_then(|v| v.as_u64()),
            Some(3) // base accounting
        );

        // Verify nested Service-Information → IMS-Information
        let svc_info = decoded.avps.get("Service-Information").unwrap();
        let ims_info = svc_info.get("IMS-Information").unwrap();
        assert!(ims_info.get("Calling-Party-Address").is_some());
        assert!(ims_info.get("Called-Party-Address").is_some());
        assert!(ims_info.get("IMS-Charging-Identifier").is_some());
    }

    #[test]
    fn acr_interim_wire_roundtrip() {
        let wire = build_acr_wire_for_test(
            AccountingRecordType::InterimRecord,
            3,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(3) // INTERIM
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
    }

    #[test]
    fn acr_stop_wire_roundtrip() {
        let wire = build_acr_wire_for_test(
            AccountingRecordType::StopRecord,
            7,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(4) // STOP
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    #[test]
    fn acr_event_wire_roundtrip() {
        let ims = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: None,
            sip_method: Some("MESSAGE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::ApplicationServer),
            ..Default::default()
        };

        let wire = build_acr_wire_for_test(
            AccountingRecordType::EventRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;event;1",
            Some(&ims),
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(1) // EVENT
        );
        // Event records use record_number = 0
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn acr_without_ims_data() {
        // Rf allows ACR without Service-Information (e.g., for non-IMS accounting)
        let wire = build_acr_wire_for_test(
            AccountingRecordType::EventRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;bare;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(decoded.avps.get("Service-Information").is_none());
    }

    // ── App ID and command code compliance ──────────────────────────────

    #[test]
    fn rf_app_id_is_base_accounting() {
        // Rf uses Acct-Application-Id = 3, NOT a vendor-specific application
        assert_eq!(dictionary::RF_APP_ID, 3);
    }

    #[test]
    fn rf_command_code_rfc6733() {
        // ACR/ACA uses command code 271 (base Diameter accounting)
        assert_eq!(dictionary::CMD_ACCOUNTING, 271);
    }

    #[test]
    fn rf_command_name_acr() {
        assert_eq!(command_name(271, true), "ACR");
    }

    #[test]
    fn rf_command_name_aca() {
        assert_eq!(command_name(271, false), "ACA");
    }

    #[test]
    fn rf_diameter_success_code() {
        assert_eq!(dictionary::DIAMETER_SUCCESS, 2001);
    }
}
