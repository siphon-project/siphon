//! Nchf_ConvergedCharging — 5G charging (TS 32.291).
//!
//! Provides a typed client for converged charging sessions: initial creation,
//! interim updates, and final release. Used by P-CSCF/IMS-AS to report
//! charging events to the CHF.

use serde::{Deserialize, Serialize};

use super::npcf::SbiError;

/// Charging data request for converged charging.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataRequest {
    /// Subscriber identifier (e.g. IMSI, MSISDN, SIP URI).
    pub subscriber_identifier: String,
    /// NF consumer identification.
    pub nf_consumer_identification: NfIdentification,
    /// Timestamp of the charging event (ISO 8601).
    pub invocation_time_stamp: String,
    /// Sequence number for this charging session.
    pub invocation_sequence_number: u32,
    /// Optional service-specific information.
    pub service_specification_info: Option<String>,
}

/// NF identification — identifies the network function sending the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfIdentification {
    /// Name of the network function.
    pub nf_name: String,
    /// Type of the network function (e.g. "P-CSCF", "S-CSCF", "AS").
    pub nf_type: String,
}

/// Charging data response from the CHF.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataResponse {
    /// Result of the charging invocation.
    pub invocation_result: InvocationResult,
    /// CHF-assigned session identifier (present on initial creation).
    pub session_id: Option<String>,
}

/// Invocation result — indicates success or failure of the charging request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationResult {
    /// Diameter-style result code (2001 = success, 5xxx = error).
    pub result_code: u32,
}

/// Nchf client for converged charging.
pub struct NchfClient {
    base_url: String,
    client: reqwest::Client,
}

impl NchfClient {
    /// Create a new Nchf client pointing at the given CHF base URL.
    pub fn new(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Initial charging request (POST /nchf-convergedcharging/v3/chargingdata).
    pub async fn create(
        &self,
        request: &ChargingDataRequest,
    ) -> Result<ChargingDataResponse, SbiError> {
        let url = format!("{}/nchf-convergedcharging/v3/chargingdata", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }

        response
            .json()
            .await
            .map_err(|error| SbiError::Deserialization(error.to_string()))
    }

    /// Update charging data (POST /nchf-convergedcharging/v3/chargingdata/{id}/update).
    pub async fn update(
        &self,
        session_id: &str,
        request: &ChargingDataRequest,
    ) -> Result<ChargingDataResponse, SbiError> {
        let url = format!(
            "{}/nchf-convergedcharging/v3/chargingdata/{}/update",
            self.base_url, session_id
        );
        let response = self
            .client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }

        response
            .json()
            .await
            .map_err(|error| SbiError::Deserialization(error.to_string()))
    }

    /// Release charging data (POST /nchf-convergedcharging/v3/chargingdata/{id}/release).
    pub async fn release(&self, session_id: &str) -> Result<(), SbiError> {
        let url = format!(
            "{}/nchf-convergedcharging/v3/chargingdata/{}/release",
            self.base_url, session_id
        );
        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() && response.status().as_u16() != 204 {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }
        Ok(())
    }

    /// Get the base URL this client is configured to use.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_charging_request() -> ChargingDataRequest {
        ChargingDataRequest {
            subscriber_identifier: "imsi-001010000000001".to_string(),
            nf_consumer_identification: NfIdentification {
                nf_name: "siphon-pcscf".to_string(),
                nf_type: "P-CSCF".to_string(),
            },
            invocation_time_stamp: "2026-03-06T12:00:00Z".to_string(),
            invocation_sequence_number: 1,
            service_specification_info: None,
        }
    }

    #[test]
    fn charging_data_request_serialization() {
        let request = make_charging_request();
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("subscriberIdentifier"));
        assert!(json.contains("nfConsumerIdentification"));
        assert!(json.contains("invocationTimeStamp"));
        assert!(json.contains("invocationSequenceNumber"));
        assert!(json.contains("imsi-001010000000001"));
    }

    #[test]
    fn charging_data_request_deserialization() {
        let json = r#"{
            "subscriberIdentifier": "msisdn-15551234567",
            "nfConsumerIdentification": {
                "nfName": "siphon-scscf",
                "nfType": "S-CSCF"
            },
            "invocationTimeStamp": "2026-03-06T15:30:00Z",
            "invocationSequenceNumber": 42,
            "serviceSpecificationInfo": "voice-call"
        }"#;
        let request: ChargingDataRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.subscriber_identifier, "msisdn-15551234567");
        assert_eq!(request.nf_consumer_identification.nf_type, "S-CSCF");
        assert_eq!(request.invocation_sequence_number, 42);
        assert_eq!(
            request.service_specification_info.as_deref(),
            Some("voice-call")
        );
    }

    #[test]
    fn nf_identification_serialization() {
        let identification = NfIdentification {
            nf_name: "siphon-pcscf".to_string(),
            nf_type: "P-CSCF".to_string(),
        };
        let json = serde_json::to_string(&identification).unwrap();
        assert!(json.contains("nfName"));
        assert!(json.contains("nfType"));
    }

    #[test]
    fn invocation_result_deserialization() {
        let json = r#"{"resultCode": 2001}"#;
        let result: InvocationResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.result_code, 2001);
    }

    #[test]
    fn invocation_result_error_code() {
        let json = r#"{"resultCode": 5012}"#;
        let result: InvocationResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.result_code, 5012);
    }

    #[test]
    fn charging_data_response_with_session_id() {
        let json = r#"{
            "invocationResult": {"resultCode": 2001},
            "sessionId": "chg-sess-12345"
        }"#;
        let response: ChargingDataResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.invocation_result.result_code, 2001);
        assert_eq!(response.session_id.as_deref(), Some("chg-sess-12345"));
    }

    #[test]
    fn charging_data_response_without_session_id() {
        let json = r#"{
            "invocationResult": {"resultCode": 2001},
            "sessionId": null
        }"#;
        let response: ChargingDataResponse = serde_json::from_str(json).unwrap();
        assert!(response.session_id.is_none());
    }

    #[test]
    fn nchf_client_base_url_trimmed() {
        let client = NchfClient::new("https://chf.5gc.example.com/", reqwest::Client::new());
        assert_eq!(client.base_url(), "https://chf.5gc.example.com");
    }
}
