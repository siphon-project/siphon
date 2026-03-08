//! Npcf_PolicyAuthorization — 5G QoS policy control (TS 29.514).
//!
//! Provides a typed client for creating, updating, and deleting app sessions
//! via the PCF policy authorization API. Used by P-CSCF to request QoS
//! resources for IMS media sessions.

use serde::{Deserialize, Serialize};

/// Media component for QoS policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaComponent {
    /// Ordinal number identifying this media component.
    pub media_component_number: u32,
    /// Media type: "AUDIO", "VIDEO", "APPLICATION", etc.
    pub media_type: String,
    /// Flow status: "ENABLED", "DISABLED", "ENABLED_UPLINK", "ENABLED_DOWNLINK".
    pub flow_status: String,
    /// Codec data (SDP codec description).
    pub codec_data: Option<String>,
}

/// App session context for Npcf_PolicyAuthorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionContext {
    /// Application Function application identifier.
    pub af_app_id: Option<String>,
    /// Media components describing the session's media flows.
    pub media_components: Vec<MediaComponent>,
    /// SIP Call-ID for correlation with SIP signaling.
    pub sip_call_id: Option<String>,
}

/// Response from PCF policy authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionContextResp {
    /// PCF-assigned session identifier.
    pub app_session_id: String,
    /// Whether the requested QoS was authorized.
    pub authorized: bool,
}

/// SBI error type.
#[derive(Debug)]
pub enum SbiError {
    /// Transport-level error (connection refused, timeout, etc.).
    Transport(String),
    /// HTTP error with status code.
    HttpError(u16),
    /// Failed to deserialize the response body.
    Deserialization(String),
}

impl std::fmt::Display for SbiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) => write!(formatter, "SBI transport error: {message}"),
            Self::HttpError(code) => write!(formatter, "SBI HTTP error: {code}"),
            Self::Deserialization(message) => {
                write!(formatter, "SBI deserialization error: {message}")
            }
        }
    }
}

impl std::error::Error for SbiError {}

/// Npcf client for policy authorization.
pub struct NpcfClient {
    base_url: String,
    client: reqwest::Client,
}

impl NpcfClient {
    /// Create a new Npcf client pointing at the given PCF base URL.
    pub fn new(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Create a new app session (POST /npcf-policyauthorization/v1/app-sessions).
    pub async fn create_app_session(
        &self,
        context: &AppSessionContext,
    ) -> Result<AppSessionContextResp, SbiError> {
        let url = format!(
            "{}/npcf-policyauthorization/v1/app-sessions",
            self.base_url
        );
        let response = self
            .client
            .post(&url)
            .json(context)
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }

        response
            .json::<AppSessionContextResp>()
            .await
            .map_err(|error| SbiError::Deserialization(error.to_string()))
    }

    /// Delete an app session (DELETE /npcf-policyauthorization/v1/app-sessions/{id}).
    pub async fn delete_app_session(&self, session_id: &str) -> Result<(), SbiError> {
        let url = format!(
            "{}/npcf-policyauthorization/v1/app-sessions/{}",
            self.base_url, session_id
        );
        let response = self
            .client
            .delete(&url)
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

    #[test]
    fn media_component_serialization() {
        let media_component = MediaComponent {
            media_component_number: 1,
            media_type: "AUDIO".to_string(),
            flow_status: "ENABLED".to_string(),
            codec_data: Some("PCMU".to_string()),
        };
        let json = serde_json::to_string(&media_component).unwrap();
        assert!(json.contains("AUDIO"));
        assert!(json.contains("PCMU"));
        assert!(json.contains("ENABLED"));
    }

    #[test]
    fn media_component_deserialization() {
        let json = r#"{
            "media_component_number": 2,
            "media_type": "VIDEO",
            "flow_status": "DISABLED",
            "codec_data": null
        }"#;
        let media_component: MediaComponent = serde_json::from_str(json).unwrap();
        assert_eq!(media_component.media_component_number, 2);
        assert_eq!(media_component.media_type, "VIDEO");
        assert!(media_component.codec_data.is_none());
    }

    #[test]
    fn app_session_context_serialization() {
        let context = AppSessionContext {
            af_app_id: Some("siphon".to_string()),
            media_components: vec![MediaComponent {
                media_component_number: 1,
                media_type: "AUDIO".to_string(),
                flow_status: "ENABLED".to_string(),
                codec_data: None,
            }],
            sip_call_id: Some("call-123@siphon.local".to_string()),
        };
        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("afAppId"));
        assert!(json.contains("sipCallId"));
        assert!(json.contains("mediaComponents"));
    }

    #[test]
    fn app_session_context_resp_deserialization() {
        let json = r#"{"appSessionId": "sess-abc-123", "authorized": true}"#;
        let response: AppSessionContextResp = serde_json::from_str(json).unwrap();
        assert_eq!(response.app_session_id, "sess-abc-123");
        assert!(response.authorized);
    }

    #[test]
    fn app_session_context_resp_unauthorized() {
        let json = r#"{"appSessionId": "sess-xyz", "authorized": false}"#;
        let response: AppSessionContextResp = serde_json::from_str(json).unwrap();
        assert!(!response.authorized);
    }

    #[test]
    fn sbi_error_display() {
        let transport_error = SbiError::Transport("connection refused".to_string());
        assert!(transport_error.to_string().contains("connection refused"));

        let http_error = SbiError::HttpError(503);
        assert!(http_error.to_string().contains("503"));

        let deser_error = SbiError::Deserialization("missing field".to_string());
        assert!(deser_error.to_string().contains("missing field"));
    }

    #[test]
    fn npcf_client_base_url_trimmed() {
        let client = NpcfClient::new("https://pcf.5gc.example.com/", reqwest::Client::new());
        assert_eq!(client.base_url(), "https://pcf.5gc.example.com");
    }

    #[test]
    fn npcf_client_base_url_no_trailing_slash() {
        let client = NpcfClient::new("https://pcf.5gc.example.com", reqwest::Client::new());
        assert_eq!(client.base_url(), "https://pcf.5gc.example.com");
    }
}
