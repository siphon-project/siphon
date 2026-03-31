//! Npcf_PolicyAuthorization — 5G QoS policy control (TS 29.514).
//!
//! Provides a typed client for creating, updating, and deleting app sessions
//! via the PCF policy authorization API. Used by P-CSCF to request QoS
//! resources for IMS media sessions.

use serde::{Deserialize, Serialize};

/// Media sub-component describing an individual IP flow within a media component.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaSubComponent {
    /// Flow number identifying this sub-component within the media component.
    pub flow_number: u32,
    /// IPFilterRule flow descriptions (e.g. "permit in ip from any to 10.0.0.1 20000").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_descriptions: Option<Vec<String>>,
    /// Flow status: "ENABLED", "DISABLED", "ENABLED_UPLINK", "ENABLED_DOWNLINK".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_status: Option<String>,
    /// Flow usage: "NO_INFO", "RTCP", "AF_SIGNALLING".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_usage: Option<String>,
}

/// Media component for QoS policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaComponent {
    /// Ordinal number identifying this media component.
    pub media_component_number: u32,
    /// Media type: "AUDIO", "VIDEO", "APPLICATION", etc.
    pub media_type: String,
    /// Flow status: "ENABLED", "DISABLED", "ENABLED_UPLINK", "ENABLED_DOWNLINK".
    pub flow_status: String,
    /// Codec data (SDP codec description).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec_data: Option<String>,
    /// Media sub-components describing individual IP flows (TS 29.514).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub med_sub_comps: Option<Vec<MediaSubComponent>>,
}

/// Event subscription for PCF notifications (TS 29.514).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSubscription {
    /// Event type (e.g. "UP_PATH_CH_EVENT", "PLMN_CH_EVENT", "QOS_NOTIF").
    pub event: String,
    /// Notification method: "EVENT_DETECTION", "ONE_TIME", "PERIODIC".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notif_method: Option<String>,
}

/// App session context for Npcf_PolicyAuthorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionContext {
    /// Application Function application identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub af_app_id: Option<String>,
    /// Media components describing the session's media flows.
    #[serde(default)]
    pub media_components: Vec<MediaComponent>,
    /// SIP Call-ID for correlation with SIP signaling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sip_call_id: Option<String>,
    /// Subscription Permanent Identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    /// UE IPv4 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ipv4: Option<String>,
    /// UE IPv6 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ipv6: Option<String>,
    /// Data Network Name (APN equivalent in 5GC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnn: Option<String>,
    /// Event subscriptions for PCF notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ev_subsc: Option<EventSubscription>,
    /// Notification URI — callback endpoint for PCF events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notif_uri: Option<String>,
    /// Supported features (feature negotiation bitstring).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// PCF event notification delivered to the notif_uri callback (TS 29.514).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PcfEventNotification {
    /// List of event notifications.
    pub ev_notifs: Vec<EventNotification>,
}

/// Individual event notification from PCF.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventNotification {
    /// Event type (matches EventSubscription.event).
    pub event: String,
    /// Affected flows (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows: Option<Vec<FlowInfo>>,
}

/// Flow information in PCF event notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowInfo {
    /// Flow identifier.
    pub flow_id: u32,
    /// Flow descriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_descriptions: Option<Vec<String>>,
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

    /// Update an app session (PATCH /npcf-policyauthorization/v1/app-sessions/{id}).
    ///
    /// Used for media renegotiation (re-INVITE/UPDATE) to modify QoS.
    pub async fn update_app_session(
        &self,
        session_id: &str,
        context: &AppSessionContext,
    ) -> Result<AppSessionContextResp, SbiError> {
        let url = format!(
            "{}/npcf-policyauthorization/v1/app-sessions/{}",
            self.base_url, session_id
        );
        let response = self
            .client
            .patch(&url)
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
            med_sub_comps: None,
        };
        let json = serde_json::to_string(&media_component).unwrap();
        assert!(json.contains("AUDIO"));
        assert!(json.contains("PCMU"));
        assert!(json.contains("ENABLED"));
    }

    #[test]
    fn media_component_deserialization() {
        let json = r#"{
            "mediaComponentNumber": 2,
            "mediaType": "VIDEO",
            "flowStatus": "DISABLED",
            "codecData": null
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
                med_sub_comps: None,
            }],
            sip_call_id: Some("call-123@siphon.local".to_string()),
            supi: None,
            ue_ipv4: None,
            ue_ipv6: None,
            dnn: None,
            ev_subsc: None,
            notif_uri: None,
            supp_feat: None,
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

    #[test]
    fn app_session_context_with_extended_fields() {
        let context = AppSessionContext {
            af_app_id: Some("siphon".to_string()),
            media_components: vec![MediaComponent {
                media_component_number: 1,
                media_type: "AUDIO".to_string(),
                flow_status: "ENABLED".to_string(),
                codec_data: None,
                med_sub_comps: Some(vec![MediaSubComponent {
                    flow_number: 1,
                    flow_descriptions: Some(vec![
                        "permit in ip from any to 10.0.0.1 20000".to_string(),
                    ]),
                    flow_status: Some("ENABLED".to_string()),
                    flow_usage: None,
                }]),
            }],
            sip_call_id: Some("call-456@siphon".to_string()),
            supi: Some("imsi-001010000000001".to_string()),
            ue_ipv4: Some("10.0.0.1".to_string()),
            ue_ipv6: None,
            dnn: Some("ims".to_string()),
            ev_subsc: Some(EventSubscription {
                event: "UP_PATH_CH_EVENT".to_string(),
                notif_method: Some("EVENT_DETECTION".to_string()),
            }),
            notif_uri: Some("http://pcscf:8080/sbi/events".to_string()),
            supp_feat: Some("1".to_string()),
        };
        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("supi"));
        assert!(json.contains("ueIpv4"));
        assert!(json.contains("dnn"));
        assert!(json.contains("evSubsc"));
        assert!(json.contains("notifUri"));
        assert!(json.contains("medSubComps"));
        assert!(json.contains("flowDescriptions"));

        // Roundtrip
        let parsed: AppSessionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(parsed.ue_ipv4.as_deref(), Some("10.0.0.1"));
        assert_eq!(parsed.dnn.as_deref(), Some("ims"));
        let sub_comps = parsed.media_components[0].med_sub_comps.as_ref().unwrap();
        assert_eq!(sub_comps[0].flow_number, 1);
    }

    #[test]
    fn pcf_event_notification_roundtrip() {
        let notification = PcfEventNotification {
            ev_notifs: vec![EventNotification {
                event: "UP_PATH_CH_EVENT".to_string(),
                flows: Some(vec![FlowInfo {
                    flow_id: 1,
                    flow_descriptions: Some(vec!["permit in ip from any to 10.0.0.1 20000".to_string()]),
                }]),
            }],
        };
        let json = serde_json::to_string(&notification).unwrap();
        assert!(json.contains("evNotifs"));
        assert!(json.contains("UP_PATH_CH_EVENT"));

        let parsed: PcfEventNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ev_notifs.len(), 1);
        assert_eq!(parsed.ev_notifs[0].event, "UP_PATH_CH_EVENT");
    }

    #[test]
    fn app_session_context_minimal_deserialization() {
        // Only required fields — all new fields should default
        let json = r#"{"mediaComponents": []}"#;
        let context: AppSessionContext = serde_json::from_str(json).unwrap();
        assert!(context.af_app_id.is_none());
        assert!(context.supi.is_none());
        assert!(context.ue_ipv4.is_none());
        assert!(context.media_components.is_empty());
    }
}
