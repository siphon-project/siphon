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

/// Result of a successful app-session create — the parsed body plus the
/// absolute resource URI from the `201 Created` `Location` header.
///
/// `location` is the replica-independent address of the created session; the
/// script persists it and hands it back on teardown so `update`/`delete` reach
/// the same PCF even from a different siphon replica (TS 29.514 §4.2.2.2).
#[derive(Debug, Clone)]
pub struct CreatedAppSession {
    /// The parsed `AppSessionContext` response body.
    pub response: AppSessionContextResp,
    /// Absolute app-session resource URI (`Location` header), if present.
    pub location: Option<String>,
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
    ///
    /// `target` overrides the base URL for this one call — used to address the
    /// N5 transaction at a BSF-discovered PCF (`pcfFqdn`) instead of the
    /// configured SCP/fallback. `None` posts to `self.base_url` (today's
    /// VoLTE-via-SCP path, byte-for-byte unchanged).
    ///
    /// Returns the parsed body plus the `Location` header (the absolute
    /// resource URI) so the caller can address the same session on teardown.
    pub async fn create_app_session(
        &self,
        target: Option<&str>,
        context: &AppSessionContext,
    ) -> Result<CreatedAppSession, SbiError> {
        let base = target
            .map(|target| target.trim_end_matches('/'))
            .unwrap_or(&self.base_url);
        let url = format!("{base}/npcf-policyauthorization/v1/app-sessions");
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

        // Capture the Location header before consuming the body. Resolve a
        // relative Location against the base we posted to.
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|location| resolve_location(base, location));

        let body = response
            .json::<AppSessionContextResp>()
            .await
            .map_err(|error| SbiError::Deserialization(error.to_string()))?;

        Ok(CreatedAppSession {
            response: body,
            location,
        })
    }

    /// Delete an app session.
    ///
    /// `session_ref` is either a bare app-session id (resolved against
    /// `self.base_url`, the legacy behaviour) or an absolute resource URI
    /// (`http(s)://…`, used verbatim — the replica-independent teardown path).
    pub async fn delete_app_session(&self, session_ref: &str) -> Result<(), SbiError> {
        let url = self.resolve_session_url(session_ref);
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

    /// Update an app session (PATCH the resource).
    ///
    /// Used for media renegotiation (re-INVITE/UPDATE) to modify QoS.
    /// `session_ref` follows the same id-or-absolute-URI rule as
    /// [`delete_app_session`].
    pub async fn update_app_session(
        &self,
        session_ref: &str,
        context: &AppSessionContext,
    ) -> Result<AppSessionContextResp, SbiError> {
        let url = self.resolve_session_url(session_ref);
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

    /// Resolve a session reference to a concrete resource URL.
    ///
    /// Absolute references (`http://`/`https://`) are used verbatim; a bare id
    /// is appended to `self.base_url`'s app-sessions collection.
    fn resolve_session_url(&self, session_ref: &str) -> String {
        if is_absolute_http_url(session_ref) {
            session_ref.to_string()
        } else {
            format!(
                "{}/npcf-policyauthorization/v1/app-sessions/{}",
                self.base_url, session_ref
            )
        }
    }

    /// Get the base URL this client is configured to use.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// Whether a string is an absolute `http`/`https` URL.
fn is_absolute_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

/// Resolve a (possibly relative) `Location` header against the base URL the
/// request was sent to. Absolute Locations are returned verbatim.
fn resolve_location(base: &str, location: &str) -> String {
    if is_absolute_http_url(location) {
        location.to_string()
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            location.trim_start_matches('/')
        )
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

    #[test]
    fn is_absolute_http_url_detects_scheme() {
        assert!(is_absolute_http_url("http://pcf/x"));
        assert!(is_absolute_http_url("https://pcf/x"));
        assert!(!is_absolute_http_url("sess-abc-123"));
        assert!(!is_absolute_http_url("/npcf-policyauthorization/v1/app-sessions/1"));
    }

    #[test]
    fn resolve_session_url_bare_id_against_base() {
        let client = NpcfClient::new("http://scp.local:8080", reqwest::Client::new());
        assert_eq!(
            client.resolve_session_url("sess-1"),
            "http://scp.local:8080/npcf-policyauthorization/v1/app-sessions/sess-1"
        );
    }

    #[test]
    fn resolve_session_url_absolute_uri_verbatim() {
        let client = NpcfClient::new("http://scp.local:8080", reqwest::Client::new());
        let absolute = "http://pcf01.5gc:8080/npcf-policyauthorization/v1/app-sessions/abc";
        assert_eq!(client.resolve_session_url(absolute), absolute);
    }

    #[test]
    fn resolve_location_relative_and_absolute() {
        assert_eq!(
            resolve_location(
                "http://pcf01:8080",
                "/npcf-policyauthorization/v1/app-sessions/x"
            ),
            "http://pcf01:8080/npcf-policyauthorization/v1/app-sessions/x"
        );
        assert_eq!(
            resolve_location("http://pcf01:8080", "http://other/abs/x"),
            "http://other/abs/x"
        );
    }

    /// Spawn an axum router on `127.0.0.1:0` and return its base URL.
    async fn spawn_mock(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    fn create_router() -> axum::Router {
        use axum::routing::post;
        axum::Router::new().route(
            "/npcf-policyauthorization/v1/app-sessions",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    [(
                        "location",
                        "/npcf-policyauthorization/v1/app-sessions/sess-xyz",
                    )],
                    r#"{"appSessionId": "sess-xyz", "authorized": true}"#,
                )
            }),
        )
    }

    #[tokio::test]
    async fn create_posts_to_target_not_base_url() {
        let base = spawn_mock(create_router()).await;
        // Base URL is unroutable; only the per-call target is reachable. If
        // the call ignored `target` it would fail with a transport error.
        let client = NpcfClient::new("http://127.0.0.1:9", reqwest::Client::new());
        let context = AppSessionContext {
            af_app_id: Some("IMS Services".to_string()),
            media_components: vec![],
            sip_call_id: None,
            supi: None,
            ue_ipv4: None,
            ue_ipv6: None,
            dnn: None,
            ev_subsc: None,
            notif_uri: None,
            supp_feat: None,
        };
        let created = client
            .create_app_session(Some(&base), &context)
            .await
            .expect("create against target must succeed");
        assert_eq!(created.response.app_session_id, "sess-xyz");
        // Location resolved against the target base.
        assert_eq!(
            created.location.as_deref(),
            Some(
                format!("{base}/npcf-policyauthorization/v1/app-sessions/sess-xyz").as_str()
            )
        );
    }

    #[tokio::test]
    async fn create_none_target_posts_to_base_url() {
        let base = spawn_mock(create_router()).await;
        let client = NpcfClient::new(&base, reqwest::Client::new());
        let context = AppSessionContext {
            af_app_id: None,
            media_components: vec![],
            sip_call_id: None,
            supi: None,
            ue_ipv4: None,
            ue_ipv6: None,
            dnn: None,
            ev_subsc: None,
            notif_uri: None,
            supp_feat: None,
        };
        let created = client
            .create_app_session(None, &context)
            .await
            .expect("create against base must succeed");
        assert!(created.response.authorized);
        assert_eq!(
            created.location.as_deref(),
            Some(
                format!("{base}/npcf-policyauthorization/v1/app-sessions/sess-xyz").as_str()
            )
        );
    }
}
