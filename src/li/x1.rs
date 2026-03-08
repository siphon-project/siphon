//! X1 Admin Interface — ETSI TS 103 221-1 intercept provisioning.
//!
//! Provides HTTPS REST endpoints for LEA/Mediation Function to manage
//! intercept targets (ActivateTask, ModifyTask, DeactivateTask).
//!
//! Supports both XML (per TS 103 221-1 §6) and JSON content types via
//! content negotiation. XML is the standard format; JSON is accepted as
//! an alternative for developer convenience.
//!
//! This runs as a separate axum HTTPS listener with mTLS, isolated
//! from the main admin API. Every operation is audit-logged.

use crate::config::LiX1Config;
use super::{AuditOperation, LiManager};
use super::target::{DeliveryType, InterceptTarget, TargetIdentity};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

// ---------------------------------------------------------------------------
// XML namespace for TS 103 221-1
// ---------------------------------------------------------------------------

const X1_XML_NAMESPACE: &str = "urn:etsi:xml:ns:li:task";

// ---------------------------------------------------------------------------
// Shared types (serialize to both JSON and XML)
// ---------------------------------------------------------------------------

/// Shared state for X1 endpoints.
#[derive(Clone)]
pub struct X1State {
    pub manager: LiManager,
    pub config: Arc<LiX1Config>,
}

/// X1 request body for ActivateTask / ModifyTask.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "task")]
pub struct ActivateTaskRequest {
    /// LIID — unique intercept identifier.
    pub liid: String,
    /// Target type: "sip_uri", "phone_number", or "ip_address".
    pub target_type: String,
    /// Target value (e.g. "sip:alice@example.com", "+1234567890", "10.0.0.1").
    pub target_value: String,
    /// Delivery type: "iri_only" or "iri_and_cc".
    #[serde(default = "default_delivery_type")]
    pub delivery_type: String,
    /// Opaque warrant reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warrant_ref: Option<String>,
    /// Mediation device identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation_id: Option<String>,
}

fn default_delivery_type() -> String {
    "iri_and_cc".to_string()
}

/// X1 response body for target status.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "taskStatus")]
pub struct TargetStatusResponse {
    pub liid: String,
    pub target_type: String,
    pub target_value: String,
    pub delivery_type: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warrant_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation_id: Option<String>,
}

/// X1 response for list of targets.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "taskList")]
pub struct TargetListResponse {
    #[serde(rename = "taskStatus")]
    pub targets: Vec<TargetStatusResponse>,
    pub count: usize,
}

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "error")]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ---------------------------------------------------------------------------
// Content negotiation
// ---------------------------------------------------------------------------

/// Whether the client wants XML (default per ETSI) or JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentFormat {
    Xml,
    Json,
}

/// Determine the response format from the Accept header.
///
/// Per TS 103 221-1, XML is the default. JSON is returned only when
/// the Accept header explicitly requests `application/json`.
fn negotiate_format(headers: &HeaderMap) -> ContentFormat {
    if let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        if accept.contains("application/json") && !accept.contains("application/xml") {
            return ContentFormat::Json;
        }
    }
    ContentFormat::Xml
}

/// Determine request body format from the Content-Type header.
fn request_format(headers: &HeaderMap) -> ContentFormat {
    if let Some(content_type) = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        if content_type.contains("application/json") {
            return ContentFormat::Json;
        }
    }
    ContentFormat::Xml
}

/// Serialize a response body to XML or JSON based on negotiated format.
fn serialize_response<T: Serialize>(value: &T, format: ContentFormat) -> (String, &'static str) {
    match format {
        ContentFormat::Xml => {
            let xml = quick_xml::se::to_string(value).unwrap_or_else(|error| {
                format!("<error>serialization failed: {error}</error>")
            });
            let xml_with_ns = inject_xml_namespace(&xml);
            (xml_with_ns, "application/xml")
        }
        ContentFormat::Json => {
            let json = serde_json::to_string(value).unwrap_or_else(|error| {
                format!("{{\"error\": \"serialization failed: {error}\"}}")
            });
            (json, "application/json")
        }
    }
}

/// Inject the ETSI XML namespace into the root element.
fn inject_xml_namespace(xml: &str) -> String {
    // quick_xml::se produces `<tagName>...` — inject xmlns before the first `>`.
    if let Some(pos) = xml.find('>') {
        let (before, after) = xml.split_at(pos);
        return format!("{before} xmlns=\"{X1_XML_NAMESPACE}\"{after}");
    }
    xml.to_string()
}

/// Parse request body from XML or JSON.
fn parse_request<T: for<'de> Deserialize<'de>>(
    body: &[u8],
    format: ContentFormat,
) -> Result<T, String> {
    match format {
        ContentFormat::Xml => {
            quick_xml::de::from_reader(body)
                .map_err(|error| format!("XML parse error: {error}"))
        }
        ContentFormat::Json => {
            serde_json::from_slice(body)
                .map_err(|error| format!("JSON parse error: {error}"))
        }
    }
}

/// Build an HTTP response with the appropriate content type.
fn build_response(body: String, content_type: &str, status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap()
}

/// Build an error response.
fn error_response(
    error_msg: String,
    code: String,
    status: StatusCode,
    format: ContentFormat,
) -> Response {
    let error = ErrorResponse { error: error_msg, code };
    let (body, content_type) = serialize_response(&error, format);
    build_response(body, content_type, status)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the X1 axum router.
pub fn x1_router(state: X1State) -> Router {
    Router::new()
        .route("/x1/targets", post(activate_task))
        .route("/x1/targets", get(list_targets))
        .route("/x1/targets/{liid}", get(get_target))
        .route("/x1/targets/{liid}", put(modify_task))
        .route("/x1/targets/{liid}", delete(deactivate_task))
        .route("/x1/targets/{liid}/ping", post(ping_target))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /x1/targets — ActivateTask (create new intercept).
async fn activate_task(
    State(state): State<X1State>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req_format = request_format(&headers);
    let resp_format = negotiate_format(&headers);

    let request: ActivateTaskRequest = match parse_request(&body, req_format) {
        Ok(request) => request,
        Err(error) => return error_response(error, "PARSE_ERROR".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    let identity = match parse_target_identity(&request.target_type, &request.target_value) {
        Ok(identity) => identity,
        Err(error) => return error_response(error, "INVALID_TARGET".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    let delivery = match parse_delivery_type(&request.delivery_type) {
        Ok(delivery) => delivery,
        Err(error) => return error_response(error, "INVALID_DELIVERY_TYPE".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    let target = InterceptTarget {
        liid: request.liid.clone(),
        target_identity: identity,
        delivery_type: delivery,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: request.warrant_ref.clone(),
        mediation_id: request.mediation_id.clone(),
    };

    let is_new = state.manager.targets().activate(target);

    let operation = if is_new {
        AuditOperation::TargetActivated
    } else {
        AuditOperation::TargetModified
    };

    state.manager.audit(
        operation,
        Some(&request.liid),
        format!(
            "target_type={} target_value={} delivery={}",
            request.target_type, request.target_value, request.delivery_type
        ),
    );

    info!(
        liid = %request.liid,
        target_type = %request.target_type,
        "X1: intercept target {}",
        if is_new { "activated" } else { "modified" }
    );

    let response = TargetStatusResponse {
        liid: request.liid,
        target_type: request.target_type,
        target_value: request.target_value,
        delivery_type: request.delivery_type,
        active: true,
        warrant_ref: request.warrant_ref,
        mediation_id: request.mediation_id,
    };

    let status = if is_new { StatusCode::CREATED } else { StatusCode::OK };
    let (body, content_type) = serialize_response(&response, resp_format);
    build_response(body, content_type, status)
}

/// GET /x1/targets/{liid} — Get intercept status.
async fn get_target(
    State(state): State<X1State>,
    headers: HeaderMap,
    Path(liid): Path<String>,
) -> Response {
    let format = negotiate_format(&headers);

    let target = match state.manager.targets().get_by_liid(&liid) {
        Some(target) => target,
        None => return error_response(
            format!("target {liid} not found"),
            "NOT_FOUND".into(),
            StatusCode::NOT_FOUND,
            format,
        ),
    };

    let response = target_to_response(&target);
    let (body, content_type) = serialize_response(&response, format);
    build_response(body, content_type, StatusCode::OK)
}

/// GET /x1/targets — List all active intercepts.
async fn list_targets(
    State(state): State<X1State>,
    headers: HeaderMap,
) -> Response {
    let format = negotiate_format(&headers);

    state.manager.audit(
        AuditOperation::TargetListed,
        None,
        "all targets listed".to_string(),
    );

    let targets: Vec<TargetStatusResponse> = state.manager.targets()
        .list_all()
        .iter()
        .map(target_to_response)
        .collect();
    let count = targets.len();

    let response = TargetListResponse { targets, count };
    let (body, content_type) = serialize_response(&response, format);
    build_response(body, content_type, StatusCode::OK)
}

/// PUT /x1/targets/{liid} — ModifyTask (update existing intercept).
async fn modify_task(
    State(state): State<X1State>,
    headers: HeaderMap,
    Path(liid): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let req_format = request_format(&headers);
    let resp_format = negotiate_format(&headers);

    let request: ActivateTaskRequest = match parse_request(&body, req_format) {
        Ok(request) => request,
        Err(error) => return error_response(error, "PARSE_ERROR".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    if request.liid != liid {
        return error_response(
            "LIID in path and body must match".into(),
            "LIID_MISMATCH".into(),
            StatusCode::BAD_REQUEST,
            resp_format,
        );
    }

    if state.manager.targets().get_by_liid(&liid).is_none() {
        return error_response(
            format!("target {liid} not found"),
            "NOT_FOUND".into(),
            StatusCode::NOT_FOUND,
            resp_format,
        );
    }

    let identity = match parse_target_identity(&request.target_type, &request.target_value) {
        Ok(identity) => identity,
        Err(error) => return error_response(error, "INVALID_TARGET".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    let delivery = match parse_delivery_type(&request.delivery_type) {
        Ok(delivery) => delivery,
        Err(error) => return error_response(error, "INVALID_DELIVERY_TYPE".into(), StatusCode::BAD_REQUEST, resp_format),
    };

    let target = InterceptTarget {
        liid: request.liid.clone(),
        target_identity: identity,
        delivery_type: delivery,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: request.warrant_ref.clone(),
        mediation_id: request.mediation_id.clone(),
    };

    state.manager.targets().activate(target);

    state.manager.audit(
        AuditOperation::TargetModified,
        Some(&liid),
        format!(
            "target_type={} target_value={} delivery={}",
            request.target_type, request.target_value, request.delivery_type
        ),
    );

    info!(liid = %liid, "X1: intercept target modified");

    let response = TargetStatusResponse {
        liid: request.liid,
        target_type: request.target_type,
        target_value: request.target_value,
        delivery_type: request.delivery_type,
        active: true,
        warrant_ref: request.warrant_ref,
        mediation_id: request.mediation_id,
    };

    let (body, content_type) = serialize_response(&response, resp_format);
    build_response(body, content_type, StatusCode::OK)
}

/// DELETE /x1/targets/{liid} — DeactivateTask (remove intercept).
async fn deactivate_task(
    State(state): State<X1State>,
    headers: HeaderMap,
    Path(liid): Path<String>,
) -> Response {
    let format = negotiate_format(&headers);

    let removed = state.manager.targets().deactivate(&liid);

    if removed.is_some() {
        state.manager.audit(
            AuditOperation::TargetDeactivated,
            Some(&liid),
            "target deactivated".to_string(),
        );
        info!(liid = %liid, "X1: intercept target deactivated");
        StatusCode::NO_CONTENT.into_response()
    } else {
        error_response(
            format!("target {liid} not found"),
            "NOT_FOUND".into(),
            StatusCode::NOT_FOUND,
            format,
        )
    }
}

/// POST /x1/targets/{liid}/ping — Keepalive/heartbeat.
async fn ping_target(
    State(state): State<X1State>,
    headers: HeaderMap,
    Path(liid): Path<String>,
) -> Response {
    let format = negotiate_format(&headers);

    if state.manager.targets().get_by_liid(&liid).is_some() {
        StatusCode::OK.into_response()
    } else {
        error_response(
            format!("target {liid} not found"),
            "NOT_FOUND".into(),
            StatusCode::NOT_FOUND,
            format,
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse target identity from request fields.
fn parse_target_identity(target_type: &str, target_value: &str) -> Result<TargetIdentity, String> {
    match target_type {
        "sip_uri" => Ok(TargetIdentity::SipUri(target_value.to_string())),
        "phone_number" => Ok(TargetIdentity::PhoneNumber(target_value.to_string())),
        "ip_address" => {
            let ip: std::net::IpAddr = target_value.parse()
                .map_err(|_| format!("invalid IP address: {target_value}"))?;
            Ok(TargetIdentity::IpAddress(ip))
        }
        other => Err(format!("unknown target_type: {other} (expected sip_uri, phone_number, or ip_address)")),
    }
}

/// Parse delivery type from request string.
fn parse_delivery_type(delivery: &str) -> Result<DeliveryType, String> {
    match delivery {
        "iri_only" => Ok(DeliveryType::IriOnly),
        "iri_and_cc" => Ok(DeliveryType::IriAndCc),
        other => Err(format!("unknown delivery_type: {other} (expected iri_only or iri_and_cc)")),
    }
}

/// Convert an InterceptTarget to a status response.
fn target_to_response(target: &InterceptTarget) -> TargetStatusResponse {
    let (target_type, target_value) = match &target.target_identity {
        TargetIdentity::SipUri(uri) => ("sip_uri".to_string(), uri.clone()),
        TargetIdentity::PhoneNumber(number) => ("phone_number".to_string(), number.clone()),
        TargetIdentity::IpAddress(ip) => ("ip_address".to_string(), ip.to_string()),
    };

    let delivery_type = match target.delivery_type {
        DeliveryType::IriOnly => "iri_only".to_string(),
        DeliveryType::IriAndCc => "iri_and_cc".to_string(),
    };

    TargetStatusResponse {
        liid: target.liid.clone(),
        target_type,
        target_value,
        delivery_type,
        active: target.active,
        warrant_ref: target.warrant_ref.clone(),
        mediation_id: target.mediation_id.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> X1State {
        let config = crate::config::LawfulInterceptConfig {
            enabled: true,
            audit_log: None,
            x1: Some(LiX1Config {
                listen: "127.0.0.1:8443".to_string(),
                tls: None,
                auth_token: None,
            }),
            x2: None,
            x3: None,
            siprec: None,
        };

        let (manager, _iri_receiver, _audit_receiver) = LiManager::new(config.clone(), 100);

        X1State {
            manager,
            config: Arc::new(config.x1.unwrap()),
        }
    }

    #[tokio::test]
    async fn activate_and_get_target_json() {
        let state = test_state();
        let app = x1_router(state);

        // Activate via JSON
        let body = serde_json::json!({
            "liid": "LI-001",
            "target_type": "sip_uri",
            "target_value": "sip:alice@example.com",
            "delivery_type": "iri_and_cc",
            "warrant_ref": "W-2026-001"
        });

        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/x1/targets")
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().get("content-type").unwrap().to_str().unwrap()
            .contains("application/json"));

        // Get with JSON accept
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/x1/targets/LI-001")
                    .header("accept", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let status: TargetStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.liid, "LI-001");
        assert_eq!(status.target_type, "sip_uri");
        assert!(status.active);
    }

    #[tokio::test]
    async fn activate_and_get_target_xml() {
        let state = test_state();
        let app = x1_router(state);

        // Activate via XML
        let xml_body = concat!(
            "<task>",
            "<liid>LI-XML-001</liid>",
            "<target_type>sip_uri</target_type>",
            "<target_value>sip:alice@example.com</target_value>",
            "<delivery_type>iri_and_cc</delivery_type>",
            "<warrant_ref>W-2026-XML</warrant_ref>",
            "</task>",
        );

        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/x1/targets")
                    .header("content-type", "application/xml")
                    .header("accept", "application/xml")
                    .body(Body::from(xml_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("application/xml"));

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("LI-XML-001"));
        assert!(body_str.contains(X1_XML_NAMESPACE));

        // Get with XML accept (default)
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/x1/targets/LI-XML-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("LI-XML-001"));
        assert!(body_str.contains("application/xml") || body_str.contains("<taskStatus"));
    }

    #[tokio::test]
    async fn deactivate_target() {
        let state = test_state();
        let app = x1_router(state);

        // Activate first
        let body = serde_json::json!({
            "liid": "LI-002",
            "target_type": "phone_number",
            "target_value": "+15551234567",
        });

        let _ = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/x1/targets")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Deactivate
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/x1/targets/LI-002")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify gone
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/x1/targets/LI-002")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_targets_empty() {
        let state = test_state();
        let app = x1_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/x1/targets")
                    .header("accept", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let list: TargetListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(list.count, 0);
        assert!(list.targets.is_empty());
    }

    #[tokio::test]
    async fn deactivate_nonexistent_returns_404() {
        let state = test_state();
        let app = x1_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/x1/targets/LI-NONEXISTENT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn parse_target_identity_variants() {
        let sip = parse_target_identity("sip_uri", "sip:alice@example.com").unwrap();
        assert!(matches!(sip, TargetIdentity::SipUri(_)));

        let phone = parse_target_identity("phone_number", "+15551234567").unwrap();
        assert!(matches!(phone, TargetIdentity::PhoneNumber(_)));

        let ip = parse_target_identity("ip_address", "10.0.0.1").unwrap();
        assert!(matches!(ip, TargetIdentity::IpAddress(_)));

        let invalid = parse_target_identity("unknown", "foo");
        assert!(invalid.is_err());

        let bad_ip = parse_target_identity("ip_address", "not-an-ip");
        assert!(bad_ip.is_err());
    }

    #[test]
    fn parse_delivery_type_variants() {
        assert_eq!(parse_delivery_type("iri_only").unwrap(), DeliveryType::IriOnly);
        assert_eq!(parse_delivery_type("iri_and_cc").unwrap(), DeliveryType::IriAndCc);
        assert!(parse_delivery_type("invalid").is_err());
    }

    #[test]
    fn content_negotiation_defaults_to_xml() {
        let headers = HeaderMap::new();
        assert_eq!(negotiate_format(&headers), ContentFormat::Xml);
    }

    #[test]
    fn content_negotiation_json_on_accept() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        assert_eq!(negotiate_format(&headers), ContentFormat::Json);
    }

    #[test]
    fn content_negotiation_xml_on_accept() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/xml".parse().unwrap());
        assert_eq!(negotiate_format(&headers), ContentFormat::Xml);
    }

    #[test]
    fn xml_serialization_includes_namespace() {
        let response = TargetStatusResponse {
            liid: "LI-001".to_string(),
            target_type: "sip_uri".to_string(),
            target_value: "sip:alice@example.com".to_string(),
            delivery_type: "iri_and_cc".to_string(),
            active: true,
            warrant_ref: None,
            mediation_id: None,
        };
        let (xml, content_type) = serialize_response(&response, ContentFormat::Xml);
        assert_eq!(content_type, "application/xml");
        assert!(xml.contains(X1_XML_NAMESPACE));
        assert!(xml.contains("LI-001"));
        assert!(xml.contains("<active>true</active>"));
    }

    #[test]
    fn xml_request_parsing() {
        let xml = concat!(
            "<task>",
            "<liid>LI-XML</liid>",
            "<target_type>phone_number</target_type>",
            "<target_value>+15551234567</target_value>",
            "<delivery_type>iri_only</delivery_type>",
            "</task>",
        );
        let parsed: ActivateTaskRequest = parse_request(xml.as_bytes(), ContentFormat::Xml).unwrap();
        assert_eq!(parsed.liid, "LI-XML");
        assert_eq!(parsed.target_type, "phone_number");
        assert_eq!(parsed.delivery_type, "iri_only");
    }
}
