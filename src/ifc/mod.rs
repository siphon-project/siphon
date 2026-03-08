//! Initial Filter Criteria (iFC) evaluation engine.
//!
//! Implements 3GPP TS 29.228 §6.6 iFC XML parsing and evaluation.
//! Used by the S-CSCF to determine which Application Servers a SIP
//! request must be routed through, based on the subscriber's service
//! profile received from the HSS via Diameter Cx SAA.

use std::collections::HashMap;
use std::fmt;

use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from iFC parsing or evaluation.
#[derive(Debug)]
pub enum IfcError {
    /// XML is malformed or unreadable.
    XmlParse(String),
    /// XML is well-formed but violates the expected schema.
    InvalidFormat(String),
}

impl fmt::Display for IfcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IfcError::XmlParse(message) => write!(formatter, "iFC XML parse error: {message}"),
            IfcError::InvalidFormat(message) => write!(formatter, "iFC format error: {message}"),
        }
    }
}

impl std::error::Error for IfcError {}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Session case for iFC evaluation (originating vs terminating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCase {
    /// Originating (request from registered user).
    Originating,
    /// Terminating (request to registered user).
    Terminating,
    /// Originating on behalf of unregistered user.
    OriginatingUnregistered,
    /// Terminating for unregistered user.
    TerminatingUnregistered,
}

impl SessionCase {
    /// Parse from the 3GPP integer encoding (TS 29.228).
    fn from_code(code: u32) -> Option<SessionCase> {
        match code {
            0 => Some(SessionCase::Originating),
            1 => Some(SessionCase::Terminating),
            2 => Some(SessionCase::OriginatingUnregistered),
            3 => Some(SessionCase::TerminatingUnregistered),
            _ => None,
        }
    }
}

impl fmt::Display for SessionCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionCase::Originating => write!(formatter, "Originating"),
            SessionCase::Terminating => write!(formatter, "Terminating"),
            SessionCase::OriginatingUnregistered => write!(formatter, "OriginatingUnregistered"),
            SessionCase::TerminatingUnregistered => write!(formatter, "TerminatingUnregistered"),
        }
    }
}

/// A single Initial Filter Criteria entry.
#[derive(Debug, Clone)]
pub struct InitialFilterCriteria {
    /// Priority (lower = evaluated first).
    pub priority: i32,
    /// Trigger point — conditions that must match.
    pub trigger_point: Option<TriggerPoint>,
    /// Application Server to route to if trigger matches.
    pub application_server: ApplicationServer,
    /// Default handling when AS is unreachable:
    /// 0 = SESSION_CONTINUED, 1 = SESSION_TERMINATED.
    pub default_handling: u32,
}

/// Trigger point — a set of conditions evaluated as CNF or DNF.
#[derive(Debug, Clone)]
pub struct TriggerPoint {
    /// Condition type: true = CNF (AND of OR groups), false = DNF (OR of AND groups).
    pub condition_type_cnf: bool,
    /// Service point triggers (the conditions).
    pub service_point_triggers: Vec<ServicePointTrigger>,
}

/// A single condition within a trigger point.
#[derive(Debug, Clone)]
pub struct ServicePointTrigger {
    /// Whether this condition is negated.
    pub condition_negated: bool,
    /// Group index for CNF/DNF grouping.
    pub group: Vec<i32>,
    /// Match on SIP method (e.g., "INVITE", "REGISTER").
    pub method: Option<String>,
    /// Match on SIP header: (header_name, optional_content_regex).
    pub header: Option<(String, Option<String>)>,
    /// Match on Request-URI.
    pub request_uri: Option<String>,
    /// Match on session case.
    pub session_case: Option<SessionCase>,
    /// Match on SDP line content: (sdp_line_type, optional_content_regex).
    pub sdp_line: Option<(String, Option<String>)>,
}

/// Application Server to route to.
#[derive(Debug, Clone)]
pub struct ApplicationServer {
    /// SIP URI of the AS (e.g., "sip:as1.example.com").
    pub server_name: String,
    /// Whether to include the original REGISTER request.
    pub include_register_request: bool,
    /// Whether to include the original REGISTER response.
    pub include_register_response: bool,
    /// Service information (opaque string passed to AS).
    pub service_info: Option<String>,
}

// ---------------------------------------------------------------------------
// XML Parsing
// ---------------------------------------------------------------------------

/// Parse iFC XML from a ServiceProfile document.
///
/// Expects XML conforming to 3GPP TS 29.228 §6.6, with a root
/// `<ServiceProfile>` element containing one or more
/// `<InitialFilterCriteria>` children.
pub fn parse_service_profile(xml: &str) -> Result<Vec<InitialFilterCriteria>, IfcError> {
    let mut reader = Reader::from_str(xml);

    let mut results: Vec<InitialFilterCriteria> = Vec::new();
    let mut depth: Vec<String> = Vec::new();

    // State for building the current iFC.
    let mut current_ifc: Option<IfcBuilder> = None;
    let mut current_trigger: Option<TriggerPointBuilder> = None;
    let mut current_spt: Option<SptBuilder> = None;
    let mut current_app_server: Option<AppServerBuilder> = None;
    let mut current_text = String::new();

    // For header SPT sub-elements.
    let mut header_name: Option<String> = None;
    let mut header_content: Option<String> = None;
    // For SDP line SPT sub-elements.
    let mut sdp_line_type: Option<String> = None;
    let mut sdp_line_content: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let tag = local_name(&element, &reader);
                match tag.as_str() {
                    "InitialFilterCriteria" => {
                        current_ifc = Some(IfcBuilder::default());
                    }
                    "TriggerPoint" => {
                        current_trigger = Some(TriggerPointBuilder::default());
                    }
                    "SPT" => {
                        current_spt = Some(SptBuilder::default());
                        header_name = None;
                        header_content = None;
                        sdp_line_type = None;
                        sdp_line_content = None;
                    }
                    "ApplicationServer" => {
                        current_app_server = Some(AppServerBuilder::default());
                    }
                    _ => {}
                }
                depth.push(tag);
                current_text.clear();
            }
            Ok(Event::End(_element)) => {
                let tag = depth.pop().unwrap_or_default();
                let text = current_text.trim().to_string();

                match tag.as_str() {
                    // --- iFC-level fields ---
                    "Priority" => {
                        if let Some(ref mut ifc) = current_ifc {
                            ifc.priority = text.parse::<i32>().ok();
                        }
                    }
                    "DefaultHandling" => {
                        if let Some(ref mut app) = current_app_server {
                            app.default_handling = text.parse::<u32>().ok();
                        }
                    }

                    // --- TriggerPoint fields ---
                    "ConditionTypeCNF" => {
                        if let Some(ref mut trigger) = current_trigger {
                            trigger.condition_type_cnf = Some(text == "1" || text.eq_ignore_ascii_case("true"));
                        }
                    }

                    // --- SPT fields ---
                    "ConditionNegated" => {
                        if let Some(ref mut spt) = current_spt {
                            spt.condition_negated = text == "1" || text.eq_ignore_ascii_case("true");
                        }
                    }
                    "Group" => {
                        if let Some(ref mut spt) = current_spt {
                            if let Ok(group) = text.parse::<i32>() {
                                spt.groups.push(group);
                            }
                        }
                    }
                    "Method" => {
                        if current_spt.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.method = Some(text);
                            }
                        }
                    }
                    "Header" => {
                        // <Header> is a container element inside <SPT> with
                        // sub-elements, but in some implementations it is a
                        // leaf text node. We handle it as a leaf in the
                        // "header_name" flow below.
                        if current_spt.is_some() && header_name.is_some() {
                            // Close of the <Header> container — assemble.
                            if let Some(ref mut spt) = current_spt {
                                spt.header = Some((
                                    header_name.take().unwrap_or_default(),
                                    header_content.take(),
                                ));
                            }
                        }
                    }
                    "HeaderName" => {
                        header_name = Some(text);
                    }
                    "Content" => {
                        // Content can appear under Header or SIPHeader.
                        if sdp_line_type.is_some() {
                            sdp_line_content = Some(text);
                        } else {
                            header_content = Some(text);
                        }
                    }
                    "RequestURI" => {
                        if let Some(ref mut spt) = current_spt {
                            spt.request_uri = Some(text);
                        }
                    }
                    "SessionCase" => {
                        if let Some(ref mut spt) = current_spt {
                            if let Ok(code) = text.parse::<u32>() {
                                spt.session_case = SessionCase::from_code(code);
                            }
                        }
                    }
                    "SIPHeader" => {
                        // Alternative element name used by some implementations.
                        if current_spt.is_some() && header_name.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.header = Some((
                                    header_name.take().unwrap_or_default(),
                                    header_content.take(),
                                ));
                            }
                        }
                    }
                    "SDPLine" => {
                        if current_spt.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.sdp_line = Some((
                                    sdp_line_type.take().unwrap_or_default(),
                                    sdp_line_content.take(),
                                ));
                            }
                        }
                    }
                    "Line" => {
                        sdp_line_type = Some(text);
                    }

                    // --- SPT close ---
                    "SPT" => {
                        if let (Some(spt), Some(ref mut trigger)) =
                            (current_spt.take(), &mut current_trigger)
                        {
                            trigger.spts.push(spt.build());
                        }
                    }

                    // --- ApplicationServer fields ---
                    "ServerName" => {
                        if let Some(ref mut app) = current_app_server {
                            app.server_name = Some(text);
                        }
                    }
                    "IncludeRegisterRequest" => {
                        if let Some(ref mut app) = current_app_server {
                            app.include_register_request =
                                text == "1" || text.eq_ignore_ascii_case("true");
                        }
                    }
                    "IncludeRegisterResponse" => {
                        if let Some(ref mut app) = current_app_server {
                            app.include_register_response =
                                text == "1" || text.eq_ignore_ascii_case("true");
                        }
                    }
                    "ServiceInfo" => {
                        if let Some(ref mut app) = current_app_server {
                            app.service_info = Some(text);
                        }
                    }

                    // --- Container closes ---
                    "TriggerPoint" => {
                        if let Some(ref mut ifc) = current_ifc {
                            if let Some(trigger) = current_trigger.take() {
                                ifc.trigger_point = Some(trigger.build());
                            }
                        }
                    }
                    "ApplicationServer" => {
                        if let Some(ref mut ifc) = current_ifc {
                            if let Some(app) = current_app_server.take() {
                                let default_handling = app.default_handling.unwrap_or(0);
                                ifc.application_server = Some(app.build()?);
                                ifc.default_handling = default_handling;
                            }
                        }
                    }
                    "InitialFilterCriteria" => {
                        if let Some(ifc) = current_ifc.take() {
                            results.push(ifc.build()?);
                        }
                    }
                    _ => {}
                }
                current_text.clear();
            }
            Ok(Event::Text(element)) => {
                current_text.push_str(
                    &element
                        .unescape()
                        .map_err(|error| IfcError::XmlParse(error.to_string()))?
                );
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(IfcError::XmlParse(error.to_string())),
            _ => {}
        }
    }

    Ok(results)
}

/// Extract the local name (without namespace prefix) from a tag.
fn local_name(element: &quick_xml::events::BytesStart, _reader: &Reader<&[u8]>) -> String {
    let full = element.name();
    let local = full.local_name();
    String::from_utf8_lossy(local.as_ref()).to_string()
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct IfcBuilder {
    priority: Option<i32>,
    trigger_point: Option<TriggerPoint>,
    application_server: Option<ApplicationServer>,
    default_handling: u32,
}

impl IfcBuilder {
    fn build(self) -> Result<InitialFilterCriteria, IfcError> {
        Ok(InitialFilterCriteria {
            priority: self
                .priority
                .ok_or_else(|| IfcError::InvalidFormat("missing Priority element".into()))?,
            trigger_point: self.trigger_point,
            application_server: self.application_server.ok_or_else(|| {
                IfcError::InvalidFormat("missing ApplicationServer element".into())
            })?,
            default_handling: self.default_handling,
        })
    }
}

#[derive(Default)]
struct TriggerPointBuilder {
    condition_type_cnf: Option<bool>,
    spts: Vec<ServicePointTrigger>,
}

impl TriggerPointBuilder {
    fn build(self) -> TriggerPoint {
        TriggerPoint {
            condition_type_cnf: self.condition_type_cnf.unwrap_or(true),
            service_point_triggers: self.spts,
        }
    }
}

#[derive(Default)]
struct SptBuilder {
    condition_negated: bool,
    groups: Vec<i32>,
    method: Option<String>,
    header: Option<(String, Option<String>)>,
    request_uri: Option<String>,
    session_case: Option<SessionCase>,
    sdp_line: Option<(String, Option<String>)>,
}

impl SptBuilder {
    fn build(self) -> ServicePointTrigger {
        ServicePointTrigger {
            condition_negated: self.condition_negated,
            group: self.groups,
            method: self.method,
            header: self.header,
            request_uri: self.request_uri,
            session_case: self.session_case,
            sdp_line: self.sdp_line,
        }
    }
}

#[derive(Default)]
struct AppServerBuilder {
    server_name: Option<String>,
    default_handling: Option<u32>,
    include_register_request: bool,
    include_register_response: bool,
    service_info: Option<String>,
}

impl AppServerBuilder {
    fn build(self) -> Result<ApplicationServer, IfcError> {
        Ok(ApplicationServer {
            server_name: self
                .server_name
                .ok_or_else(|| IfcError::InvalidFormat("missing ServerName element".into()))?,
            include_register_request: self.include_register_request,
            include_register_response: self.include_register_response,
            service_info: self.service_info,
        })
    }
}

// ---------------------------------------------------------------------------
// Evaluation engine
// ---------------------------------------------------------------------------

/// Evaluate iFC rules against a SIP request.
///
/// Returns the list of Application Servers to route through, ordered by
/// priority (ascending — lower priority value is evaluated first).
pub fn evaluate<'a>(
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
    ifcs: &'a [InitialFilterCriteria],
) -> Vec<&'a ApplicationServer> {
    let mut sorted: Vec<&InitialFilterCriteria> = ifcs.iter().collect();
    sorted.sort_by_key(|ifc| ifc.priority);

    sorted
        .into_iter()
        .filter(|ifc| matches_ifc(ifc, method, request_uri, headers, session_case))
        .map(|ifc| &ifc.application_server)
        .collect()
}

/// Check whether a single iFC matches the given request parameters.
fn matches_ifc(
    ifc: &InitialFilterCriteria,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    match &ifc.trigger_point {
        None => true, // No trigger point → always matches.
        Some(trigger) => evaluate_trigger_point(trigger, method, request_uri, headers, session_case),
    }
}

/// Evaluate a trigger point (CNF or DNF) against request parameters.
fn evaluate_trigger_point(
    trigger: &TriggerPoint,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    if trigger.service_point_triggers.is_empty() {
        return true;
    }

    // Group SPTs by their group indices.
    let mut groups: HashMap<i32, Vec<&ServicePointTrigger>> = HashMap::new();
    for spt in &trigger.service_point_triggers {
        if spt.group.is_empty() {
            // No group specified — treat as group 0.
            groups.entry(0).or_default().push(spt);
        } else {
            for &group_index in &spt.group {
                groups.entry(group_index).or_default().push(spt);
            }
        }
    }

    if trigger.condition_type_cnf {
        // CNF: AND of OR groups.
        // For each group, at least one SPT must match. All groups must pass.
        groups.values().all(|spts| {
            spts.iter()
                .any(|spt| evaluate_spt(spt, method, request_uri, headers, session_case))
        })
    } else {
        // DNF: OR of AND groups.
        // For each group, all SPTs must match. At least one group must pass.
        groups.values().any(|spts| {
            spts.iter()
                .all(|spt| evaluate_spt(spt, method, request_uri, headers, session_case))
        })
    }
}

/// Evaluate a single Service Point Trigger condition.
fn evaluate_spt(
    spt: &ServicePointTrigger,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    let raw_result = evaluate_spt_condition(spt, method, request_uri, headers, session_case);

    if spt.condition_negated {
        !raw_result
    } else {
        raw_result
    }
}

/// Evaluate the raw condition of an SPT (before negation).
fn evaluate_spt_condition(
    spt: &ServicePointTrigger,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    // Method match.
    if let Some(ref expected_method) = spt.method {
        return method.eq_ignore_ascii_case(expected_method);
    }

    // Header match.
    if let Some((ref header_name, ref content_pattern)) = spt.header {
        let matching_headers: Vec<&str> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(header_name))
            .map(|(_, value)| value.as_str())
            .collect();

        if matching_headers.is_empty() {
            return false;
        }

        if let Some(pattern) = content_pattern {
            // Check if any matching header value matches the regex.
            if let Ok(regex) = Regex::new(pattern) {
                return matching_headers.iter().any(|value| regex.is_match(value));
            }
            // If regex is invalid, fall back to substring match.
            return matching_headers
                .iter()
                .any(|value| value.contains(pattern.as_str()));
        }

        // Header exists, no content check required.
        return true;
    }

    // Request-URI match.
    if let Some(ref uri_pattern) = spt.request_uri {
        if let Ok(regex) = Regex::new(uri_pattern) {
            return regex.is_match(request_uri);
        }
        return request_uri.contains(uri_pattern.as_str());
    }

    // Session case match.
    if let Some(ref expected_case) = spt.session_case {
        return session_case == *expected_case;
    }

    // SDP line match (simplified — checks headers for Content-Type: application/sdp
    // and body content via headers list, since we don't have full body access here).
    if let Some((ref _line_type, ref _content_pattern)) = spt.sdp_line {
        // SDP matching requires body access which is not provided in the
        // evaluation interface. Return false for now; callers should
        // pre-filter or extend the API if SDP matching is needed.
        return false;
    }

    // No condition matched — should not happen for a well-formed SPT.
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_ifc_xml() -> &'static str {
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mmtel@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        )
    }

    #[test]
    fn parse_simple_ifc() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        assert_eq!(ifcs.len(), 1);

        let ifc = &ifcs[0];
        assert_eq!(ifc.priority, 0);
        assert_eq!(ifc.default_handling, 0);
        assert_eq!(ifc.application_server.server_name, "sip:mmtel@example.com");

        let trigger = ifc.trigger_point.as_ref().unwrap();
        assert!(trigger.condition_type_cnf);
        assert_eq!(trigger.service_point_triggers.len(), 1);

        let spt = &trigger.service_point_triggers[0];
        assert!(!spt.condition_negated);
        assert_eq!(spt.group, vec![0]);
        assert_eq!(spt.method.as_deref(), Some("INVITE"));
    }

    #[test]
    fn parse_multiple_ifcs() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mmtel@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>1</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:voicemail@example.com</ServerName>\n",
            "      <DefaultHandling>1</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 2);
        assert_eq!(ifcs[0].priority, 0);
        assert_eq!(
            ifcs[0].application_server.server_name,
            "sip:mmtel@example.com"
        );
        assert_eq!(ifcs[1].priority, 1);
        assert_eq!(
            ifcs[1].application_server.server_name,
            "sip:voicemail@example.com"
        );
        assert_eq!(ifcs[1].default_handling, 1);
    }

    #[test]
    fn parse_ifc_no_trigger_point() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:always@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 1);
        assert!(ifcs[0].trigger_point.is_none());
        assert_eq!(
            ifcs[0].application_server.server_name,
            "sip:always@example.com"
        );
    }

    #[test]
    fn parse_ifc_with_header_condition() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SIPHeader>\n",
            "          <HeaderName>P-Asserted-Identity</HeaderName>\n",
            "          <Content>sip:.*@example\\.com</Content>\n",
            "        </SIPHeader>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:header-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 1);

        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        let (ref header_name, ref content) = spt.header.as_ref().unwrap();
        assert_eq!(header_name, "P-Asserted-Identity");
        assert_eq!(content.as_deref(), Some("sip:.*@example\\.com"));
    }

    #[test]
    fn parse_ifc_with_session_case() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SessionCase>1</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:term-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        assert_eq!(spt.session_case, Some(SessionCase::Terminating));
    }

    #[test]
    fn evaluate_method_match() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "sip:mmtel@example.com");
    }

    #[test]
    fn evaluate_method_no_match() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();

        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_cnf_logic() {
        // CNF: AND of OR groups.
        // Group 0: Method=INVITE OR Method=UPDATE
        // Group 1: SessionCase=Originating
        // Both groups must pass.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>UPDATE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>1</Group>\n",
            "        <SessionCase>0</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:cnf-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE + Originating → match (group 0: INVITE matches, group 1: Originating matches)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // UPDATE + Originating → match (group 0: UPDATE matches, group 1: Originating matches)
        let results = evaluate(
            "UPDATE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // INVITE + Terminating → no match (group 1 fails)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Terminating,
            &ifcs,
        );
        assert!(results.is_empty());

        // REGISTER + Originating → no match (group 0 fails)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_dnf_logic() {
        // DNF: OR of AND groups.
        // Group 0: Method=INVITE (alone → must match INVITE)
        // Group 1: Method=REGISTER (alone → must match REGISTER)
        // Either group passing is sufficient.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>0</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>1</Group>\n",
            "        <Method>REGISTER</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:dnf-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE → match (group 0 passes)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // REGISTER → match (group 1 passes)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // OPTIONS → no match (neither group passes)
        let results = evaluate(
            "OPTIONS",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_condition_negated() {
        // Negated method match: NOT REGISTER → should match anything except REGISTER.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>1</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>REGISTER</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:neg-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE → match (NOT REGISTER is true)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // REGISTER → no match (NOT REGISTER is false)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_no_trigger_always_matches() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:always@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Any method should match.
        for method in &["INVITE", "REGISTER", "OPTIONS", "BYE", "CANCEL"] {
            let results = evaluate(
                method,
                "sip:any@example.com",
                &[],
                SessionCase::Originating,
                &ifcs,
            );
            assert_eq!(results.len(), 1, "method {method} should match");
        }
    }

    #[test]
    fn evaluate_priority_ordering() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>10</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:low-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:high-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mid-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].server_name, "sip:high-priority@example.com");
        assert_eq!(results[1].server_name, "sip:mid-priority@example.com");
        assert_eq!(results[2].server_name, "sip:low-priority@example.com");
    }

    #[test]
    fn evaluate_session_case_originating() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SessionCase>0</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:orig-only@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Originating → match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // Terminating → no match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Terminating,
            &ifcs,
        );
        assert!(results.is_empty());

        // OriginatingUnregistered → no match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::OriginatingUnregistered,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn session_case_display() {
        assert_eq!(SessionCase::Originating.to_string(), "Originating");
        assert_eq!(SessionCase::Terminating.to_string(), "Terminating");
        assert_eq!(
            SessionCase::OriginatingUnregistered.to_string(),
            "OriginatingUnregistered"
        );
        assert_eq!(
            SessionCase::TerminatingUnregistered.to_string(),
            "TerminatingUnregistered"
        );
    }

    #[test]
    fn evaluate_header_match_with_regex() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SIPHeader>\n",
            "          <HeaderName>P-Asserted-Identity</HeaderName>\n",
            "          <Content>sip:.*@example\\.com</Content>\n",
            "        </SIPHeader>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:header-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Matching header value
        let headers = vec![(
            "P-Asserted-Identity".to_string(),
            "sip:alice@example.com".to_string(),
        )];
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &headers,
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // Non-matching header value
        let headers = vec![(
            "P-Asserted-Identity".to_string(),
            "sip:alice@other.com".to_string(),
        )];
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &headers,
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());

        // Missing header entirely
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_request_uri_match() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <RequestURI>sip:.*@example\\.com</RequestURI>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:ruri-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        let results = evaluate(
            "INVITE",
            "sip:bob@other.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn ifc_error_display() {
        let xml_err = IfcError::XmlParse("bad xml".into());
        assert!(xml_err.to_string().contains("bad xml"));

        let fmt_err = IfcError::InvalidFormat("missing field".into());
        assert!(fmt_err.to_string().contains("missing field"));
    }

    #[test]
    fn parse_ifc_missing_server_name() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let result = parse_service_profile(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ifc_missing_priority() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:test@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let result = parse_service_profile(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_service_info() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:info-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "      <ServiceInfo>mmtel;conference</ServiceInfo>\n",
            "      <IncludeRegisterRequest>1</IncludeRegisterRequest>\n",
            "      <IncludeRegisterResponse>1</IncludeRegisterResponse>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        let app_server = &ifcs[0].application_server;
        assert_eq!(app_server.service_info.as_deref(), Some("mmtel;conference"));
        assert!(app_server.include_register_request);
        assert!(app_server.include_register_response);
    }
}
