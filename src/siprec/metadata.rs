//! RFC 7866 recording metadata XML generation and parsing.
//!
//! **Generation**: Builds the `application/rs-metadata+xml` body part for
//! SIPREC INVITE requests sent by the SRC.
//!
//! **Parsing**: Extracts session, participant, and stream information from
//! inbound SIPREC INVITEs received by the SRS.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("missing required element: {0}")]
    MissingElement(String),
}

impl From<quick_xml::Error> for MetadataError {
    fn from(error: quick_xml::Error) -> Self {
        Self::Xml(error.to_string())
    }
}

// ---------------------------------------------------------------------------
// Parsed metadata types
// ---------------------------------------------------------------------------

/// Parsed RFC 7866 recording metadata from a SIPREC INVITE.
#[derive(Debug, Clone)]
pub struct RecordingMetadata {
    /// Recording session ID (from `<session session_id="...">`).
    pub session_id: String,
    /// Participants in the recorded call.
    pub participants: Vec<Participant>,
    /// Media streams being recorded.
    pub streams: Vec<StreamInfo>,
}

/// A participant in the recorded call.
#[derive(Debug, Clone)]
pub struct Participant {
    /// Participant ID attribute.
    pub participant_id: String,
    /// Address of Record (from `<nameID aor="...">`).
    pub aor: String,
    /// Optional display name.
    pub name: Option<String>,
}

/// A media stream being recorded.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID attribute.
    pub stream_id: String,
    /// Session ID this stream belongs to.
    pub session_id: String,
    /// Stream label (correlates with SDP `a=label`).
    pub label: String,
}

// ---------------------------------------------------------------------------
// Generation (SRC → SRS direction)
// ---------------------------------------------------------------------------

/// Build RFC 7866 recording metadata XML.
///
/// The metadata describes the participants and streams being recorded.
pub fn build_recording_metadata(
    session_id: &str,
    caller_uri: &str,
    callee_uri: &str,
) -> String {
    let caller_participant_id = format!("part-{}", &session_id[..8]);
    let callee_participant_id = format!("part-{}", &session_id[8..16.min(session_id.len())]);
    let stream_id = format!("stream-{}", &session_id[..8]);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns="urn:ietf:params:xml:ns:recording:1">
  <datamode>complete</datamode>
  <session session_id="{session_id}">
    <sipSessionID>{session_id}</sipSessionID>
  </session>
  <participant participant_id="{caller_participant_id}">
    <nameID aor="{caller_uri}"/>
  </participant>
  <participant participant_id="{callee_participant_id}">
    <nameID aor="{callee_uri}"/>
  </participant>
  <stream stream_id="{stream_id}" session_id="{session_id}">
    <label>main-audio</label>
  </stream>
</recording>"#
    )
}

// ---------------------------------------------------------------------------
// Parsing (SRS ← SRC direction)
// ---------------------------------------------------------------------------

/// Parse RFC 7866 recording metadata XML into structured data.
///
/// Extracts session ID, participants (with AoR), and stream labels from
/// the `application/rs-metadata+xml` body part of a SIPREC INVITE.
pub fn parse_recording_metadata(xml: &str) -> Result<RecordingMetadata, MetadataError> {
    let mut reader = Reader::from_str(xml);

    let mut session_id: Option<String> = None;
    let mut participants = Vec::new();
    let mut streams = Vec::new();

    // Current parsing context.
    let mut current_participant_id: Option<String> = None;
    let mut current_participant_aor: Option<String> = None;
    let mut current_participant_name: Option<String> = None;
    let mut current_stream_id: Option<String> = None;
    let mut current_stream_session_id: Option<String> = None;
    let mut current_label: Option<String> = None;
    let mut inside_label = false;
    let mut inside_name = false;

    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(ref element)) | Ok(Event::Empty(ref element)) => {
                let local_name = element.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                match name {
                    "session" => {
                        if session_id.is_none() {
                            session_id = get_attribute(element, "session_id");
                        }
                    }
                    "participant" => {
                        current_participant_id = get_attribute(element, "participant_id");
                        current_participant_aor = None;
                        current_participant_name = None;
                    }
                    "nameID" | "nameId" => {
                        if let Some(aor) = get_attribute(element, "aor") {
                            current_participant_aor = Some(aor);
                        }
                    }
                    "name" => {
                        inside_name = true;
                    }
                    "stream" => {
                        current_stream_id = get_attribute(element, "stream_id");
                        current_stream_session_id = get_attribute(element, "session_id");
                        current_label = None;
                    }
                    "label" => {
                        inside_label = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref text)) => {
                if inside_label {
                    if let Ok(value) = text.unescape() {
                        current_label = Some(value.trim().to_string());
                    }
                }
                if inside_name {
                    if let Ok(value) = text.unescape() {
                        current_participant_name = Some(value.trim().to_string());
                    }
                }
            }
            Ok(Event::End(ref element)) => {
                let local_name = element.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                match name {
                    "participant" => {
                        if let (Some(participant_id), Some(aor)) =
                            (current_participant_id.take(), current_participant_aor.take())
                        {
                            participants.push(Participant {
                                participant_id,
                                aor,
                                name: current_participant_name.take(),
                            });
                        }
                    }
                    "stream" => {
                        if let (Some(stream_id), Some(stream_session_id)) =
                            (current_stream_id.take(), current_stream_session_id.take())
                        {
                            streams.push(StreamInfo {
                                stream_id,
                                session_id: stream_session_id,
                                label: current_label.take().unwrap_or_default(),
                            });
                        }
                    }
                    "label" => inside_label = false,
                    "name" => inside_name = false,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
            _ => {}
        }
        buffer.clear();
    }

    let session_id = session_id.ok_or_else(|| MetadataError::MissingElement("session".to_string()))?;

    Ok(RecordingMetadata {
        session_id,
        participants,
        streams,
    })
}

/// Extract an attribute value from an XML element.
fn get_attribute(element: &BytesStart, attribute_name: &str) -> Option<String> {
    for attribute in element.attributes().flatten() {
        let key = std::str::from_utf8(attribute.key.as_ref()).unwrap_or("");
        if key == attribute_name {
            return attribute.unescape_value().ok().map(|value| value.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Generation tests (existing) ---

    #[test]
    fn metadata_contains_session_id() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
        );
        assert!(xml.contains("abc12345-6789-0000-0000-000000000000"));
        assert!(xml.contains("sip:alice@example.com"));
        assert!(xml.contains("sip:bob@example.com"));
    }

    #[test]
    fn metadata_is_valid_xml_structure() {
        let xml = build_recording_metadata(
            "test-session-id-0000-0000-000000000000",
            "sip:caller@host.com",
            "sip:callee@host.com",
        );
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<recording xmlns="));
        assert!(xml.contains("<participant"));
        assert!(xml.contains("<stream"));
        assert!(xml.contains("<datamode>complete</datamode>"));
        assert!(xml.contains("</recording>"));
    }

    #[test]
    fn metadata_has_two_participants() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:alice@example.com",
            "sip:bob@example.com",
        );
        let count = xml.matches("<participant").count();
        assert_eq!(count, 2);
    }

    // --- Parsing tests (new) ---

    #[test]
    fn parse_roundtrip() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
        );
        let metadata = parse_recording_metadata(&xml).unwrap();

        assert_eq!(metadata.session_id, "abc12345-6789-0000-0000-000000000000");
        assert_eq!(metadata.participants.len(), 2);
        assert_eq!(metadata.participants[0].aor, "sip:alice@example.com");
        assert_eq!(metadata.participants[1].aor, "sip:bob@example.com");
        assert_eq!(metadata.streams.len(), 1);
        assert_eq!(metadata.streams[0].label, "main-audio");
    }

    #[test]
    fn parse_participant_ids() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:caller@host.com",
            "sip:callee@host.com",
        );
        let metadata = parse_recording_metadata(&xml).unwrap();

        assert_eq!(metadata.participants[0].participant_id, "part-aaaabbbb");
        assert_eq!(metadata.participants[1].participant_id, "part--cccc-dd");
    }

    #[test]
    fn parse_stream_session_id() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:a@x.com",
            "sip:b@x.com",
        );
        let metadata = parse_recording_metadata(&xml).unwrap();
        assert_eq!(metadata.streams[0].session_id, "aaaabbbb-cccc-dddd-eeee-ffffffffffff");
    }

    #[test]
    fn parse_missing_session_errors() {
        let xml = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>complete</datamode>\n",
            "</recording>",
        );
        let result = parse_recording_metadata(xml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("session"));
    }

    #[test]
    fn parse_external_metadata() {
        // Metadata from a different SRC implementation (not ours).
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>complete</datamode>\n",
            "  <session session_id=\"ext-sess-001\">\n",
            "    <sipSessionID>ext-sess-001</sipSessionID>\n",
            "  </session>\n",
            "  <participant participant_id=\"p1\">\n",
            "    <nameID aor=\"sip:external@vendor.com\"/>\n",
            "  </participant>\n",
            "  <participant participant_id=\"p2\">\n",
            "    <nameID aor=\"sip:customer@our.com\"/>\n",
            "  </participant>\n",
            "  <stream stream_id=\"s1\" session_id=\"ext-sess-001\">\n",
            "    <label>caller-audio</label>\n",
            "  </stream>\n",
            "  <stream stream_id=\"s2\" session_id=\"ext-sess-001\">\n",
            "    <label>callee-audio</label>\n",
            "  </stream>\n",
            "</recording>",
        );

        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.session_id, "ext-sess-001");
        assert_eq!(metadata.participants.len(), 2);
        assert_eq!(metadata.participants[0].aor, "sip:external@vendor.com");
        assert_eq!(metadata.participants[1].aor, "sip:customer@our.com");
        assert_eq!(metadata.streams.len(), 2);
        assert_eq!(metadata.streams[0].label, "caller-audio");
        assert_eq!(metadata.streams[1].label, "callee-audio");
    }

    #[test]
    fn parse_empty_xml_errors() {
        let result = parse_recording_metadata("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_no_participants_ok() {
        // Valid XML but no participants — still valid structure.
        let xml = concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <session session_id=\"sess-1\"/>\n",
            "</recording>",
        );
        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.session_id, "sess-1");
        assert!(metadata.participants.is_empty());
    }
}
