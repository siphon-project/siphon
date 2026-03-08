//! RFC 7866 recording metadata XML generation.
//!
//! Generates the `application/rs-metadata+xml` body part for SIPREC
//! INVITE requests to the SRS.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
