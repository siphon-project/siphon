//! Minimal SDP parser for codec filtering.
//!
//! Provides functionality to parse SDP bodies, extract/modify media lines
//! (`m=`) and codec attributes (`a=rtpmap`), and filter codecs by name.
//!
//! This is NOT a full SDP parser — it handles the common cases needed for
//! codec filtering in a SIP proxy/B2BUA context.

use std::collections::HashSet;

/// A parsed media line from SDP.
#[derive(Debug, Clone)]
pub struct MediaLine {
    /// Media type: "audio", "video", "application", etc.
    pub media_type: String,
    /// Port number.
    pub port: u16,
    /// Protocol: "RTP/AVP", "RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF", etc.
    pub protocol: String,
    /// Payload type numbers.
    pub formats: Vec<u16>,
    /// Codec attributes keyed by payload type.
    pub rtpmap: Vec<(u16, String)>,
    /// fmtp attributes keyed by payload type.
    pub fmtp: Vec<(u16, String)>,
    /// Other attributes (not rtpmap/fmtp) for this media section.
    pub other_attrs: Vec<String>,
}

/// A parsed SDP body.
#[derive(Debug, Clone)]
pub struct SdpBody {
    /// Session-level lines (v=, o=, s=, c=, t=, etc.) before first m= line.
    pub session_lines: Vec<String>,
    /// Media sections.
    pub media_sections: Vec<MediaLine>,
}

impl SdpBody {
    /// Parse an SDP body from a string.
    pub fn parse(sdp: &str) -> Self {
        let mut session_lines = Vec::new();
        let mut media_sections = Vec::new();
        let mut current_media: Option<MediaLine> = None;

        for line in sdp.lines() {
            let line = line.trim_end_matches('\r');

            if line.starts_with("m=") {
                // Save previous media section
                if let Some(media) = current_media.take() {
                    media_sections.push(media);
                }
                // Parse new media line: m=audio 49170 RTP/AVP 0 8 97
                current_media = Some(parse_media_line(line));
            } else if let Some(ref mut media) = current_media {
                // We're inside a media section
                if line.starts_with("a=rtpmap:") {
                    // a=rtpmap:97 opus/48000/2
                    if let Some((pt, codec)) = parse_rtpmap(line) {
                        media.rtpmap.push((pt, codec));
                    }
                } else if line.starts_with("a=fmtp:") {
                    // a=fmtp:97 minptime=10;useinbandfec=1
                    if let Some((pt, params)) = parse_fmtp(line) {
                        media.fmtp.push((pt, params));
                    }
                } else {
                    media.other_attrs.push(line.to_string());
                }
            } else {
                // Session-level line
                session_lines.push(line.to_string());
            }
        }

        // Save last media section
        if let Some(media) = current_media {
            media_sections.push(media);
        }

        SdpBody {
            session_lines,
            media_sections,
        }
    }

    /// Filter codecs: keep only codecs whose names match the given list.
    ///
    /// Matching is case-insensitive. Codec names are compared against the
    /// encoding name in `a=rtpmap` (e.g., "PCMU", "PCMA", "opus", "telephone-event").
    ///
    /// Static payload types (0-95) without explicit rtpmap are matched by their
    /// well-known names.
    pub fn filter_codecs(&mut self, keep: &[&str]) {
        let keep_set: HashSet<String> = keep.iter().map(|s| s.to_lowercase()).collect();

        for media in &mut self.media_sections {
            let kept_pts: HashSet<u16> = media
                .formats
                .iter()
                .filter(|&&pt| {
                    // Check rtpmap first
                    if let Some(codec_name) = media.rtpmap.iter().find(|(rpt, _)| *rpt == pt) {
                        let name = codec_name.1.split('/').next().unwrap_or("");
                        return keep_set.contains(&name.to_lowercase());
                    }
                    // Fall back to well-known static payload types
                    if let Some(name) = static_codec_name(pt) {
                        return keep_set.contains(&name.to_lowercase());
                    }
                    false
                })
                .copied()
                .collect();

            media.formats.retain(|pt| kept_pts.contains(pt));
            media.rtpmap.retain(|(pt, _)| kept_pts.contains(pt));
            media.fmtp.retain(|(pt, _)| kept_pts.contains(pt));
        }
    }

    /// Remove codecs by name. Opposite of `filter_codecs`.
    pub fn remove_codecs(&mut self, remove: &[&str]) {
        let remove_set: HashSet<String> = remove.iter().map(|s| s.to_lowercase()).collect();

        for media in &mut self.media_sections {
            let removed_pts: HashSet<u16> = media
                .formats
                .iter()
                .filter(|&&pt| {
                    if let Some(codec_name) = media.rtpmap.iter().find(|(rpt, _)| *rpt == pt) {
                        let name = codec_name.1.split('/').next().unwrap_or("");
                        return remove_set.contains(&name.to_lowercase());
                    }
                    if let Some(name) = static_codec_name(pt) {
                        return remove_set.contains(&name.to_lowercase());
                    }
                    false
                })
                .copied()
                .collect();

            media.formats.retain(|pt| !removed_pts.contains(pt));
            media.rtpmap.retain(|(pt, _)| !removed_pts.contains(pt));
            media.fmtp.retain(|(pt, _)| !removed_pts.contains(pt));
        }
    }

}

impl std::fmt::Display for SdpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in &self.session_lines {
            write!(f, "{line}\r\n")?;
        }

        for media in &self.media_sections {
            // m=audio 49170 RTP/AVP 0 8 97
            let formats: Vec<String> = media.formats.iter().map(|pt| pt.to_string()).collect();
            write!(
                f,
                "m={} {} {} {}\r\n",
                media.media_type,
                media.port,
                media.protocol,
                formats.join(" ")
            )?;

            // Other attributes first (c=, b=, etc.)
            for attr in &media.other_attrs {
                write!(f, "{attr}\r\n")?;
            }

            // rtpmap attributes
            for (pt, codec) in &media.rtpmap {
                write!(f, "a=rtpmap:{pt} {codec}\r\n")?;
            }

            // fmtp attributes
            for (pt, params) in &media.fmtp {
                write!(f, "a=fmtp:{pt} {params}\r\n")?;
            }
        }

        Ok(())
    }
}

/// Parse an `m=` line into a MediaLine.
fn parse_media_line(line: &str) -> MediaLine {
    let content = line.strip_prefix("m=").unwrap_or(line);
    let parts: Vec<&str> = content.split_whitespace().collect();

    let media_type = parts.first().unwrap_or(&"audio").to_string();
    let port = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let protocol = parts.get(2).unwrap_or(&"RTP/AVP").to_string();
    let formats: Vec<u16> = parts[3..]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    MediaLine {
        media_type,
        port,
        protocol,
        formats,
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        other_attrs: Vec::new(),
    }
}

/// Parse `a=rtpmap:97 opus/48000/2` → (97, "opus/48000/2")
fn parse_rtpmap(line: &str) -> Option<(u16, String)> {
    let content = line.strip_prefix("a=rtpmap:")?;
    let (pt_str, codec) = content.split_once(' ')?;
    let pt = pt_str.parse().ok()?;
    Some((pt, codec.to_string()))
}

/// Parse `a=fmtp:97 minptime=10` → (97, "minptime=10")
fn parse_fmtp(line: &str) -> Option<(u16, String)> {
    let content = line.strip_prefix("a=fmtp:")?;
    let (pt_str, params) = content.split_once(' ')?;
    let pt = pt_str.parse().ok()?;
    Some((pt, params.to_string()))
}

/// Well-known static codec names for payload types 0-34.
fn static_codec_name(pt: u16) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU"),
        3 => Some("GSM"),
        4 => Some("G723"),
        5 => Some("DVI4"),
        6 => Some("DVI4"),
        7 => Some("LPC"),
        8 => Some("PCMA"),
        9 => Some("G722"),
        10 => Some("L16"),
        11 => Some("L16"),
        12 => Some("QCELP"),
        13 => Some("CN"),
        14 => Some("MPA"),
        15 => Some("G728"),
        18 => Some("G729"),
        25 => Some("CelB"),
        26 => Some("JPEG"),
        28 => Some("nv"),
        31 => Some("H261"),
        32 => Some("MPV"),
        33 => Some("MP2T"),
        34 => Some("H263"),
        _ => None,
    }
}

/// Rewrite an SDP body in a SIP message: filter codecs and return the new body + Content-Length.
pub fn rewrite_sdp_body(body: &str, keep_codecs: &[&str]) -> (String, usize) {
    let mut sdp = SdpBody::parse(body);
    sdp.filter_codecs(keep_codecs);
    let new_body = sdp.to_string();
    let length = new_body.len();
    (new_body, length)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SDP: &str = concat!(
        "v=0\r\n",
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 49170 RTP/AVP 0 8 97 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:97 opus/48000/2\r\n",
        "a=fmtp:97 minptime=10;useinbandfec=1\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=fmtp:101 0-16\r\n",
    );

    #[test]
    fn parse_sdp_session_lines() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        assert_eq!(sdp.session_lines.len(), 5);
        assert!(sdp.session_lines[0].starts_with("v="));
    }

    #[test]
    fn parse_sdp_media_section() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        assert_eq!(sdp.media_sections.len(), 1);

        let media = &sdp.media_sections[0];
        assert_eq!(media.media_type, "audio");
        assert_eq!(media.port, 49170);
        assert_eq!(media.protocol, "RTP/AVP");
        assert_eq!(media.formats, vec![0, 8, 97, 101]);
    }

    #[test]
    fn parse_rtpmap_attributes() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let media = &sdp.media_sections[0];

        assert_eq!(media.rtpmap.len(), 4);
        assert_eq!(media.rtpmap[0], (0, "PCMU/8000".to_string()));
        assert_eq!(media.rtpmap[1], (8, "PCMA/8000".to_string()));
        assert_eq!(media.rtpmap[2], (97, "opus/48000/2".to_string()));
        assert_eq!(media.rtpmap[3], (101, "telephone-event/8000".to_string()));
    }

    #[test]
    fn parse_fmtp_attributes() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let media = &sdp.media_sections[0];

        assert_eq!(media.fmtp.len(), 2);
        assert_eq!(media.fmtp[0].0, 97);
        assert!(media.fmtp[0].1.contains("minptime=10"));
        assert_eq!(media.fmtp[1].0, 101);
    }

    #[test]
    fn filter_codecs_keep_pcmu_pcma() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["PCMU", "PCMA"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 8]);
        assert_eq!(media.rtpmap.len(), 2);
        assert!(media.fmtp.is_empty()); // opus and telephone-event fmtp removed
    }

    #[test]
    fn filter_codecs_case_insensitive() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["pcmu", "Opus"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 97]);
    }

    #[test]
    fn remove_codecs() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.remove_codecs(&["telephone-event"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 8, 97]);
        assert!(!media.rtpmap.iter().any(|(_, c)| c.contains("telephone-event")));
    }

    #[test]
    fn serialize_roundtrip() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let output = sdp.to_string();

        // Re-parse should produce same structure
        let reparsed = SdpBody::parse(&output);
        assert_eq!(reparsed.session_lines.len(), sdp.session_lines.len());
        assert_eq!(reparsed.media_sections.len(), sdp.media_sections.len());
        assert_eq!(
            reparsed.media_sections[0].formats,
            sdp.media_sections[0].formats
        );
    }

    #[test]
    fn filter_then_serialize() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["PCMU", "PCMA"]);
        let output = sdp.to_string();

        assert!(output.contains("m=audio 49170 RTP/AVP 0 8"));
        assert!(output.contains("a=rtpmap:0 PCMU/8000"));
        assert!(output.contains("a=rtpmap:8 PCMA/8000"));
        assert!(!output.contains("opus"));
        assert!(!output.contains("telephone-event"));
    }

    #[test]
    fn rewrite_sdp_body_function() {
        let (new_body, length) = rewrite_sdp_body(SAMPLE_SDP, &["PCMU"]);
        assert!(new_body.contains("PCMU"));
        assert!(!new_body.contains("PCMA"));
        assert!(!new_body.contains("opus"));
        assert_eq!(length, new_body.len());
    }

    #[test]
    fn empty_sdp() {
        let sdp = SdpBody::parse("");
        assert!(sdp.session_lines.is_empty());
        assert!(sdp.media_sections.is_empty());
    }

    #[test]
    fn multiple_media_sections() {
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "m=video 5006 RTP/AVP 96\r\n",
            "a=rtpmap:96 H264/90000\r\n",
        );

        let sdp = SdpBody::parse(sdp_str);
        assert_eq!(sdp.media_sections.len(), 2);
        assert_eq!(sdp.media_sections[0].media_type, "audio");
        assert_eq!(sdp.media_sections[1].media_type, "video");
    }

    #[test]
    fn static_codec_names() {
        assert_eq!(static_codec_name(0), Some("PCMU"));
        assert_eq!(static_codec_name(8), Some("PCMA"));
        assert_eq!(static_codec_name(9), Some("G722"));
        assert_eq!(static_codec_name(18), Some("G729"));
        assert_eq!(static_codec_name(99), None);
    }

    #[test]
    fn filter_static_codecs_without_rtpmap() {
        // Some endpoints don't send rtpmap for static PTs
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0 8\r\n",
        );

        let mut sdp = SdpBody::parse(sdp_str);
        sdp.filter_codecs(&["PCMU"]);

        assert_eq!(sdp.media_sections[0].formats, vec![0]);
    }
}
