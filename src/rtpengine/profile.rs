//! RTP media profiles and their translation to RTPEngine NG protocol flags.
//!
//! Each profile describes a media transcoding/relay scenario (e.g. SRTP on the
//! UE side, plain RTP on the core side).  The profile determines which NG flags
//! are sent in `offer` and `answer` commands.

use std::fmt;

/// A media relay profile describing how RTPEngine should handle the media.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpProfile {
    /// Regular SIP/UDP or SIP/TCP UE: SRTP on UE side, RTP on core side.
    SrtpToRtp,
    /// WebSocket UE (ws://): RTP AVPF on UE side, RTP on core side.
    WsToRtp,
    /// Secure WebSocket UE (wss://): DTLS-SRTP AVPF on UE side, RTP on core side.
    WssToRtp,
    /// IMS-internal leg: plain RTP on both sides (passthrough).
    RtpPassthrough,
}

impl RtpProfile {
    /// Parse a profile from a string name.
    pub fn from_name(name: &str) -> Option<RtpProfile> {
        match name {
            "srtp_to_rtp" => Some(RtpProfile::SrtpToRtp),
            "ws_to_rtp" => Some(RtpProfile::WsToRtp),
            "wss_to_rtp" => Some(RtpProfile::WssToRtp),
            "rtp_passthrough" => Some(RtpProfile::RtpPassthrough),
            _ => None,
        }
    }

    /// Get the NG flags for the offer side (caller → RTPEngine).
    pub fn offer_flags(&self) -> NgFlags {
        match self {
            RtpProfile::SrtpToRtp => NgFlags {
                transport_protocol: Some("RTP/SAVP".to_string()),
                ice: Some("remove".to_string()),
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["external".to_string(), "internal".to_string()],
            },
            RtpProfile::WsToRtp => NgFlags {
                transport_protocol: Some("RTP/AVPF".to_string()),
                ice: Some("force".to_string()),
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["external".to_string(), "internal".to_string()],
            },
            RtpProfile::WssToRtp => NgFlags {
                transport_protocol: Some("RTP/SAVPF".to_string()),
                ice: Some("force".to_string()),
                dtls: Some("passive".to_string()),
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["external".to_string(), "internal".to_string()],
            },
            RtpProfile::RtpPassthrough => NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec!["trust-address".to_string()],
                direction: vec![],
            },
        }
    }

    /// Get the NG flags for the answer side (callee → RTPEngine).
    pub fn answer_flags(&self) -> NgFlags {
        match self {
            RtpProfile::SrtpToRtp => NgFlags {
                transport_protocol: Some("RTP/AVP".to_string()),
                ice: Some("remove".to_string()),
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["internal".to_string(), "external".to_string()],
            },
            RtpProfile::WsToRtp => NgFlags {
                transport_protocol: Some("RTP/AVP".to_string()),
                ice: Some("remove".to_string()),
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["internal".to_string(), "external".to_string()],
            },
            RtpProfile::WssToRtp => NgFlags {
                transport_protocol: Some("RTP/AVP".to_string()),
                ice: Some("remove".to_string()),
                dtls: Some("off".to_string()),
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec![],
                direction: vec!["internal".to_string(), "external".to_string()],
            },
            RtpProfile::RtpPassthrough => NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".to_string(), "session-connection".to_string()],
                flags: vec!["trust-address".to_string()],
                direction: vec![],
            },
        }
    }
}

impl fmt::Display for RtpProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpProfile::SrtpToRtp => write!(formatter, "srtp_to_rtp"),
            RtpProfile::WsToRtp => write!(formatter, "ws_to_rtp"),
            RtpProfile::WssToRtp => write!(formatter, "wss_to_rtp"),
            RtpProfile::RtpPassthrough => write!(formatter, "rtp_passthrough"),
        }
    }
}

/// NG protocol flags sent with offer/answer commands.
#[derive(Debug, Clone, Default)]
pub struct NgFlags {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin", "session-connection".
    pub replace: Vec<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    pub direction: Vec<String>,
}

impl NgFlags {
    /// Convert these flags to bencode dict entries to merge into the command dict.
    pub fn to_bencode_pairs(&self) -> Vec<(&str, super::bencode::BencodeValue)> {
        use super::bencode::BencodeValue;

        let mut pairs = Vec::new();

        if let Some(transport_protocol) = &self.transport_protocol {
            pairs.push((
                "transport-protocol",
                BencodeValue::string(transport_protocol),
            ));
        }
        if let Some(ice) = &self.ice {
            pairs.push(("ICE", BencodeValue::string(ice)));
        }
        if let Some(dtls) = &self.dtls {
            pairs.push(("DTLS", BencodeValue::string(dtls)));
        }
        if !self.replace.is_empty() {
            let items: Vec<&str> = self.replace.iter().map(|s| s.as_str()).collect();
            pairs.push(("replace", BencodeValue::string_list(&items)));
        }
        if !self.flags.is_empty() {
            let items: Vec<&str> = self.flags.iter().map(|s| s.as_str()).collect();
            pairs.push(("flags", BencodeValue::string_list(&items)));
        }
        if !self.direction.is_empty() {
            let items: Vec<&str> = self.direction.iter().map(|s| s.as_str()).collect();
            pairs.push(("direction", BencodeValue::string_list(&items)));
        }

        pairs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_all_profiles() {
        assert_eq!(RtpProfile::from_name("srtp_to_rtp"), Some(RtpProfile::SrtpToRtp));
        assert_eq!(RtpProfile::from_name("ws_to_rtp"), Some(RtpProfile::WsToRtp));
        assert_eq!(RtpProfile::from_name("wss_to_rtp"), Some(RtpProfile::WssToRtp));
        assert_eq!(RtpProfile::from_name("rtp_passthrough"), Some(RtpProfile::RtpPassthrough));
    }

    #[test]
    fn from_name_invalid() {
        assert_eq!(RtpProfile::from_name("invalid"), None);
        assert_eq!(RtpProfile::from_name(""), None);
    }

    #[test]
    fn display_roundtrip() {
        for profile in &[
            RtpProfile::SrtpToRtp,
            RtpProfile::WsToRtp,
            RtpProfile::WssToRtp,
            RtpProfile::RtpPassthrough,
        ] {
            let name = profile.to_string();
            assert_eq!(RtpProfile::from_name(&name), Some(*profile));
        }
    }

    #[test]
    fn srtp_to_rtp_offer_flags() {
        let flags = RtpProfile::SrtpToRtp.offer_flags();
        assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(flags.ice.as_deref(), Some("remove"));
        assert!(flags.dtls.is_none());
        assert_eq!(flags.replace, vec!["origin", "session-connection"]);
        assert!(flags.flags.is_empty());
        assert_eq!(flags.direction, vec!["external", "internal"]);
    }

    #[test]
    fn srtp_to_rtp_answer_flags() {
        let flags = RtpProfile::SrtpToRtp.answer_flags();
        assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(flags.ice.as_deref(), Some("remove"));
        assert_eq!(flags.direction, vec!["internal", "external"]);
    }

    #[test]
    fn ws_to_rtp_offer_flags() {
        let flags = RtpProfile::WsToRtp.offer_flags();
        assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/AVPF"));
        assert_eq!(flags.ice.as_deref(), Some("force"));
    }

    #[test]
    fn wss_to_rtp_offer_flags() {
        let flags = RtpProfile::WssToRtp.offer_flags();
        assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/SAVPF"));
        assert_eq!(flags.ice.as_deref(), Some("force"));
        assert_eq!(flags.dtls.as_deref(), Some("passive"));
    }

    #[test]
    fn wss_to_rtp_answer_flags() {
        let flags = RtpProfile::WssToRtp.answer_flags();
        assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(flags.ice.as_deref(), Some("remove"));
        assert_eq!(flags.dtls.as_deref(), Some("off"));
    }

    #[test]
    fn rtp_passthrough_flags() {
        let offer = RtpProfile::RtpPassthrough.offer_flags();
        let answer = RtpProfile::RtpPassthrough.answer_flags();
        assert!(offer.transport_protocol.is_none());
        assert!(offer.ice.is_none());
        assert_eq!(offer.flags, vec!["trust-address"]);
        assert!(offer.direction.is_empty());
        // Passthrough: offer and answer flags are symmetric.
        assert_eq!(offer.flags, answer.flags);
    }

    #[test]
    fn ng_flags_to_bencode_pairs_full() {
        let flags = RtpProfile::WssToRtp.offer_flags();
        let pairs = flags.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"transport-protocol"));
        assert!(keys.contains(&"ICE"));
        assert!(keys.contains(&"DTLS"));
        assert!(keys.contains(&"replace"));
        assert!(keys.contains(&"direction"));
        // No flags for WSS offer.
        assert!(!keys.contains(&"flags"));
    }

    #[test]
    fn ng_flags_to_bencode_pairs_minimal() {
        let flags = NgFlags::default();
        let pairs = flags.to_bencode_pairs();
        assert!(pairs.is_empty());
    }
}
