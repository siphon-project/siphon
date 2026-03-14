//! RTP media profiles and their translation to RTPEngine NG protocol flags.
//!
//! Each profile describes a media transcoding/relay scenario (e.g. SRTP on the
//! UE side, plain RTP on the core side).  The profile determines which NG flags
//! are sent in `offer` and `answer` commands.
//!
//! Four built-in profiles are always available:
//!   srtp_to_rtp, ws_to_rtp, wss_to_rtp, rtp_passthrough
//!
//! Operators can define additional profiles (or override built-ins) in the YAML
//! config under `media.profiles`.

use std::collections::HashMap;

use crate::config::{MediaProfileConfig, NgFlagsConfig};

/// A single media profile: offer flags + answer flags.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub offer: NgFlags,
    pub answer: NgFlags,
}

/// Registry of named media profiles.
///
/// Populated at startup from built-in defaults + YAML config.  Shared via
/// `Arc<ProfileRegistry>` so that the Python API and dispatcher can look up
/// profiles by name.
#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    profiles: HashMap<String, ProfileEntry>,
}

impl ProfileRegistry {
    /// Create a registry containing only the built-in profiles.
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("srtp_to_rtp".into(), Self::builtin_srtp_to_rtp());
        profiles.insert("ws_to_rtp".into(), Self::builtin_ws_to_rtp());
        profiles.insert("wss_to_rtp".into(), Self::builtin_wss_to_rtp());
        profiles.insert("rtp_passthrough".into(), Self::builtin_rtp_passthrough());
        profiles.insert("srs_recording".into(), Self::builtin_srs_recording());
        Self { profiles }
    }

    /// Create a registry from built-in defaults + custom YAML profiles.
    /// Custom profiles override built-ins with the same name.
    pub fn from_config(custom: &HashMap<String, MediaProfileConfig>) -> Self {
        let mut registry = Self::new();
        for (name, config) in custom {
            registry.profiles.insert(
                name.clone(),
                ProfileEntry {
                    offer: NgFlags::from_config(&config.offer),
                    answer: NgFlags::from_config(&config.answer),
                },
            );
        }
        registry
    }

    /// Look up a profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileEntry> {
        self.profiles.get(name)
    }

    /// List all available profile names (sorted for deterministic error messages).
    pub fn profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    // --- Built-in profiles ---

    fn builtin_srtp_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_ws_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVPF".into()),
                ice: Some("force".into()),
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_wss_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVPF".into()),
                ice: Some("force".into()),
                dtls: Some("passive".into()),
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_srs_recording() -> ProfileEntry {
        // SIPREC SRS recording profile:
        // - replace origin + session-connection so RTPEngine rewrites o=/c=
        // - media handover + port latching for NAT/SIPREC source port flexibility
        // - trust-address to accept RTP from any source
        // - ICE remove, DTLS off (recording sink, no oer security needed)
        // - direction public/public (both sides are external-facing)
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into(), "session-connection".into()],
                flags: vec![
                    "media handover".into(),
                    "port latching".into(),
                ],
                direction: vec!["public".into(), "public".into()],
                record_call: true,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into(), "session-connection".into()],
                flags: vec![
                    "media handover".into(),
                    "port latching".into(),
                ],
                direction: vec!["public".into(), "public".into()],
                record_call: true,
                record_path: None,
            },
        }
    }

    fn builtin_rtp_passthrough() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec!["trust-address".into()],
                direction: vec![],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".into()],
                flags: vec!["trust-address".into()],
                direction: vec![],
                record_call: false,
                record_path: None,
            },
        }
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
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
    /// SDP fields to replace: "origin".
    pub replace: Vec<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    pub direction: Vec<String>,
    /// Enable call recording in RTPEngine.
    pub record_call: bool,
    /// Directory path for RTPEngine to write recording files.
    pub record_path: Option<String>,
}

impl NgFlags {
    /// Build from the YAML config representation.
    pub fn from_config(config: &NgFlagsConfig) -> Self {
        Self {
            transport_protocol: config.transport_protocol.clone(),
            ice: config.ice.clone(),
            dtls: config.dtls.clone(),
            replace: config.replace.clone(),
            flags: config.flags.clone(),
            direction: config.direction.clone(),
            record_call: config.record_call,
            record_path: config.record_path.clone(),
        }
    }

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
        if self.record_call {
            pairs.push(("record call", BencodeValue::string("yes")));
        }
        if let Some(record_path) = &self.record_path {
            pairs.push(("recording-dir", BencodeValue::string(record_path)));
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
    fn default_registry_has_builtins() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("srtp_to_rtp").is_some());
        assert!(registry.get("ws_to_rtp").is_some());
        assert!(registry.get("wss_to_rtp").is_some());
        assert!(registry.get("rtp_passthrough").is_some());
        assert!(registry.get("srs_recording").is_some());
    }

    #[test]
    fn unknown_profile_returns_none() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("invalid").is_none());
        assert!(registry.get("").is_none());
    }

    #[test]
    fn profile_names_sorted() {
        let registry = ProfileRegistry::new();
        let names = registry.profile_names();
        assert_eq!(names.len(), 5);
        // Sorted alphabetically
        assert_eq!(names[0], "rtp_passthrough");
        assert_eq!(names[1], "srs_recording");
        assert_eq!(names[4], "wss_to_rtp");
    }

    #[test]
    fn custom_profile_from_config() {
        let mut custom = HashMap::new();
        custom.insert(
            "my_profile".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("RTP/SAVPF".into()),
                    ice: Some("force".into()),
                    dtls: Some("passive".into()),
                    replace: vec!["origin".into()],
                    flags: vec![],
                    direction: vec!["external".into(), "internal".into()],
                    record_call: false,
                    record_path: None,
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("RTP/AVP".into()),
                    ice: Some("remove".into()),
                    dtls: Some("off".into()),
                    replace: vec!["origin".into()],
                    flags: vec![],
                    direction: vec!["internal".into(), "external".into()],
                    record_call: false,
                    record_path: None,
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        // Custom profile exists
        let entry = registry.get("my_profile").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVPF"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
        // Built-ins still exist
        assert!(registry.get("srtp_to_rtp").is_some());
        assert_eq!(registry.profile_names().len(), 6);
    }

    #[test]
    fn custom_profile_overrides_builtin() {
        let mut custom = HashMap::new();
        custom.insert(
            "srtp_to_rtp".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/OFFER".into()),
                    ice: None,
                    dtls: None,
                    replace: vec![],
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/ANSWER".into()),
                    ice: None,
                    dtls: None,
                    replace: vec![],
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("CUSTOM/OFFER")
        );
    }

    #[test]
    fn srtp_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert!(entry.offer.dtls.is_none());
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert!(entry.offer.flags.is_empty());
        assert_eq!(entry.offer.direction, vec!["external", "internal"]);
    }

    #[test]
    fn srtp_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.direction, vec!["internal", "external"]);
    }

    #[test]
    fn ws_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("ws_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/AVPF"));
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
    }

    #[test]
    fn wss_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("RTP/SAVPF")
        );
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
        assert_eq!(entry.offer.dtls.as_deref(), Some("passive"));
    }

    #[test]
    fn wss_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
    }

    #[test]
    fn rtp_passthrough_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("rtp_passthrough").unwrap();
        assert!(entry.offer.transport_protocol.is_none());
        assert!(entry.offer.ice.is_none());
        assert_eq!(entry.offer.flags, vec!["trust-address"]);
        assert!(entry.offer.direction.is_empty());
        // Passthrough: offer and answer flags are symmetric.
        assert_eq!(entry.offer.flags, entry.answer.flags);
    }

    #[test]
    fn ng_flags_to_bencode_pairs_full() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        let pairs = entry.offer.to_bencode_pairs();
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
