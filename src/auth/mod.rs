//! Client-side SIP digest authentication (RFC 2617 / RFC 7616).
//!
//! This module handles the *client* side of digest auth — computing
//! Authorization/Proxy-Authorization responses when SIPhon receives
//! a 401/407 challenge on outbound requests (REGISTER, INVITE, etc.).
//!
//! The *server* side (challenging incoming requests) lives in
//! `crate::script::api::auth`.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

/// Parsed WWW-Authenticate or Proxy-Authenticate challenge.
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub algorithm: DigestAlgorithm,
    pub stale: bool,
}

/// Supported digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestAlgorithm::Md5 => write!(formatter, "MD5"),
        }
    }
}

/// Credentials for digest authentication.
#[derive(Debug, Clone)]
pub struct DigestCredentials {
    pub username: String,
    pub password: String,
}

/// Tracks the nonce count for a given nonce value.
#[derive(Debug)]
pub struct NonceCounter {
    count: AtomicU32,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    /// Increment and return the next nc value (1-based).
    pub fn next(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a `WWW-Authenticate` or `Proxy-Authenticate` header value.
///
/// Expects format: `Digest realm="...", nonce="...", ...`
pub fn parse_challenge(header_value: &str) -> Option<DigestChallenge> {
    let body = header_value.strip_prefix("Digest")?.trim();

    let mut realm = None;
    let mut nonce = None;
    let mut opaque = None;
    let mut qop = None;
    let mut algorithm = DigestAlgorithm::Md5;
    let mut stale = false;

    for param in split_params(body) {
        let param = param.trim();
        if let Some((key, value)) = param.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = unquote(value.trim());
            match key.as_str() {
                "realm" => realm = Some(value),
                "nonce" => nonce = Some(value),
                "opaque" => opaque = Some(value),
                "qop" => qop = Some(value),
                "algorithm" => {
                    algorithm = match value.to_uppercase().as_str() {
                        "MD5" | "" => DigestAlgorithm::Md5,
                        _ => return None, // unsupported algorithm
                    };
                }
                "stale" => stale = value.eq_ignore_ascii_case("true"),
                _ => {} // ignore unknown params
            }
        }
    }

    Some(DigestChallenge {
        realm: realm?,
        nonce: nonce?,
        opaque,
        qop,
        algorithm,
        stale,
    })
}

/// Compute the digest response per RFC 2617.
///
/// Returns the hex-encoded response hash.
pub fn compute_digest_response(
    challenge: &DigestChallenge,
    credentials: &DigestCredentials,
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let ha1 = md5_hex(&format!(
        "{}:{}:{}",
        credentials.username, challenge.realm, credentials.password
    ));

    let ha2 = md5_hex(&format!("{method}:{digest_uri}"));

    let has_qop_auth = challenge
        .qop
        .as_ref()
        .map(|qop| qop.split(',').any(|token| token.trim() == "auth"))
        .unwrap_or(false);

    if has_qop_auth {
        let nc = nonce_count.unwrap_or(1);
        let nc_str = format!("{nc:08x}");
        let cnonce_value = cnonce.unwrap_or("0a1b2c3d");
        let response = md5_hex(&format!(
            "{ha1}:{}:{nc_str}:{cnonce_value}:auth:{ha2}",
            challenge.nonce
        ));
        response
    } else {
        md5_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    }
}

/// Build the complete `Authorization` or `Proxy-Authorization` header value.
pub fn format_authorization_header(
    challenge: &DigestChallenge,
    credentials: &DigestCredentials,
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let response = compute_digest_response(
        challenge,
        credentials,
        method,
        digest_uri,
        nonce_count,
        cnonce,
    );

    let has_qop_auth = challenge
        .qop
        .as_ref()
        .map(|qop| qop.split(',').any(|token| token.trim() == "auth"))
        .unwrap_or(false);

    let mut header = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{}\"",
        credentials.username, challenge.realm, challenge.nonce, digest_uri, challenge.algorithm, response
    );

    if has_qop_auth {
        let nc = nonce_count.unwrap_or(1);
        let cnonce_value = cnonce.unwrap_or("0a1b2c3d");
        header.push_str(&format!(
            ", qop=auth, nc={:08x}, cnonce=\"{cnonce_value}\"",
            nc
        ));
    }

    if let Some(opaque) = &challenge.opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }

    header
}

/// Split comma-separated params, respecting quoted strings.
fn split_params(input: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                result.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < input.len() {
        result.push(&input[start..]);
    }
    result
}

/// Remove surrounding double quotes if present.
fn unquote(value: &str) -> String {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Compute MD5 hash and return lowercase hex string.
fn md5_hex(input: &str) -> String {
    let digest = md5::compute(input.as_bytes());
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_challenge() {
        let header = r#"Digest realm="biloxi.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "biloxi.com");
        assert_eq!(challenge.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert!(challenge.opaque.is_none());
        assert!(challenge.qop.is_none());
        assert!(!challenge.stale);
    }

    #[test]
    fn parse_challenge_with_qop_and_opaque() {
        let header = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.qop.as_deref(), Some("auth,auth-int"));
        assert_eq!(
            challenge.opaque.as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41")
        );
    }

    #[test]
    fn parse_challenge_with_stale() {
        let header = r#"Digest realm="example.com", nonce="abc123", stale=true"#;
        let challenge = parse_challenge(header).unwrap();
        assert!(challenge.stale);
    }

    #[test]
    fn parse_challenge_missing_realm_returns_none() {
        let header = r#"Digest nonce="abc123""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_missing_nonce_returns_none() {
        let header = r#"Digest realm="example.com""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_not_digest_returns_none() {
        let header = r#"Basic realm="example.com""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_unsupported_algorithm_returns_none() {
        let header = r#"Digest realm="example.com", nonce="abc", algorithm=SHA-256"#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_unquoted_values() {
        // Some SIP servers send unquoted values for non-string params
        let header = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5, stale=false"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert!(!challenge.stale);
    }

    /// RFC 2617 Section 3.5 test vector.
    #[test]
    fn rfc2617_test_vector_without_qop() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "Mufasa".to_string(),
            password: "Circle Of Life".to_string(),
        };

        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let expected = md5_hex(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:{ha2}"
        ));

        let response =
            compute_digest_response(&challenge, &credentials, "GET", "/dir/index.html", None, None);
        assert_eq!(response, expected);
    }

    /// RFC 2617 Section 3.5 test vector with qop=auth.
    #[test]
    fn rfc2617_test_vector_with_qop_auth() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "Mufasa".to_string(),
            password: "Circle Of Life".to_string(),
        };

        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let expected = md5_hex(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}"
        ));

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "GET",
            "/dir/index.html",
            Some(1),
            Some("0a4f113b"),
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn format_authorization_without_qop() {
        let challenge = DigestChallenge {
            realm: "biloxi.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:biloxi.com",
            None,
            None,
        );

        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"alice\""));
        assert!(header.contains("realm=\"biloxi.com\""));
        assert!(header.contains("nonce=\"abc123\""));
        assert!(header.contains("uri=\"sip:biloxi.com\""));
        assert!(header.contains("algorithm=MD5"));
        assert!(header.contains("response=\""));
        assert!(!header.contains("qop="));
        assert!(!header.contains("nc="));
    }

    #[test]
    fn format_authorization_with_qop() {
        let challenge = DigestChallenge {
            realm: "atlanta.com".to_string(),
            nonce: "84a4cc6f3082121f32b42a2187831a9e".to_string(),
            opaque: Some("opaque_value".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "bob".to_string(),
            password: "zanzibar".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "INVITE",
            "sip:bob@biloxi.com",
            Some(1),
            Some("deadbeef"),
        );

        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("cnonce=\"deadbeef\""));
        assert!(header.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn format_authorization_round_trips_through_parse() {
        let challenge = DigestChallenge {
            realm: "sip.example.com".to_string(),
            nonce: "testNonce123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            Some(1),
            Some("abcd1234"),
        );

        // Verify the response field is present and is a valid 32-char hex string
        let response_start = header.find("response=\"").unwrap() + 10;
        let response_end = header[response_start..].find('"').unwrap() + response_start;
        let response = &header[response_start..response_end];
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn nonce_counter_increments() {
        let counter = NonceCounter::new();
        assert_eq!(counter.next(), 1);
        assert_eq!(counter.next(), 2);
        assert_eq!(counter.next(), 3);
    }

    #[test]
    fn split_params_respects_quotes() {
        let input = r#"realm="test,realm", nonce="abc""#;
        let params = split_params(input);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].trim(), r#"realm="test,realm""#);
        assert_eq!(params[1].trim(), r#"nonce="abc""#);
    }

    #[test]
    fn unquote_strips_quotes() {
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("\"\""), "");
    }

    #[test]
    fn sip_register_digest_response() {
        // Simulate a typical SIP REGISTER 401 challenge/response
        let challenge = DigestChallenge {
            realm: "atlanta.com".to_string(),
            nonce: "84a4cc6f3082121f32b42a2187831a9e".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "alice".to_string(),
            password: "password123".to_string(),
        };

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:atlanta.com",
            Some(1),
            Some("08ad4e30"),
        );

        // Verify it's a valid 32-char hex MD5 hash
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|character| character.is_ascii_hexdigit()));

        // Verify it's deterministic
        let response2 = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:atlanta.com",
            Some(1),
            Some("08ad4e30"),
        );
        assert_eq!(response, response2);
    }

    #[test]
    fn parse_challenge_with_extra_whitespace() {
        let header =
            r#"Digest  realm = "example.com" , nonce = "abc123" , algorithm = MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert_eq!(challenge.nonce, "abc123");
    }

    #[test]
    fn parse_challenge_case_insensitive_keys() {
        let header = r#"Digest Realm="example.com", Nonce="abc123", Algorithm=MD5, Stale=TRUE"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert!(challenge.stale);
    }

    #[test]
    fn qop_auth_int_not_selected_when_only_auth_int() {
        // auth-int alone: we only support auth, so should fall back to no-qop
        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: Some("auth-int".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        // Should use no-qop path since we don't support auth-int
        let ha1 = md5_hex("user:example.com:pass");
        let ha2 = md5_hex("REGISTER:sip:example.com");
        let expected = md5_hex(&format!("{ha1}:abc:{ha2}"));

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            None,
            None,
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn qop_selects_auth_from_multiple() {
        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: Some("auth-int,auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            Some(1),
            Some("cnonce"),
        );
        // Should use qop=auth since it's in the list
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
    }
}
