//! RFC 8224 `Identity` header — full form.
//!
//! The header value carries the full compact JWS PASSporT followed by the
//! `info`, `alg`, and `ppt` parameters, e.g.:
//!
//! ```text
//! Identity: eyJhbGc...header.eyJhdHRl...claims.sig;info=<https://certs.example.com/sti.pem>;alg=ES256;ppt=shaken
//! ```
//!
//! A single SIP message may carry multiple `Identity` headers (e.g. a base
//! `shaken` PASSporT plus a `div` PASSporT for a diverted call), so callers
//! parse the list returned by `SipHeaders::get_all("Identity")`.

use super::error::StirError;

/// A parsed `Identity` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityHeader {
    /// The compact JWS PASSporT (`header.claims.signature`).
    pub token: String,
    /// `info` parameter — the certificate URL (angle brackets stripped).
    pub info: Option<String>,
    /// `alg` parameter (should be `ES256`).
    pub alg: Option<String>,
    /// `ppt` parameter (`shaken`, `div`, …).
    pub ppt: Option<String>,
}

/// Build an `Identity` header value from a signed PASSporT token.
pub fn build(token: &str, x5u: &str, ppt: &str) -> String {
    format!("{token};info=<{x5u}>;alg=ES256;ppt={ppt}")
}

/// Parse an `Identity` header value into its token + parameters.
pub fn parse(value: &str) -> Result<IdentityHeader, StirError> {
    let mut parts = value.split(';');
    let token = parts
        .next()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| StirError::Parse("empty Identity header".to_string()))?
        .to_string();

    let mut info = None;
    let mut alg = None;
    let mut ppt = None;

    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let (name, raw_value) = match param.split_once('=') {
            Some((name, value)) => (name.trim(), value.trim()),
            None => (param, ""),
        };
        match name.to_ascii_lowercase().as_str() {
            "info" => info = Some(strip_angle_brackets(raw_value).to_string()),
            "alg" => alg = Some(raw_value.to_string()),
            "ppt" => ppt = Some(strip_quotes(raw_value).to_string()),
            _ => {}
        }
    }

    Ok(IdentityHeader {
        token,
        info,
        alg,
        ppt,
    })
}

/// Strip a single pair of surrounding angle brackets (`<...>`), if present.
fn strip_angle_brackets(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('<')
        .and_then(|inner| inner.strip_suffix('>'))
        .unwrap_or(value)
}

/// Strip a single pair of surrounding double quotes, if present.
fn strip_quotes(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_full_form() {
        let value = build("h.c.s", "https://certs.example.com/sti.pem", "shaken");
        assert_eq!(
            value,
            "h.c.s;info=<https://certs.example.com/sti.pem>;alg=ES256;ppt=shaken"
        );
    }

    #[test]
    fn parse_round_trips_build() {
        let value = build("aaa.bbb.ccc", "https://c.example/cert.pem", "shaken");
        let parsed = parse(&value).unwrap();
        assert_eq!(parsed.token, "aaa.bbb.ccc");
        assert_eq!(parsed.info.as_deref(), Some("https://c.example/cert.pem"));
        assert_eq!(parsed.alg.as_deref(), Some("ES256"));
        assert_eq!(parsed.ppt.as_deref(), Some("shaken"));
    }

    #[test]
    fn parse_div_ppt() {
        let parsed = parse("t.o.k;info=<https://c/cert>;alg=ES256;ppt=div").unwrap();
        assert_eq!(parsed.ppt.as_deref(), Some("div"));
    }

    #[test]
    fn parse_tolerates_whitespace_and_quoting() {
        let parsed =
            parse("  t.o.k ; info = <https://c/cert> ; alg = ES256 ; ppt = \"shaken\" ").unwrap();
        assert_eq!(parsed.token, "t.o.k");
        assert_eq!(parsed.info.as_deref(), Some("https://c/cert"));
        assert_eq!(parsed.ppt.as_deref(), Some("shaken"));
    }

    #[test]
    fn parse_token_only() {
        let parsed = parse("just.a.token").unwrap();
        assert_eq!(parsed.token, "just.a.token");
        assert_eq!(parsed.info, None);
        assert_eq!(parsed.alg, None);
        assert_eq!(parsed.ppt, None);
    }

    #[test]
    fn parse_empty_rejected() {
        assert!(parse("").is_err());
        assert!(parse(";info=<x>").is_err());
    }
}
