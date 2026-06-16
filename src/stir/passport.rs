//! PASSporT (RFC 8225) model and ES256 JWS compact serialization.
//!
//! A PASSporT is a JWT signed with ES256 (ECDSA on P-256 with SHA-256).
//! SHAKEN (ATIS-1000074) and the diverted-call extension (RFC 8946 `div`)
//! are both expressed as PASSporTs with a `ppt` value of `shaken` / `div`.
//!
//! Claims and header fields are serialized with keys in lexicographic order
//! per RFC 8225 §9 so the canonical form is reproducible.

use base64::Engine as _;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::error::StirError;

/// URL-safe base64 without padding — the JWS/JOSE encoding (RFC 7515 §2).
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// SHAKEN attestation level (ATIS-1000074 §5.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    /// Full attestation — the SP authenticated the calling party and is
    /// authorized to use the calling number.
    A,
    /// Partial attestation — the SP authenticated the call origination but
    /// cannot verify the calling number.
    B,
    /// Gateway attestation — the SP has no relationship with the caller.
    C,
}

impl Attestation {
    /// Single-character wire form used in the `attest` claim.
    pub fn as_str(self) -> &'static str {
        match self {
            Attestation::A => "A",
            Attestation::B => "B",
            Attestation::C => "C",
        }
    }

    /// Parse from a string (`"A"`, `"B"`, `"C"`, case-insensitive).
    pub fn parse(value: &str) -> Result<Self, StirError> {
        match value.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Attestation::A),
            "B" => Ok(Attestation::B),
            "C" => Ok(Attestation::C),
            other => Err(StirError::Encode(format!(
                "invalid attestation level {other:?} (expected A, B, or C)"
            ))),
        }
    }
}

/// PASSporT protected header (RFC 8225 §6, fields in lexicographic order).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PassportHeader {
    alg: String,
    ppt: String,
    typ: String,
    x5u: String,
}

/// Originating / diverting identity claim — a single telephone number.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TnClaim {
    tn: String,
}

/// Destination identity claim — one or more telephone numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DestClaim {
    tn: Vec<String>,
}

/// SHAKEN PASSporT claims (ATIS-1000074, lexicographic key order).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShakenClaims {
    attest: String,
    dest: DestClaim,
    iat: i64,
    orig: TnClaim,
    origid: String,
}

/// Diverted-call (`div`) PASSporT claims (RFC 8946, lexicographic key order).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DivClaims {
    dest: DestClaim,
    div: TnClaim,
    iat: i64,
    orig: TnClaim,
}

/// A PASSporT decoded from an Identity header, with the parts needed to
/// verify the signature retained.
#[derive(Debug, Clone)]
pub struct ParsedPassport {
    /// `alg` from the protected header.
    pub alg: String,
    /// `ppt` from the protected header (`"shaken"`, `"div"`, …).
    pub ppt: String,
    /// `typ` from the protected header (should be `"passport"`).
    pub typ: String,
    /// `x5u` certificate URL from the protected header.
    pub x5u: String,
    /// Fully-decoded claim set as JSON (exposed to scripts).
    pub claims: serde_json::Value,
    /// The `header.claims` string the signature is computed over.
    signing_input: String,
    /// Raw signature bytes (JOSE R||S form, 64 bytes for P-256).
    signature: Vec<u8>,
}

impl ParsedPassport {
    /// Value of the `iat` claim, if present and numeric.
    pub fn iat(&self) -> Option<i64> {
        self.claims.get("iat").and_then(|value| value.as_i64())
    }

    /// Value of the `attest` claim (SHAKEN only).
    pub fn attestation(&self) -> Option<String> {
        self.claims
            .get("attest")
            .and_then(|value| value.as_str())
            .map(|s| s.to_string())
    }

    /// Value of the `origid` claim (SHAKEN only).
    pub fn origid(&self) -> Option<String> {
        self.claims
            .get("origid")
            .and_then(|value| value.as_str())
            .map(|s| s.to_string())
    }

    /// Originating telephone number from the `orig` claim.
    pub fn orig_tn(&self) -> Option<String> {
        self.claims
            .get("orig")
            .and_then(|orig| orig.get("tn"))
            .and_then(|tn| tn.as_str())
            .map(|s| s.to_string())
    }

    /// Destination telephone numbers from the `dest` claim.
    pub fn dest_tns(&self) -> Vec<String> {
        self.claims
            .get("dest")
            .and_then(|dest| dest.get("tn"))
            .and_then(|tn| tn.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|value| value.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Verify the ES256 signature against the supplied public key.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> bool {
        let signature = match Signature::from_slice(&self.signature) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        verifying_key
            .verify(self.signing_input.as_bytes(), &signature)
            .is_ok()
    }
}

/// Encode header + claims into a compact JWS and ES256-sign it.
fn encode_and_sign<H, C>(
    signing_key: &SigningKey,
    header: &H,
    claims: &C,
) -> Result<String, StirError>
where
    H: Serialize,
    C: Serialize,
{
    let header_json =
        serde_json::to_vec(header).map_err(|error| StirError::Encode(error.to_string()))?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|error| StirError::Encode(error.to_string()))?;

    let signing_input = format!("{}.{}", B64.encode(header_json), B64.encode(claims_json));

    let signature: Signature = signing_key
        .try_sign(signing_input.as_bytes())
        .map_err(|error| StirError::Encode(format!("ES256 signing failed: {error}")))?;

    Ok(format!(
        "{signing_input}.{}",
        B64.encode(signature.to_bytes())
    ))
}

/// Build and sign a SHAKEN PASSporT (`ppt=shaken`).
pub fn build_shaken_token(
    signing_key: &SigningKey,
    x5u: &str,
    attestation: Attestation,
    orig_tn: &str,
    dest_tn: &str,
    origid: &str,
    iat: i64,
) -> Result<String, StirError> {
    let header = PassportHeader {
        alg: "ES256".to_string(),
        ppt: "shaken".to_string(),
        typ: "passport".to_string(),
        x5u: x5u.to_string(),
    };
    let claims = ShakenClaims {
        attest: attestation.as_str().to_string(),
        dest: DestClaim {
            tn: vec![dest_tn.to_string()],
        },
        iat,
        orig: TnClaim {
            tn: orig_tn.to_string(),
        },
        origid: origid.to_string(),
    };
    encode_and_sign(signing_key, &header, &claims)
}

/// Build and sign a diverted-call PASSporT (`ppt=div`, RFC 8946).
pub fn build_div_token(
    signing_key: &SigningKey,
    x5u: &str,
    orig_tn: &str,
    dest_tn: &str,
    div_tn: &str,
    iat: i64,
) -> Result<String, StirError> {
    let header = PassportHeader {
        alg: "ES256".to_string(),
        ppt: "div".to_string(),
        typ: "passport".to_string(),
        x5u: x5u.to_string(),
    };
    let claims = DivClaims {
        dest: DestClaim {
            tn: vec![dest_tn.to_string()],
        },
        div: TnClaim {
            tn: div_tn.to_string(),
        },
        iat,
        orig: TnClaim {
            tn: orig_tn.to_string(),
        },
    };
    encode_and_sign(signing_key, &header, &claims)
}

/// Parse a compact JWS PASSporT (`header.claims.signature`) into its parts.
pub fn parse_token(token: &str) -> Result<ParsedPassport, StirError> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| StirError::Parse("missing header segment".to_string()))?;
    let claims_b64 = parts
        .next()
        .ok_or_else(|| StirError::Parse("missing claims segment".to_string()))?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| StirError::Parse("missing signature segment".to_string()))?;
    if parts.next().is_some() {
        return Err(StirError::Parse(
            "too many segments (expected header.claims.signature)".to_string(),
        ));
    }

    let header_bytes = B64
        .decode(header_b64)
        .map_err(|error| StirError::Parse(format!("header base64url: {error}")))?;
    let header: PassportHeader = serde_json::from_slice(&header_bytes)
        .map_err(|error| StirError::Parse(format!("header JSON: {error}")))?;

    let claims_bytes = B64
        .decode(claims_b64)
        .map_err(|error| StirError::Parse(format!("claims base64url: {error}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|error| StirError::Parse(format!("claims JSON: {error}")))?;

    let signature = B64
        .decode(signature_b64)
        .map_err(|error| StirError::Parse(format!("signature base64url: {error}")))?;

    Ok(ParsedPassport {
        alg: header.alg,
        ppt: header.ppt,
        typ: header.typ,
        x5u: header.x5u,
        claims,
        signing_input: format!("{header_b64}.{claims_b64}"),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    fn test_key() -> SigningKey {
        // Deterministic 32-byte scalar — fine for tests (never a real key).
        let bytes = [7u8; 32];
        SigningKey::from_bytes(&bytes.into()).expect("valid test scalar")
    }

    #[test]
    fn attestation_round_trip() {
        for level in ["A", "B", "C"] {
            assert_eq!(Attestation::parse(level).unwrap().as_str(), level);
        }
        assert_eq!(Attestation::parse("a").unwrap(), Attestation::A);
        assert!(Attestation::parse("Z").is_err());
    }

    #[test]
    fn shaken_sign_parse_verify_round_trip() {
        let key = test_key();
        let verifying = VerifyingKey::from(&key);
        let token = build_shaken_token(
            &key,
            "https://certs.example.com/sti.pem",
            Attestation::A,
            "12155550112",
            "12025550100",
            "123e4567-e89b-12d3-a456-426655440000",
            1443208345,
        )
        .unwrap();

        let parsed = parse_token(&token).unwrap();
        assert_eq!(parsed.alg, "ES256");
        assert_eq!(parsed.ppt, "shaken");
        assert_eq!(parsed.typ, "passport");
        assert_eq!(parsed.x5u, "https://certs.example.com/sti.pem");
        assert_eq!(parsed.attestation().as_deref(), Some("A"));
        assert_eq!(parsed.orig_tn().as_deref(), Some("12155550112"));
        assert_eq!(parsed.dest_tns(), vec!["12025550100".to_string()]);
        assert_eq!(parsed.iat(), Some(1443208345));
        assert_eq!(
            parsed.origid().as_deref(),
            Some("123e4567-e89b-12d3-a456-426655440000")
        );
        assert!(parsed.verify_signature(&verifying));
    }

    #[test]
    fn div_sign_parse_verify_round_trip() {
        let key = test_key();
        let verifying = VerifyingKey::from(&key);
        let token = build_div_token(
            &key,
            "https://certs.example.com/sti.pem",
            "12155550112",
            "12025550100",
            "12155550199",
            1443208345,
        )
        .unwrap();

        let parsed = parse_token(&token).unwrap();
        assert_eq!(parsed.ppt, "div");
        assert_eq!(parsed.orig_tn().as_deref(), Some("12155550112"));
        assert_eq!(parsed.dest_tns(), vec!["12025550100".to_string()]);
        assert_eq!(
            parsed
                .claims
                .get("div")
                .and_then(|d| d.get("tn"))
                .and_then(|t| t.as_str()),
            Some("12155550199")
        );
        assert!(parsed.verify_signature(&verifying));
    }

    #[test]
    fn tampered_claims_fail_verification() {
        let key = test_key();
        let verifying = VerifyingKey::from(&key);
        let token = build_shaken_token(
            &key,
            "https://certs.example.com/sti.pem",
            Attestation::A,
            "12155550112",
            "12025550100",
            "origid-1",
            1443208345,
        )
        .unwrap();

        // Flip the claims segment to a different attestation/number.
        let forged_claims = serde_json::json!({
            "attest": "A",
            "dest": {"tn": ["12025550100"]},
            "iat": 1443208345,
            "orig": {"tn": "19998887777"},
            "origid": "origid-1"
        });
        let parts: Vec<&str> = token.split('.').collect();
        let forged_payload = B64.encode(serde_json::to_vec(&forged_claims).unwrap());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

        let parsed = parse_token(&forged).unwrap();
        assert_eq!(parsed.orig_tn().as_deref(), Some("19998887777"));
        assert!(
            !parsed.verify_signature(&verifying),
            "signature must not validate over tampered claims"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let token = build_shaken_token(
            &test_key(),
            "https://certs.example.com/sti.pem",
            Attestation::B,
            "12155550112",
            "12025550100",
            "origid-2",
            1443208345,
        )
        .unwrap();
        let other_key = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let other_vk = VerifyingKey::from(&other_key);
        let parsed = parse_token(&token).unwrap();
        assert!(!parsed.verify_signature(&other_vk));
    }

    #[test]
    fn malformed_tokens_rejected() {
        assert!(parse_token("only-one-segment").is_err());
        assert!(parse_token("a.b").is_err());
        assert!(parse_token("a.b.c.d").is_err());
        assert!(parse_token("!!!.###.$$$").is_err());
    }
}
