//! Typed CSeq header per RFC 3261 §20.16.
//!
//! Wire format: `1 INVITE`

use std::fmt;

use crate::sip::message::Method;

/// A parsed CSeq header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    /// Sequence number.
    pub sequence: u32,
    /// SIP method.
    pub method: Method,
}

impl CSeq {
    /// Parse a CSeq value: `"1 INVITE"`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        let (seq_str, method_str) = input
            .split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| format!("CSeq missing space between seq and method: {input}"))?;

        let sequence = seq_str
            .trim()
            .parse::<u32>()
            .map_err(|error| format!("CSeq bad sequence number '{seq_str}': {error}"))?;

        let method = Method::from_str(method_str.trim());

        Ok(CSeq { sequence, method })
    }
}

impl fmt::Display for CSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.sequence, self.method.as_str())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invite() {
        let cseq = CSeq::parse("1 INVITE").unwrap();
        assert_eq!(cseq.sequence, 1);
        assert_eq!(cseq.method, Method::Invite);
    }

    #[test]
    fn parse_register() {
        let cseq = CSeq::parse("42 REGISTER").unwrap();
        assert_eq!(cseq.sequence, 42);
        assert_eq!(cseq.method, Method::Register);
    }

    #[test]
    fn parse_high_sequence() {
        let cseq = CSeq::parse("4294967295 OPTIONS").unwrap();
        assert_eq!(cseq.sequence, u32::MAX);
        assert_eq!(cseq.method, Method::Options);
    }

    #[test]
    fn parse_extension_method() {
        let cseq = CSeq::parse("7 PUBLISH").unwrap();
        assert_eq!(cseq.sequence, 7);
        assert_eq!(cseq.method, Method::Publish);
    }

    #[test]
    fn display_round_trip() {
        let cseq = CSeq::parse("314 BYE").unwrap();
        let serialized = cseq.to_string();
        assert_eq!(serialized, "314 BYE");
        let reparsed = CSeq::parse(&serialized).unwrap();
        assert_eq!(cseq, reparsed);
    }

    #[test]
    fn parse_with_extra_whitespace() {
        let cseq = CSeq::parse("  100   SUBSCRIBE  ").unwrap();
        assert_eq!(cseq.sequence, 100);
        assert_eq!(cseq.method, Method::Subscribe);
    }

    #[test]
    fn reject_missing_method() {
        assert!(CSeq::parse("42").is_err());
    }

    #[test]
    fn reject_bad_sequence() {
        assert!(CSeq::parse("abc INVITE").is_err());
    }
}
