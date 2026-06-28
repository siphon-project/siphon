//! Error type for the STIR/SHAKEN module.

use thiserror::Error;

/// Errors produced while signing or verifying STIR/SHAKEN PASSporTs.
#[derive(Debug, Error)]
pub enum StirError {
    /// `stir.sign()` was called but no `stir.signing` block is configured.
    #[error("STIR signing is not configured (missing stir.signing block)")]
    SigningNotConfigured,

    /// `stir.verify()` was called but no `stir.verification` block is configured.
    #[error("STIR verification is not configured (missing stir.verification block)")]
    VerificationNotConfigured,

    /// The configured signing private key could not be loaded.
    #[error("failed to load STIR signing key: {0}")]
    KeyLoad(String),

    /// A configured trust anchor (STI-CA root) could not be loaded/parsed.
    #[error("failed to load STIR trust anchor: {0}")]
    TrustAnchorLoad(String),

    /// JSON / base64url encoding of the PASSporT failed.
    #[error("failed to encode PASSporT: {0}")]
    Encode(String),

    /// The Identity header / PASSporT could not be parsed.
    #[error("failed to parse PASSporT: {0}")]
    Parse(String),

    /// Could not build the reqwest client used for x5u fetches.
    #[error("failed to build HTTP client for x5u fetch: {0}")]
    HttpClient(String),

    /// The originating or destination telephone number was required but
    /// could not be determined from the request (and was not supplied).
    #[error("missing telephone number: {0}")]
    MissingTn(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_descriptive() {
        assert!(StirError::SigningNotConfigured
            .to_string()
            .contains("signing is not configured"));
        assert!(StirError::KeyLoad("bad pem".into())
            .to_string()
            .contains("bad pem"));
        assert!(StirError::MissingTn("orig".into())
            .to_string()
            .contains("orig"));
    }
}
