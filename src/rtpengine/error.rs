//! RTPEngine error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RtpEngineError {
    #[error("RTPEngine I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("RTPEngine bencode decode error: {0}")]
    Decode(String),

    #[error("RTPEngine protocol error: {0}")]
    Protocol(String),

    #[error("RTPEngine timeout: no response within {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("RTPEngine returned error: {0}")]
    EngineError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_display() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "socket gone");
        let error: RtpEngineError = io_error.into();
        assert!(error.to_string().contains("socket gone"));
    }

    #[test]
    fn decode_error_display() {
        let error = RtpEngineError::Decode("unexpected byte 0xff".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine bencode decode error: unexpected byte 0xff"
        );
    }

    #[test]
    fn protocol_error_display() {
        let error = RtpEngineError::Protocol("missing result field".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine protocol error: missing result field"
        );
    }

    #[test]
    fn timeout_error_display() {
        let error = RtpEngineError::Timeout { timeout_ms: 1000 };
        assert_eq!(
            error.to_string(),
            "RTPEngine timeout: no response within 1000ms"
        );
    }

    #[test]
    fn engine_error_display() {
        let error = RtpEngineError::EngineError("session not found".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine returned error: session not found"
        );
    }

    #[test]
    fn error_is_debug() {
        let error = RtpEngineError::Decode("test".to_string());
        let debug = format!("{:?}", error);
        assert!(debug.contains("Decode"));
    }
}
