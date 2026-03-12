//! SRS storage backends — persist recording metadata after session ends.
//!
//! Two backends are supported:
//! - **File**: Writes a JSON metadata file per session alongside the audio files.
//! - **HTTP**: POSTs JSON metadata to a webhook endpoint.

use std::path::Path;

use tracing::{error, info};

use super::RecordingRecord;
use crate::config::SrsConfig;

/// Store a completed recording using the configured backend.
pub async fn store_recording(config: &SrsConfig, record: &RecordingRecord) {
    match config.backend.as_str() {
        "http" => store_http(config, record).await,
        _ => store_file(config, record).await,
    }
}

/// File backend — write JSON metadata to disk.
async fn store_file(config: &SrsConfig, record: &RecordingRecord) {
    let base_dir = config.file.as_ref()
        .map(|file_config| file_config.base_dir.clone())
        .unwrap_or_else(|| config.recording_dir.clone());

    let dir = Path::new(&base_dir).join(&record.session_id);

    // Create the directory if it doesn't exist.
    if let Err(error) = tokio::fs::create_dir_all(&dir).await {
        error!(
            session_id = %record.session_id,
            dir = %dir.display(),
            error = %error,
            "SRS: failed to create recording directory"
        );
        return;
    }

    let metadata_path = dir.join("metadata.json");
    match serde_json::to_string_pretty(record) {
        Ok(json) => {
            if let Err(error) = tokio::fs::write(&metadata_path, json.as_bytes()).await {
                error!(
                    session_id = %record.session_id,
                    path = %metadata_path.display(),
                    error = %error,
                    "SRS: failed to write metadata file"
                );
            } else {
                info!(
                    session_id = %record.session_id,
                    path = %metadata_path.display(),
                    "SRS: metadata written"
                );
            }
        }
        Err(error) => {
            error!(
                session_id = %record.session_id,
                error = %error,
                "SRS: failed to serialize metadata"
            );
        }
    }
}

/// HTTP backend — POST JSON metadata to the configured webhook URL.
async fn store_http(config: &SrsConfig, record: &RecordingRecord) {
    let http_config = match &config.http {
        Some(config) => config,
        None => {
            error!("SRS: HTTP backend configured but no `http` section in config");
            return;
        }
    };

    let json = match serde_json::to_string(record) {
        Ok(json) => json,
        Err(error) => {
            error!(
                session_id = %record.session_id,
                error = %error,
                "SRS: failed to serialize metadata for HTTP"
            );
            return;
        }
    };

    let client = reqwest::Client::new();
    let mut request_builder = client
        .post(&http_config.url)
        .header("Content-Type", "application/json")
        .body(json);

    if let Some(auth_header) = &http_config.auth_header {
        request_builder = request_builder.header("Authorization", auth_header);
    }

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                info!(
                    session_id = %record.session_id,
                    url = %http_config.url,
                    status = %status,
                    "SRS: metadata posted to webhook"
                );
            } else {
                error!(
                    session_id = %record.session_id,
                    url = %http_config.url,
                    status = %status,
                    "SRS: webhook returned non-success status"
                );
            }
        }
        Err(error) => {
            error!(
                session_id = %record.session_id,
                url = %http_config.url,
                error = %error,
                "SRS: failed to POST metadata to webhook"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srs::{ParticipantRecord, StreamRecord};

    fn test_record() -> RecordingRecord {
        RecordingRecord {
            session_id: "test-session-001".to_string(),
            recording_call_id: "call-1".to_string(),
            original_call_id: None,
            participants: vec![
                ParticipantRecord {
                    participant_id: "p1".to_string(),
                    aor: "sip:alice@example.com".to_string(),
                    name: None,
                },
            ],
            streams: vec![
                StreamRecord {
                    stream_id: "s1".to_string(),
                    label: "caller-audio".to_string(),
                },
            ],
            state: "completed".to_string(),
            duration_secs: 120,
            recording_dir: Some("/tmp/test/test-session-001".to_string()),
        }
    }

    #[tokio::test]
    async fn file_backend_writes_metadata() {
        let temp_dir = std::env::temp_dir().join("siphon-srs-test");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;

        let config = SrsConfig {
            enabled: true,
            recording_dir: temp_dir.display().to_string(),
            max_sessions: 100,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
        };

        let record = test_record();
        store_recording(&config, &record).await;

        let metadata_path = temp_dir.join("test-session-001").join("metadata.json");
        assert!(metadata_path.exists());

        let content = tokio::fs::read_to_string(&metadata_path).await.unwrap();
        assert!(content.contains("test-session-001"));
        assert!(content.contains("alice@example.com"));
        assert!(content.contains("caller-audio"));

        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["session_id"], "test-session-001");
        assert_eq!(parsed["duration_secs"], 120);

        // Clean up.
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn recording_record_json_structure() {
        let record = test_record();
        let json = serde_json::to_string_pretty(&record).unwrap();

        // Verify key fields are present.
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"recording_call_id\""));
        assert!(json.contains("\"participants\""));
        assert!(json.contains("\"streams\""));
        assert!(json.contains("\"duration_secs\""));
        assert!(json.contains("\"state\""));
    }
}
