//! 5G Service-Based Interface (SBI) client support.
//!
//! Provides typed HTTP/2 JSON clients for 5G core network functions:
//! - Npcf (Policy Control Function) — QoS policy authorization
//! - Nchf (Charging Function) — converged charging
//!
//! Uses `reqwest` for HTTP transport. Full NRF discovery and OAuth2
//! token management are planned for future implementation.

pub mod npcf;
pub mod nchf;

/// Configuration for SBI client connections.
#[derive(Debug, Clone)]
pub struct SbiConfig {
    /// NRF discovery endpoint (optional, for service discovery).
    pub nrf_url: Option<String>,
    /// Default timeout for SBI requests in seconds.
    pub timeout_secs: u64,
    /// OAuth2 client credentials (optional).
    pub oauth2_client_id: Option<String>,
    pub oauth2_client_secret: Option<String>,
}

impl Default for SbiConfig {
    fn default() -> Self {
        Self {
            nrf_url: None,
            timeout_secs: 5,
            oauth2_client_id: None,
            oauth2_client_secret: None,
        }
    }
}

/// SBI client manager — holds HTTP clients for each NF type.
#[derive(Debug)]
pub struct SbiManager {
    config: SbiConfig,
    http_client: reqwest::Client,
}

impl SbiManager {
    pub fn new(config: SbiConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();
        Self { config, http_client }
    }

    /// Get the HTTP client for making SBI requests.
    pub fn client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Get the NRF URL if configured.
    pub fn nrf_url(&self) -> Option<&str> {
        self.config.nrf_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbi_config_defaults() {
        let config = SbiConfig::default();
        assert!(config.nrf_url.is_none());
        assert_eq!(config.timeout_secs, 5);
        assert!(config.oauth2_client_id.is_none());
        assert!(config.oauth2_client_secret.is_none());
    }

    #[test]
    fn sbi_config_with_values() {
        let config = SbiConfig {
            nrf_url: Some("https://nrf.5gc.example.com".to_string()),
            timeout_secs: 10,
            oauth2_client_id: Some("siphon-pcscf".to_string()),
            oauth2_client_secret: Some("secret123".to_string()),
        };
        assert_eq!(config.nrf_url.as_deref(), Some("https://nrf.5gc.example.com"));
        assert_eq!(config.timeout_secs, 10);
    }

    #[test]
    fn sbi_manager_creation() {
        let manager = SbiManager::new(SbiConfig::default());
        assert!(manager.nrf_url().is_none());
    }

    #[test]
    fn sbi_manager_with_nrf() {
        let config = SbiConfig {
            nrf_url: Some("https://nrf.local:8443".to_string()),
            ..Default::default()
        };
        let manager = SbiManager::new(config);
        assert_eq!(manager.nrf_url(), Some("https://nrf.local:8443"));
    }
}
