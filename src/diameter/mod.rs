//! Diameter protocol support for SIPhon.
//!
//! Implements RFC 6733 (Diameter Base Protocol) with application modules for:
//! - **Cx** (TS 29.228/229): IMS registration — MAR/MAA, SAR/SAA, UAR/UAA, LIR/LIA
//! - **Sh** (TS 29.329): IMS user data — UDR/UDA, PUR/PUA, SNR/SNA
//! - **Rx** (TS 29.214): QoS policy — AAR/AAA, STR/STA, RAR/RAA, ASR/ASA
//! - **Ro** (TS 32.299): IMS online charging — CCR/CCA
//! - **Rf** (TS 32.299): IMS offline charging — ACR/ACA
//!
//! Transport supports both TCP and SCTP with automatic CER/CEA capability
//! exchange and DWR/DWA watchdog keepalives.

pub mod codec;
pub mod cx;
pub mod dictionary;
pub mod peer;
pub mod rf;
pub mod ro;
pub mod rx;
pub mod sh;
pub mod transport;

use std::sync::Arc;

use crate::diameter::codec::*;
use crate::diameter::dictionary::avp;
use crate::diameter::peer::DiameterPeer;

/// High-level Diameter Cx client for IMS authentication.
///
/// Wraps a connected `DiameterPeer` and provides typed request/response methods
/// for the Cx interface (S-CSCF ↔ HSS).
pub struct DiameterClient {
    peer: Arc<DiameterPeer>,
}

impl DiameterClient {
    /// Create a new client from an already-connected peer.
    pub fn new(peer: Arc<DiameterPeer>) -> Self {
        Self { peer }
    }

    /// Get the underlying peer handle.
    pub fn peer(&self) -> &Arc<DiameterPeer> {
        &self.peer
    }

    /// Send a UAR (User-Authorization-Request) and return the UAA.
    pub async fn send_uar(
        &self,
        public_identity: &str,
        visited_network_id: &str,
        user_auth_type: Option<u32>,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
            avp::VISITED_NETWORK_IDENTIFIER,
            visited_network_id.as_bytes(),
        ));
        if let Some(auth_type) = user_auth_type {
            avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_AUTHORIZATION_TYPE, auth_type));
        }

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_USER_AUTHORIZATION,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a SAR (Server-Assignment-Request) and return the SAA.
    pub async fn send_sar(
        &self,
        public_identity: &str,
        server_name: &str,
        server_assignment_type: u32,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, server_name));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SERVER_ASSIGNMENT_TYPE, server_assignment_type));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_DATA_ALREADY_AVAILABLE, 0));

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_SERVER_ASSIGNMENT,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a LIR (Location-Info-Request) and return the LIA.
    pub async fn send_lir(
        &self,
        public_identity: &str,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_LOCATION_INFO,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a MAR (Multimedia-Auth-Request) and return the MAA.
    pub async fn send_mar(
        &self,
        public_identity: &str,
        sip_num_auth_items: u32,
        sip_auth_scheme: &str,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        // Build SIP-Auth-Data-Item grouped AVP
        let mut auth_children = Vec::new();
        auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SIP_AUTHENTICATION_SCHEME,
            sip_auth_scheme,
        ));
        let sip_auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, sip_num_auth_items));
        avp_bytes.extend_from_slice(&sip_auth_data_item);

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Shutdown the underlying peer connection.
    pub fn shutdown(&self) {
        self.peer.shutdown();
    }
}

// ---------------------------------------------------------------------------
// DiameterManager
// ---------------------------------------------------------------------------

use dashmap::DashMap;

/// Manages multiple Diameter peer connections.
///
/// Created at startup from config, holds connected clients indexed by peer name.
pub struct DiameterManager {
    clients: DashMap<String, Arc<DiameterClient>>,
}

impl Default for DiameterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterManager {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }

    /// Register a connected client under its peer name.
    pub fn register(&self, name: String, client: Arc<DiameterClient>) {
        self.clients.insert(name, client);
    }

    /// Get a client by peer name.
    pub fn client(&self, name: &str) -> Option<Arc<DiameterClient>> {
        self.clients.get(name).map(|entry| Arc::clone(entry.value()))
    }

    /// Get the first available client (for single-peer setups).
    pub fn any_client(&self) -> Option<Arc<DiameterClient>> {
        self.clients.iter().next().map(|entry| Arc::clone(entry.value()))
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.clients.len()
    }

    /// Shutdown all peers.
    pub fn shutdown_all(&self) {
        for entry in self.clients.iter() {
            entry.value().shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::PeerConfig;

    #[test]
    fn manager_empty() {
        let manager = DiameterManager::new();
        assert_eq!(manager.peer_count(), 0);
        assert!(manager.client("hss1").is_none());
        assert!(manager.any_client().is_none());
    }

    #[test]
    fn manager_register_and_lookup() {
        let manager = DiameterManager::new();

        // Create a minimal peer config for testing
        let config = PeerConfig {
            host: "hss1.example.com".to_string(),
            port: 3868,
            origin_host: "siphon.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: None,
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        };

        // We cannot create a real DiameterPeer (requires TCP), so we test
        // the manager's DashMap logic by verifying the API contract.
        // Use a tokio runtime to create a peer via channels.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
            let peer = Arc::new(peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(DiameterClient::new(Arc::clone(&peer)));

            manager.register("hss1".to_string(), Arc::clone(&client));
            assert_eq!(manager.peer_count(), 1);
            assert!(manager.client("hss1").is_some());
            assert!(manager.client("hss2").is_none());
            assert!(manager.any_client().is_some());
        });
    }

    #[test]
    fn manager_shutdown_all() {
        let manager = DiameterManager::new();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let config = PeerConfig {
                host: "hss1.example.com".to_string(),
                port: 3868,
                origin_host: "siphon.example.com".to_string(),
                origin_realm: "example.com".to_string(),
                destination_host: None,
                destination_realm: "example.com".to_string(),
                local_ip: "10.0.0.1".parse().unwrap(),
                application_ids: vec![],
                watchdog_interval: 30,
                reconnect_delay: 5,
                product_name: "SIPhon".to_string(),
                firmware_revision: 100,
            };

            let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
            let peer = Arc::new(peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(DiameterClient::new(peer));

            manager.register("hss1".to_string(), client);

            // Should not panic
            manager.shutdown_all();
            assert_eq!(manager.peer_count(), 1);
        });
    }
}
