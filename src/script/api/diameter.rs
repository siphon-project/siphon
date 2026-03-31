//! PyO3 wrapper for Diameter peer management — exposed to Python as `diameter`.
//!
//! Scripts use:
//! ```python
//! from siphon import diameter
//!
//! # Check if a peer is connected
//! if diameter.is_connected("hss1"):
//!     log.info("HSS peer is up")
//!
//! # Cx: query HSS for S-CSCF assignment (I-CSCF)
//! result = diameter.cx_uar("sip:alice@ims.example.com", "ims.example.com")
//! if result:
//!     scscf = result["server_name"]
//!
//! # Cx: confirm server assignment after REGISTER auth (S-CSCF)
//! result = diameter.cx_sar("sip:alice@ims.example.com", "sip:scscf.ims.example.com:6060")
//! if result:
//!     ifc_xml = result.get("user_data")
//!
//! # Cx: locate serving S-CSCF for non-REGISTER requests (I-CSCF)
//! result = diameter.cx_lir("sip:alice@ims.example.com")
//!
//! # Rx: request QoS resources from PCRF (P-CSCF)
//! result = diameter.rx_aar(session_id="rx-sess-1", media_type="audio",
//!                          framed_ip="10.0.0.1", flow_description="permit in 17 from any")
//! if result:
//!     log.info(f"Rx AAR result: {result['result_code']}")
//!
//! # Rx: release QoS resources (P-CSCF)
//! diameter.rx_str("rx-sess-1")
//! ```

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::warn;

use crate::diameter::cx::{octet_string_as_utf8, required_str};
use crate::diameter::rx::extract_result_code;
use crate::diameter::DiameterManager;

/// Python-visible Diameter namespace.
#[pyclass(name = "DiameterNamespace", skip_from_py_object)]
pub struct PyDiameter {
    manager: Arc<DiameterManager>,
}

impl PyDiameter {
    pub fn new(manager: Arc<DiameterManager>) -> Self {
        Self { manager }
    }
}

#[pymethods]
impl PyDiameter {
    /// Check if a peer is connected.
    ///
    /// Args:
    ///     peer_name: Name of the Diameter peer (e.g. "hss1").
    ///
    /// Returns:
    ///     ``True`` if the peer has a registered client connection.
    fn is_connected(&self, peer_name: &str) -> bool {
        self.manager.client(peer_name).is_some()
    }

    /// Get the number of connected peers.
    ///
    /// Returns:
    ///     The number of peers currently registered in the manager.
    fn peer_count(&self) -> usize {
        self.manager.peer_count()
    }

    /// Send a Cx User-Authorization-Request to the HSS.
    ///
    /// Used by the I-CSCF to discover which S-CSCF should handle a REGISTER.
    /// The HSS returns the assigned S-CSCF in the Server-Name AVP.
    ///
    /// Args:
    ///     public_identity: The user's public identity (e.g. ``"sip:alice@ims.example.com"``).
    ///     visited_network_id: Visited network identifier (defaults to ``""``).
    ///     user_auth_type: User-Authorization-Type AVP value (3GPP TS 29.229).
    ///         ``0`` = REGISTRATION, ``1`` = DE_REGISTRATION,
    ///         ``2`` = REGISTRATION_AND_CAPABILITIES.  Omit to not send the AVP.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``server_name`` (str or None),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, visited_network_id=None, user_auth_type=None))]
    fn cx_uar<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        visited_network_id: Option<&str>,
        user_auth_type: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_uar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let visited = visited_network_id.unwrap_or("");
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.send_uar(public_identity, visited, user_auth_type))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let server_name = required_str(&message.avps, "Server-Name");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("server_name", server_name)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_uar failed");
                Ok(None)
            }
        }
    }

    /// Send a Cx Server-Assignment-Request to the HSS.
    ///
    /// Used by the S-CSCF after successful REGISTER authentication to confirm
    /// server assignment and download the user profile (iFC XML).
    ///
    /// Args:
    ///     public_identity: The user's public identity.
    ///     server_name: This S-CSCF's SIP URI (defaults to ``""``).
    ///     assignment_type: Server-Assignment-Type (default 1 = REGISTRATION).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``user_data`` (str or None, iFC XML),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, server_name=None, assignment_type=1))]
    fn cx_sar<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        server_name: Option<&str>,
        assignment_type: u32,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_sar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let name = server_name.unwrap_or("");
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.send_sar(public_identity, name, assignment_type))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                // User-Data AVP (code 606, 3GPP) carries iFC XML as OctetString
                let user_data = octet_string_as_utf8(&message.avps, "User-Data");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("user_data", user_data)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_sar failed");
                Ok(None)
            }
        }
    }

    /// Send a Cx Location-Info-Request to the HSS.
    ///
    /// Used by the I-CSCF to find the serving S-CSCF for non-REGISTER requests
    /// (INVITE, SUBSCRIBE, etc.).
    ///
    /// Args:
    ///     public_identity: The target user's public identity.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``server_name`` (str or None),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity,))]
    fn cx_lir<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_lir: no Diameter peer connected");
                return Ok(None);
            }
        };

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.send_lir(public_identity))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let server_name = required_str(&message.avps, "Server-Name");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("server_name", server_name)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_lir failed");
                Ok(None)
            }
        }
    }

    /// Send an Rx AA-Request to the PCRF for QoS resource reservation.
    ///
    /// Used by the P-CSCF when SDP is negotiated during session setup
    /// (INVITE 200 OK) to request dedicated bearer resources.
    ///
    /// Args:
    ///     session_id: Rx session identifier (or None to auto-generate).
    ///     media_type: Media type string (``"audio"``, ``"video"``).
    ///     framed_ip: UE's IP address for the media flow.
    ///     flow_description: IPFilterRule for the media flow
    ///         (e.g. ``"permit in 17 from any to 10.0.0.1 49170"``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``session_id`` (str),
    ///     or ``None`` if no Rx peer is connected.
    #[pyo3(signature = (session_id=None, media_type="audio", framed_ip=None, flow_description=None))]
    fn rx_aar<'py>(
        &self,
        python: Python<'py>,
        session_id: Option<&str>,
        media_type: &str,
        framed_ip: Option<&str>,
        flow_description: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("rx_aar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let media_type_num: u32 = match media_type {
            "audio" => 0,
            "video" => 1,
            "data" => 2,
            "application" => 3,
            "control" => 4,
            "text" => 5,
            "message" => 6,
            _ => 0xFFFFFFFF,
        };

        use crate::diameter::codec::*;
        use crate::diameter::dictionary::{self, avp};

        let peer = client.peer();
        let hbh = peer.next_hbh();
        let e2e = peer.next_e2e();
        let session = session_id
            .map(String::from)
            .unwrap_or_else(|| peer.new_session_id());
        let config = peer.config();

        let mut payload = Vec::with_capacity(512);
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session));
        payload.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, dictionary::RX_APP_ID));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        payload.extend_from_slice(&encode_avp_utf8(
            avp::DESTINATION_REALM,
            &config.destination_realm,
        ));

        // Media-Component-Description
        let mut mcd_inner = Vec::new();
        mcd_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MEDIA_COMPONENT_NUMBER, 1));
        mcd_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MEDIA_TYPE, media_type_num));

        if let Some(flow) = flow_description {
            let mut msc_inner = Vec::new();
            msc_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_NUMBER, 1));
            msc_inner.extend_from_slice(&encode_avp_octet_3gpp(
                avp::FLOW_DESCRIPTION,
                flow.as_bytes(),
            ));
            mcd_inner
                .extend_from_slice(&encode_avp_grouped_3gpp(avp::MEDIA_SUB_COMPONENT, &msc_inner));
        }

        payload.extend_from_slice(&encode_avp_grouped_3gpp(
            avp::MEDIA_COMPONENT_DESCRIPTION,
            &mcd_inner,
        ));

        if let Some(ip) = framed_ip {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                payload.extend_from_slice(&encode_avp_octet(
                    avp::FRAMED_IP_ADDRESS,
                    &addr.octets(),
                ));
            }
        }

        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_AA,
            dictionary::RX_APP_ID,
            hbh,
            e2e,
            &payload,
        );

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(peer.send_request(wire))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("session_id", &session)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "rx_aar failed");
                Ok(None)
            }
        }
    }

    /// Send an Rx Session-Termination-Request to the PCRF.
    ///
    /// Used by the P-CSCF when a SIP session ends (BYE) to release
    /// the dedicated bearer resources.
    ///
    /// Args:
    ///     session_id: The Rx session ID from the original AAR.
    ///
    /// Returns:
    ///     Result code (int), or ``None`` if no Rx peer is connected.
    /// Register a handler for incoming Registration-Termination-Request (RTR).
    ///
    /// The HSS sends RTR (command 304) to force deregistration. Siphon
    /// automatically sends the RTA (result 2001) after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(public_identity, reason_code, reason_info)``.
    ///
    /// Usage:
    ///
    /// ```python,ignore
    /// @diameter.on_rtr
    /// def handle_rtr(public_identity, reason_code, reason_info):
    ///     registrar.remove(public_identity)
    /// ```
    #[staticmethod]
    fn on_rtr(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_rtr", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    #[pyo3(signature = (session_id,))]
    fn rx_str(&self, session_id: &str) -> PyResult<Option<u32>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("rx_str: no Diameter peer connected");
                return Ok(None);
            }
        };

        let peer = client.peer();
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(crate::diameter::rx::send_str(
                peer,
                session_id,
                crate::diameter::rx::TERMINATION_CAUSE_LOGOUT,
            ))
        });

        match answer {
            Ok(result_code) => Ok(Some(result_code)),
            Err(error) => {
                warn!(error = %error, "rx_str failed");
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::DiameterManager;

    #[test]
    fn empty_manager_no_peers() {
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        assert_eq!(py_diameter.peer_count(), 0);
        assert!(!py_diameter.is_connected("hss1"));
    }

    #[test]
    fn connected_after_register() {
        let manager = Arc::new(DiameterManager::new());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let config = crate::diameter::peer::PeerConfig {
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
            let peer = Arc::new(crate::diameter::peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(crate::diameter::DiameterClient::new(peer));
            manager.register("hss1".to_string(), client);
        });

        let py_diameter = PyDiameter::new(manager);
        assert_eq!(py_diameter.peer_count(), 1);
        assert!(py_diameter.is_connected("hss1"));
        assert!(!py_diameter.is_connected("hss2"));
    }

    #[test]
    fn cx_uar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_uar(python, "sip:alice@example.com", None, None)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_uar_with_user_auth_type_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_uar(python, "sip:alice@example.com", None, Some(0))
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_sar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_sar(python, "sip:alice@example.com", None, 1)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_lir_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_lir(python, "sip:alice@example.com")
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn rx_aar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .rx_aar(python, None, "audio", None, None)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn rx_str_returns_none_without_peer() {
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        let result = py_diameter.rx_str("rx-session-1").unwrap();
        assert!(result.is_none());
    }
}
