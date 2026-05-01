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

use crate::diameter::codec::{
    self, encode_avp_address_ipv4, encode_avp_grouped, encode_avp_grouped_3gpp, encode_avp_octet,
    encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp, encode_avp_u64, encode_avp_utf8,
    encode_avp_utf8_3gpp, encode_diameter_message, encode_vendor_specific_app_id, FLAG_PROXIABLE,
    FLAG_REQUEST,
};
use crate::diameter::cx::{octet_string_as_utf8, required_str};
use crate::diameter::dictionary::{self, avp, AvpDef, AvpType};
use crate::diameter::rx::extract_result_code;
use crate::diameter::DiameterManager;

/// Extract Sh Data-Reference(s) from a Python object that may be ``int`` or ``list[int]``.
fn extract_references(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u32>> {
    if let Ok(single) = obj.extract::<u32>() {
        return Ok(vec![single]);
    }
    obj.extract::<Vec<u32>>()
}

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

    /// Register a handler for incoming Re-Auth-Request (RAR) from the PCRF.
    ///
    /// The PCRF sends RAR (command 258) when PCC rules change (e.g. bearer
    /// loss, QoS modification). Siphon automatically sends RAA (result 2001)
    /// after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(session_id, abort_cause, specific_actions)``.
    ///
    /// Usage:
    ///
    /// ```python,ignore
    /// @diameter.on_rar
    /// def handle_rar(session_id, abort_cause, specific_actions):
    ///     if 2 in specific_actions:  # INDICATION_OF_LOSS_OF_BEARER
    ///         log.warn(f"Bearer lost for session {session_id}")
    /// ```
    #[staticmethod]
    fn on_rar(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_rar", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Register a handler for incoming Abort-Session-Request (ASR) from the PCRF.
    ///
    /// The PCRF sends ASR (command 274) to force Rx session teardown. Siphon
    /// automatically sends ASA (result 2001) after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(session_id, abort_cause, origin_host)``.
    ///
    /// Usage:
    ///
    /// ```python,ignore
    /// @diameter.on_asr
    /// def handle_asr(session_id, abort_cause, origin_host):
    ///     log.info(f"Session abort from {origin_host}: {session_id}")
    /// ```
    #[staticmethod]
    fn on_asr(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_asr", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Register a handler for incoming Sh Push-Notification-Request (PNR) from the HSS.
    ///
    /// The HSS sends PNR (command 309, Sh) when a subscribed user's profile
    /// changes (MMTEL config edit via XCAP, CFU activation, etc.). Siphon
    /// automatically sends PNA (result 2001) after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(public_identity, user_data_xml)``. ``user_data_xml``
    ///         is the Sh-Data XML payload, or ``None`` if the PNR had no payload.
    ///
    /// Usage:
    ///
    /// ```python,ignore
    /// @diameter.on_pnr
    /// def handle_pnr(public_identity, user_data_xml):
    ///     cache.put("simservs", public_identity, user_data_xml)
    /// ```
    #[staticmethod]
    fn on_pnr(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_pnr", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Send a Sh User-Data-Request to the HSS (AS role).
    ///
    /// Used by an Application Server (e.g. MMTEL-AS) to fetch user profile
    /// data (simservs XML, iFC, public identities, etc.).
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: One of the TS 29.328 §7.6 Data-Reference values
    ///         (e.g. ``0`` = Repository-Data, ``11`` = IMS-User-State,
    ///         ``13`` = Initial-Filter-Criteria).  Accepts an ``int`` or a
    ///         ``list[int]`` for multiple references.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required when Data-Reference is Repository-Data.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``user_data`` (str or None,
    ///     the Sh-Data XML payload), or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, data_reference, service_indication=None))]
    fn sh_udr<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: &Bound<'_, PyAny>,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_udr: no Diameter peer connected");
                return Ok(None);
            }
        };

        let references = extract_references(data_reference)?;

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_udr(
                public_identity,
                &references,
                service_indication,
            ))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let user_data = octet_string_as_utf8(&message.avps, "User-Data-Sh");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("user_data", user_data)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_udr failed");
                Ok(None)
            }
        }
    }

    /// Send a Sh Profile-Update-Request to the HSS (AS role).
    ///
    /// Used by an Application Server to upload updated user profile data
    /// (e.g. simservs XML after XCAP PUT).
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: Data-Reference value (usually ``0`` for Repository-Data).
    ///     xml: UTF-8 XML payload for the User-Data-Sh AVP.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required by the HSS when Data-Reference is Repository-Data
    ///         (TS 29.328 §6.1.3 — Repository-Data is keyed on
    ///         ``(Public-Identity, Service-Indication)``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), or ``None`` if no peer is connected.
    #[pyo3(signature = (public_identity, data_reference, xml, service_indication=None))]
    fn sh_pur<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: u32,
        xml: &str,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_pur: no Diameter peer connected");
                return Ok(None);
            }
        };

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_pur(
                public_identity,
                data_reference,
                xml,
                service_indication,
            ))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_pur failed");
                Ok(None)
            }
        }
    }

    /// Send a Sh Subscribe-Notifications-Request to the HSS (AS role).
    ///
    /// Used by an Application Server to subscribe (or unsubscribe) for
    /// notifications about a user's profile changes. The HSS will later push
    /// updates via PNR — register a handler via ``@diameter.on_pnr``.
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: Data-Reference (int) or list of references to subscribe to.
    ///     subs_req_type: ``0`` = SUBSCRIBE, ``1`` = UNSUBSCRIBE.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required by the HSS when Data-Reference is Repository-Data
    ///         (TS 29.328 §6.1.4 — Repository-Data is keyed on
    ///         ``(Public-Identity, Service-Indication)``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), or ``None`` if no peer is connected.
    #[pyo3(signature = (public_identity, data_reference, subs_req_type, service_indication=None))]
    fn sh_snr<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: &Bound<'_, PyAny>,
        subs_req_type: u32,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_snr: no Diameter peer connected");
                return Ok(None);
            }
        };

        let references = extract_references(data_reference)?;

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_snr(
                public_identity,
                &references,
                subs_req_type,
                service_indication,
            ))
        });

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_snr failed");
                Ok(None)
            }
        }
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

    /// Send an S6c Send-Routing-Info-for-SM request to the HSS.
    ///
    /// Used by the SMSC role (e.g. ip-sm-gw) to discover the served-node
    /// (MME or SGSN) for an MT-SMS delivery. The HSS answer carries the
    /// served-node identity which the SMSC then uses on SGd as the
    /// destination for the actual MT-Forward-Short-Message (TFR).
    ///
    /// Args:
    ///     msisdn: E.164 number of the called party (no leading ``+``).
    ///     sc_address: GT of the originating SMSC.
    ///     sm_rp_mti: SM-RP Message Type Indicator —
    ///         0 = SMS Deliver (typical MT delivery),
    ///         1 = SMS Status Report.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), ``user_name`` (IMSI, optional),
    ///     ``sgsn_number`` (str, set when 2G/3G delivery), and
    ///     ``mme_number_for_mt_sms`` (str, set when LTE delivery).
    ///     ``None`` when no Diameter peer is connected.
    #[pyo3(signature = (msisdn, sc_address, sm_rp_mti=None))]
    fn s6c_srr<'py>(
        &self,
        python: Python<'py>,
        msisdn: &str,
        sc_address: &str,
        sm_rp_mti: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("s6c_srr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.send_srr(msisdn, sc_address, sm_rp_mti))
        });
        match answer {
            Ok(message) => match crate::diameter::s6c::parse_sra(&message) {
                Some(sra) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", sra.result_code)?;
                    dict.set_item("experimental_result_code", sra.experimental_result_code)?;
                    dict.set_item("user_name", sra.user_name)?;
                    dict.set_item("sgsn_number", sra.sgsn_number)?;
                    dict.set_item("mme_number_for_mt_sms", sra.mme_number_for_mt_sms)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("s6c_srr: HSS answer was not parseable as SRA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "s6c_srr failed");
                Ok(None)
            }
        }
    }

    /// Send an S6c Report-SM-Delivery-Status request to the HSS.
    ///
    /// Used after delivery to inform the HSS of the final outcome so it
    /// can release any held queueing state.
    ///
    /// Args:
    ///     user_name: IMSI of the served subscriber.
    ///     sc_address: GT of the originating SMSC.
    ///     delivery_outcome: TS 29.336 outcome enum —
    ///         0 = SUCCESSFUL_TRANSFER,
    ///         1 = ABSENT_USER,
    ///         2 = UE_MEMORY_CAPACITY_EXCEEDED,
    ///         3 = SUCCESSFUL_TRANSFER_NOT_LAST,
    ///         4 = TEMPORARY_ERROR.
    #[pyo3(signature = (user_name, sc_address, delivery_outcome))]
    fn s6c_rsr<'py>(
        &self,
        python: Python<'py>,
        user_name: &str,
        sc_address: &str,
        delivery_outcome: u32,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("s6c_rsr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                client.send_rsr(user_name, sc_address, delivery_outcome),
            )
        });
        match answer {
            Ok(message) => match crate::diameter::s6c::parse_rsa(&message) {
                Some(rsa) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", rsa.result_code)?;
                    dict.set_item("experimental_result_code", rsa.experimental_result_code)?;
                    dict.set_item("user_name", rsa.user_name)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("s6c_rsr: HSS answer was not parseable as RSA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "s6c_rsr failed");
                Ok(None)
            }
        }
    }

    /// Send an SGd MT-Forward-Short-Message request to the served node
    /// (MME for LTE, SGSN for 2G/3G). Carries the SMS-DELIVER TPDU in
    /// the SM-RP-UI AVP.
    ///
    /// Args:
    ///     user_name: IMSI of the recipient UE.
    ///     sc_address: GT of the originating SMSC.
    ///     sm_rp_ui: SMS-DELIVER TPDU bytes (TS 23.040).
    ///     smsmi_correlation_id: Optional opaque correlation reference
    ///         the SMSC uses to bind the TFR to its own queueing state.
    ///     sm_rp_mti: SM-RP MTI — 0 = SMS Deliver, 1 = Status Report.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``absent_user_diagnostic``
    ///     (int or None — set when the UE was unreachable).
    #[pyo3(signature = (user_name, sc_address, sm_rp_ui, smsmi_correlation_id=None, sm_rp_mti=None))]
    fn sgd_tfr<'py>(
        &self,
        python: Python<'py>,
        user_name: &str,
        sc_address: &str,
        sm_rp_ui: &[u8],
        smsmi_correlation_id: Option<&str>,
        sm_rp_mti: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sgd_tfr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_tfr(
                user_name,
                sc_address,
                sm_rp_ui,
                smsmi_correlation_id,
                sm_rp_mti,
            ))
        });
        match answer {
            Ok(message) => match crate::diameter::sgd::parse_tfa(&message) {
                Some(tfa) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", tfa.result_code)?;
                    dict.set_item("experimental_result_code", tfa.experimental_result_code)?;
                    dict.set_item("absent_user_diagnostic", tfa.absent_user_diagnostic)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("sgd_tfr: peer answer was not parseable as TFA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "sgd_tfr failed");
                Ok(None)
            }
        }
    }

    /// Register a handler for incoming S6c Alert-Service-Centre-Request
    /// (ALR) from the HSS.
    ///
    /// The HSS sends ALR (command 8388648) when a previously-unreachable
    /// UE has registered or moved into coverage — a signal to the SMSC
    /// to drain any pending MT-SMS queue. Siphon automatically sends
    /// ALA (result 2001) after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(public_identity, msisdn)``.
    ///         ``public_identity`` is the IMSI from User-Name; ``msisdn``
    ///         is the UE's E.164 number when the ALR carried it
    ///         (otherwise an empty string).
    #[staticmethod]
    fn on_alr(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_alr", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Register a handler for incoming SGd MO-Forward-Short-Message-Request
    /// (OFR) from the MME (or SGSN/MSC).
    ///
    /// The MME sends OFR (command 8388645) carrying a UE-originated SMS
    /// (SMS-SUBMIT TPDU). Siphon automatically sends OFA (result 2001)
    /// after the handler returns.
    ///
    /// Args:
    ///     func: Callback ``fn(user_name, sc_address, sm_rp_ui)``.
    ///         ``sm_rp_ui`` is the raw SMS-SUBMIT TPDU bytes (`bytes`).
    #[staticmethod]
    fn on_ofr(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("diameter.on_ofr", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Originate a Diameter request by spec name + application name +
    /// AVP kwargs. Generic counterpart of the typed helpers (`cx_uar`,
    /// `s6c_srr`, etc.) — useful for addons that need to drive
    /// applications whose full helper coverage isn't in siphon-core, or
    /// for scripts that prefer working in the spec's vocabulary.
    ///
    /// Args:
    ///     command: Diameter command name. Accepts the long form
    ///         (e.g. ``"Send-Routing-Info-for-SM-Request"``), the long
    ///         form without the ``-Request`` suffix, or the 3-letter
    ///         acronym (``"SRR"``). Case-insensitive.
    ///     application: Application short name (``"Cx"``, ``"S6c"``,
    ///         ``"SGd"``, …). Case-insensitive.
    ///     avps: Per-AVP keyword arguments. Keys are ``snake_case``
    ///         translations of the dictionary's Title-Kebab-Case names
    ///         (``msisdn`` → ``MSISDN``, ``sc_address`` → ``SC-Address``,
    ///         ``sm_rp_ui`` → ``SM-RP-UI``, …). Values are encoded by
    ///         the AVP's declared type:
    ///           UTF8String / DiameterIdentity → ``str``
    ///           OctetString                   → ``bytes`` or ``str``
    ///           Unsigned32 / Enumerated       → ``int``
    ///           Unsigned64                    → ``int``
    ///           Address (IPv4)                → ``str`` (dotted-quad)
    ///         Grouped AVPs are not supported via kwargs — use the
    ///         typed helper for those commands.
    ///     peer: Optional peer name override (defaults to any
    ///         connected peer for the application).
    ///     timeout_ms: Per-request timeout (default 10000ms — the same
    ///         default the underlying peer applies).
    ///
    /// Returns:
    ///     Dict with all answer AVPs (snake_case keys) plus
    ///     ``result_code``, or ``None`` when no peer is connected /
    ///     the peer rejected the message / the answer was malformed.
    ///
    /// Raises ``ValueError`` for unknown command/application names or
    /// unrecognised AVP kwargs.
    #[pyo3(signature = (
        command,
        application,
        peer=None,
        timeout_ms=10_000,
        **avps,
    ))]
    fn send_request<'py>(
        &self,
        python: Python<'py>,
        command: &str,
        application: &str,
        peer: Option<&str>,
        timeout_ms: u64,
        avps: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let _ = timeout_ms; // forwarded peer applies its own timeout today

        let command_code = dictionary::command_code_by_name(command).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter command name: {command}"
            ))
        })?;
        let (app_vendor, app_id) = dictionary::app_id_by_name(application).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter application name: {application}"
            ))
        })?;

        let client = match peer {
            Some(name) => self.manager.client(name),
            None => self.manager.any_client(),
        };
        let client = match client {
            Some(client) => client,
            None => {
                warn!(
                    command = command,
                    application = application,
                    "diameter.send_request: no peer connected"
                );
                return Ok(None);
            }
        };

        let session_id = client.peer().new_session_id();
        let hbh = client.peer().next_hbh();
        let e2e = client.peer().next_e2e();
        let config = client.peer().config().clone();

        let mut avp_bytes = Vec::with_capacity(256);
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(
            avp::DESTINATION_REALM,
            &config.destination_realm,
        ));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(app_vendor, app_id));

        if let Some(kwargs) = avps {
            for (key, value) in kwargs.iter() {
                let key_str: String = key.extract().map_err(|error| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "AVP kwarg name must be str: {error}"
                    ))
                })?;
                // Reserved kwargs siphon consumes itself — never travel
                // on the wire.
                if matches!(key_str.as_str(), "peer" | "timeout_ms" | "command" | "application")
                {
                    continue;
                }
                let avp_def = dictionary::lookup_avp_by_python_name(&key_str).ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown AVP kwarg: {key_str}"
                    ))
                })?;
                let encoded = encode_kwarg_avp(avp_def, &value)?;
                avp_bytes.extend_from_slice(&encoded);
            }
        }

        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            command_code,
            app_id,
            hbh,
            e2e,
            &avp_bytes,
        );

        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.peer().send_request(wire))
        });
        let message = match answer {
            Ok(message) => message,
            Err(error) => {
                warn!(error = %error, command = command, "diameter.send_request failed");
                return Ok(None);
            }
        };

        let dict = decode_avps_to_pydict(python, &message.avps)?;
        Ok(Some(dict))
    }

    /// Register a generic handler for an incoming Diameter command.
    ///
    /// Companion to `send_request` — accepts the same flexible naming
    /// for ``command`` and ``application``. Resolves both at decoration
    /// time and stores the handler under a canonical key so that all
    /// of ``"Alert-SC-Request"``, ``"Alert-Service-Centre-Request"``,
    /// and ``"ALR"`` end up in the same handler list when the dispatcher
    /// matches an incoming ALR.
    ///
    /// Siphon auto-sends a generic 2001-Success answer for the same
    /// command code after the handler returns. Custom result codes are
    /// not yet wired through — typed helpers (`@on_alr`, `@on_ofr`)
    /// remain the path for those flows.
    ///
    /// Args:
    ///     command: Diameter command name (long form, suffix-stripped,
    ///         or 3-letter acronym).
    ///     application: Application short name.
    ///
    /// Usage:
    ///
    /// ```python,ignore
    /// @diameter.on_command("Alert-SC-Request", application="S6c")
    /// def drain_pending(public_identity, msisdn, **other_avps):
    ///     ...
    /// ```
    #[staticmethod]
    #[pyo3(signature = (command, application))]
    fn on_command<'py>(
        python: Python<'py>,
        command: &str,
        application: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let command_code = dictionary::command_code_by_name(command).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter command name: {command}"
            ))
        })?;
        let (_vendor, app_id) = dictionary::app_id_by_name(application).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter application name: {application}"
            ))
        })?;
        let canonical_command = dictionary::command_name_by_code(command_code)
            .unwrap_or(command)
            .to_owned();
        let canonical_app = dictionary::app_name_by_id(app_id)
            .unwrap_or(application)
            .to_owned();
        let kind = format!("diameter.on_command:{canonical_app}:{canonical_command}");

        // Closure decorator — captures the canonical kind and writes
        // the registered function into _siphon_registry on first call.
        let kind_for_closure = kind.clone();
        let closure = pyo3::types::PyCFunction::new_closure(
            python,
            None,
            None,
            move |args: &Bound<'_, pyo3::types::PyTuple>,
                  _kwargs: Option<&Bound<'_, PyDict>>|
                  -> PyResult<Py<PyAny>> {
                let py = args.py();
                let func = args.get_item(0)?;
                let asyncio = py.import("asyncio")?;
                let is_async = asyncio
                    .call_method1("iscoroutinefunction", (&func,))?
                    .is_truthy()?;
                let registry = py.import("_siphon_registry")?;
                let metadata = PyDict::new(py);
                metadata.set_item("command", &kind_for_closure)?;
                registry.call_method1(
                    "register",
                    (
                        kind_for_closure.as_str(),
                        py.None(),
                        &func,
                        is_async,
                        &metadata,
                    ),
                )?;
                Ok(func.unbind())
            },
        )?;
        Ok(closure.into_any())
    }
}

// ---------------------------------------------------------------------------
// Generic AVP encoding from Python kwargs
// ---------------------------------------------------------------------------

/// Encode a single AVP value (Python object → wire bytes) using the
/// AVP's declared type from the dictionary. Picks the 3GPP-flagged
/// encoder when the AVP is vendor-specific, the base encoder otherwise.
fn encode_kwarg_avp(def: &AvpDef, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let is_vendor = def.is_vendor_specific();
    match def.data_type {
        AvpType::UTF8String | AvpType::DiameterIdentity => {
            let s: String = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects str, got {error}",
                    def.name
                ))
            })?;
            Ok(if is_vendor {
                encode_avp_utf8_3gpp(def.code, &s)
            } else {
                encode_avp_utf8(def.code, &s)
            })
        }
        AvpType::OctetString => {
            // Accept bytes directly (raw payload, e.g. SM-RP-UI TPDU)
            // or str (encoded as UTF-8, e.g. MSISDN, SC-Address).
            let bytes: Vec<u8> = if let Ok(b) = value.extract::<Vec<u8>>() {
                b
            } else if let Ok(s) = value.extract::<String>() {
                s.into_bytes()
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects bytes or str",
                    def.name
                )));
            };
            Ok(if is_vendor {
                encode_avp_octet_3gpp(def.code, &bytes)
            } else {
                encode_avp_octet(def.code, &bytes)
            })
        }
        AvpType::Unsigned32 | AvpType::Enumerated => {
            let n: u32 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (u32 range), got {error}",
                    def.name
                ))
            })?;
            Ok(if is_vendor {
                encode_avp_u32_3gpp(def.code, n)
            } else {
                encode_avp_u32(def.code, n)
            })
        }
        AvpType::Unsigned64 => {
            let n: u64 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (u64 range), got {error}",
                    def.name
                ))
            })?;
            // No vendor variant in the codec for u64 — only one Unsigned64
            // 3GPP AVP exists in the dictionary today (CC-Sub-Session-Id).
            // Treat as plain u64 with vendor flag handled by encode_avp.
            Ok(encode_avp_u64(def.code, n))
        }
        AvpType::Integer32 => {
            let n: i32 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (i32 range), got {error}",
                    def.name
                ))
            })?;
            Ok(crate::diameter::codec::encode_avp_i32_3gpp(def.code, n))
        }
        AvpType::Address => {
            let s: String = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects str (IPv4 dotted-quad), got {error}",
                    def.name
                ))
            })?;
            let ip: std::net::Ipv4Addr = s.parse().map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "{} invalid IPv4 address {s:?}: {error}",
                    def.name
                ))
            })?;
            Ok(encode_avp_address_ipv4(def.code, ip))
        }
        AvpType::Time => Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "{} (Time AVPs) is not supported via kwargs — use a typed helper",
            def.name
        ))),
        AvpType::Grouped => {
            // Allow an empty grouped marker by passing None — useful for
            // a few AVPs that act as flags. Real grouped encoding (sub-AVPs
            // from a nested dict) is deferred until an actual use case
            // shows up; today scripts that need grouped AVPs use the
            // typed helpers.
            if value.is_none() {
                Ok(if is_vendor {
                    encode_avp_grouped_3gpp(def.code, &[])
                } else {
                    encode_avp_grouped(def.code, &[])
                })
            } else {
                Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} (Grouped AVP) requires a typed helper — \
                     scripted nested-AVP construction is not yet supported",
                    def.name
                )))
            }
        }
    }
}

/// Convert a `serde_json::Value` of decoded AVPs to a Python dict with
/// snake_case keys. Used to surface the answer AVPs to the script.
/// Public to the dispatcher so the `@on_command` fallback can build
/// kwargs without re-implementing the conversion.
pub(crate) fn avps_json_to_pydict<'py>(
    python: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    decode_avps_to_pydict(python, value)
}

fn decode_avps_to_pydict<'py>(
    python: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);
    if let Some(map) = value.as_object() {
        for (name, child) in map {
            let key = avp_name_to_snake(name);
            let py_value = json_to_py(python, child)?;
            dict.set_item(key, py_value)?;
        }
    }
    Ok(dict)
}

/// Translate a Title-Kebab AVP name to snake_case for Python.
fn avp_name_to_snake(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '-' => '_',
            ch => ch.to_ascii_lowercase(),
        })
        .collect()
}

fn json_to_py<'py>(
    python: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Py<PyAny>> {
    Ok(match value {
        serde_json::Value::Null => python.None(),
        serde_json::Value::Bool(b) => b
            .into_pyobject(python)
            .map(|v| v.to_owned().into_any().unbind())
            .unwrap_or_else(|_| python.None()),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else if let Some(i) = n.as_i64() {
                i.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else {
                python.None()
            }
        }
        serde_json::Value::String(s) => s
            .as_str()
            .into_pyobject(python)
            .map(|v| v.into_any().unbind())
            .unwrap_or_else(|_| python.None()),
        serde_json::Value::Array(items) => {
            let list = pyo3::types::PyList::empty(python);
            for item in items {
                list.append(json_to_py(python, item)?)?;
            }
            list.into_any().unbind()
        }
        serde_json::Value::Object(_) => {
            decode_avps_to_pydict(python, value)?.into_any().unbind()
        }
    })
}

/// Build the canonical dispatch key that
/// `dispatcher.rs` uses to look up custom Diameter handlers from a
/// `(command_code, app_id)` pair. Returned `None` if either side has
/// no canonical name in the dictionary.
pub(crate) fn custom_handler_kind(app_id: u32, command_code: u32) -> Option<String> {
    let app = dictionary::app_name_by_id(app_id)?;
    let command = dictionary::command_name_by_code(command_code)?;
    Some(format!("diameter.on_command:{app}:{command}"))
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

    #[test]
    fn sh_udr_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let data_reference = 0u32.into_pyobject(python).unwrap();
            let result = py_diameter
                .sh_udr(
                    python,
                    "sip:alice@ims.example.com",
                    data_reference.as_any(),
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn sh_pur_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .sh_pur(
                    python,
                    "sip:alice@ims.example.com",
                    0,
                    "<simservs/>",
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn sh_snr_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let data_reference = vec![0u32, 17u32].into_pyobject(python).unwrap();
            let result = py_diameter
                .sh_snr(
                    python,
                    "sip:alice@ims.example.com",
                    data_reference.as_any(),
                    0,
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn extract_references_accepts_int_and_list() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let single = 17u32.into_pyobject(python).unwrap();
            assert_eq!(extract_references(single.as_any()).unwrap(), vec![17]);

            let list = vec![0u32, 11u32].into_pyobject(python).unwrap();
            assert_eq!(extract_references(list.as_any()).unwrap(), vec![0, 11]);
        });
    }

    // -----------------------------------------------------------------
    // Generic API surface — send_request / on_command
    // -----------------------------------------------------------------

    #[test]
    fn custom_handler_kind_round_trips_canonical() {
        let kind = custom_handler_kind(
            crate::diameter::dictionary::S6C_APP_ID,
            crate::diameter::dictionary::CMD_ALERT_SERVICE_CENTRE,
        )
        .expect("known app/cmd must produce a kind");
        assert_eq!(kind, "diameter.on_command:S6c:Alert-Service-Centre");

        let kind = custom_handler_kind(
            crate::diameter::dictionary::SGD_APP_ID,
            crate::diameter::dictionary::CMD_MO_FORWARD_SHORT_MESSAGE,
        )
        .expect("known app/cmd must produce a kind");
        assert_eq!(kind, "diameter.on_command:SGd:MO-Forward-Short-Message");
    }

    #[test]
    fn custom_handler_kind_returns_none_for_unknown() {
        // Bogus app id 99999 — not in the dictionary.
        assert!(custom_handler_kind(99_999, 1).is_none());
    }

    #[test]
    fn send_request_rejects_unknown_command() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter.send_request(
                python,
                "Bogus-Command-Request",
                "S6c",
                None,
                10_000,
                None,
            );
            let error = result.expect_err("unknown command must error");
            let msg = format!("{error}");
            assert!(msg.contains("unknown Diameter command"), "msg: {msg}");
        });
    }

    #[test]
    fn send_request_rejects_unknown_application() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter.send_request(
                python,
                "Send-Routing-Info-for-SM-Request",
                "BogusApp",
                None,
                10_000,
                None,
            );
            let error = result.expect_err("unknown app must error");
            let msg = format!("{error}");
            assert!(msg.contains("unknown Diameter application"), "msg: {msg}");
        });
    }

    #[test]
    fn send_request_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .send_request(
                    python,
                    "Send-Routing-Info-for-SM-Request",
                    "S6c",
                    None,
                    10_000,
                    None,
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn encode_kwarg_avp_encodes_string_octet() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name("sc_address")
            .expect("sc_address must resolve");
        pyo3::Python::attach(|python| {
            let value = "31611111111".into_pyobject(python).unwrap();
            let encoded = encode_kwarg_avp(avp_def, value.as_any()).unwrap();
            assert!(!encoded.is_empty(), "OctetString AVP must produce bytes");
        });
    }

    #[test]
    fn encode_kwarg_avp_encodes_bytes_octet() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name("sm_rp_ui")
            .expect("sm_rp_ui must resolve");
        pyo3::Python::attach(|python| {
            let value = pyo3::types::PyBytes::new(python, &[0xDE, 0xAD, 0xBE, 0xEF]);
            let encoded = encode_kwarg_avp(avp_def, value.as_any()).unwrap();
            assert!(!encoded.is_empty());
        });
    }

    #[test]
    fn encode_kwarg_avp_rejects_grouped_with_value() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name(
            "smsmi_correlation_id",
        )
        .expect("smsmi_correlation_id must resolve");
        pyo3::Python::attach(|python| {
            let value = "anything".into_pyobject(python).unwrap();
            let result = encode_kwarg_avp(avp_def, value.as_any());
            let error = result.expect_err("grouped AVP must reject scalar value");
            let msg = format!("{error}");
            assert!(msg.contains("Grouped AVP"), "msg: {msg}");
        });
    }

    #[test]
    fn avp_name_to_snake_handles_acronyms() {
        assert_eq!(avp_name_to_snake("Session-Id"), "session_id");
        assert_eq!(avp_name_to_snake("MSISDN"), "msisdn");
        assert_eq!(avp_name_to_snake("SC-Address"), "sc_address");
        assert_eq!(avp_name_to_snake("SM-RP-UI"), "sm_rp_ui");
        assert_eq!(avp_name_to_snake("SMSMI-Correlation-ID"), "smsmi_correlation_id");
    }

    #[test]
    fn on_command_resolves_canonical_kind() {
        // Multiple input forms must produce the same canonical kind so
        // the dispatcher can dispatch deterministically.
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            // Use a no-op function to register; we then peek into the
            // registry to verify the canonical kind string.
            let registry_mod = match python.import("_siphon_registry") {
                Ok(m) => m,
                Err(_) => {
                    // Module isn't preloaded in this isolated test —
                    // build it on the fly the way engine.rs does.
                    crate::script::api::ensure_registry(python).unwrap();
                    python.import("_siphon_registry").unwrap()
                }
            };
            registry_mod.call_method0("clear").unwrap();

            let func = python
                .eval(c"lambda **kw: None", None, None)
                .unwrap()
                .unbind();

            // Three name forms — all must resolve to the same kind.
            for name in ["Alert-SC-Request", "Alert-Service-Centre-Request", "ALR"] {
                let decorator = PyDiameter::on_command(python, name, "S6c").unwrap();
                let _ = decorator.call1((&func,)).unwrap();
            }

            let entries = registry_mod.call_method0("entries").unwrap();
            let entries: Vec<(String, Option<String>, Py<PyAny>, bool, Py<PyAny>)> =
                entries.extract().unwrap();
            assert_eq!(entries.len(), 3);
            for entry in &entries {
                assert_eq!(entry.0, "diameter.on_command:S6c:Alert-Service-Centre");
            }

            registry_mod.call_method0("clear").unwrap();
        });
    }
}
