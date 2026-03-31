//! PyO3 `sbi` namespace — bridges Python `sbi.create_session()` to the
//! Rust [`NpcfClient`] for 5G N5/Npcf policy authorization.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::warn;

use crate::sbi::npcf::{AppSessionContext, MediaComponent, NpcfClient};

/// Python-visible SBI namespace.
#[pyclass(name = "SbiNamespace", skip_from_py_object)]
pub struct PySbi {
    client: Arc<NpcfClient>,
}

impl PySbi {
    pub fn new(client: Arc<NpcfClient>) -> Self {
        Self { client }
    }
}

#[pymethods]
impl PySbi {
    /// Create an N5 app session for QoS policy authorization.
    ///
    /// Returns a dict with ``app_session_id`` and ``authorized``, or None on failure.
    #[pyo3(signature = (af_app_id=None, sip_call_id=None, supi=None, ue_ipv4=None, ue_ipv6=None, dnn=None, notif_uri=None, media_type="AUDIO", flow_status="ENABLED"))]
    fn create_session<'py>(
        &self,
        python: Python<'py>,
        af_app_id: Option<&str>,
        sip_call_id: Option<&str>,
        supi: Option<&str>,
        ue_ipv4: Option<&str>,
        ue_ipv6: Option<&str>,
        dnn: Option<&str>,
        notif_uri: Option<&str>,
        media_type: &str,
        flow_status: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let context = AppSessionContext {
            af_app_id: af_app_id.map(String::from),
            media_components: vec![MediaComponent {
                media_component_number: 1,
                media_type: media_type.to_string(),
                flow_status: flow_status.to_string(),
                codec_data: None,
                med_sub_comps: None,
            }],
            sip_call_id: sip_call_id.map(String::from),
            supi: supi.map(String::from),
            ue_ipv4: ue_ipv4.map(String::from),
            ue_ipv6: ue_ipv6.map(String::from),
            dnn: dnn.map(String::from),
            ev_subsc: None,
            notif_uri: notif_uri.map(String::from),
            supp_feat: None,
        };

        let client = Arc::clone(&self.client);
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.create_app_session(&context))
        });

        match result {
            Ok(response) => {
                let dict = PyDict::new(python);
                dict.set_item("app_session_id", &response.app_session_id)?;
                dict.set_item("authorized", response.authorized)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sbi.create_session failed");
                Ok(None)
            }
        }
    }

    /// Delete an N5 app session.
    ///
    /// Returns True on success, False on failure.
    fn delete_session(&self, session_id: &str) -> PyResult<bool> {
        let client = Arc::clone(&self.client);
        let sid = session_id.to_string();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.delete_app_session(&sid))
        });

        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "sbi.delete_session failed");
                Ok(false)
            }
        }
    }

    /// Update an N5 app session (media renegotiation).
    ///
    /// Returns a dict with ``app_session_id`` and ``authorized``, or None on failure.
    #[pyo3(signature = (session_id, media_type="AUDIO", flow_status="ENABLED"))]
    fn update_session<'py>(
        &self,
        python: Python<'py>,
        session_id: &str,
        media_type: &str,
        flow_status: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let context = AppSessionContext {
            af_app_id: None,
            media_components: vec![MediaComponent {
                media_component_number: 1,
                media_type: media_type.to_string(),
                flow_status: flow_status.to_string(),
                codec_data: None,
                med_sub_comps: None,
            }],
            sip_call_id: None,
            supi: None,
            ue_ipv4: None,
            ue_ipv6: None,
            dnn: None,
            ev_subsc: None,
            notif_uri: None,
            supp_feat: None,
        };

        let client = Arc::clone(&self.client);
        let sid = session_id.to_string();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.update_app_session(&sid, &context))
        });

        match result {
            Ok(response) => {
                let dict = PyDict::new(python);
                dict.set_item("app_session_id", &response.app_session_id)?;
                dict.set_item("authorized", response.authorized)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sbi.update_session failed");
                Ok(None)
            }
        }
    }
}
