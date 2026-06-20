//! PyO3 `sbi` namespace — bridges Python `sbi.create_session()` to the
//! Rust [`NpcfClient`] for 5G N5/Npcf policy authorization.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use tracing::warn;

use crate::sbi::npcf::{AppSessionContext, MediaComponent, MediaSubComponent, NpcfClient};

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
    /// Args:
    ///     af_app_id: AF-Application identifier (default ``"IMS Services"``).
    ///     sip_call_id: SIP Call-ID for correlation.
    ///     supi: Subscription Permanent Identifier.
    ///     ue_ipv4: UE IPv4 address.
    ///     ue_ipv6: UE IPv6 address.
    ///     dnn: Data Network Name.
    ///     notif_uri: PCF event callback URI.
    ///     media_components: list of media-component dicts (same shape as
    ///         :func:`diameter.rx_aar`'s ``media_components``).  Each dict
    ///         carries ``number``, ``media_type``, optional ``flow_status``,
    ///         ``codec_data``, and a ``flows`` list whose entries carry
    ///         ``number``, ``descriptions`` (IPFilterRules), and optional
    ///         ``status`` / ``usage``.
    ///
    /// Returns a dict with ``app_session_id`` and ``authorized``, or ``None``
    /// on failure.
    #[pyo3(signature = (
        af_app_id="IMS Services",
        sip_call_id=None,
        supi=None,
        ue_ipv4=None,
        ue_ipv6=None,
        dnn=None,
        notif_uri=None,
        media_components=None,
    ))]
    fn create_session<'py>(
        &self,
        python: Python<'py>,
        af_app_id: &str,
        sip_call_id: Option<&str>,
        supi: Option<&str>,
        ue_ipv4: Option<&str>,
        ue_ipv6: Option<&str>,
        dnn: Option<&str>,
        notif_uri: Option<&str>,
        media_components: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let components = match media_components {
            Some(obj) => parse_sbi_media_components(obj)?,
            None => Vec::new(),
        };

        let context = AppSessionContext {
            af_app_id: Some(af_app_id.to_string()),
            media_components: components,
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
        let result = crate::script::detach_block_on(client.create_app_session(&context));

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
        let result = crate::script::detach_block_on(client.delete_app_session(&sid));

        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "sbi.delete_session failed");
                Ok(false)
            }
        }
    }

    /// Update an N5 app session — media renegotiation (re-INVITE / UPDATE).
    ///
    /// Same kwarg shape as :func:`create_session` minus the addressing
    /// fields the PCF already holds from the original create.
    #[pyo3(signature = (
        session_id,
        media_components=None,
    ))]
    fn update_session<'py>(
        &self,
        python: Python<'py>,
        session_id: &str,
        media_components: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let components = match media_components {
            Some(obj) => parse_sbi_media_components(obj)?,
            None => Vec::new(),
        };

        let context = AppSessionContext {
            af_app_id: None,
            media_components: components,
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
        let result = crate::script::detach_block_on(client.update_app_session(&sid, &context));

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

/// Normalize a media-type alias into the upper-cased string the 5G SBI
/// schema expects (TS 29.514 §5.6.3.2).
fn media_type_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "audio" => "AUDIO",
        "video" => "VIDEO",
        "data" => "DATA",
        "application" => "APPLICATION",
        "control" => "CONTROL",
        "text" => "TEXT",
        "message" => "MESSAGE",
        "other" => "OTHER",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown media_type {other:?} (expected audio|video|data|application|control|text|message|other)"
            )));
        }
    }
    .to_string())
}

fn flow_status_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "enabled" => "ENABLED",
        "disabled" => "DISABLED",
        "removed" => "REMOVED",
        "enabled-up" | "enabled_uplink" | "enabled-uplink" => "ENABLED_UPLINK",
        "enabled-down" | "enabled_downlink" | "enabled-downlink" => "ENABLED_DOWNLINK",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow_status {other:?} (expected enabled|disabled|removed|enabled-up|enabled-down)"
            )));
        }
    }
    .to_string())
}

fn flow_usage_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "no_information" | "no-information" | "none" => "NO_INFO",
        "rtcp" => "RTCP",
        "af_signalling" | "af-signalling" | "signalling" => "AF_SIGNALLING",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow usage {other:?} (expected no_information|rtcp|af_signalling)"
            )));
        }
    }
    .to_string())
}

/// Parse a Python list of dicts into a `Vec<sbi::npcf::MediaComponent>`.
/// Mirrors the dict shape consumed by ``diameter.rx_aar`` but emits the
/// camelCase / UPPER_SNAKE strings the Npcf API requires.
fn parse_sbi_media_components(obj: &Bound<'_, PyAny>) -> PyResult<Vec<MediaComponent>> {
    let list = obj.cast::<PyList>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("media_components must be a list of dicts")
    })?;

    let mut out = Vec::with_capacity(list.len());
    for (idx, item) in list.iter().enumerate() {
        let component_dict = item.cast::<PyDict>().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(format!(
                "media_components[{idx}] must be a dict"
            ))
        })?;

        let number: u32 = component_dict
            .get_item("number")?
            .ok_or_else(|| {
                pyo3::exceptions::PyKeyError::new_err(format!(
                    "media_components[{idx}] missing 'number'"
                ))
            })?
            .extract()?;

        let media_type_str: String = component_dict
            .get_item("media_type")?
            .ok_or_else(|| {
                pyo3::exceptions::PyKeyError::new_err(format!(
                    "media_components[{idx}] missing 'media_type'"
                ))
            })?
            .extract()?;
        let media_type = media_type_to_sbi(&media_type_str)?;

        let flow_status = match component_dict.get_item("flow_status")? {
            Some(value) => {
                let s: String = value.extract()?;
                flow_status_to_sbi(&s)?
            }
            None => "ENABLED".to_string(),
        };

        let codec_data: Option<String> = match component_dict.get_item("codec_data")? {
            Some(value) => {
                // The Rx side stores codec data as raw bytes per RFC 4566 SDP
                // octets; the SBI schema requires a string.  Decode lossily
                // so call sites can pass bytes uniformly.
                if let Ok(text) = value.extract::<String>() {
                    Some(text)
                } else {
                    let raw: Vec<u8> = value.extract()?;
                    Some(String::from_utf8_lossy(&raw).into_owned())
                }
            }
            None => None,
        };

        let mut med_sub_comps: Vec<MediaSubComponent> = Vec::new();
        if let Some(flows_obj) = component_dict.get_item("flows")? {
            let flows_list = flows_obj.cast::<PyList>().map_err(|_| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "media_components[{idx}].flows must be a list"
                ))
            })?;
            for (fidx, flow_item) in flows_list.iter().enumerate() {
                let flow_dict = flow_item.cast::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "media_components[{idx}].flows[{fidx}] must be a dict"
                    ))
                })?;

                let flow_number: u32 = flow_dict
                    .get_item("number")?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyKeyError::new_err(format!(
                            "media_components[{idx}].flows[{fidx}] missing 'number'"
                        ))
                    })?
                    .extract()?;

                let descriptions = match flow_dict.get_item("descriptions")? {
                    Some(value) => {
                        let descs: Vec<String> = value.extract()?;
                        if descs.is_empty() {
                            None
                        } else {
                            Some(descs)
                        }
                    }
                    None => None,
                };

                let flow_status_inner = match flow_dict.get_item("status")? {
                    Some(value) => {
                        let s: String = value.extract()?;
                        Some(flow_status_to_sbi(&s)?)
                    }
                    None => None,
                };

                let flow_usage = match flow_dict.get_item("usage")? {
                    Some(value) => {
                        let s: String = value.extract()?;
                        Some(flow_usage_to_sbi(&s)?)
                    }
                    None => None,
                };

                med_sub_comps.push(MediaSubComponent {
                    flow_number,
                    flow_descriptions: descriptions,
                    flow_status: flow_status_inner,
                    flow_usage,
                });
            }
        }

        out.push(MediaComponent {
            media_component_number: number,
            media_type,
            flow_status,
            codec_data,
            med_sub_comps: if med_sub_comps.is_empty() {
                None
            } else {
                Some(med_sub_comps)
            },
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn make_component_dict<'py>(python: Python<'py>) -> Bound<'py, PyDict> {
        let dict = PyDict::new(python);
        dict.set_item("number", 1u32).unwrap();
        dict.set_item("media_type", "audio").unwrap();

        let flows = PyList::empty(python);
        let flow = PyDict::new(python);
        flow.set_item("number", 1u32).unwrap();
        flow.set_item("usage", "rtcp").unwrap();
        flow.set_item(
            "descriptions",
            vec![
                "permit out 17 from 10.0.0.1 50001 to 10.0.0.2 30001",
                "permit in 17 from 10.0.0.2 30001 to 10.0.0.1 50001",
            ],
        )
        .unwrap();
        flows.append(flow).unwrap();
        dict.set_item("flows", flows).unwrap();
        dict
    }

    #[test]
    fn parse_sbi_media_components_basic() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let list = PyList::empty(python);
            list.append(make_component_dict(python)).unwrap();

            let parsed = parse_sbi_media_components(list.as_any()).unwrap();
            assert_eq!(parsed.len(), 1);
            let component = &parsed[0];
            assert_eq!(component.media_component_number, 1);
            assert_eq!(component.media_type, "AUDIO");
            assert_eq!(component.flow_status, "ENABLED");
            let subs = component.med_sub_comps.as_ref().unwrap();
            assert_eq!(subs.len(), 1);
            assert_eq!(subs[0].flow_number, 1);
            assert_eq!(subs[0].flow_usage.as_deref(), Some("RTCP"));
            let descs = subs[0].flow_descriptions.as_ref().unwrap();
            assert_eq!(descs.len(), 2);
            assert!(descs[0].starts_with("permit out 17 from"));
        });
    }

    #[test]
    fn parse_sbi_rejects_missing_number() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("media_type", "audio").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let error = parse_sbi_media_components(list.as_any()).unwrap_err();
            assert!(error.to_string().contains("number"));
        });
    }

    #[test]
    fn parsed_component_serializes_to_med_sub_comps_json() {
        // End-to-end check: the parsed component MUST serialize into the
        // ``medSubComps`` envelope (TS 29.514 §5.6.2.4).  Pre-spec, the
        // Python binding hardcoded ``med_sub_comps: None`` so the
        // serialized JSON never contained ``medSubComps`` — defeating PCF
        // gating on any non-trivial UPF.
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let list = PyList::empty(python);
            list.append(make_component_dict(python)).unwrap();
            let parsed = parse_sbi_media_components(list.as_any()).unwrap();
            let json = serde_json::to_string(&parsed[0]).unwrap();
            assert!(
                json.contains("medSubComps"),
                "MediaComponent JSON must include medSubComps: {json}"
            );
            assert!(
                json.contains("flowDescriptions"),
                "med_sub_comps[*].flowDescriptions must reach the wire: {json}"
            );
            assert!(json.contains("RTCP"), "Flow-Usage RTCP must survive: {json}");
            assert!(
                json.contains("permit out 17 from 10.0.0.1 50001"),
                "5-tuple Flow-Description must survive: {json}"
            );
        });
    }

    #[test]
    fn parse_sbi_rejects_unknown_media_type() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("number", 1u32).unwrap();
            component.set_item("media_type", "hologram").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let error = parse_sbi_media_components(list.as_any()).unwrap_err();
            assert!(error.to_string().contains("hologram"));
        });
    }
}
