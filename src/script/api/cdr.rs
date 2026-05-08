//! Python `cdr` namespace — write CDRs from scripts.
//!
//! Allows Python scripts to manually write CDRs with custom fields:
//! ```python
//! from siphon import cdr
//! cdr.write(request, extra={"billing_id": "B-12345"})
//! ```

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::cdr;

/// Python-facing CDR namespace.
#[pyclass(name = "CdrNamespace")]
pub struct PyCdrNamespace;

impl Default for PyCdrNamespace {
    fn default() -> Self {
        Self
    }
}

impl PyCdrNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyCdrNamespace {
    /// Write a CDR from a Python script.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///     extra: Optional dict of extra fields to include in the CDR.
    ///
    /// Returns:
    ///     True if the CDR was queued, False if CDR system is not enabled or channel is full.
    ///
    /// **Rf auto-stamp:** when an Rf accounting session is currently
    /// tracked for this SIP dialog (proxy or B2BUA auto-emit hooks),
    /// the resulting CDR is automatically annotated with
    /// `rf_session_id` and `rf_result_code` so operators can correlate
    /// billing with the corresponding Diameter accounting record.
    /// Manual `extra={"rf_session_id": ...}` values take precedence.
    #[pyo3(signature = (request, extra=None))]
    fn write(&self, request: &super::request::PyRequest, extra: Option<&Bound<'_, PyDict>>) -> bool {
        if !cdr::is_enabled() {
            return false;
        }

        let mut record = cdr::Cdr::new(
            request.cdr_call_id(),
            request.cdr_from_uri(),
            request.cdr_to_uri(),
            request.cdr_ruri(),
            request.cdr_method(),
            request.cdr_source_ip(),
            request.cdr_transport(),
        );

        // Auto-stamp Rf correlation when a session is tracked for this
        // dialog.  Tries the caller's tag first (proxy ACR-START stored
        // it under <Call-ID>\0<From-tag>); falls back to the callee's
        // tag for callee-initiated BYE flows.  Manual `extra` overrides
        // below, so scripts can still set explicit values.
        let dialog_keys = request.cdr_rf_dialog_key_candidates();
        for key in &dialog_keys {
            if let Some((session_id, result_code)) =
                crate::diameter::rf_service::lookup_rf_for_dialog(key)
            {
                record = record.with_rf_session_id(session_id);
                if let Some(rc) = result_code {
                    record = record.with_rf_result_code(rc);
                }
                break;
            }
        }

        if let Some(extra_dict) = extra {
            for (key, value) in extra_dict.iter() {
                if let (Ok(k), Ok(v)) = (key.extract::<String>(), value.extract::<String>()) {
                    record = record.with_extra(k, v);
                }
            }
        }

        cdr::write(record)
    }

    /// Check if the CDR system is enabled.
    #[getter]
    fn enabled(&self) -> bool {
        cdr::is_enabled()
    }
}
