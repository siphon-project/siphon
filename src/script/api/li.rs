//! Python `li` namespace — lawful intercept operations from scripts.
//!
//! Allows Python scripts to check intercept targets and trigger LI/SIPREC:
//! ```python
//! from siphon import li
//!
//! if li.is_target(request):
//!     li.intercept(request)    # emit IRI + start X3/SIPREC
//!
//! li.record(request)           # start SIPREC recording (proxy mode)
//! li.record(call)              # start SIPREC recording (B2BUA mode)
//! li.stop_recording(request)   # stop SIPREC for this call
//! li.stop_recording(call)      # stop SIPREC for this call
//! ```

use pyo3::prelude::*;

use crate::li::{self, IriEvent, IriEventType, LiManager};
use crate::li::target::DeliveryType;

/// Python-facing LI namespace.
#[pyclass(name = "LiNamespace")]
pub struct PyLiNamespace {
    manager: LiManager,
}

impl PyLiNamespace {
    pub fn new(manager: LiManager) -> Self {
        Self { manager }
    }

    /// Emit an IRI-Report event for recording start.
    fn emit_recording_iri(
        &self,
        call_id: String,
        method: String,
        from_uri: Option<String>,
        to_uri: Option<String>,
        ruri: Option<String>,
        source_ip: Option<std::net::IpAddr>,
    ) {
        let event = IriEvent {
            liid: format!("SIPREC-{call_id}"),
            correlation_id: call_id,
            event_type: IriEventType::Report,
            timestamp: std::time::SystemTime::now(),
            sip_method: method,
            status_code: None,
            from_uri: from_uri.unwrap_or_default(),
            to_uri: to_uri.unwrap_or_default(),
            request_uri: ruri,
            source_ip,
            destination_ip: None,
            delivery_type: DeliveryType::IriAndCc,
            raw_message: None,
        };
        self.manager.emit_iri(event);
    }

    /// Emit an IRI-End event for recording stop.
    fn emit_stop_recording_iri(
        &self,
        call_id: String,
        method: String,
        from_uri: Option<String>,
        to_uri: Option<String>,
        ruri: Option<String>,
        source_ip: Option<std::net::IpAddr>,
    ) {
        let event = IriEvent {
            liid: format!("SIPREC-{call_id}"),
            correlation_id: call_id,
            event_type: IriEventType::End,
            timestamp: std::time::SystemTime::now(),
            sip_method: method,
            status_code: None,
            from_uri: from_uri.unwrap_or_default(),
            to_uri: to_uri.unwrap_or_default(),
            request_uri: ruri,
            source_ip,
            destination_ip: None,
            delivery_type: DeliveryType::IriAndCc,
            raw_message: None,
        };
        self.manager.emit_iri(event);
    }
}

#[pymethods]
impl PyLiNamespace {
    /// Check if a request matches an active intercept target.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if the request's From, To, or RURI matches an active target.
    fn is_target(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        let matches = self.manager.check_message(
            request.li_ruri().as_deref(),
            request.li_from_uri().as_deref(),
            request.li_to_uri().as_deref(),
            request.li_source_ip(),
        );
        !matches.is_empty()
    }

    /// Trigger interception for a matching request (emit IRI-BEGIN + start media capture).
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if interception was triggered for at least one matching target.
    fn intercept(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        let matches = self.manager.check_message(
            request.li_ruri().as_deref(),
            request.li_from_uri().as_deref(),
            request.li_to_uri().as_deref(),
            request.li_source_ip(),
        );

        if matches.is_empty() {
            return false;
        }

        for target in &matches {
            let event = IriEvent {
                liid: target.liid.clone(),
                correlation_id: request.li_call_id(),
                event_type: IriEventType::Begin,
                timestamp: std::time::SystemTime::now(),
                sip_method: request.li_method(),
                status_code: None,
                from_uri: request.li_from_uri().unwrap_or_default(),
                to_uri: request.li_to_uri().unwrap_or_default(),
                request_uri: request.li_ruri(),
                source_ip: request.li_source_ip(),
                destination_ip: None,
                delivery_type: target.delivery_type,
                raw_message: None,
            };
            self.manager.emit_iri(event);

            self.manager.audit(
                li::AuditOperation::InterceptMatch,
                Some(&target.liid),
                format!(
                    "intercept triggered: method={} call_id={}",
                    request.li_method(),
                    request.li_call_id(),
                ),
            );
        }

        true
    }

    /// Start SIPREC recording for a request or call.
    ///
    /// Accepts either a Request (proxy mode) or Call (B2BUA mode).
    /// In B2BUA mode, sets the li_record flag on the call so that the
    /// dispatcher will start SIPREC recording on answer.
    ///
    /// Args:
    ///     target: A Request or Call object.
    ///
    /// Returns:
    ///     True if recording was initiated.
    fn record(&self, target: &Bound<'_, PyAny>) -> PyResult<bool> {
        if !self.manager.is_enabled() {
            return Ok(false);
        }

        // Try PyCall first (B2BUA mode).
        if let Ok(mut call) = target.cast::<super::call::PyCall>().map(|c| c.borrow_mut()) {
            let call_id = call.li_call_id();
            let from_uri = call.li_from_uri();
            let to_uri = call.li_to_uri();
            let ruri = call.li_ruri();
            let source_ip = call.li_source_ip();
            call.set_li_record();
            self.emit_recording_iri(call_id, "INVITE".to_string(), from_uri, to_uri, ruri, source_ip);
            return Ok(true);
        }

        // Try PyRequest (proxy mode).
        if let Ok(request) = target.cast::<super::request::PyRequest>().map(|r| r.borrow()) {
            self.emit_recording_iri(
                request.li_call_id(),
                request.li_method(),
                request.li_from_uri(),
                request.li_to_uri(),
                request.li_ruri(),
                request.li_source_ip(),
            );
            return Ok(true);
        }

        Err(pyo3::exceptions::PyTypeError::new_err(
            "record() expects a Request or Call object",
        ))
    }

    /// Stop interception for a request.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if a stop event was emitted.
    fn stop_intercept(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        let matches = self.manager.check_message(
            request.li_ruri().as_deref(),
            request.li_from_uri().as_deref(),
            request.li_to_uri().as_deref(),
            request.li_source_ip(),
        );

        if matches.is_empty() {
            return false;
        }

        for target in &matches {
            let event = IriEvent {
                liid: target.liid.clone(),
                correlation_id: request.li_call_id(),
                event_type: IriEventType::End,
                timestamp: std::time::SystemTime::now(),
                sip_method: request.li_method(),
                status_code: None,
                from_uri: request.li_from_uri().unwrap_or_default(),
                to_uri: request.li_to_uri().unwrap_or_default(),
                request_uri: request.li_ruri(),
                source_ip: request.li_source_ip(),
                destination_ip: None,
                delivery_type: target.delivery_type,
                raw_message: None,
            };
            self.manager.emit_iri(event);
        }

        true
    }

    /// Stop SIPREC recording for a request or call.
    ///
    /// Accepts either a Request or Call object.
    ///
    /// Args:
    ///     target: A Request or Call object.
    ///
    /// Returns:
    ///     True if a stop event was emitted.
    fn stop_recording(&self, target: &Bound<'_, PyAny>) -> PyResult<bool> {
        if !self.manager.is_enabled() {
            return Ok(false);
        }

        // Try PyCall first.
        if let Ok(call) = target.cast::<super::call::PyCall>().map(|c| c.borrow()) {
            self.emit_stop_recording_iri(
                call.li_call_id(),
                "BYE".to_string(),
                call.li_from_uri(),
                call.li_to_uri(),
                call.li_ruri(),
                call.li_source_ip(),
            );
            return Ok(true);
        }

        // Try PyRequest.
        if let Ok(request) = target.cast::<super::request::PyRequest>().map(|r| r.borrow()) {
            self.emit_stop_recording_iri(
                request.li_call_id(),
                request.li_method(),
                request.li_from_uri(),
                request.li_to_uri(),
                request.li_ruri(),
                request.li_source_ip(),
            );
            return Ok(true);
        }

        Err(pyo3::exceptions::PyTypeError::new_err(
            "stop_recording() expects a Request or Call object",
        ))
    }

    /// Check if the LI subsystem is enabled.
    #[getter]
    fn is_enabled(&self) -> bool {
        self.manager.is_enabled()
    }
}
