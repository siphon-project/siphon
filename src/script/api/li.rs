//! Python `li` namespace — lawful intercept operations from scripts.
//!
//! Allows Python scripts to check intercept targets and trigger LI/SIPREC:
//! ```python
//! from siphon import li
//!
//! if li.is_target(request):
//!     li.intercept(request)    # emit IRI + start X3/SIPREC
//!
//! li.record(request)           # start SIPREC recording
//! li.stop_recording(request)   # stop SIPREC for this call
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

    /// Start SIPREC recording for a request (without full LI).
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if recording was initiated.
    fn record(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }

        // Emit IRI-Report to signal recording start (even without X1 target).
        let event = IriEvent {
            liid: format!("SIPREC-{}", request.li_call_id()),
            correlation_id: request.li_call_id(),
            event_type: IriEventType::Report,
            timestamp: std::time::SystemTime::now(),
            sip_method: request.li_method(),
            status_code: None,
            from_uri: request.li_from_uri().unwrap_or_default(),
            to_uri: request.li_to_uri().unwrap_or_default(),
            request_uri: request.li_ruri(),
            source_ip: request.li_source_ip(),
            destination_ip: None,
            delivery_type: DeliveryType::IriAndCc,
            raw_message: None,
        };
        self.manager.emit_iri(event);
        true
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

    /// Stop SIPREC recording for a request.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if a stop event was emitted.
    fn stop_recording(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        let event = IriEvent {
            liid: format!("SIPREC-{}", request.li_call_id()),
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
            delivery_type: DeliveryType::IriAndCc,
            raw_message: None,
        };
        self.manager.emit_iri(event);
        true
    }

    /// Check if the LI subsystem is enabled.
    #[getter]
    fn is_enabled(&self) -> bool {
        self.manager.is_enabled()
    }
}
