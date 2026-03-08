//! Python API — the `siphon` module that scripts import from.
//!
//! This module injects the pure-Python `siphon` package into `sys.modules`
//! so that user scripts can write `from siphon import proxy, b2bua, log`.
//!
//! The registry (`_siphon_registry`) is a separate module that decorators
//! write into; the Rust engine reads it after script execution.

pub mod auth;
pub mod cache;
pub mod call;
pub mod cdr;
pub mod diameter;
pub mod gateway;
pub mod li;
pub mod log;
pub mod presence;
pub mod proxy_utils;
pub mod registrant;
pub mod registrar;
pub mod reply;
pub mod request;
pub mod rtpengine;
pub mod sip_uri;

use std::ffi::CString;
use std::sync::OnceLock;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::error::{Result, SiphonError};

/// Tuple of (auth, registrar, log, proxy_utils, cache) singletons.
type SingletonTuple = (Py<PyAny>, Py<PyAny>, Py<PyAny>, Py<PyAny>, Py<PyAny>);

/// Rust-backed singletons: (auth, registrar, log, proxy_utils, cache).
static RUST_SINGLETONS: OnceLock<SingletonTuple> = OnceLock::new();

/// Optional RTPEngine singleton — set only when `media.rtpengine` is configured.
static RTPENGINE_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional gateway singleton — set only when `gateway` is configured.
static GATEWAY_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional CDR singleton — set only when `cdr` is configured and enabled.
static CDR_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional registration singleton — set only when `registrant` is configured.
static REGISTRATION_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional LI singleton — set only when `lawful_intercept` is configured.
static LI_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional Diameter singleton — set only when `diameter` is configured.
static DIAMETER_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional presence singleton — set only when presence is needed.
static PRESENCE_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// The Registrar Arc — stored so the dispatcher can subscribe to change events.
static REGISTRAR_ARC: OnceLock<std::sync::Arc<crate::registrar::Registrar>> = OnceLock::new();

/// Get the shared Registrar (set during `set_rust_singletons`).
pub fn registrar_arc() -> Option<&'static std::sync::Arc<crate::registrar::Registrar>> {
    REGISTRAR_ARC.get()
}

/// Store Rust-backed singletons for injection into the siphon module.
///
/// Must be called once at startup, before any user script is loaded.
/// After this, every call to `install_siphon_module()` will automatically
/// replace the Python stubs with these Rust objects.
pub fn set_rust_singletons(
    python: Python<'_>,
    py_auth: auth::PyAuth,
    py_registrar: registrar::PyRegistrar,
    py_log: log::PyLogNamespace,
    py_proxy_utils: proxy_utils::PyProxyUtils,
    py_cache: cache::PyCacheNamespace,
) -> Result<()> {
    // Store the Registrar Arc for event subscription before converting to Py<PyAny>.
    let _ = REGISTRAR_ARC.set(std::sync::Arc::clone(py_registrar.registrar()));

    let auth_py: Py<PyAny> = Py::new(python, py_auth)
        .map_err(|error| SiphonError::Script(format!("Py::new(auth): {error}")))?
        .into_any();
    let reg_py: Py<PyAny> = Py::new(python, py_registrar)
        .map_err(|error| SiphonError::Script(format!("Py::new(registrar): {error}")))?
        .into_any();
    let log_py: Py<PyAny> = Py::new(python, py_log)
        .map_err(|error| SiphonError::Script(format!("Py::new(log): {error}")))?
        .into_any();
    let proxy_utils_py: Py<PyAny> = Py::new(python, py_proxy_utils)
        .map_err(|error| SiphonError::Script(format!("Py::new(proxy_utils): {error}")))?
        .into_any();
    let cache_py: Py<PyAny> = Py::new(python, py_cache)
        .map_err(|error| SiphonError::Script(format!("Py::new(cache): {error}")))?
        .into_any();

    let _ = RUST_SINGLETONS.set((auth_py, reg_py, log_py, proxy_utils_py, cache_py));
    Ok(())
}

/// Store the RTPEngine singleton for injection into the siphon module.
///
/// Called at startup only when `media.rtpengine` is configured.
pub fn set_rtpengine_singleton(
    python: Python<'_>,
    py_rtpengine: rtpengine::PyRtpEngine,
) -> Result<()> {
    let rtpengine_py: Py<PyAny> = Py::new(python, py_rtpengine)
        .map_err(|error| SiphonError::Script(format!("Py::new(rtpengine): {error}")))?
        .into_any();
    let _ = RTPENGINE_SINGLETON.set(rtpengine_py);
    Ok(())
}

/// Store the CDR singleton for injection into the siphon module.
///
/// Called at startup only when `cdr` is configured and enabled.
pub fn set_cdr_singleton(
    python: Python<'_>,
    py_cdr: cdr::PyCdrNamespace,
) -> Result<()> {
    let cdr_py: Py<PyAny> = Py::new(python, py_cdr)
        .map_err(|error| SiphonError::Script(format!("Py::new(cdr): {error}")))?
        .into_any();
    let _ = CDR_SINGLETON.set(cdr_py);
    Ok(())
}

/// Store the gateway singleton for injection into the siphon module.
///
/// Called at startup only when `gateway` is configured.
pub fn set_gateway_singleton(
    python: Python<'_>,
    py_gateway: gateway::PyGateway,
) -> Result<()> {
    let gateway_py: Py<PyAny> = Py::new(python, py_gateway)
        .map_err(|error| SiphonError::Script(format!("Py::new(gateway): {error}")))?
        .into_any();
    let _ = GATEWAY_SINGLETON.set(gateway_py);
    Ok(())
}

/// Store the registration singleton for injection into the siphon module.
///
/// Called at startup only when `registrant` is configured.
pub fn set_registration_singleton(
    python: Python<'_>,
    py_registration: registrant::PyRegistration,
) -> Result<()> {
    let registration_py: Py<PyAny> = Py::new(python, py_registration)
        .map_err(|error| SiphonError::Script(format!("Py::new(registration): {error}")))?
        .into_any();
    let _ = REGISTRATION_SINGLETON.set(registration_py);
    Ok(())
}

/// Store the LI singleton for injection into the siphon module.
///
/// Called at startup only when `lawful_intercept` is configured and enabled.
pub fn set_li_singleton(
    python: Python<'_>,
    py_li: li::PyLiNamespace,
) -> Result<()> {
    let li_py: Py<PyAny> = Py::new(python, py_li)
        .map_err(|error| SiphonError::Script(format!("Py::new(li): {error}")))?
        .into_any();
    let _ = LI_SINGLETON.set(li_py);
    Ok(())
}

/// Store the Diameter singleton for injection into the siphon module.
///
/// Called at startup only when `diameter` is configured.
pub fn set_diameter_singleton(
    python: Python<'_>,
    py_diameter: diameter::PyDiameter,
) -> Result<()> {
    let diameter_py: Py<PyAny> = Py::new(python, py_diameter)
        .map_err(|error| SiphonError::Script(format!("Py::new(diameter): {error}")))?
        .into_any();
    let _ = DIAMETER_SINGLETON.set(diameter_py);
    Ok(())
}

/// Store the presence singleton for injection into the siphon module.
///
/// Called at startup when the presence subsystem is available.
pub fn set_presence_singleton(
    python: Python<'_>,
    py_presence: presence::PyPresence,
) -> Result<()> {
    let presence_py: Py<PyAny> = Py::new(python, py_presence)
        .map_err(|error| SiphonError::Script(format!("Py::new(presence): {error}")))?
        .into_any();
    let _ = PRESENCE_SINGLETON.set(presence_py);
    Ok(())
}

/// Ensure the `_siphon_registry` module exists in `sys.modules`.
///
/// Idempotent — safe to call multiple times.
pub fn ensure_registry(python: Python<'_>) -> Result<()> {
    let sys = python
        .import("sys")
        .map_err(|error| SiphonError::Script(format!("import sys: {error}")))?;
    let modules = sys
        .getattr("modules")
        .map_err(|error| SiphonError::Script(format!("sys.modules: {error}")))?;

    let registry_name = "_siphon_registry";
    if let Ok(existing) = modules.get_item(registry_name) {
        if !existing.is_none() {
            return Ok(());
        }
    }

    let registry_source = CString::new(include_str!("registry.py")).unwrap();
    let file_name = CString::new("_siphon_registry.py").unwrap();
    let module_cname = CString::new(registry_name).unwrap();
    let module = PyModule::from_code(python, &registry_source, &file_name, &module_cname)
        .map_err(|error| {
            SiphonError::Script(format!("registry module: {error}"))
        })?;

    modules
        .set_item(registry_name, &module)
        .map_err(|error| SiphonError::Script(format!("sys.modules insert: {error}")))?;

    Ok(())
}

/// Install the `siphon` Python package into `sys.modules`.
///
/// Creates (or recreates) the module each time. If Rust singletons have been
/// registered via `set_rust_singletons()`, they replace the Python stubs
/// before any user script can import them.
pub fn install_siphon_module(python: Python<'_>) -> Result<()> {
    let source = CString::new(include_str!("siphon_package.py")).unwrap();
    let file_name = CString::new("siphon/__init__.py").unwrap();
    let module_name = CString::new("siphon").unwrap();

    let module = PyModule::from_code(python, &source, &file_name, &module_name)
        .map_err(|error| {
            SiphonError::Script(format!("failed to create siphon module: {error}"))
        })?;

    // If Rust singletons are available, inject them now — before any user
    // script does `from siphon import auth`.
    if let Some((auth_py, reg_py, log_py, proxy_utils_py, cache_py)) = RUST_SINGLETONS.get() {
        module
            .setattr("auth", auth_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr auth: {error}")))?;
        module
            .setattr("registrar", reg_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr registrar: {error}")))?;
        module
            .setattr("log", log_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr log: {error}")))?;
        module
            .setattr("cache", cache_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr cache: {error}")))?;

        // Inject proxy utilities onto the existing proxy namespace
        let proxy_ns = module
            .getattr("proxy")
            .map_err(|error| SiphonError::Script(format!("getattr proxy: {error}")))?;
        proxy_ns
            .setattr("_utils", proxy_utils_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr proxy._utils: {error}")))?;
    }

    // Inject optional RTPEngine singleton (only when media.rtpengine is configured).
    if let Some(rtpengine_py) = RTPENGINE_SINGLETON.get() {
        module
            .setattr("rtpengine", rtpengine_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr rtpengine: {error}")))?;
    }

    // Inject optional gateway singleton.
    if let Some(gateway_py) = GATEWAY_SINGLETON.get() {
        module
            .setattr("gateway", gateway_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr gateway: {error}")))?;
    }

    // Inject optional CDR singleton.
    if let Some(cdr_py) = CDR_SINGLETON.get() {
        module
            .setattr("cdr", cdr_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr cdr: {error}")))?;
    }

    // Inject optional registration singleton.
    if let Some(registration_py) = REGISTRATION_SINGLETON.get() {
        module
            .setattr("registration", registration_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr registration: {error}")))?;
    }

    // Inject optional LI singleton.
    if let Some(li_py) = LI_SINGLETON.get() {
        module
            .setattr("li", li_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr li: {error}")))?;
    }

    // Inject optional Diameter singleton.
    if let Some(diameter_py) = DIAMETER_SINGLETON.get() {
        module
            .setattr("diameter", diameter_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr diameter: {error}")))?;
    }

    // Inject optional presence singleton.
    if let Some(presence_py) = PRESENCE_SINGLETON.get() {
        module
            .setattr("presence", presence_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr presence: {error}")))?;
    }

    let sys = python
        .import("sys")
        .map_err(|error| SiphonError::Script(format!("import sys: {error}")))?;
    let modules = sys
        .getattr("modules")
        .map_err(|error| SiphonError::Script(format!("sys.modules: {error}")))?;

    modules
        .set_item("siphon", &module)
        .map_err(|error| SiphonError::Script(format!("sys.modules['siphon'] = ...: {error}")))?;

    Ok(())
}
