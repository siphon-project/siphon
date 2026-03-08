//! PyO3 `log` namespace — bridges Python `log.info(msg)` to Rust `tracing`.

use pyo3::prelude::*;

/// Python-visible log namespace.
///
/// Scripts use: `from siphon import log` then `log.info("message")`.
#[pyclass(name = "LogNamespace")]
pub struct PyLogNamespace;

#[pymethods]
impl PyLogNamespace {
    fn debug(&self, message: &str) {
        tracing::debug!(target: "siphon::script", "{}", message);
    }

    fn info(&self, message: &str) {
        tracing::info!(target: "siphon::script", "{}", message);
    }

    fn warn(&self, message: &str) {
        tracing::warn!(target: "siphon::script", "{}", message);
    }

    /// Alias for `warn()` — Python convention uses `warning`.
    fn warning(&self, message: &str) {
        tracing::warn!(target: "siphon::script", "{}", message);
    }

    fn error(&self, message: &str) {
        tracing::error!(target: "siphon::script", "{}", message);
    }
}

impl Default for PyLogNamespace {
    fn default() -> Self {
        Self
    }
}

impl PyLogNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_namespace_creation() {
        // Just verifies the struct can be created without panics.
        let _log = PyLogNamespace::new();
    }
}
