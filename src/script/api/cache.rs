//! Python `cache` namespace — async fetch/store for named caches.
//!
//! Replaces the Python stub `_CacheNamespace` with a Rust-backed implementation
//! that delegates to `CacheManager` (local LRU + optional Redis).

use std::sync::Arc;

use pyo3::prelude::*;

use crate::cache::CacheManager;

/// Python-facing cache namespace.
#[pyclass(name = "CacheNamespace")]
pub struct PyCacheNamespace {
    manager: Arc<CacheManager>,
}

impl PyCacheNamespace {
    pub fn new(manager: Arc<CacheManager>) -> Self {
        Self { manager }
    }
}

#[pymethods]
impl PyCacheNamespace {
    /// Fetch a value from a named cache.
    ///
    /// Returns the cached string value, or `None` if not found or cache
    /// doesn't exist. This is an async method on the Python side.
    fn fetch<'py>(&self, py: Python<'py>, name: String, key: String) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.fetch(&name, &key).await)
        })
    }

    /// Store a value in a named cache.
    ///
    /// Returns `True` if the named cache exists and the value was stored,
    /// `False` if the cache name is unknown.
    fn store<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        value: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.store(&name, &key, &value).await)
        })
    }

    /// Check if a named cache exists in the configuration.
    fn has_cache(&self, name: &str) -> bool {
        self.manager.has_cache(name)
    }
}
