//! Python `cache` namespace — async fetch/store/delete for named caches.
//!
//! Replaces the Python stub `_CacheNamespace` with a Rust-backed implementation
//! that delegates to `CacheManager` (local LRU + optional Redis).
//!
//! Keys starting with `siphon:` are reserved for internal use (registrar,
//! iFC store, etc.) and rejected from Python scripts.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::cache::CacheManager;

/// Reject keys with the `siphon:` prefix — reserved for internal subsystems.
fn validate_key(key: &str) -> PyResult<()> {
    if key.starts_with("siphon:") {
        Err(pyo3::exceptions::PyValueError::new_err(
            "keys starting with 'siphon:' are reserved for internal use",
        ))
    } else {
        Ok(())
    }
}

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

    /// Store a value in a named cache with optional TTL.
    ///
    /// Returns `True` if the named cache exists and the value was stored,
    /// `False` if the cache name is unknown.
    ///
    /// Args:
    ///     name: Cache name (from ``siphon.yaml`` cache list).
    ///     key: Cache key string.
    ///     value: Value to store.
    ///     ttl: Optional TTL in seconds.  When set, the key expires in Redis
    ///         after this duration (uses ``SETEX``).  Without TTL, the key
    ///         persists until the cache's configured TTL evicts it.
    #[pyo3(signature = (name, key, value, ttl=None))]
    fn store<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        value: String,
        ttl: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.store(&name, &key, &value, ttl).await)
        })
    }

    /// Delete a key from a named cache.
    ///
    /// Returns `True` if the named cache exists (key may or may not have existed),
    /// `False` if the cache name is unknown.
    fn delete<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.delete(&name, &key).await)
        })
    }

    /// Check if a named cache exists in the configuration.
    fn has_cache(&self, name: &str) -> bool {
        self.manager.has_cache(name)
    }
}
