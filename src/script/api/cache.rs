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

    /// Push an item onto the right of a Redis list (FIFO when paired
    /// with :meth:`list_pop_all`).
    ///
    /// Args:
    ///     name: Cache name (must reference a Redis-backed entry —
    ///         local-LRU-only caches don't have list semantics).
    ///     key: List key. Reserved keys (``siphon:`` prefix) are rejected.
    ///     item: String value to append.
    ///
    /// Returns the list's new length on success, ``None`` when the
    /// cache is unknown or Redis is unavailable / the command failed.
    fn list_push<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        item: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_push(&name, &key, &item).await)
        })
    }

    /// Atomically read and clear a Redis list. Returns the items in
    /// FIFO order; empty list when the key was absent, the cache is
    /// unknown, or Redis is unavailable.
    ///
    /// Implementation uses a MULTI/EXEC pipeline so concurrent
    /// producers don't lose items between the read and the delete.
    fn list_pop_all<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_pop_all(&name, &key).await)
        })
    }

    /// Set a TTL (seconds) on an existing key.
    ///
    /// Returns ``True`` when the timeout was set, ``False`` when the
    /// key did not exist, the cache is unknown, or the backend
    /// rejected the command. Useful after :meth:`list_push` to bound
    /// queue lifetime.
    fn expire<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        ttl: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.expire(&name, &key, ttl).await)
        })
    }

    /// Check whether ``key`` exists in the named cache.
    ///
    /// Considers the local LRU first (in-process), then Redis. Returns
    /// ``False`` for unknown cache names.
    fn exists<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.exists(&name, &key).await)
        })
    }
}
