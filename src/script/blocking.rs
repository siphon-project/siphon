//! Running blocking Rust-API futures from synchronous script handlers without
//! stalling the free-threaded interpreter.

use std::future::Future;

/// Drive `future` to completion, blocking the current handler thread, with the
/// Python interpreter **released** for the duration.
///
/// # Why this is mandatory (free-threaded CPython 3.14t)
///
/// Script handlers run *attached* to the interpreter. The cyclic GC performs a
/// stop-the-world that pauses every attached thread at a safe point. A handler
/// that parks in a blocking Rust-API call (Diameter to the HSS/PCRF, an HTTP
/// HA1 fetch, …) **while still attached** can never reach that safe point, so
/// the next thread to allocate cyclic garbage — which Python does constantly —
/// blocks behind the GC, stalling every other handler. Depending on which
/// thread can release the block, the stall is either transient (intermittent
/// failures, e.g. a second REGISTER that "doesn't come in") or, when the only
/// thread that could complete the blocked call is itself caught in the
/// stop-the-world, a permanent engine-wide deadlock.
///
/// Releasing the interpreter with [`pyo3::Python::detach`] for the blocking
/// window puts this thread at a GC safe point; [`tokio::task::block_in_place`]
/// keeps the tokio worker pool from starving while we block.
///
/// # Requirements
///
/// Call only from a thread that holds a Python thread state — every siphon
/// worker does (persistent attach on the executor / tokio threads), and
/// `Python::attach` re-attaches cheaply when one is already held. `future` and
/// its output must not hold Python references (`Ungil`); blocking Rust-API
/// futures never do.
pub(crate) fn detach_block_on<F>(future: F) -> F::Output
where
    F: Future + pyo3::marker::Ungil + Send,
    F::Output: pyo3::marker::Ungil + Send,
{
    pyo3::Python::attach(|python| {
        python.detach(move || {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
        })
    })
}
