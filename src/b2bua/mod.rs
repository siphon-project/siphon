//! B2BUA (Back-to-Back User Agent) — two-leg call state machine.
//!
//! The B2BUA bridges two independent SIP dialogs: the A leg (caller → SIPhon)
//! and the B leg (SIPhon → callee).  Unlike the proxy, the B2BUA terminates
//! and re-originates every SIP message, giving Python scripts full control over
//! header manipulation, topology hiding, and media anchoring.
//!
//! Forking is supported via [`fork::B2buaFork`]: the B2BUA can ring multiple
//! B legs simultaneously (parallel) or try them in sequence (sequential).

pub mod fork;
pub mod manager;
pub mod transfer;
