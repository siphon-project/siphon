//! B2BUA (Back-to-Back User Agent) — actor-based call leg model.
//!
//! Each call leg runs as an independent actor (tokio task) that owns its SIP
//! dialog state and communicates with peer legs via message channels.
//!
//! ## Modules
//!
//! - [`actor`]: Core actor types — `LegActor`, `CallActor`, `LegHandle`,
//!   `LegRegistry`, dialog state, and intercommunication messages.
//! - [`fork`]: Forking state machine (parallel/sequential B-leg strategies).
//! - [`transfer`]: REFER/Replaces call transfer handling.
//! - [`header_policy`]: Versioned per-call header policy (which headers
//!   cross the trust boundary, which are stripped, rewritten, or translated).

pub mod actor;
pub mod fork;
pub mod header_policy;
pub mod transfer;
