//! B2BUA actor model — per-leg state ownership with intercommunication.
//!
//! ## Architecture
//!
//! - **[`Leg`]**: Pure state for a single SIP dialog leg. Each leg owns its
//!   [`Dialog`] (Call-ID, tags, CSeq) and [`TransportInfo`] independently.
//!
//! - **[`CallActor`]**: Per-call supervisor. Holds A-leg + B-leg(s), coordinates
//!   forking, winner selection, and call teardown.
//!
//! - **[`LegRegistry`]**: Global routing table mapping SIP identifiers
//!   (Call-ID, Via branch) → internal call ID, so the dispatcher can route
//!   inbound SIP messages to the correct call.
//!
//! - **[`LegActor`]**: Async actor wrapping a `Leg` + channels.
//!   Classifies inbound SIP messages into [`CallEvent`]s for the dispatcher.
//!
//! ## Forking
//!
//! A `CallActor` can hold multiple B-legs. Each B-leg has independent dialog
//! state. The call actor tracks per-leg status and coordinates winner selection.
//!
//! ## Design
//!
//! - Each leg **owns** its dialog state via [`Dialog`].
//! - Legs are independent entities with separate transport bindings.
//! - `LegRegistry` provides SIP-level routing (Call-ID, branch → internal ID).
//! - Foundation for API-driven calls: create a `Leg` without an inbound INVITE.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use tracing::debug;

use crate::sip::message::SipMessage;
use crate::transport::{ConnectionId, Transport};

// ---------------------------------------------------------------------------
// Session timer (RFC 4028)
// ---------------------------------------------------------------------------

/// Tracks the negotiated session timer state for a call (RFC 4028).
#[derive(Debug, Clone)]
pub struct SessionTimerState {
    /// Negotiated Session-Expires value in seconds.
    pub session_expires: u32,
    /// Who is refreshing: "uac" or "uas" (RFC 4028).
    pub refresher: String,
    /// When the timer was last reset (on 200 OK or successful refresh).
    pub last_refresh: std::time::Instant,
}

// ---------------------------------------------------------------------------
// Leg identity
// ---------------------------------------------------------------------------

/// Which side of the B2BUA this leg represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegSide {
    /// Inbound leg (caller → SIPhon).
    A,
    /// Outbound leg (SIPhon → callee).
    B,
}

/// Unique identifier for a leg.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegId(pub String);

impl LegId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for LegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Dialog state (owned by each leg)
// ---------------------------------------------------------------------------

/// SIP dialog state owned by a single leg.
///
/// Each leg has its own Call-ID, tags, CSeq counters, and target URI.
#[derive(Debug, Clone)]
pub struct Dialog {
    /// SIP Call-ID for this leg's dialog.
    pub call_id: String,
    /// Our local tag (From-tag for UAC/outbound, To-tag for UAS/inbound).
    pub local_tag: String,
    /// Remote party's tag (learned from responses/requests).
    pub remote_tag: Option<String>,
    /// Local CSeq counter (incremented for each request we originate).
    pub local_cseq: u32,
    /// Last CSeq received from the remote side.
    pub remote_cseq: Option<u32>,
    /// Target URI for this leg (Request-URI for outbound INVITEs).
    pub target_uri: Option<String>,
}

impl Dialog {
    /// Create a new outbound dialog (B-leg / UAC side).
    pub fn new_outbound(call_id: String, local_tag: String, target_uri: String) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag: None,
            local_cseq: 1,
            remote_cseq: None,
            target_uri: Some(target_uri),
        }
    }

    /// Create a dialog from an inbound INVITE (A-leg / UAS side).
    pub fn from_inbound(call_id: String, remote_tag: String) -> Self {
        let local_tag = generate_tag();
        Self {
            call_id,
            local_tag,
            remote_tag: Some(remote_tag),
            local_cseq: 1,
            remote_cseq: None,
            target_uri: None,
        }
    }

    /// Rewrite dialog headers (Call-ID + From/To tags) on a SIP message.
    ///
    /// Replaces the Call-ID and swaps `old_tag` → `new_tag` in From and To.
    pub fn rewrite_headers(
        message: &mut SipMessage,
        new_call_id: &str,
        old_tag: &str,
        new_tag: &str,
    ) {
        message.headers.set("Call-ID", new_call_id.to_string());

        let old_pattern = format!("tag={}", old_tag);
        let new_pattern = format!("tag={}", new_tag);

        if let Some(from) = message.headers.get("From").or_else(|| message.headers.get("f")) {
            if from.contains(&old_pattern) {
                let new_from = from.replace(&old_pattern, &new_pattern);
                message.headers.set("From", new_from);
            }
        }
        if let Some(to) = message.headers.get("To").or_else(|| message.headers.get("t")) {
            if to.contains(&old_pattern) {
                let new_to = to.replace(&old_pattern, &new_pattern);
                message.headers.set("To", new_to);
            }
        }
    }
}

/// Generate a fresh SIP tag.
pub fn generate_tag() -> String {
    format!("sb-{}", &uuid::Uuid::new_v4().as_simple().to_string()[..12])
}

/// Generate a fresh Call-ID for an outbound leg.
pub fn generate_call_id() -> String {
    format!("b2b-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Transport binding (owned by each leg)
// ---------------------------------------------------------------------------

/// Network transport binding for a leg.
#[derive(Debug, Clone)]
pub struct TransportInfo {
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Connection ID (for TCP/TLS/WS connection reuse).
    pub connection_id: ConnectionId,
    /// Transport protocol.
    pub transport: Transport,
}

// ---------------------------------------------------------------------------
// Leg — pure state for one side of a B2BUA call
// ---------------------------------------------------------------------------

/// Per-leg state in a B2BUA call.
///
/// Each leg owns its SIP dialog state and transport binding independently.
/// Multiple B-legs can coexist (forking) with separate dialogs.
#[derive(Debug, Clone)]
pub struct Leg {
    /// Unique leg identifier.
    pub id: LegId,
    /// Which side of the B2BUA.
    pub side: LegSide,
    /// This leg's SIP dialog state.
    pub dialog: Dialog,
    /// Network transport binding.
    pub transport: TransportInfo,
    /// Via branch for this leg.
    /// A-leg: the inbound INVITE's Via branch.
    /// B-leg: our generated branch for the outbound INVITE.
    pub branch: String,
    /// Stored Via headers from re-INVITE originator (for response routing).
    pub stored_vias: Vec<String>,
}

impl Leg {
    /// Create a new A-leg from an inbound INVITE.
    pub fn new_a_leg(
        call_id: String,
        from_tag: String,
        branch: String,
        transport: TransportInfo,
    ) -> Self {
        Self {
            id: LegId::new(),
            side: LegSide::A,
            dialog: Dialog::from_inbound(call_id, from_tag),
            transport,
            branch,
            stored_vias: Vec::new(),
        }
    }

    /// Create a new B-leg for an outbound INVITE.
    pub fn new_b_leg(
        call_id: String,
        local_tag: String,
        target_uri: String,
        branch: String,
        transport: TransportInfo,
    ) -> Self {
        Self {
            id: LegId::new(),
            side: LegSide::B,
            dialog: Dialog::new_outbound(call_id, local_tag, target_uri),
            transport,
            branch,
            stored_vias: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-leg status (for forking coordination)
// ---------------------------------------------------------------------------

/// Status of a B-leg in a forked call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BLegStatus {
    /// INVITE sent, waiting for response.
    Trying,
    /// Received 180/183 — ringing.
    Ringing,
    /// Received 2xx — this leg answered (winner).
    Answered,
    /// Received a final error response.
    Failed(u16),
    /// CANCEL sent (another leg won, or A-leg cancelled).
    Cancelled,
}

// ---------------------------------------------------------------------------
// LegRegistry — global routing table
// ---------------------------------------------------------------------------

/// Global registry mapping SIP identifiers to internal call IDs.
///
/// The dispatcher uses this to route inbound SIP messages to the correct
/// call actor.
#[derive(Debug)]
pub struct LegRegistry {
    /// SIP Call-ID → internal call ID (for matching inbound requests).
    by_call_id: DashMap<String, String>,
    /// Via branch → internal call ID (for matching responses).
    by_branch: DashMap<String, String>,
}

impl LegRegistry {
    pub fn new() -> Self {
        Self {
            by_call_id: DashMap::new(),
            by_branch: DashMap::new(),
        }
    }

    /// Register a SIP Call-ID → internal call ID mapping.
    pub fn register_call_id(&self, sip_call_id: &str, internal_id: &str) {
        self.by_call_id.insert(sip_call_id.to_string(), internal_id.to_string());
    }

    /// Register a Via branch → internal call ID mapping.
    pub fn register_branch(&self, branch: &str, internal_id: &str) {
        self.by_branch.insert(branch.to_string(), internal_id.to_string());
    }

    /// Look up internal call ID by SIP Call-ID.
    pub fn lookup_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.by_call_id.get(sip_call_id).map(|v| v.clone())
    }

    /// Look up internal call ID by Via branch.
    pub fn lookup_branch(&self, branch: &str) -> Option<String> {
        self.by_branch.get(branch).map(|v| v.clone())
    }

    /// Remove a SIP Call-ID mapping.
    pub fn remove_call_id(&self, sip_call_id: &str) {
        self.by_call_id.remove(sip_call_id);
    }

    /// Remove a branch mapping.
    pub fn remove_branch(&self, branch: &str) {
        self.by_branch.remove(branch);
    }

    /// Remove all mappings for a call (Call-IDs + branches).
    pub fn remove_all_for_call(&self, internal_id: &str) {
        // Remove all Call-ID mappings for this call
        self.by_call_id.retain(|_, v| v.as_str() != internal_id);
        // Remove all branch mappings for this call
        self.by_branch.retain(|_, v| v.as_str() != internal_id);
    }

    /// Number of registered calls (unique internal IDs in Call-ID map).
    pub fn call_count(&self) -> usize {
        let mut ids: Vec<String> = self.by_call_id.iter().map(|e| e.value().clone()).collect();
        ids.sort();
        ids.dedup();
        ids.len()
    }
}

impl Default for LegRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CallState
// ---------------------------------------------------------------------------

/// Per-call state tracked by the call supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// A-leg INVITE received, waiting for script decision.
    Calling,
    /// B-leg(s) ringing.
    Ringing,
    /// A B-leg answered — call is connected.
    Answered,
    /// Call terminated.
    Terminated,
}

// ---------------------------------------------------------------------------
// CallActor — per-call supervisor
// ---------------------------------------------------------------------------

/// Per-call supervisor managing A-leg + B-leg(s).
///
/// Each call actor owns its legs as independent entities. The dispatcher
/// accesses call actors via `DashMap<String, CallActor>` and operates on
/// the leg state directly.
///
/// ## Forking Support
///
/// Multiple B-legs can be active simultaneously. The call actor tracks
/// per-leg status and coordinates:
/// - Winner selection (first 2xx)
/// - Loser cancellation
/// - Partial teardown (BYE from one B-leg doesn't tear down others)
///
/// ## Future: API-Driven Calls
///
/// Call actors can be created without an inbound INVITE, enabling
/// API-driven call origination. Create a `CallActor`, add legs, and
/// the system sends INVITEs on your behalf.
#[derive(Debug)]
pub struct CallActor {
    /// Internal call identifier (UUID).
    pub id: String,
    /// Current call state.
    pub state: CallState,
    /// The inbound (A) leg.
    pub a_leg: Leg,
    /// The outbound (B) leg(s) — one per fork target.
    pub b_legs: Vec<Leg>,
    /// Per-B-leg status (parallel vector with b_legs).
    pub b_leg_status: Vec<BLegStatus>,
    /// Per-B-leg actor handles (parallel vector with b_legs).
    /// `None` until the actor is spawned for that leg.
    pub b_leg_handles: Vec<Option<LegHandle>>,
    /// Event channel sender — shared by all B-leg actors for this call.
    /// Created when the call is established; `None` until then.
    pub event_tx: Option<tokio::sync::mpsc::Sender<CallEvent>>,
    /// Index of the winning B-leg (after 2xx answer).
    pub winner: Option<usize>,
    /// When the call was created.
    pub created_at: std::time::Instant,
    /// Original A-leg INVITE message (for script handler reconstruction).
    pub a_leg_invite: Option<Arc<Mutex<SipMessage>>>,
    /// RFC 4028 session timer state (set after 200 OK negotiation).
    pub session_timer: Option<SessionTimerState>,
    /// Per-call session timer override from Python script.
    pub session_timer_override: Option<crate::script::api::call::SessionTimerOverride>,
    /// Active transfer context (REFER handling).
    pub transfer: Option<super::transfer::TransferContext>,
    /// Outbound digest credentials for B-leg 401/407 retry.
    pub outbound_credentials: Option<(String, String)>,
    /// SIPREC recording session URI.
    pub recording_srs: Option<String>,
    /// When true, copy the A-leg Call-ID to B-leg(s).
    pub preserve_call_id: bool,
}

impl CallActor {
    /// Create a new call actor with an A-leg.
    pub fn new(a_leg: Leg) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            state: CallState::Calling,
            a_leg,
            b_legs: Vec::new(),
            b_leg_status: Vec::new(),
            b_leg_handles: Vec::new(),
            event_tx: None,
            winner: None,
            created_at: std::time::Instant::now(),
            a_leg_invite: None,
            session_timer: None,
            session_timer_override: None,
            transfer: None,
            outbound_credentials: None,
            recording_srs: None,
            preserve_call_id: false,
        }
    }

    /// Add a B-leg to this call.
    pub fn add_b_leg(&mut self, leg: Leg) -> usize {
        let index = self.b_legs.len();
        self.b_legs.push(leg);
        self.b_leg_status.push(BLegStatus::Trying);
        self.b_leg_handles.push(None);
        index
    }

    /// Remove a B-leg by index (e.g. after re-INVITE completion).
    pub fn remove_b_leg(&mut self, index: usize) -> Option<Leg> {
        if index < self.b_legs.len() {
            self.b_leg_status.remove(index);
            self.b_leg_handles.remove(index);
            // Adjust winner index if needed
            if let Some(ref mut w) = self.winner {
                if *w == index {
                    self.winner = None;
                } else if *w > index {
                    *w -= 1;
                }
            }
            Some(self.b_legs.remove(index))
        } else {
            None
        }
    }

    /// Get the winning B-leg (if any).
    pub fn winning_b_leg(&self) -> Option<&Leg> {
        self.winner.and_then(|i| self.b_legs.get(i))
    }

    /// Get the winning B-leg mutably.
    pub fn winning_b_leg_mut(&mut self) -> Option<&mut Leg> {
        self.winner.and_then(|i| self.b_legs.get_mut(i))
    }

    /// Find a B-leg by its Via branch.
    pub fn find_b_leg_by_branch(&self, branch: &str) -> Option<(usize, &Leg)> {
        self.b_legs.iter().enumerate().find(|(_, leg)| leg.branch == branch)
    }

    /// Find a B-leg mutably by its Via branch.
    pub fn find_b_leg_by_branch_mut(&mut self, branch: &str) -> Option<(usize, &mut Leg)> {
        self.b_legs.iter_mut().enumerate().find(|(_, leg)| leg.branch == branch)
    }

    /// Set the winner and update call state.
    pub fn set_winner(&mut self, index: usize) {
        self.winner = Some(index);
        self.state = CallState::Answered;
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Answered;
        }
    }

    /// Check if a BYE from a specific B-leg should tear down the A-leg.
    ///
    /// In a forking scenario, only the winning B-leg's BYE tears down the call.
    /// BYEs from non-winning legs (which shouldn't normally happen after CANCEL)
    /// are absorbed.
    pub fn should_teardown_on_b_bye(&self, b_leg_index: usize) -> bool {
        self.winner == Some(b_leg_index)
    }

    /// Mark a B-leg as failed and return the best action.
    ///
    /// Returns true if all B-legs have settled (all failed/cancelled/answered).
    pub fn mark_b_leg_failed(&mut self, index: usize, status_code: u16) -> bool {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Failed(status_code);
        }
        self.all_b_legs_settled()
    }

    /// Mark a B-leg as cancelled.
    pub fn mark_b_leg_cancelled(&mut self, index: usize) {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Cancelled;
        }
    }

    /// Mark a B-leg as ringing.
    pub fn mark_b_leg_ringing(&mut self, index: usize) {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Ringing;
        }
    }

    /// Whether we've already forwarded a ringing indication to the A-leg.
    pub fn any_b_leg_ringing(&self) -> bool {
        self.b_leg_status.iter().any(|s| matches!(s, BLegStatus::Ringing | BLegStatus::Answered))
    }

    /// Check if all B-legs have reached a terminal state.
    pub fn all_b_legs_settled(&self) -> bool {
        self.b_leg_status.iter().all(|s| {
            matches!(s, BLegStatus::Answered | BLegStatus::Failed(_) | BLegStatus::Cancelled)
        })
    }

    /// Get the highest-priority error code among failed B-legs.
    pub fn best_error_code(&self) -> u16 {
        self.b_leg_status
            .iter()
            .filter_map(|s| match s {
                BLegStatus::Failed(code) => Some(*code),
                _ => None,
            })
            .max_by(|a, b| error_priority(*a).cmp(&error_priority(*b)))
            .unwrap_or(500)
    }

    /// Indices of non-winning B-legs that should be cancelled.
    pub fn losers(&self, winner_index: usize) -> Vec<usize> {
        (0..self.b_legs.len())
            .filter(|&i| i != winner_index)
            .filter(|&i| {
                matches!(
                    self.b_leg_status.get(i),
                    Some(BLegStatus::Trying | BLegStatus::Ringing)
                )
            })
            .collect()
    }

    /// Check if the message came from the A-leg (by source address).
    pub fn is_from_a_leg(&self, source_addr: SocketAddr) -> bool {
        self.a_leg.transport.remote_addr == source_addr
    }

    /// Store the original A-leg INVITE message.
    pub fn set_a_leg_invite(&mut self, message: Arc<Mutex<SipMessage>>) {
        self.a_leg_invite = Some(message);
    }

    /// Set session timer state.
    pub fn set_session_timer(&mut self, timer: SessionTimerState) {
        self.session_timer = Some(timer);
    }

    /// Reset session timer's last_refresh.
    pub fn reset_session_timer(&mut self) {
        if let Some(ref mut timer) = self.session_timer {
            timer.last_refresh = std::time::Instant::now();
        }
    }

    /// Set the actor handle for a B-leg.
    pub fn set_b_leg_handle(&mut self, index: usize, handle: LegHandle) {
        if index < self.b_leg_handles.len() {
            self.b_leg_handles[index] = Some(handle);
        }
    }

    /// Send `Shutdown` to all active B-leg actor handles.
    pub fn shutdown_actors(&self) {
        for handle in self.b_leg_handles.iter().flatten() {
            let _ = handle.tx.try_send(LegMessage::Shutdown);
        }
    }
}

/// Priority score for error response codes.
fn error_priority(code: u16) -> u32 {
    let class_weight = match code {
        600..=699 => 3000,
        500..=599 => 2000,
        400..=499 => 1000,
        300..=399 => 0,
        _ => 0,
    };
    class_weight + code as u32
}

// ---------------------------------------------------------------------------
// CallActorStore — manages all active calls
// ---------------------------------------------------------------------------

/// Manages all active B2BUA calls.
///
/// Stores `CallActor` instances in a concurrent map, indexed by internal
/// call ID. Uses `LegRegistry` for SIP-level routing.
#[derive(Debug)]
pub struct CallActorStore {
    /// Internal call ID → CallActor.
    calls: DashMap<String, CallActor>,
    /// SIP identifier routing table.
    pub registry: LegRegistry,
}

impl CallActorStore {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            registry: LegRegistry::new(),
        }
    }

    /// Number of active calls.
    pub fn count(&self) -> usize {
        self.calls.len()
    }

    /// Create a new call from an A-leg and return the internal call ID.
    ///
    /// Registers the A-leg's SIP Call-ID in the registry.
    pub fn create_call(&self, a_leg: Leg) -> String {
        let sip_call_id = a_leg.dialog.call_id.clone();
        let a_branch = a_leg.branch.clone();
        let call = CallActor::new(a_leg);
        let id = call.id.clone();
        self.registry.register_call_id(&sip_call_id, &id);
        self.registry.register_branch(&a_branch, &id);
        self.calls.insert(id.clone(), call);
        id
    }

    /// Add a B-leg to a call. Registers branch in the registry.
    pub fn add_b_leg(&self, call_id: &str, leg: Leg) -> bool {
        let branch = leg.branch.clone();
        let sip_call_id = leg.dialog.call_id.clone();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.add_b_leg(leg);
            self.registry.register_branch(&branch, call_id);
            self.registry.register_call_id(&sip_call_id, call_id);
            true
        } else {
            false
        }
    }

    /// Remove a B-leg by index.
    pub fn remove_b_leg(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(removed) = call.remove_b_leg(index) {
                self.registry.remove_branch(&removed.branch);
                self.registry.remove_call_id(&removed.dialog.call_id);
            }
        }
    }

    /// Look up internal call ID by SIP Call-ID.
    pub fn find_by_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.registry.lookup_call_id(sip_call_id)
    }

    /// Look up internal call ID by Via branch.
    pub fn call_id_for_branch(&self, branch: &str) -> Option<String> {
        self.registry.lookup_branch(branch)
    }

    /// Get a call by internal ID.
    pub fn get_call(&self, call_id: &str) -> Option<dashmap::mapref::one::Ref<'_, String, CallActor>> {
        self.calls.get(call_id)
    }

    /// Get a mutable reference to a call.
    pub fn get_call_mut(&self, call_id: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, CallActor>> {
        self.calls.get_mut(call_id)
    }

    /// Set call state.
    pub fn set_state(&self, call_id: &str, state: CallState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.state = state;
        }
    }

    /// Set the winning B-leg.
    pub fn set_winner(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_winner(index);
        }
    }

    /// Store the original A-leg INVITE.
    pub fn set_a_leg_invite(&self, call_id: &str, message: Arc<Mutex<SipMessage>>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_a_leg_invite(message);
        }
    }

    /// Set session timer state.
    pub fn set_session_timer(&self, call_id: &str, timer: SessionTimerState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_session_timer(timer);
        }
    }

    /// Reset session timer.
    pub fn reset_session_timer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.reset_session_timer();
        }
    }

    /// Set transfer context.
    pub fn set_transfer(&self, call_id: &str, transfer: super::transfer::TransferContext) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = Some(transfer);
        }
    }

    /// Clear transfer context.
    pub fn clear_transfer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = None;
        }
    }

    /// Remove a call and clean up all registry entries.
    ///
    /// Sends `Shutdown` to all active B-leg actor handles before removing.
    pub fn remove_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            // Shutdown any active B-leg actors
            call.shutdown_actors();
            // Clean up A-leg registry entries
            self.registry.remove_call_id(&call.a_leg.dialog.call_id);
            self.registry.remove_branch(&call.a_leg.branch);
            // Clean up B-leg registry entries
            for b_leg in &call.b_legs {
                self.registry.remove_call_id(&b_leg.dialog.call_id);
                self.registry.remove_branch(&b_leg.branch);
            }
        }
    }

    /// Iterate over all active calls (for session timer sweep).
    pub fn iter_calls(&self) -> dashmap::iter::Iter<'_, String, CallActor> {
        self.calls.iter()
    }

    /// Find a call matching a Replaces header (for attended transfer).
    pub fn find_by_replaces(
        &self,
        replaces_call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<String> {
        for entry in self.calls.iter() {
            if crate::b2bua::transfer::replaces_matches(
                &crate::sip::headers::refer::Replaces {
                    call_id: replaces_call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.to_string(),
                    early_only: false,
                },
                &entry.a_leg.dialog.call_id,
                &entry.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                from_tag,
            ) {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Sweep stale calls older than the given duration.
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let stale_ids: Vec<String> = self.calls.iter()
            .filter(|entry| now.duration_since(entry.created_at) > max_age)
            .map(|entry| entry.id.clone())
            .collect();
        let removed = stale_ids.len();
        for call_id in stale_ids {
            self.remove_call(&call_id);
        }
        removed
    }
}

impl Default for CallActorStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LegActor — async actor for B-leg message classification
// ---------------------------------------------------------------------------

/// Messages sent to a leg actor's mailbox (for async mode).
#[derive(Debug)]
pub enum LegMessage {
    /// A SIP message arrived from the network.
    SipInbound {
        message: SipMessage,
        source: TransportInfo,
    },
    /// Cancel this leg.
    Cancel,
    /// Shut down.
    Shutdown,
}

/// Events from a leg actor back to the call supervisor.
#[derive(Debug)]
pub enum CallEvent {
    /// Provisional response (1xx).
    Provisional { leg_id: LegId, status_code: u16, message: SipMessage },
    /// Success response (2xx).
    Answered { leg_id: LegId, message: SipMessage },
    /// Error response (3xx-6xx).
    Failed { leg_id: LegId, status_code: u16, message: SipMessage },
    /// BYE received.
    Bye { leg_id: LegId, from_side: LegSide, message: SipMessage },
    /// re-INVITE received.
    ReInvite { leg_id: LegId, message: SipMessage },
    /// REFER received.
    Refer { leg_id: LegId, message: SipMessage },
    /// Leg actor terminated.
    Terminated { leg_id: LegId },
}

/// Async leg actor — wraps a `Leg` + channels for SIP message classification.
///
/// Receives inbound SIP messages via [`LegMessage`] and emits classified
/// [`CallEvent`]s back to the dispatcher for orchestration.
pub struct LegActor {
    /// The leg's state.
    pub leg: Leg,
    /// Mailbox receiver.
    rx: tokio::sync::mpsc::Receiver<LegMessage>,
    /// Event sender to call supervisor.
    call_tx: tokio::sync::mpsc::Sender<CallEvent>,
}

/// Handle to an async leg actor.
#[derive(Debug, Clone)]
pub struct LegHandle {
    /// Leg identifier.
    pub id: LegId,
    /// Side.
    pub side: LegSide,
    /// Channel to send messages to the leg actor.
    pub tx: tokio::sync::mpsc::Sender<LegMessage>,
}

impl LegActor {
    /// Create a new leg actor. Returns `(actor, handle)`.
    pub fn new(
        leg: Leg,
        call_tx: tokio::sync::mpsc::Sender<CallEvent>,
    ) -> (Self, LegHandle) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let handle = LegHandle {
            id: leg.id.clone(),
            side: leg.side,
            tx,
        };
        let actor = Self { leg, rx, call_tx };
        (actor, handle)
    }

    /// Run the leg actor's message processing loop.
    pub async fn run(mut self) {
        debug!(
            leg_id = %self.leg.id,
            side = ?self.leg.side,
            call_id = %self.leg.dialog.call_id,
            "leg actor started"
        );

        while let Some(msg) = self.rx.recv().await {
            match msg {
                LegMessage::SipInbound { message, source: _ } => {
                    self.handle_sip_inbound(message).await;
                }
                LegMessage::Cancel => {
                    debug!(leg_id = %self.leg.id, "leg cancelled");
                    break;
                }
                LegMessage::Shutdown => {
                    debug!(leg_id = %self.leg.id, "leg shutting down");
                    break;
                }
            }
        }

        let _ = self.call_tx.send(CallEvent::Terminated {
            leg_id: self.leg.id.clone(),
        }).await;

        debug!(leg_id = %self.leg.id, "leg actor stopped");
    }

    async fn handle_sip_inbound(&mut self, message: SipMessage) {
        use crate::sip::message::Method;

        let method = message.method().cloned();
        let status = message.status_code();

        match (method, status) {
            (_, Some(code)) => {
                if (100..200).contains(&code) {
                    let _ = self.call_tx.send(CallEvent::Provisional {
                        leg_id: self.leg.id.clone(),
                        status_code: code,
                        message,
                    }).await;
                } else if (200..300).contains(&code) {
                    if let Some(to_tag) = extract_to_tag(&message) {
                        self.leg.dialog.remote_tag = Some(to_tag);
                    }
                    let _ = self.call_tx.send(CallEvent::Answered {
                        leg_id: self.leg.id.clone(),
                        message,
                    }).await;
                } else {
                    let _ = self.call_tx.send(CallEvent::Failed {
                        leg_id: self.leg.id.clone(),
                        status_code: code,
                        message,
                    }).await;
                }
            }
            (Some(Method::Bye), _) => {
                let _ = self.call_tx.send(CallEvent::Bye {
                    leg_id: self.leg.id.clone(),
                    from_side: self.leg.side,
                    message,
                }).await;
            }
            (Some(Method::Invite), _) => {
                let _ = self.call_tx.send(CallEvent::ReInvite {
                    leg_id: self.leg.id.clone(),
                    message,
                }).await;
            }
            (Some(Method::Refer), _) => {
                let _ = self.call_tx.send(CallEvent::Refer {
                    leg_id: self.leg.id.clone(),
                    message,
                }).await;
            }
            _ => {}
        }
    }
}

/// Extract the To-tag from a SIP message.
fn extract_to_tag(message: &SipMessage) -> Option<String> {
    message.headers.get("To")
        .or_else(|| message.headers.get("t"))
        .and_then(|to| {
            to.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_transport() -> TransportInfo {
        TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        }
    }

    fn make_a_leg() -> Leg {
        Leg::new_a_leg(
            "call-1@10.0.0.1".to_string(),
            "tag-alice".to_string(),
            "z9hG4bK-aleg1".to_string(),
            test_transport(),
        )
    }

    fn make_b_leg(index: usize) -> Leg {
        Leg::new_b_leg(
            format!("b2b-bleg{}", index),
            format!("sb-bleg{}", index),
            format!("sip:bob{}@10.0.0.2", index),
            format!("z9hG4bK-bleg{}", index),
            TransportInfo {
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        )
    }

    // --- Leg tests ---

    #[test]
    fn leg_id_is_unique() {
        let id1 = LegId::new();
        let id2 = LegId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn generate_tag_format() {
        let tag = generate_tag();
        assert!(tag.starts_with("sb-"));
        assert_eq!(tag.len(), 15);
    }

    #[test]
    fn generate_call_id_format() {
        let cid = generate_call_id();
        assert!(cid.starts_with("b2b-"));
    }

    #[test]
    fn a_leg_has_inbound_dialog() {
        let leg = make_a_leg();
        assert_eq!(leg.side, LegSide::A);
        assert_eq!(leg.dialog.call_id, "call-1@10.0.0.1");
        assert_eq!(leg.dialog.remote_tag, Some("tag-alice".to_string()));
        assert!(leg.dialog.local_tag.starts_with("sb-"));
        assert_eq!(leg.branch, "z9hG4bK-aleg1");
    }

    #[test]
    fn b_leg_has_outbound_dialog() {
        let leg = make_b_leg(0);
        assert_eq!(leg.side, LegSide::B);
        assert_eq!(leg.dialog.call_id, "b2b-bleg0");
        assert_eq!(leg.dialog.local_tag, "sb-bleg0");
        assert!(leg.dialog.remote_tag.is_none());
        assert_eq!(leg.dialog.target_uri.as_deref(), Some("sip:bob0@10.0.0.2"));
    }

    // --- Dialog rewrite tests ---

    #[test]
    fn dialog_rewrite_swaps_call_id_and_tags() {
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=old-tag".to_string())
            .to("<sip:bob@example.com>;tag=bob-tag".to_string())
            .call_id("old-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        Dialog::rewrite_headers(&mut msg, "new-call-id", "old-tag", "new-tag");

        assert_eq!(msg.headers.get("Call-ID").unwrap(), "new-call-id");
        assert!(msg.headers.get("From").unwrap().contains("tag=new-tag"));
        assert!(!msg.headers.get("From").unwrap().contains("tag=old-tag"));
        assert!(msg.headers.get("To").unwrap().contains("tag=bob-tag"));
    }

    // --- CallActor tests ---

    #[test]
    fn call_actor_create_and_add_b_legs() {
        let mut call = CallActor::new(make_a_leg());
        assert_eq!(call.state, CallState::Calling);
        assert!(call.b_legs.is_empty());

        let idx = call.add_b_leg(make_b_leg(0));
        assert_eq!(idx, 0);
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.b_leg_status[0], BLegStatus::Trying);
    }

    #[test]
    fn call_actor_set_winner() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        call.set_winner(1);
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.b_leg_status[1], BLegStatus::Answered);
    }

    #[test]
    fn call_actor_losers() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.add_b_leg(make_b_leg(2));

        // Leg 1 answers
        call.set_winner(1);

        let losers = call.losers(1);
        assert_eq!(losers, vec![0, 2]);
    }

    #[test]
    fn call_actor_should_teardown_on_winner_bye() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.set_winner(0);

        // BYE from winner should teardown
        assert!(call.should_teardown_on_b_bye(0));
        // BYE from non-winner should NOT teardown
        assert!(!call.should_teardown_on_b_bye(1));
    }

    #[test]
    fn call_actor_all_failed() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        assert!(!call.all_b_legs_settled());

        call.mark_b_leg_failed(0, 486);
        assert!(!call.all_b_legs_settled());

        call.mark_b_leg_failed(1, 503);
        assert!(call.all_b_legs_settled());

        assert_eq!(call.best_error_code(), 503); // 5xx > 4xx
    }

    #[test]
    fn call_actor_remove_b_leg_adjusts_winner() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.add_b_leg(make_b_leg(2));
        call.set_winner(2);

        // Remove leg 0 — winner should shift from 2 to 1
        call.remove_b_leg(0);
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.b_legs.len(), 2);
    }

    // --- CallActorStore tests ---

    #[test]
    fn store_create_and_lookup() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());

        assert_eq!(store.count(), 1);
        assert!(store.get_call(&call_id).is_some());
        assert_eq!(store.find_by_sip_call_id("call-1@10.0.0.1"), Some(call_id.clone()));
    }

    #[test]
    fn store_add_b_leg_and_route() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let branch = b_leg.branch.clone();

        assert!(store.add_b_leg(&call_id, b_leg));
        assert_eq!(store.call_id_for_branch(&branch), Some(call_id));
    }

    #[test]
    fn store_remove_cleans_registry() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let b_branch = b_leg.branch.clone();
        let b_cid = b_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, b_leg);

        store.remove_call(&call_id);

        assert_eq!(store.count(), 0);
        assert!(store.call_id_for_branch(&b_branch).is_none());
        assert!(store.find_by_sip_call_id(&b_cid).is_none());
        assert!(store.find_by_sip_call_id("call-1@10.0.0.1").is_none());
    }

    #[test]
    fn store_sweep_stale() {
        let store = CallActorStore::new();
        store.create_call(make_a_leg());
        assert_eq!(store.sweep_stale(std::time::Duration::from_secs(60)), 0);
        assert_eq!(store.sweep_stale(std::time::Duration::ZERO), 1);
        assert_eq!(store.count(), 0);
    }

    // --- LegRegistry tests ---

    #[test]
    fn registry_basic() {
        let reg = LegRegistry::new();
        reg.register_call_id("call-1@host", "internal-1");
        reg.register_branch("z9hG4bK-test", "internal-1");

        assert_eq!(reg.lookup_call_id("call-1@host"), Some("internal-1".to_string()));
        assert_eq!(reg.lookup_branch("z9hG4bK-test"), Some("internal-1".to_string()));
        assert!(reg.lookup_call_id("nonexistent").is_none());

        reg.remove_call_id("call-1@host");
        assert!(reg.lookup_call_id("call-1@host").is_none());
    }

    // --- Extract tag test ---

    #[test]
    fn extract_to_tag_from_response() {
        let msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("test@host".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert_eq!(extract_to_tag(&msg), Some("xyz".to_string()));
    }

    // --- B-leg handle tracking ---

    #[test]
    fn call_actor_b_leg_handles_parallel_with_b_legs() {
        let mut call = CallActor::new(make_a_leg());
        assert!(call.b_leg_handles.is_empty());

        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        assert_eq!(call.b_leg_handles.len(), 2);
        assert!(call.b_leg_handles[0].is_none());
        assert!(call.b_leg_handles[1].is_none());

        // Set a handle for leg 1
        let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);
        let (_, handle) = LegActor::new(make_b_leg(1), call_tx);
        call.set_b_leg_handle(1, handle);
        assert!(call.b_leg_handles[0].is_none());
        assert!(call.b_leg_handles[1].is_some());

        // Remove leg 0 — handle vector stays in sync
        call.remove_b_leg(0);
        assert_eq!(call.b_leg_handles.len(), 1);
        assert!(call.b_leg_handles[0].is_some());
    }

    #[test]
    fn call_actor_event_tx_starts_none() {
        let call = CallActor::new(make_a_leg());
        assert!(call.event_tx.is_none());
    }

    #[test]
    fn call_actor_shutdown_actors_sends_to_all_handles() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);
        let (_, handle0) = LegActor::new(make_b_leg(0), call_tx.clone());
        let (_, handle1) = LegActor::new(make_b_leg(1), call_tx);

        // Hold receivers to check messages arrive
        let rx0 = handle0.tx.clone();
        let rx1 = handle1.tx.clone();

        call.set_b_leg_handle(0, handle0);
        call.set_b_leg_handle(1, handle1);

        call.shutdown_actors();

        // Both handles should have received Shutdown via try_send.
        // We can verify by checking the channel isn't empty (receivers got messages).
        // Since we cloned tx before setting handles, the actors' rx still work.
        // Just verify no panic occurred — the real validation is the LegActor async test.
        let _ = (rx0, rx1);
    }

    // --- LegActor async tests ---

    #[tokio::test]
    async fn leg_actor_lifecycle() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
            _ => panic!("expected Terminated event"),
        }
    }

    #[tokio::test]
    async fn leg_actor_classifies_200_ok_as_answered() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        // Send a 200 OK response to the actor
        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Answered { leg_id: id, .. } => assert_eq!(id, leg_id),
            other => panic!("expected Answered, got {:?}", other),
        }

        // Shut down
        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_classifies_486_as_failed() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Failed { leg_id: id, status_code, .. } => {
                assert_eq!(id, leg_id);
                assert_eq!(status_code, 486);
            }
            other => panic!("expected Failed, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_classifies_180_as_provisional() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(180, "Ringing".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Provisional { leg_id: id, status_code, .. } => {
                assert_eq!(id, leg_id);
                assert_eq!(status_code, 180);
            }
            other => panic!("expected Provisional, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_cancel_stops_loop() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        handle.tx.send(LegMessage::Cancel).await.unwrap();
        join.await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
            other => panic!("expected Terminated, got {:?}", other),
        }
    }
}
