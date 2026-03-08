//! Proxy forking and response aggregation — RFC 3261 §16.7.
//!
//! When a Python script calls `request.fork(targets)`, the proxy creates one
//! client transaction per target.  The [`ForkAggregator`] collects responses
//! from all branches and decides what to forward upstream.
//!
//! # Parallel strategy (default)
//!
//! All branches are started simultaneously.  The aggregator follows RFC 3261
//! §16.7 step 3:
//!
//! - **First 2xx** → forward to UAC, CANCEL all other pending branches.
//! - **6xx received** → forward immediately, CANCEL all other branches.
//! - **All branches failed** → forward the "best" error response.
//!   Priority: 6xx > 5xx > 4xx; within a class, highest code wins.
//! - **Provisional (1xx)** → forward the first 100 Trying; forward every
//!   180 Ringing / 183 Session Progress from any branch.
//!
//! # Sequential strategy
//!
//! Branches are tried one at a time in the order provided (typically sorted by
//! `Contact` q-value descending).  On a non-2xx final response, the next branch
//! is attempted.  A 2xx or 6xx terminates the sequence immediately.

use crate::sip::uri::SipUri;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which forking behaviour the proxy should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkStrategy {
    /// Send to all targets simultaneously; first 2xx wins.
    #[default]
    Parallel,
    /// Try targets one at a time; move to next on failure.
    Sequential,
}

/// Per-branch state in a forked request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchState {
    /// Branch created but INVITE not yet sent.
    Pending,
    /// INVITE sent, no response yet.
    Trying,
    /// A provisional response (1xx) was received.
    Proceeding(u16),
    /// A final response was received.
    Completed(u16),
    /// Branch was cancelled (e.g. another branch won with 2xx).
    Cancelled,
}

/// A single branch of a forked request.
#[derive(Debug, Clone)]
pub struct ForkBranch {
    /// The target URI for this branch.
    pub target: SipUri,
    /// Current state of this branch.
    pub state: BranchState,
}

/// Action the proxy core should take after a branch response arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkAction {
    /// A 2xx was received — forward it upstream and CANCEL all other branches.
    Forward2xx,
    /// A 6xx was received — forward it upstream and CANCEL all other branches.
    Forward6xx,
    /// Waiting for more branches to complete (parallel mode).
    ContinueWaiting,
    /// All branches failed — forward the best error response upstream.
    ForwardBestError(u16),
    /// Sequential mode: start the branch at the given index.
    TryNext(usize),
    /// Forward a provisional response upstream (180/183 from any branch).
    ForwardProvisional(u16),
}

/// Aggregates responses from multiple forked branches.
///
/// Created when the Python script calls `request.fork(targets)`.  The proxy
/// core feeds branch responses into [`on_branch_response`](Self::on_branch_response)
/// and acts on the returned [`ForkAction`].
#[derive(Debug)]
pub struct ForkAggregator {
    /// All branches for this fork.
    pub branches: Vec<ForkBranch>,
    /// Forking strategy.
    pub strategy: ForkStrategy,
    /// Whether we already forwarded a 100 Trying upstream.
    sent_100: bool,
}

impl ForkAggregator {
    /// Create a new aggregator for the given targets and strategy.
    pub fn new(targets: Vec<SipUri>, strategy: ForkStrategy) -> Self {
        let branches = targets
            .into_iter()
            .map(|target| ForkBranch {
                target,
                state: BranchState::Pending,
            })
            .collect();

        Self {
            branches,
            strategy,
            sent_100: false,
        }
    }

    /// Number of branches.
    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }

    /// Returns `true` when every branch has reached a terminal state
    /// ([`Completed`](BranchState::Completed) or [`Cancelled`](BranchState::Cancelled)).
    pub fn is_complete(&self) -> bool {
        self.branches.iter().all(|branch| {
            matches!(
                branch.state,
                BranchState::Completed(_) | BranchState::Cancelled
            )
        })
    }

    /// Mark a branch as [`Trying`](BranchState::Trying) (INVITE sent).
    pub fn mark_trying(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].state = BranchState::Trying;
        }
    }

    /// Mark a branch as [`Cancelled`](BranchState::Cancelled).
    pub fn mark_cancelled(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].state = BranchState::Cancelled;
        }
    }

    /// Feed a response from branch `index` into the aggregator.
    ///
    /// Returns the [`ForkAction`] the proxy core should take.
    pub fn on_branch_response(&mut self, index: usize, status_code: u16) -> ForkAction {
        if index >= self.branches.len() {
            return ForkAction::ContinueWaiting;
        }

        // Provisional (1xx)
        if (100..200).contains(&status_code) {
            self.branches[index].state = BranchState::Proceeding(status_code);
            if status_code == 100 {
                if self.sent_100 {
                    return ForkAction::ContinueWaiting;
                }
                self.sent_100 = true;
            }
            // Forward 100 (first only), 180, 183 from any branch
            return ForkAction::ForwardProvisional(status_code);
        }

        // Final response
        self.branches[index].state = BranchState::Completed(status_code);

        // 2xx — immediate win
        if (200..300).contains(&status_code) {
            return ForkAction::Forward2xx;
        }

        // 6xx — immediate termination
        if status_code >= 600 {
            return ForkAction::Forward6xx;
        }

        // 3xx–5xx — depends on strategy
        match self.strategy {
            ForkStrategy::Parallel => {
                if self.is_complete() {
                    ForkAction::ForwardBestError(self.best_error())
                } else {
                    ForkAction::ContinueWaiting
                }
            }
            ForkStrategy::Sequential => {
                // Find the next pending branch
                if let Some(next) = self.next_pending_branch() {
                    ForkAction::TryNext(next)
                } else {
                    ForkAction::ForwardBestError(self.best_error())
                }
            }
        }
    }

    /// The "best" (highest-priority) error code among completed branches.
    ///
    /// Priority: 6xx > 5xx > 4xx > 3xx.  Within a class, the highest code wins.
    fn best_error(&self) -> u16 {
        self.branches
            .iter()
            .filter_map(|branch| match branch.state {
                BranchState::Completed(code) if code >= 300 => Some(code),
                _ => None,
            })
            .max_by(|a, b| error_priority(*a).cmp(&error_priority(*b)))
            .unwrap_or(500)
    }

    /// Index of the next [`Pending`](BranchState::Pending) branch, if any.
    fn next_pending_branch(&self) -> Option<usize> {
        self.branches
            .iter()
            .position(|branch| branch.state == BranchState::Pending)
    }
}

/// Priority score for error response codes.
///
/// Higher score = higher priority when selecting the "best" error to forward.
/// 6xx class beats 5xx, 5xx beats 4xx, 4xx beats 3xx.
/// Within a class, higher code wins.
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

#[cfg(test)]
mod tests;
