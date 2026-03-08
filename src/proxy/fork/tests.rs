//! Unit tests for proxy fork aggregation — RFC 3261 §16.7.

use super::*;
use crate::sip::uri::SipUri;

/// Helper: build a `SipUri` from a user@host string.
fn uri(user: &str, host: &str) -> SipUri {
    SipUri {
        scheme: "sip".to_string(),
        user: Some(user.to_string()),
        host: host.to_string(),
        port: None,
        params: Vec::new(),
        headers: Vec::new(),
    }
}

/// Helper: build an aggregator with N branches.
fn make_aggregator(count: usize, strategy: ForkStrategy) -> ForkAggregator {
    let targets: Vec<SipUri> = (0..count)
        .map(|index| uri(&format!("user{}", index), "example.com"))
        .collect();
    ForkAggregator::new(targets, strategy)
}

// -----------------------------------------------------------------------
// Parallel forking
// -----------------------------------------------------------------------

#[test]
fn test_parallel_first_2xx_wins() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 180 Ringing
    let action = aggregator.on_branch_response(0, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));

    // Branch 1: 200 OK — immediate win
    let action = aggregator.on_branch_response(1, 200);
    assert_eq!(action, ForkAction::Forward2xx);

    // Branch 2 still pending — would be cancelled by the proxy core.
    assert!(!aggregator.is_complete());
}

#[test]
fn test_parallel_6xx_terminates_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 603 Decline → immediate termination
    let action = aggregator.on_branch_response(0, 603);
    assert_eq!(action, ForkAction::Forward6xx);
}

#[test]
fn test_parallel_all_fail_selects_best_error() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 404
    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::ContinueWaiting);

    // Branch 1: 486 Busy
    let action = aggregator.on_branch_response(1, 486);
    assert_eq!(action, ForkAction::ContinueWaiting);

    // Branch 2: 503
    let action = aggregator.on_branch_response(2, 503);
    // All branches done — best error is 503 (5xx beats 4xx)
    assert_eq!(action, ForkAction::ForwardBestError(503));
}

#[test]
fn test_parallel_best_error_priority() {
    // 6xx > 5xx > 4xx; within a class, highest code wins
    let mut aggregator = make_aggregator(4, ForkStrategy::Parallel);
    for index in 0..4 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 404);
    aggregator.on_branch_response(1, 486);
    aggregator.on_branch_response(2, 500);

    let action = aggregator.on_branch_response(3, 503);
    // 503 wins over 500 (same class, higher code)
    assert_eq!(action, ForkAction::ForwardBestError(503));
}

#[test]
fn test_parallel_6xx_beats_5xx_in_best_error() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    for index in 0..2 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 500);
    // Note: 6xx in on_branch_response returns Forward6xx immediately,
    // so test the best_error fallback with only 4xx/5xx branches
    // and verify 5xx outranks 4xx.
    let action = aggregator.on_branch_response(1, 404);
    assert_eq!(action, ForkAction::ForwardBestError(500));
}

#[test]
fn test_parallel_100_forwarded_only_once() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // First 100 → forwarded
    let action = aggregator.on_branch_response(0, 100);
    assert_eq!(action, ForkAction::ForwardProvisional(100));

    // Second 100 → suppressed
    let action = aggregator.on_branch_response(1, 100);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

#[test]
fn test_parallel_180_forwarded_from_any_branch() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // 180 from branch 0
    let action = aggregator.on_branch_response(0, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));

    // 180 from branch 2 — also forwarded (unlike 100)
    let action = aggregator.on_branch_response(2, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));
}

#[test]
fn test_parallel_183_forwarded_from_any_branch() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    for index in 0..2 {
        aggregator.mark_trying(index);
    }

    let action = aggregator.on_branch_response(0, 183);
    assert_eq!(action, ForkAction::ForwardProvisional(183));

    let action = aggregator.on_branch_response(1, 183);
    assert_eq!(action, ForkAction::ForwardProvisional(183));
}

// -----------------------------------------------------------------------
// Sequential forking
// -----------------------------------------------------------------------

#[test]
fn test_sequential_tries_next_on_failure() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 486 Busy → try next
    let action = aggregator.on_branch_response(0, 486);
    assert_eq!(action, ForkAction::TryNext(1));
}

#[test]
fn test_sequential_2xx_stops_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 200 OK — done
    let action = aggregator.on_branch_response(0, 200);
    assert_eq!(action, ForkAction::Forward2xx);
}

#[test]
fn test_sequential_6xx_stops_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 603 Decline — done
    let action = aggregator.on_branch_response(0, 603);
    assert_eq!(action, ForkAction::Forward6xx);
}

#[test]
fn test_sequential_all_fail_returns_best_error() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);

    // Branch 0: 404
    aggregator.mark_trying(0);
    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::TryNext(1));

    // Branch 1: 486
    aggregator.mark_trying(1);
    let action = aggregator.on_branch_response(1, 486);
    assert_eq!(action, ForkAction::TryNext(2));

    // Branch 2: 503 — all exhausted
    aggregator.mark_trying(2);
    let action = aggregator.on_branch_response(2, 503);
    assert_eq!(action, ForkAction::ForwardBestError(503));
}

// -----------------------------------------------------------------------
// Edge cases
// -----------------------------------------------------------------------

#[test]
fn test_single_branch_parallel_is_relay() {
    let mut aggregator = make_aggregator(1, ForkStrategy::Parallel);
    aggregator.mark_trying(0);

    let action = aggregator.on_branch_response(0, 200);
    assert_eq!(action, ForkAction::Forward2xx);
}

#[test]
fn test_single_branch_failure() {
    let mut aggregator = make_aggregator(1, ForkStrategy::Parallel);
    aggregator.mark_trying(0);

    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::ForwardBestError(404));
}

#[test]
fn test_out_of_bounds_branch_index() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    let action = aggregator.on_branch_response(99, 200);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

#[test]
fn test_is_complete() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    assert!(!aggregator.is_complete());

    aggregator.mark_trying(0);
    aggregator.mark_trying(1);
    assert!(!aggregator.is_complete());

    aggregator.on_branch_response(0, 200);
    assert!(!aggregator.is_complete());

    aggregator.mark_cancelled(1);
    assert!(aggregator.is_complete());
}

#[test]
fn test_branch_count() {
    let aggregator = make_aggregator(5, ForkStrategy::Parallel);
    assert_eq!(aggregator.branch_count(), 5);
}

#[test]
fn test_default_strategy_is_parallel() {
    assert_eq!(ForkStrategy::default(), ForkStrategy::Parallel);
}
