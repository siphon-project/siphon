//! Integration tests for B2BUA functionality.
//!
//! Tests cross-module interactions: dialog store management during B2BUA call flows,
//! registrar lookups for routing B2BUA calls, and transaction key handling.

use siphon::b2bua::manager::{ALeg, BLeg, CallManager, CallState};
use siphon::dialog::{Dialog, DialogId, DialogStore, DialogState};
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::uri::SipUri;
use siphon::sip::message::Method;
use siphon::transaction::key::TransactionKey;
use siphon::transport::{ConnectionId, Transport};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// B2BUA two-leg dialog management
// ---------------------------------------------------------------------------

#[test]
fn b2bua_two_leg_dialog_correlation() {
    let store = DialogStore::new();

    // Leg A: caller → B2BUA (UAS perspective)
    let leg_a = Dialog::new_uas(
        "b2bua-call-001".to_string(),
        "b2bua-tag-a".to_string(),
        "caller-tag".to_string(),
        1,
        vec![],
        Some(SipUri::new("caller.example.com".to_string()).with_user("alice".to_string())),
        Some(SipUri::new("b2bua.example.com".to_string())),
        Some(SipUri::new("caller.example.com".to_string()).with_user("alice".to_string())),
    );
    let leg_a_id = leg_a.id.clone();
    store.insert(leg_a);

    // Leg B: B2BUA → callee (UAC perspective)
    let leg_b = Dialog::new_uac(
        "b2bua-call-001-leg-b".to_string(),
        "b2bua-tag-b".to_string(),
        "callee-tag".to_string(),
        1,
        vec![],
        Some(SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()).with_port(5060)),
        Some(SipUri::new("b2bua.example.com".to_string())),
        Some(SipUri::new("biloxi.com".to_string()).with_user("bob".to_string())),
    );
    let leg_b_id = leg_b.id.clone();
    store.insert(leg_b);

    assert_eq!(store.count(), 2);
    assert_eq!(store.confirmed_count(), 0);

    // Callee answers (200 OK on leg B) → confirm both legs
    assert!(store.confirm(&leg_b_id));
    assert!(store.confirm(&leg_a_id));
    assert_eq!(store.confirmed_count(), 2);

    // BYE on leg A → terminate both legs
    store.terminate(&leg_a_id);
    store.terminate(&leg_b_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA routing: registrar lookup drives leg-B destination
// ---------------------------------------------------------------------------

#[test]
fn b2bua_routes_to_registered_contact() {
    let registrar = Registrar::default();

    // Bob registers from his device
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string())
                .with_user("bob".to_string())
                .with_port(5060),
            3600,
            1.0,
            "bob-reg-001".into(),
            1,
        )
        .unwrap();

    // B2BUA receives INVITE for bob@example.com — look up where to send leg B
    let contacts = registrar.lookup("sip:bob@example.com");
    assert_eq!(contacts.len(), 1);

    // Use the contact URI as the leg-B target
    let target = &contacts[0].uri;
    assert_eq!(target.user.as_deref(), Some("bob"));
    assert_eq!(target.host, "10.0.0.50");
    assert_eq!(target.port, Some(5060));

    // Create the leg-B dialog toward the registered contact
    let store = DialogStore::new();
    let leg_b = Dialog::new_uac(
        "b2bua-route-001".to_string(),
        "b2bua-tag".to_string(),
        String::new(), // remote tag not yet known (will come in response)
        1,
        vec![],
        Some(target.clone()),
        None,
        None,
    );
    store.insert(leg_b);
    assert_eq!(store.count(), 1);
}

// ---------------------------------------------------------------------------
// B2BUA generates separate transaction keys per leg
// ---------------------------------------------------------------------------

#[test]
fn b2bua_legs_have_independent_transaction_keys() {
    // Leg A: incoming INVITE
    let leg_a_branch = TransactionKey::generate_branch();
    let leg_a_key = TransactionKey::new(leg_a_branch.clone(), Method::Invite, "10.0.0.1:5060".to_string());

    // Leg B: outgoing INVITE (B2BUA generates a new branch)
    let leg_b_branch = TransactionKey::generate_branch();
    let leg_b_key = TransactionKey::new(leg_b_branch.clone(), Method::Invite, "10.0.0.2:5060".to_string());

    // The two legs must have different transaction keys
    assert_ne!(leg_a_key, leg_b_key);
    assert_ne!(leg_a_branch, leg_b_branch);

    // Both branches are valid RFC 3261 branches
    assert!(TransactionKey::is_rfc3261_branch(&leg_a_branch));
    assert!(TransactionKey::is_rfc3261_branch(&leg_b_branch));
}

// ---------------------------------------------------------------------------
// B2BUA deregistration during active call
// ---------------------------------------------------------------------------

#[test]
fn deregister_during_active_b2bua_call() {
    let registrar = Registrar::default();
    let dialog_store = DialogStore::new();

    // Register bob
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()),
            3600,
            1.0,
            "bob-reg".into(),
            1,
        )
        .unwrap();

    // Establish a B2BUA call to bob
    let dialog = Dialog::new_uac(
        "active-call-001".to_string(),
        "b2bua".to_string(),
        "bob-resp".to_string(),
        1,
        vec![],
        Some(SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string())),
        None,
        None,
    );
    let dialog_id = dialog.id.clone();
    dialog_store.insert(dialog);
    dialog_store.confirm(&dialog_id);

    // Bob deregisters (Expires=0) while call is active
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()),
            0,
            1.0,
            "bob-reg".into(),
            2,
        )
        .unwrap();

    // Bob is no longer registered
    assert!(!registrar.is_registered("sip:bob@example.com"));

    // But the active dialog is still intact (registration and dialogs are independent)
    assert_eq!(dialog_store.count(), 1);
    assert_eq!(dialog_store.confirmed_count(), 1);
    let active = dialog_store.get(&dialog_id).unwrap();
    assert_eq!(active.state, DialogState::Confirmed);
}

// ---------------------------------------------------------------------------
// Dialog ID reversal for B2BUA perspective switching
// ---------------------------------------------------------------------------

#[test]
fn dialog_id_reversal_for_perspective_switch() {
    let caller_perspective = DialogId::new(
        "call-perspective-001".to_string(),
        "caller-tag".to_string(),
        "b2bua-tag".to_string(),
    );

    let b2bua_perspective = caller_perspective.reversed();
    assert_eq!(b2bua_perspective.local_tag, "b2bua-tag");
    assert_eq!(b2bua_perspective.remote_tag, "caller-tag");
    assert_eq!(b2bua_perspective.call_id, "call-perspective-001");

    // Double reversal returns to original
    let back = b2bua_perspective.reversed();
    assert_eq!(back, caller_perspective);
}

// ---------------------------------------------------------------------------
// B2BUA full call flow: INVITE → 180 → 200 → BYE
// ---------------------------------------------------------------------------

fn make_a_leg(call_id: &str) -> ALeg {
    ALeg {
        source_addr: "10.0.0.1:5060".parse().unwrap(),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        branch: "z9hG4bK-aleg".to_string(),
        call_id: call_id.to_string(),
        from_tag: "alice-tag".to_string(),
    }
}

fn make_b_leg(target: &str) -> BLeg {
    let addr: SocketAddr = target.parse().unwrap_or("10.0.0.2:5060".parse().unwrap());
    BLeg {
        destination: addr,
        transport: Transport::Udp,
        branch: TransactionKey::generate_branch(),
        target_uri: format!("sip:bob@{}", target),
        call_id: siphon::b2bua::manager::generate_b_leg_call_id(),
        from_tag: siphon::b2bua::manager::generate_b_leg_from_tag(),
        stored_vias: vec![],
    }
}

#[test]
fn b2bua_full_call_lifecycle() {
    let manager = CallManager::new();

    // 1. INVITE arrives → create call
    let a_leg = make_a_leg("call-lifecycle@test");
    let call_id = manager.create_call(a_leg);
    assert_eq!(manager.count(), 1);
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // 2. Script dials → add B-leg
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    manager.add_b_leg(&call_id, b_leg);
    assert_eq!(manager.call_id_for_branch(&b_branch), Some(call_id.clone()));

    // 3. B-leg sends 180 Ringing → state changes to Ringing
    manager.set_state(&call_id, CallState::Ringing);
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Ringing);
    }

    // 4. B-leg sends 200 OK → call answered, winner set
    manager.set_winner(&call_id, 0);
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    // 5. BYE received → terminate and cleanup
    manager.set_state(&call_id, CallState::Terminated);
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
    assert!(manager.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA error propagation: B-leg failure → call cleanup
// ---------------------------------------------------------------------------

#[test]
fn b2bua_error_propagation() {
    let manager = CallManager::new();

    let call_id = manager.create_call(make_a_leg("call-error@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    manager.add_b_leg(&call_id, b_leg);

    // B-leg returns 486 Busy Here → remove call
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
    assert!(manager.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA BYE bridging: A→B and B→A
// ---------------------------------------------------------------------------

#[test]
fn b2bua_bye_from_a_leg_bridges_to_b_leg() {
    let manager = CallManager::new();

    let a_leg = make_a_leg("call-bye-a@test");
    let call_id = manager.create_call(a_leg);
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_destination = b_leg.destination;
    manager.add_b_leg(&call_id, b_leg);
    manager.set_winner(&call_id, 0);

    // BYE from A-leg (source matches a_leg.source_addr)
    let call = manager.get_call(&call_id).unwrap();
    let from_a = call.a_leg.source_addr == "10.0.0.1:5060".parse::<SocketAddr>().unwrap();
    assert!(from_a);

    // Verify we can find the B-leg winner to forward BYE to
    assert_eq!(call.winner, Some(0));
    assert_eq!(call.b_legs[0].destination, b_destination);
    drop(call);

    manager.set_state(&call_id, CallState::Terminated);
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

#[test]
fn b2bua_bye_from_b_leg_bridges_to_a_leg() {
    let manager = CallManager::new();

    let a_leg = make_a_leg("call-bye-b@test");
    let a_source = a_leg.source_addr;
    let call_id = manager.create_call(a_leg);
    manager.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    manager.set_winner(&call_id, 0);

    // BYE from B-leg (source is NOT a_leg.source_addr)
    let b_leg_source: SocketAddr = "10.0.0.2:5060".parse().unwrap();
    let call = manager.get_call(&call_id).unwrap();
    let from_a = b_leg_source == call.a_leg.source_addr;
    assert!(!from_a); // This is from B-leg

    // Forward to A-leg
    assert_eq!(call.a_leg.source_addr, a_source);
    drop(call);

    manager.set_state(&call_id, CallState::Terminated);
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL: A-leg CANCEL → cancel B-legs
// ---------------------------------------------------------------------------

#[test]
fn b2bua_cancel_removes_call() {
    let manager = CallManager::new();

    let call_id = manager.create_call(make_a_leg("call-cancel@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    manager.add_b_leg(&call_id, b_leg);

    // Call is in Calling state — CANCEL should terminate it
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // CANCEL → set terminated, remove
    manager.set_state(&call_id, CallState::Terminated);
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

#[test]
fn b2bua_cancel_ignored_after_answer() {
    let manager = CallManager::new();

    let call_id = manager.create_call(make_a_leg("call-cancel-late@test"));
    manager.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    manager.set_winner(&call_id, 0);

    // Call is Answered — CANCEL should not change state
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
    }

    // In B2BUA, CANCEL after answer: we return 200 OK to CANCEL but don't terminate
    // (the actual call termination comes via BYE)
}

// ---------------------------------------------------------------------------
// B2BUA multi-leg forking
// ---------------------------------------------------------------------------

#[test]
fn b2bua_multi_leg_forking() {
    let manager = CallManager::new();
    let call_id = manager.create_call(make_a_leg("call-fork@test"));

    // Fork to 3 B-legs
    for i in 0..3 {
        let b_leg = BLeg {
            destination: format!("10.0.0.{}:5060", i + 2).parse().unwrap(),
            transport: Transport::Udp,
            branch: TransactionKey::generate_branch(),
            target_uri: format!("sip:bob@10.0.0.{}", i + 2),
            call_id: siphon::b2bua::manager::generate_b_leg_call_id(),
            from_tag: siphon::b2bua::manager::generate_b_leg_from_tag(),
            stored_vias: vec![],
        };
        manager.add_b_leg(&call_id, b_leg);
    }

    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 3);
    }

    // Second B-leg answers first
    manager.set_winner(&call_id, 1);
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.state, CallState::Answered);
    }

    // Cleanup
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

// ---------------------------------------------------------------------------
// Transaction key for CANCEL has same branch, different method
// ---------------------------------------------------------------------------

#[test]
fn cancel_transaction_key_differs_from_invite() {
    let branch = TransactionKey::generate_branch();
    let invite_key = TransactionKey::new(branch.clone(), Method::Invite, "10.0.0.1:5060".to_string());
    let cancel_key = TransactionKey::new(branch.clone(), Method::Cancel, "10.0.0.1:5060".to_string());

    // CANCEL creates its own transaction (same branch but different method)
    assert_ne!(invite_key, cancel_key);
    assert_eq!(invite_key.branch, cancel_key.branch);
}

// ---------------------------------------------------------------------------
// Transaction layer: client transaction lifecycle
// ---------------------------------------------------------------------------

#[test]
fn client_transaction_lifecycle_options() {
    use siphon::transaction::TransactionManager;
    use siphon::transaction::state::{Transport as TxnTransport, Action, TimerName};
    use siphon::transaction::{ClientEvent};
    use siphon::transaction::state::NictEvent;

    let manager = TransactionManager::default();

    let request = SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts-txn".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("txn-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Create client transaction
    let (key, actions) = manager.new_client_transaction(request, TxnTransport::Udp).unwrap();
    assert_eq!(manager.count(), 1);
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::F, _))));
    assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::E, _))));

    // Receive 200 OK
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts-txn".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("txn-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager.process_client_event(
        &key,
        ClientEvent::Nict(NictEvent::FinalResponse(response)),
    ).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    // UDP: enters Completed with Timer K, then terminates
}

#[test]
fn server_transaction_lifecycle_options() {
    use siphon::transaction::TransactionManager;
    use siphon::transaction::state::{Transport as TxnTransport, Action};
    use siphon::transaction::ServerEvent;
    use siphon::transaction::state::NistEvent;

    let manager = TransactionManager::default();

    let request = SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv-opts".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("srv-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Create server transaction
    let (key, actions) = manager.new_server_transaction(&request, TxnTransport::Udp).unwrap();
    assert_eq!(manager.count(), 1);
    assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));

    // TU sends 200 OK
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv-opts".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("srv-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager.process_server_event(
        &key,
        ServerEvent::Nist(NistEvent::TuFinal(response)),
    ).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    // UDP NIST: enters Completed with Timer J (not immediately terminated)
}

// ---------------------------------------------------------------------------
// B2BUA A-leg INVITE storage for handler reconstruction
// ---------------------------------------------------------------------------

#[test]
fn b2bua_a_leg_invite_stored_and_available_through_lifecycle() {
    let manager = CallManager::new();

    // Create call
    let a_leg = make_a_leg("call-invite-store@test");
    let call_id = manager.create_call(a_leg);

    // Build and store an INVITE with SDP body
    let invite = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("example.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-store-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=store-tag".to_string())
        .to("<sip:bob@example.com>".to_string())
        .call_id("call-invite-store@test".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    let invite_arc = Arc::new(Mutex::new(invite));
    manager.set_a_leg_invite(&call_id, Arc::clone(&invite_arc));

    // Add B-leg, answer the call
    manager.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    manager.set_winner(&call_id, 0);

    // A-leg INVITE should still be available after answer (for on_answer handler)
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let stored_invite = call.a_leg_invite.as_ref().expect("a_leg_invite should be stored");
        let msg = stored_invite.lock().unwrap();
        assert_eq!(msg.headers.get("From").map(|s| s.contains("store-tag")), Some(true));
    }

    // A-leg INVITE should still be available at BYE time (for on_bye handler)
    manager.set_state(&call_id, CallState::Terminated);
    {
        let call = manager.get_call(&call_id).unwrap();
        assert!(call.a_leg_invite.is_some());
    }

    // After removal, everything is cleaned up
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA media session store tracks call lifecycle
// ---------------------------------------------------------------------------

#[test]
fn media_session_store_lifecycle() {
    use siphon::rtpengine::session::{MediaSession, MediaSessionStore};
    let store = MediaSessionStore::new();

    // Offer: create session (from_tag known, to_tag not yet)
    let session = MediaSession {
        call_id: "media-lifecycle@test".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: None,
        profile: "srtp_to_rtp".to_string(),
        created_at: std::time::Instant::now(),
    };
    store.insert(session);
    assert_eq!(store.len(), 1);

    // Answer: set to_tag
    store.set_to_tag("media-lifecycle@test", "bob-tag".to_string());
    {
        let session = store.get("media-lifecycle@test").unwrap();
        assert_eq!(session.to_tag.as_deref(), Some("bob-tag"));
    }

    // BYE: remove session
    let removed = store.remove("media-lifecycle@test");
    assert!(removed.is_some());
    assert_eq!(store.len(), 0);
}

// ---------------------------------------------------------------------------
// RFC 4028 Session timer tests
// ---------------------------------------------------------------------------

#[test]
fn session_timer_config_parsing() {
    use siphon::config::{Config, SessionRefresher};

    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  session_expires: 1800
  min_se: 90
  refresher: uac
  enabled: true
"#;
    let config = Config::from_str(yaml).unwrap();
    let timer = config.session_timer.unwrap();
    assert_eq!(timer.session_expires, 1800);
    assert_eq!(timer.min_se, 90);
    assert_eq!(timer.refresher, SessionRefresher::Uac);
    assert!(timer.enabled);
}

#[test]
fn session_timer_state_lifecycle() {
    use siphon::b2bua::manager::SessionTimerState;

    let manager = CallManager::new();
    let a_leg = ALeg {
        source_addr: "10.0.0.1:5060".parse().unwrap(),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        branch: "z9hG4bK-timer-test".to_string(),
        call_id: "timer-lifecycle@test".to_string(),
        from_tag: "alice-tag".to_string(),
    };
    let call_id = manager.create_call(a_leg);

    // No timer initially
    {
        let call = manager.get_call(&call_id).unwrap();
        assert!(call.session_timer.is_none());
    }

    // Add B-leg and set to Answered
    let b_leg = BLeg {
        destination: "10.0.0.2:5060".parse().unwrap(),
        transport: Transport::Udp,
        branch: "z9hG4bK-bleg-timer".to_string(),
        target_uri: "sip:bob@10.0.0.2".to_string(),
        call_id: "b2b-timer-test".to_string(),
        from_tag: "sb-timer-test".to_string(),
        stored_vias: vec![],
    };
    manager.add_b_leg(&call_id, b_leg);
    manager.set_winner(&call_id, 0);

    // Activate session timer (simulating 200 OK processing)
    let timer = SessionTimerState {
        session_expires: 1800,
        refresher: "b2bua".to_string(),
        last_refresh: std::time::Instant::now(),
    };
    manager.set_session_timer(&call_id, timer);

    // Verify timer is active
    {
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let timer = call.session_timer.as_ref().unwrap();
        assert_eq!(timer.session_expires, 1800);
        assert_eq!(timer.refresher, "b2bua");
    }

    // Reset timer (simulating successful refresh)
    let before = {
        let call = manager.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    std::thread::sleep(std::time::Duration::from_millis(10));
    manager.reset_session_timer(&call_id);
    let after = {
        let call = manager.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    assert!(after > before);

    // Remove call cleans up timer
    manager.remove_call(&call_id);
    assert!(manager.get_call(&call_id).is_none());
}

#[test]
fn session_timer_headers_in_b_leg_invite() {
    // Verify that Session-Expires, Min-SE, and Supported:timer headers
    // are injected into the B-leg INVITE SIP message.
    let invite = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=st-test".to_string())
        .to("<sip:bob@biloxi.com>".to_string())
        .call_id("session-timer-test@10.0.0.1".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Simulate what b2bua_send_b_leg_invite does: clone the invite and add headers
    let mut b_leg_invite = invite.clone();
    let session_expires = 1800u32;
    let min_se = 90u32;

    b_leg_invite.headers.add("Supported", "timer".to_string());
    b_leg_invite.headers.add(
        "Session-Expires",
        format!("{};refresher=uac", session_expires),
    );
    b_leg_invite.headers.add("Min-SE", min_se.to_string());

    // Verify headers are present and correct
    assert_eq!(
        b_leg_invite.headers.get("Supported"),
        Some(&"timer".to_string())
    );
    assert_eq!(
        b_leg_invite.headers.get("Session-Expires"),
        Some(&"1800;refresher=uac".to_string())
    );
    assert_eq!(
        b_leg_invite.headers.get("Min-SE"),
        Some(&"90".to_string())
    );

    // Verify the serialized message includes the headers
    let serialized = b_leg_invite.to_bytes();
    let serialized_str = String::from_utf8_lossy(&serialized);
    assert!(serialized_str.contains("Session-Expires: 1800;refresher=uac"));
    assert!(serialized_str.contains("Min-SE: 90"));
    assert!(serialized_str.contains("Supported: timer"));
}

#[test]
fn reinvite_detection_by_to_tag() {
    // Test that re-INVITE detection works by checking To-tag presence
    // and matching Call-ID against the call manager.
    let manager = CallManager::new();
    let a_leg = ALeg {
        source_addr: "10.0.0.1:5060".parse().unwrap(),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        branch: "z9hG4bK-reinvite-test".to_string(),
        call_id: "reinvite-detect@test".to_string(),
        from_tag: "alice-tag".to_string(),
    };
    let _call_id = manager.create_call(a_leg);

    // Simulate checking if an INVITE with a To-tag and matching Call-ID is a re-INVITE
    let sip_call_id = "reinvite-detect@test";
    let to_tag = Some("bob-tag".to_string());

    let is_reinvite = to_tag.is_some()
        && manager.find_by_sip_call_id(sip_call_id).is_some();

    assert!(is_reinvite, "INVITE with To-tag and matching Call-ID should be detected as re-INVITE");

    // Initial INVITE (no To-tag) should NOT be detected as re-INVITE
    let to_tag_none: Option<String> = None;
    let is_initial = to_tag_none.is_some()
        && manager.find_by_sip_call_id(sip_call_id).is_some();
    assert!(!is_initial, "INVITE without To-tag should not be a re-INVITE");

    // Unknown Call-ID should NOT be detected as re-INVITE
    let is_unknown = to_tag.is_some()
        && manager.find_by_sip_call_id("unknown@test").is_some();
    assert!(!is_unknown, "INVITE with unknown Call-ID should not be a re-INVITE");
}

#[test]
fn session_timer_per_call_override_on_call_manager() {
    use siphon::script::api::call::SessionTimerOverride;

    // Test that per-call session timer overrides are stored on the CallManager
    let manager = CallManager::new();
    let a_leg = ALeg {
        source_addr: "10.0.0.1:5060".parse().unwrap(),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        branch: "z9hG4bK-override-mgr".to_string(),
        call_id: "override-mgr@test".to_string(),
        from_tag: "tag-override".to_string(),
    };
    let call_id = manager.create_call(a_leg);

    // Store override on the call
    if let Some(mut call_ref) = manager.get_call_mut(&call_id) {
        call_ref.session_timer_override = Some(SessionTimerOverride {
            session_expires: 3600,
            min_se: 120,
            refresher: "uas".to_string(),
        });
    }

    // Verify override persists
    let call_ref = manager.get_call(&call_id).unwrap();
    let stored = call_ref.session_timer_override.as_ref().unwrap();
    assert_eq!(stored.session_expires, 3600);
    assert_eq!(stored.min_se, 120);
    assert_eq!(stored.refresher, "uas");
}
