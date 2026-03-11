//! Integration tests for B2BUA functionality.
//!
//! Tests cross-module interactions: dialog store management during B2BUA call flows,
//! registrar lookups for routing B2BUA calls, and transaction key handling.

use siphon::b2bua::actor::{
    CallActorStore, CallEvent, CallState, Leg, LegActor, LegMessage, TransportInfo,
    SessionTimerState, generate_call_id, generate_tag,
};
use siphon::dialog::{Dialog, DialogId, DialogStore, DialogState};
use siphon::registrar::Registrar;
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

fn make_a_leg(call_id: &str) -> Leg {
    Leg::new_a_leg(
        call_id.to_string(),
        "alice-tag".to_string(),
        "z9hG4bK-aleg".to_string(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        },
    )
}

fn make_b_leg(target: &str) -> Leg {
    let addr: SocketAddr = target.parse().unwrap_or("10.0.0.2:5060".parse().unwrap());
    Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        format!("sip:bob@{}", target),
        TransactionKey::generate_branch(),
        TransportInfo {
            remote_addr: addr,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        },
    )
}

#[test]
fn b2bua_full_call_lifecycle() {
    let store = CallActorStore::new();

    // 1. INVITE arrives → create call
    let a_leg = make_a_leg("call-lifecycle@test");
    let call_id = store.create_call(a_leg);
    assert_eq!(store.count(), 1);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // 2. Script dials → add B-leg
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);
    assert_eq!(store.call_id_for_branch(&b_branch), Some(call_id.clone()));

    // 3. B-leg sends 180 Ringing → state changes to Ringing
    store.set_state(&call_id, CallState::Ringing);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Ringing);
    }

    // 4. B-leg sends 200 OK → call answered, winner set
    store.set_winner(&call_id, 0);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    // 5. BYE received → terminate and cleanup
    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA error propagation: B-leg failure → call cleanup
// ---------------------------------------------------------------------------

#[test]
fn b2bua_error_propagation() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-error@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);

    // B-leg returns 486 Busy Here → remove call
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA BYE bridging: A→B and B→A
// ---------------------------------------------------------------------------

#[test]
fn b2bua_bye_from_a_leg_bridges_to_b_leg() {
    let store = CallActorStore::new();

    let a_leg = make_a_leg("call-bye-a@test");
    let call_id = store.create_call(a_leg);
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_destination = b_leg.transport.remote_addr;
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // BYE from A-leg (source matches a_leg transport addr)
    let call = store.get_call(&call_id).unwrap();
    let from_a = call.a_leg.transport.remote_addr == "10.0.0.1:5060".parse::<SocketAddr>().unwrap();
    assert!(from_a);

    // Verify we can find the B-leg winner to forward BYE to
    assert_eq!(call.winner, Some(0));
    assert_eq!(call.b_legs[0].transport.remote_addr, b_destination);
    drop(call);

    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

#[test]
fn b2bua_bye_from_b_leg_bridges_to_a_leg() {
    let store = CallActorStore::new();

    let a_leg = make_a_leg("call-bye-b@test");
    let a_source = a_leg.transport.remote_addr;
    let call_id = store.create_call(a_leg);
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // BYE from B-leg (source is NOT a_leg transport addr)
    let b_leg_source: SocketAddr = "10.0.0.2:5060".parse().unwrap();
    let call = store.get_call(&call_id).unwrap();
    let from_a = b_leg_source == call.a_leg.transport.remote_addr;
    assert!(!from_a); // This is from B-leg

    // Forward to A-leg
    assert_eq!(call.a_leg.transport.remote_addr, a_source);
    drop(call);

    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL: A-leg CANCEL → cancel B-legs
// ---------------------------------------------------------------------------

#[test]
fn b2bua_cancel_removes_call() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-cancel@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);

    // Call is in Calling state — CANCEL should terminate it
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // CANCEL → set terminated, remove
    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

#[test]
fn b2bua_cancel_ignored_after_answer() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-cancel-late@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // Call is Answered — CANCEL should not change state
    {
        let call = store.get_call(&call_id).unwrap();
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
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("call-fork@test"));

    // Fork to 3 B-legs
    for i in 0..3 {
        let b_leg = Leg::new_b_leg(
            generate_call_id(),
            generate_tag(),
            format!("sip:bob@10.0.0.{}", i + 2),
            TransactionKey::generate_branch(),
            TransportInfo {
                remote_addr: format!("10.0.0.{}:5060", i + 2).parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        );
        store.add_b_leg(&call_id, b_leg);
    }

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 3);
    }

    // Second B-leg answers first
    store.set_winner(&call_id, 1);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.state, CallState::Answered);
    }

    // Cleanup
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
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
    let store = CallActorStore::new();

    // Create call
    let a_leg = make_a_leg("call-invite-store@test");
    let call_id = store.create_call(a_leg);

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
    store.set_a_leg_invite(&call_id, Arc::clone(&invite_arc));

    // Add B-leg, answer the call
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // A-leg INVITE should still be available after answer (for on_answer handler)
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let stored_invite = call.a_leg_invite.as_ref().expect("a_leg_invite should be stored");
        let msg = stored_invite.lock().unwrap();
        assert_eq!(msg.headers.get("From").map(|s| s.contains("store-tag")), Some(true));
    }

    // A-leg INVITE should still be available at BYE time (for on_bye handler)
    store.set_state(&call_id, CallState::Terminated);
    {
        let call = store.get_call(&call_id).unwrap();
        assert!(call.a_leg_invite.is_some());
    }

    // After removal, everything is cleaned up
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
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
    let store = CallActorStore::new();
    let a_leg = make_a_leg("timer-lifecycle@test");
    let call_id = store.create_call(a_leg);

    // No timer initially
    {
        let call = store.get_call(&call_id).unwrap();
        assert!(call.session_timer.is_none());
    }

    // Add B-leg and set to Answered
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Activate session timer (simulating 200 OK processing)
    let timer = SessionTimerState {
        session_expires: 1800,
        refresher: "b2bua".to_string(),
        last_refresh: std::time::Instant::now(),
    };
    store.set_session_timer(&call_id, timer);

    // Verify timer is active
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let timer = call.session_timer.as_ref().unwrap();
        assert_eq!(timer.session_expires, 1800);
        assert_eq!(timer.refresher, "b2bua");
    }

    // Reset timer (simulating successful refresh)
    let before = {
        let call = store.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    std::thread::sleep(std::time::Duration::from_millis(10));
    store.reset_session_timer(&call_id);
    let after = {
        let call = store.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    assert!(after > before);

    // Remove call cleans up timer
    store.remove_call(&call_id);
    assert!(store.get_call(&call_id).is_none());
}


#[test]
fn session_timer_per_call_override_on_call_actor_store() {
    use siphon::script::api::call::SessionTimerOverride;

    let store = CallActorStore::new();
    let a_leg = make_a_leg("override-mgr@test");
    let call_id = store.create_call(a_leg);

    // Store override on the call
    if let Some(mut call_ref) = store.get_call_mut(&call_id) {
        call_ref.session_timer_override = Some(SessionTimerOverride {
            session_expires: 3600,
            min_se: 120,
            refresher: "uas".to_string(),
        });
    }

    // Verify override persists
    let call_ref = store.get_call(&call_id).unwrap();
    let stored = call_ref.session_timer_override.as_ref().unwrap();
    assert_eq!(stored.session_expires, 3600);
    assert_eq!(stored.min_se, 120);
    assert_eq!(stored.refresher, "uas");
}

// ---------------------------------------------------------------------------
// LegActor integration: remove_call terminates spawned actor tasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remove_call_terminates_actor_tasks() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg("actor-terminate@test");
    let call_id = store.create_call(a_leg);

    let (event_tx, _event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = store.get_call_mut(&call_id) {
        call.event_tx = Some(event_tx.clone());
    }

    // Spawn two B-leg actors
    let mut joins = Vec::new();
    for addr in &["10.0.0.2:5060", "10.0.0.3:5060"] {
        let b_leg = make_b_leg(addr);
        let b_leg_clone = b_leg.clone();
        store.add_b_leg(&call_id, b_leg);

        let (actor, handle) = LegActor::new(b_leg_clone, event_tx.clone());
        joins.push(tokio::spawn(actor.run()));

        let index = store.get_call(&call_id).unwrap().b_legs.len() - 1;
        if let Some(mut call) = store.get_call_mut(&call_id) {
            call.set_b_leg_handle(index, handle);
        }
    }

    // Actors should be running
    for join in &joins {
        assert!(!join.is_finished());
    }

    // remove_call sends Shutdown to all actor handles
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);

    // All actor tasks should terminate
    for join in joins {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            join,
        ).await.expect("actor task did not terminate").unwrap();
    }
}

// ---------------------------------------------------------------------------
// B2BUA re-INVITE B-leg lifecycle (target_uri marking + cleanup)
// ---------------------------------------------------------------------------

#[test]
fn reinvite_b_leg_non2xx_removed() {
    // When a re-INVITE gets a non-2xx response (e.g. 491 Request Pending),
    // the re-INVITE B-leg entry should be removed after ACKing.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-non2xx@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Simulate a re-INVITE by adding a tracking B-leg entry
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:a2b".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);

    // Verify re-INVITE entry exists at index 1
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("reinvite:a2b"));
    }

    // Simulate non-2xx response → remove re-INVITE entry
    store.remove_b_leg(&call_id, 1);

    // Verify only the winning B-leg remains
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.winner, Some(0));
    }
}

#[test]
fn reinvite_b_leg_2xx_marked_done() {
    // When a re-INVITE gets a 2xx response, the B-leg entry should be
    // marked as "reinvite_done:" instead of removed, so retransmitted
    // 200 OKs can still be matched and re-ACKed.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-2xx@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Simulate a re-INVITE tracking entry
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:b2a".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);

    // Simulate 2xx response → mark as done (not removed)
    store.set_b_leg_target_uri(&call_id, 1, "reinvite_done:b2a".to_string());

    // Verify the entry still exists for retransmission matching
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("reinvite_done:b2a"));
        assert_eq!(call.b_legs[1].branch, reinvite_branch);
    }

    // The branch should still be resolvable to the call
    assert_eq!(store.call_id_for_branch(&reinvite_branch), Some(call_id.clone()));

    // Winner index unaffected
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(0));
        assert_eq!(call.b_legs[0].branch, b_branch);
    }
}

#[test]
fn reinvite_done_entry_cleaned_on_call_removal() {
    // Marked "reinvite_done:" entries should be cleaned up when the call ends.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-cleanup@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // Add and mark a re-INVITE entry as done
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:a2b".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);
    store.set_b_leg_target_uri(&call_id, 1, "reinvite_done:a2b".to_string());

    // remove_call should clean up everything including the done entry
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&reinvite_branch).is_none());
}

#[test]
fn set_b_leg_target_uri_no_panic_on_invalid_index() {
    // Setting target_uri on a non-existent index should be a no-op.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("target-uri-invalid@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));

    // Index 5 doesn't exist — should not panic
    store.set_b_leg_target_uri(&call_id, 5, "reinvite_done:a2b".to_string());

    // Original B-leg unaffected
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 1);
        assert!(call.b_legs[0].dialog.target_uri.as_deref().unwrap().starts_with("sip:"));
    }
}
