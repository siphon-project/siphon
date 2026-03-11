//! Transaction state machines per RFC 3261 §17.
//!
//! Each state machine is a pure function: `(State, Event) → (State, Vec<Action>)`.
//! No I/O, no async — the caller (TransactionManager) drives timers and sends messages.

use std::time::Duration;

use crate::sip::message::SipMessage;
use crate::transaction::timer::TimerConfig;

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

/// Transport type — affects which timers are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Unreliable (UDP) — retransmissions needed.
    Udp,
    /// Reliable (TCP/TLS/WS/WSS) — no retransmissions.
    Reliable,
}

impl From<crate::transport::Transport> for Transport {
    fn from(t: crate::transport::Transport) -> Self {
        match t {
            crate::transport::Transport::Udp => Transport::Udp,
            _ => Transport::Reliable,
        }
    }
}

/// An action the transaction layer asks the transport/TU to perform.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a SIP message over the transport.
    SendMessage(SipMessage),
    /// Pass a received message to the Transaction User (TU).
    PassToTu(SipMessage),
    /// Start or restart a timer that fires after `duration`.
    StartTimer(TimerName, Duration),
    /// Cancel a running timer.
    CancelTimer(TimerName),
    /// Report a timeout error to the TU.
    Timeout,
    /// Transaction is terminated — the manager should remove it.
    Terminated,
}

/// Named timers used across all state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerName {
    A, B,       // ICT
    D,          // ICT
    E, F,       // NICT
    K,          // NICT
    G, H,       // IST
    I,          // IST
    J,          // NIST
}

// ===========================================================================
// Non-INVITE Server Transaction (NIST) — RFC 3261 §17.2.2
// ===========================================================================

/// NIST states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistState {
    /// Initial state: request received, waiting for TU response.
    Trying,
    /// A provisional (1xx) response was sent.
    Proceeding,
    /// A final (2xx-6xx) response was sent. Absorbing retransmits.
    Completed,
    /// Transaction is done.
    Terminated,
}

/// Events that a NIST can receive.
#[derive(Debug, Clone)]
pub enum NistEvent {
    /// A request retransmit arrived from the network.
    RequestRetransmit(SipMessage),
    /// The TU sends a provisional response (1xx).
    TuProvisional(SipMessage),
    /// The TU sends a final response (2xx-6xx).
    TuFinal(SipMessage),
    /// Timer J fired (completed → terminated).
    TimerJ,
}

/// Non-INVITE Server Transaction state machine.
#[derive(Debug)]
pub struct Nist {
    pub state: NistState,
    pub transport: Transport,
    pub timers: TimerConfig,
    /// Last response sent (for retransmit on request retransmit).
    pub last_response: Option<SipMessage>,
}

impl Nist {
    pub fn new(transport: Transport, timers: TimerConfig) -> Self {
        Self {
            state: NistState::Trying,
            transport,
            timers,
            last_response: None,
        }
    }

    /// Process an event and return the resulting actions.
    pub fn process(&mut self, event: NistEvent) -> Vec<Action> {
        match (&self.state, event) {
            // -- Trying --
            (NistState::Trying, NistEvent::RequestRetransmit(_)) => {
                // Absorb retransmit silently in Trying (no response to resend yet)
                vec![]
            }
            (NistState::Trying, NistEvent::TuProvisional(response)) => {
                self.state = NistState::Proceeding;
                self.last_response = Some(response.clone());
                vec![Action::SendMessage(response)]
            }
            (NistState::Trying, NistEvent::TuFinal(response)) => {
                self.state = NistState::Completed;
                self.last_response = Some(response.clone());
                let timer_j = match self.transport {
                    Transport::Udp => self.timers.timer_j_udp(),
                    Transport::Reliable => self.timers.timer_j_tcp(),
                };
                let mut actions = vec![Action::SendMessage(response)];
                if timer_j.is_zero() {
                    self.state = NistState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::J, timer_j));
                }
                actions
            }

            // -- Proceeding --
            (NistState::Proceeding, NistEvent::RequestRetransmit(_)) => {
                // Retransmit last provisional response
                match &self.last_response {
                    Some(response) => vec![Action::SendMessage(response.clone())],
                    None => vec![],
                }
            }
            (NistState::Proceeding, NistEvent::TuProvisional(response)) => {
                self.last_response = Some(response.clone());
                vec![Action::SendMessage(response)]
            }
            (NistState::Proceeding, NistEvent::TuFinal(response)) => {
                self.state = NistState::Completed;
                self.last_response = Some(response.clone());
                let timer_j = match self.transport {
                    Transport::Udp => self.timers.timer_j_udp(),
                    Transport::Reliable => self.timers.timer_j_tcp(),
                };
                let mut actions = vec![Action::SendMessage(response)];
                if timer_j.is_zero() {
                    self.state = NistState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::J, timer_j));
                }
                actions
            }

            // -- Completed --
            (NistState::Completed, NistEvent::RequestRetransmit(_)) => {
                // Retransmit last final response
                match &self.last_response {
                    Some(response) => vec![Action::SendMessage(response.clone())],
                    None => vec![],
                }
            }
            (NistState::Completed, NistEvent::TimerJ) => {
                self.state = NistState::Terminated;
                vec![Action::Terminated]
            }

            // -- Terminated or invalid --
            (NistState::Terminated, _) => vec![],
            _ => vec![],
        }
    }
}

// ===========================================================================
// INVITE Server Transaction (IST) — RFC 3261 §17.2.1
// ===========================================================================

/// IST states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IstState {
    /// Initial: INVITE received, waiting for TU response.
    Proceeding,
    /// Final non-2xx sent, waiting for ACK.
    Completed,
    /// ACK received after non-2xx (absorbing retransmits).
    Confirmed,
    /// Transaction is done.
    Terminated,
    /// 2xx sent — transaction layer steps aside, TU handles ACK.
    Accepted,
}

/// Events that an IST can receive.
#[derive(Debug, Clone)]
pub enum IstEvent {
    /// INVITE retransmit from the network.
    InviteRetransmit(SipMessage),
    /// TU sends a provisional response (1xx).
    TuProvisional(SipMessage),
    /// TU sends a 2xx response.
    Tu2xx(SipMessage),
    /// TU sends a non-2xx final response (3xx-6xx).
    TuNon2xxFinal(SipMessage),
    /// ACK received from the network.
    AckReceived(SipMessage),
    /// Timer G fired (retransmit response for UDP).
    TimerG,
    /// Timer H fired (ACK wait timeout).
    TimerH,
    /// Timer I fired (confirmed → terminated).
    TimerI,
}

/// INVITE Server Transaction state machine.
#[derive(Debug)]
pub struct Ist {
    pub state: IstState,
    pub transport: Transport,
    pub timers: TimerConfig,
    pub last_response: Option<SipMessage>,
    /// Current Timer G interval (doubles each fire, capped at T2).
    pub timer_g_interval: Duration,
}

impl Ist {
    pub fn new(transport: Transport, timers: TimerConfig) -> Self {
        let timer_g_interval = timers.timer_g_initial();
        Self {
            state: IstState::Proceeding,
            transport,
            timers,
            last_response: None,
            timer_g_interval,
        }
    }

    pub fn process(&mut self, event: IstEvent) -> Vec<Action> {
        match (&self.state, event) {
            // -- Proceeding --
            (IstState::Proceeding, IstEvent::InviteRetransmit(_)) => {
                // Retransmit last provisional if we have one
                match &self.last_response {
                    Some(response) => vec![Action::SendMessage(response.clone())],
                    None => vec![],
                }
            }
            (IstState::Proceeding, IstEvent::TuProvisional(response)) => {
                self.last_response = Some(response.clone());
                vec![Action::SendMessage(response)]
            }
            (IstState::Proceeding, IstEvent::Tu2xx(response)) => {
                // 2xx: transaction steps aside, TU owns retransmissions
                self.state = IstState::Accepted;
                vec![Action::SendMessage(response), Action::Terminated]
            }
            (IstState::Proceeding, IstEvent::TuNon2xxFinal(response)) => {
                self.state = IstState::Completed;
                self.last_response = Some(response.clone());
                let mut actions = vec![Action::SendMessage(response)];
                // Start Timer H (ACK wait)
                actions.push(Action::StartTimer(TimerName::H, self.timers.timer_h()));
                // Start Timer G for UDP retransmissions
                if self.transport == Transport::Udp {
                    self.timer_g_interval = self.timers.timer_g_initial();
                    actions.push(Action::StartTimer(TimerName::G, self.timer_g_interval));
                }
                actions
            }

            // -- Completed --
            (IstState::Completed, IstEvent::InviteRetransmit(_)) => {
                // Retransmit final response
                match &self.last_response {
                    Some(response) => vec![Action::SendMessage(response.clone())],
                    None => vec![],
                }
            }
            (IstState::Completed, IstEvent::TimerG) => {
                // Retransmit final response, double interval
                match &self.last_response {
                    Some(response) => {
                        self.timer_g_interval = self.timers.next_retransmit(self.timer_g_interval);
                        vec![
                            Action::SendMessage(response.clone()),
                            Action::StartTimer(TimerName::G, self.timer_g_interval),
                        ]
                    }
                    None => vec![],
                }
            }
            (IstState::Completed, IstEvent::TimerH) => {
                // ACK timeout — inform TU, terminate
                self.state = NistState::Terminated.into();
                vec![
                    Action::CancelTimer(TimerName::G),
                    Action::Timeout,
                    Action::Terminated,
                ]
            }
            (IstState::Completed, IstEvent::AckReceived(_)) => {
                self.state = IstState::Confirmed;
                let timer_i = match self.transport {
                    Transport::Udp => self.timers.timer_i_udp(),
                    Transport::Reliable => self.timers.timer_i_tcp(),
                };
                let mut actions = vec![Action::CancelTimer(TimerName::G), Action::CancelTimer(TimerName::H)];
                if timer_i.is_zero() {
                    self.state = IstState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::I, timer_i));
                }
                actions
            }

            // -- Confirmed --
            (IstState::Confirmed, IstEvent::AckReceived(_)) => {
                // Absorb ACK retransmits silently
                vec![]
            }
            (IstState::Confirmed, IstEvent::TimerI) => {
                self.state = IstState::Terminated;
                vec![Action::Terminated]
            }

            // -- Accepted / Terminated / invalid --
            (IstState::Accepted, _) | (IstState::Terminated, _) => vec![],
            _ => vec![],
        }
    }
}

// Conversion helper for the Timer H handler
impl From<NistState> for IstState {
    fn from(state: NistState) -> Self {
        match state {
            NistState::Terminated => IstState::Terminated,
            _ => IstState::Terminated, // only used for terminated
        }
    }
}

// ===========================================================================
// Non-INVITE Client Transaction (NICT) — RFC 3261 §17.1.2
// ===========================================================================

/// NICT states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NictState {
    /// Initial: request sent, waiting for response.
    Trying,
    /// Provisional (1xx) received.
    Proceeding,
    /// Final response received. Absorbing retransmits.
    Completed,
    /// Transaction is done.
    Terminated,
}

/// Events that a NICT can receive.
#[derive(Debug, Clone)]
pub enum NictEvent {
    /// Timer E fired (retransmit request for UDP).
    TimerE,
    /// Timer F fired (transaction timeout).
    TimerF,
    /// Timer K fired (completed → terminated).
    TimerK,
    /// A provisional (1xx) response received from the network.
    Provisional(SipMessage),
    /// A final (2xx-6xx) response received from the network.
    FinalResponse(SipMessage),
}

/// Non-INVITE Client Transaction state machine.
#[derive(Debug)]
pub struct Nict {
    pub state: NictState,
    pub transport: Transport,
    pub timers: TimerConfig,
    /// The original request (for retransmissions).
    pub request: SipMessage,
    /// Current Timer E interval.
    pub timer_e_interval: Duration,
}

impl Nict {
    /// Create and start a new NICT. Returns the initial actions (send request, start timers).
    pub fn new(request: SipMessage, transport: Transport, timers: TimerConfig) -> (Self, Vec<Action>) {
        let timer_e_interval = timers.timer_e_initial();
        let nict = Self {
            state: NictState::Trying,
            transport,
            timers,
            request: request.clone(),
            timer_e_interval,
        };
        let mut actions = vec![Action::SendMessage(request)];
        // Start Timer F (overall timeout)
        actions.push(Action::StartTimer(TimerName::F, nict.timers.timer_f()));
        // Start Timer E for UDP
        if transport == Transport::Udp {
            actions.push(Action::StartTimer(TimerName::E, timer_e_interval));
        }
        (nict, actions)
    }

    pub fn process(&mut self, event: NictEvent) -> Vec<Action> {
        match (&self.state, event) {
            // -- Trying --
            (NictState::Trying, NictEvent::TimerE) => {
                // Retransmit, double interval (capped at T2)
                self.timer_e_interval = self.timers.next_retransmit(self.timer_e_interval);
                vec![
                    Action::SendMessage(self.request.clone()),
                    Action::StartTimer(TimerName::E, self.timer_e_interval),
                ]
            }
            (NictState::Trying, NictEvent::TimerF) => {
                self.state = NictState::Terminated;
                vec![Action::CancelTimer(TimerName::E), Action::Timeout, Action::Terminated]
            }
            (NictState::Trying, NictEvent::Provisional(response)) => {
                self.state = NictState::Proceeding;
                vec![Action::PassToTu(response)]
            }
            (NictState::Trying, NictEvent::FinalResponse(response)) => {
                self.state = NictState::Completed;
                let timer_k = match self.transport {
                    Transport::Udp => self.timers.timer_k_udp(),
                    Transport::Reliable => self.timers.timer_k_tcp(),
                };
                let mut actions = vec![
                    Action::CancelTimer(TimerName::E),
                    Action::CancelTimer(TimerName::F),
                    Action::PassToTu(response),
                ];
                if timer_k.is_zero() {
                    self.state = NictState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::K, timer_k));
                }
                actions
            }

            // -- Proceeding --
            (NictState::Proceeding, NictEvent::TimerE) => {
                // In Proceeding, retransmit interval is T2 (not doubling)
                vec![
                    Action::SendMessage(self.request.clone()),
                    Action::StartTimer(TimerName::E, self.timers.t2),
                ]
            }
            (NictState::Proceeding, NictEvent::TimerF) => {
                self.state = NictState::Terminated;
                vec![Action::CancelTimer(TimerName::E), Action::Timeout, Action::Terminated]
            }
            (NictState::Proceeding, NictEvent::Provisional(response)) => {
                vec![Action::PassToTu(response)]
            }
            (NictState::Proceeding, NictEvent::FinalResponse(response)) => {
                self.state = NictState::Completed;
                let timer_k = match self.transport {
                    Transport::Udp => self.timers.timer_k_udp(),
                    Transport::Reliable => self.timers.timer_k_tcp(),
                };
                let mut actions = vec![
                    Action::CancelTimer(TimerName::E),
                    Action::CancelTimer(TimerName::F),
                    Action::PassToTu(response),
                ];
                if timer_k.is_zero() {
                    self.state = NictState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::K, timer_k));
                }
                actions
            }

            // -- Completed --
            (NictState::Completed, NictEvent::TimerK) => {
                self.state = NictState::Terminated;
                vec![Action::Terminated]
            }
            (NictState::Completed, NictEvent::FinalResponse(_)) => {
                // Absorb response retransmits
                vec![]
            }

            // -- Terminated or invalid --
            (NictState::Terminated, _) => vec![],
            _ => vec![],
        }
    }
}

// ===========================================================================
// INVITE Client Transaction (ICT) — RFC 3261 §17.1.1
// ===========================================================================

/// ICT states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IctState {
    /// Initial: INVITE sent, waiting for response.
    Calling,
    /// Provisional (1xx) received.
    Proceeding,
    /// Non-2xx final received, ACK sent, absorbing retransmits.
    Completed,
    /// Transaction is done.
    Terminated,
}

/// Events that an ICT can receive.
#[derive(Debug, Clone)]
pub enum IctEvent {
    /// Timer A fired (retransmit INVITE for UDP).
    TimerA,
    /// Timer B fired (INVITE transaction timeout).
    TimerB,
    /// Timer D fired (completed → terminated).
    TimerD,
    /// A provisional (1xx) response received.
    Provisional(SipMessage),
    /// A 2xx response received.
    Response2xx(SipMessage),
    /// A non-2xx final (3xx-6xx) response received.
    ResponseNon2xx(SipMessage),
}

/// INVITE Client Transaction state machine.
#[derive(Debug)]
pub struct Ict {
    pub state: IctState,
    pub transport: Transport,
    pub timers: TimerConfig,
    pub request: SipMessage,
    /// Current Timer A interval.
    pub timer_a_interval: Duration,
}

impl Ict {
    /// Create and start a new ICT. Returns the initial actions.
    pub fn new(request: SipMessage, transport: Transport, timers: TimerConfig) -> (Self, Vec<Action>) {
        let timer_a_interval = timers.timer_a_initial();
        let ict = Self {
            state: IctState::Calling,
            transport,
            timers,
            request: request.clone(),
            timer_a_interval,
        };
        let mut actions = vec![Action::SendMessage(request)];
        // Start Timer B (overall timeout)
        actions.push(Action::StartTimer(TimerName::B, ict.timers.timer_b()));
        // Start Timer A for UDP
        if transport == Transport::Udp {
            actions.push(Action::StartTimer(TimerName::A, timer_a_interval));
        }
        (ict, actions)
    }

    pub fn process(&mut self, event: IctEvent) -> Vec<Action> {
        match (&self.state, event) {
            // -- Calling --
            (IctState::Calling, IctEvent::TimerA) => {
                // FIX: Cap at T2 using next_retransmit (RFC 3261 §17.1.1.2)
                self.timer_a_interval = self.timers.next_retransmit(self.timer_a_interval);
                vec![
                    Action::SendMessage(self.request.clone()),
                    Action::StartTimer(TimerName::A, self.timer_a_interval),
                ]
            }
            (IctState::Calling, IctEvent::TimerB) => {
                self.state = IctState::Terminated;
                vec![Action::CancelTimer(TimerName::A), Action::Timeout, Action::Terminated]
            }
            (IctState::Calling, IctEvent::Provisional(response)) => {
                self.state = IctState::Proceeding;
                vec![Action::PassToTu(response)]
            }
            (IctState::Calling, IctEvent::Response2xx(response)) => {
                // 2xx to INVITE: transaction layer steps aside
                self.state = IctState::Terminated;
                vec![
                    Action::CancelTimer(TimerName::A),
                    Action::CancelTimer(TimerName::B),
                    Action::PassToTu(response),
                    Action::Terminated,
                ]
            }
            (IctState::Calling, IctEvent::ResponseNon2xx(response)) => {
                self.state = IctState::Completed;
                let timer_d = match self.transport {
                    Transport::Udp => self.timers.timer_d_udp(),
                    Transport::Reliable => self.timers.timer_d_tcp(),
                };
                let mut actions = vec![
                    Action::CancelTimer(TimerName::A),
                    Action::CancelTimer(TimerName::B),
                    Action::PassToTu(response),
                ];
                if timer_d.is_zero() {
                    self.state = IctState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::D, timer_d));
                }
                actions
            }

            // -- Proceeding --
            (IctState::Proceeding, IctEvent::TimerA) => {
                // FIX: Handle Timer A in Proceeding state (RFC 3261 §17.1.1.2)
                // Retransmit INVITE and restart Timer A (capped at T2)
                self.timer_a_interval = self.timers.next_retransmit(self.timer_a_interval);
                vec![
                    Action::SendMessage(self.request.clone()),
                    Action::StartTimer(TimerName::A, self.timer_a_interval),
                ]
            }
            (IctState::Proceeding, IctEvent::Provisional(response)) => {
                vec![Action::PassToTu(response)]
            }
            (IctState::Proceeding, IctEvent::Response2xx(response)) => {
                self.state = IctState::Terminated;
                vec![
                    Action::CancelTimer(TimerName::A),
                    Action::CancelTimer(TimerName::B),
                    Action::PassToTu(response),
                    Action::Terminated,
                ]
            }
            (IctState::Proceeding, IctEvent::ResponseNon2xx(response)) => {
                self.state = IctState::Completed;
                let timer_d = match self.transport {
                    Transport::Udp => self.timers.timer_d_udp(),
                    Transport::Reliable => self.timers.timer_d_tcp(),
                };
                let mut actions = vec![
                    // FIX: Cancel Timer A on non-2xx in Proceeding (RFC 3261 §17.1.1.2)
                    Action::CancelTimer(TimerName::A),
                    Action::CancelTimer(TimerName::B),
                    Action::PassToTu(response),
                ];
                if timer_d.is_zero() {
                    self.state = IctState::Terminated;
                    actions.push(Action::Terminated);
                } else {
                    actions.push(Action::StartTimer(TimerName::D, timer_d));
                }
                actions
            }

            // -- Completed --
            (IctState::Completed, IctEvent::ResponseNon2xx(_)) => {
                // Absorb retransmits — ACK is sent by TU/transport layer
                vec![]
            }
            (IctState::Completed, IctEvent::TimerD) => {
                self.state = IctState::Terminated;
                vec![Action::Terminated]
            }

            // -- Terminated or invalid --
            (IctState::Terminated, _) => vec![],
            _ => vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn dummy_request() -> SipMessage {
        SipMessageBuilder::new()
            .request(Method::Options, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("test-call-id".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn dummy_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
            .call_id("invite-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn dummy_response(code: u16, reason: &str) -> SipMessage {
        SipMessageBuilder::new()
            .response(code, reason.to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("test-call-id".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn has_action<F: Fn(&Action) -> bool>(actions: &[Action], predicate: F) -> bool {
        actions.iter().any(|a| predicate(a))
    }

    fn has_send(actions: &[Action]) -> bool {
        has_action(actions, |a| matches!(a, Action::SendMessage(_)))
    }

    fn has_pass_to_tu(actions: &[Action]) -> bool {
        has_action(actions, |a| matches!(a, Action::PassToTu(_)))
    }

    fn has_terminated(actions: &[Action]) -> bool {
        has_action(actions, |a| matches!(a, Action::Terminated))
    }

    fn has_timeout(actions: &[Action]) -> bool {
        has_action(actions, |a| matches!(a, Action::Timeout))
    }

    fn has_timer(actions: &[Action], name: TimerName) -> bool {
        has_action(actions, |a| matches!(a, Action::StartTimer(n, _) if *n == name))
    }

    fn has_cancel_timer(actions: &[Action], name: TimerName) -> bool {
        has_action(actions, |a| matches!(a, Action::CancelTimer(n) if *n == name))
    }

    // =======================================================================
    // NIST tests
    // =======================================================================

    #[test]
    fn nist_trying_absorbs_retransmit() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        let actions = nist.process(NistEvent::RequestRetransmit(dummy_request()));
        assert!(actions.is_empty());
        assert_eq!(nist.state, NistState::Trying);
    }

    #[test]
    fn nist_trying_to_proceeding() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        let response = dummy_response(100, "Trying");
        let actions = nist.process(NistEvent::TuProvisional(response));
        assert_eq!(nist.state, NistState::Proceeding);
        assert!(has_send(&actions));
    }

    #[test]
    fn nist_trying_to_completed_udp() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        let response = dummy_response(200, "OK");
        let actions = nist.process(NistEvent::TuFinal(response));
        assert_eq!(nist.state, NistState::Completed);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::J));
    }

    #[test]
    fn nist_trying_to_completed_tcp_immediate_terminate() {
        let mut nist = Nist::new(Transport::Reliable, TimerConfig::default());
        let response = dummy_response(200, "OK");
        let actions = nist.process(NistEvent::TuFinal(response));
        assert_eq!(nist.state, NistState::Terminated);
        assert!(has_send(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn nist_proceeding_retransmits_last_response() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        nist.process(NistEvent::TuProvisional(dummy_response(100, "Trying")));
        let actions = nist.process(NistEvent::RequestRetransmit(dummy_request()));
        assert!(has_send(&actions));
    }

    #[test]
    fn nist_completed_retransmits_final() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        nist.process(NistEvent::TuFinal(dummy_response(200, "OK")));
        assert_eq!(nist.state, NistState::Completed);
        let actions = nist.process(NistEvent::RequestRetransmit(dummy_request()));
        assert!(has_send(&actions));
    }

    #[test]
    fn nist_timer_j_terminates() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        nist.process(NistEvent::TuFinal(dummy_response(200, "OK")));
        let actions = nist.process(NistEvent::TimerJ);
        assert_eq!(nist.state, NistState::Terminated);
        assert!(has_terminated(&actions));
    }

    #[test]
    fn nist_full_lifecycle_trying_proceeding_completed_terminated() {
        let mut nist = Nist::new(Transport::Udp, TimerConfig::default());
        assert_eq!(nist.state, NistState::Trying);

        nist.process(NistEvent::TuProvisional(dummy_response(100, "Trying")));
        assert_eq!(nist.state, NistState::Proceeding);

        nist.process(NistEvent::TuFinal(dummy_response(200, "OK")));
        assert_eq!(nist.state, NistState::Completed);

        nist.process(NistEvent::TimerJ);
        assert_eq!(nist.state, NistState::Terminated);
    }

    // =======================================================================
    // IST tests
    // =======================================================================

    #[test]
    fn ist_proceeding_retransmits_provisional() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuProvisional(dummy_response(100, "Trying")));
        let actions = ist.process(IstEvent::InviteRetransmit(dummy_invite()));
        assert!(has_send(&actions));
    }

    #[test]
    fn ist_2xx_terminates_immediately() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        let actions = ist.process(IstEvent::Tu2xx(dummy_response(200, "OK")));
        assert_eq!(ist.state, IstState::Accepted);
        assert!(has_send(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ist_non2xx_enters_completed_with_timers() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        let actions = ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        assert_eq!(ist.state, IstState::Completed);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::H));
        assert!(has_timer(&actions, TimerName::G));
    }

    #[test]
    fn ist_non2xx_tcp_no_timer_g() {
        let mut ist = Ist::new(Transport::Reliable, TimerConfig::default());
        let actions = ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        assert_eq!(ist.state, IstState::Completed);
        assert!(has_timer(&actions, TimerName::H));
        assert!(!has_timer(&actions, TimerName::G));
    }

    #[test]
    fn ist_completed_ack_enters_confirmed() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        let actions = ist.process(IstEvent::AckReceived(dummy_request()));
        assert_eq!(ist.state, IstState::Confirmed);
        assert!(has_timer(&actions, TimerName::I));
    }

    #[test]
    fn ist_completed_ack_tcp_immediate_terminate() {
        let mut ist = Ist::new(Transport::Reliable, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        let actions = ist.process(IstEvent::AckReceived(dummy_request()));
        assert_eq!(ist.state, IstState::Terminated);
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ist_timer_g_retransmits_and_doubles() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));

        let actions = ist.process(IstEvent::TimerG);
        assert!(has_send(&actions));
        // Timer G interval should have doubled (500ms → 1000ms)
        assert_eq!(ist.timer_g_interval, Duration::from_millis(1000));

        let actions = ist.process(IstEvent::TimerG);
        assert!(has_send(&actions));
        assert_eq!(ist.timer_g_interval, Duration::from_millis(2000));
    }

    #[test]
    fn ist_timer_h_timeout() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        let actions = ist.process(IstEvent::TimerH);
        assert_eq!(ist.state, IstState::Terminated);
        assert!(has_timeout(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ist_confirmed_absorbs_ack_retransmit() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        ist.process(IstEvent::AckReceived(dummy_request()));
        assert_eq!(ist.state, IstState::Confirmed);
        let actions = ist.process(IstEvent::AckReceived(dummy_request()));
        assert!(actions.is_empty());
    }

    #[test]
    fn ist_timer_i_terminates() {
        let mut ist = Ist::new(Transport::Udp, TimerConfig::default());
        ist.process(IstEvent::TuNon2xxFinal(dummy_response(486, "Busy Here")));
        ist.process(IstEvent::AckReceived(dummy_request()));
        let actions = ist.process(IstEvent::TimerI);
        assert_eq!(ist.state, IstState::Terminated);
        assert!(has_terminated(&actions));
    }

    // =======================================================================
    // NICT tests
    // =======================================================================

    #[test]
    fn nict_new_sends_request_and_starts_timers() {
        let (nict, actions) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        assert_eq!(nict.state, NictState::Trying);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::F));
        assert!(has_timer(&actions, TimerName::E));
    }

    #[test]
    fn nict_tcp_no_timer_e() {
        let (_, actions) = Nict::new(dummy_request(), Transport::Reliable, TimerConfig::default());
        assert!(has_timer(&actions, TimerName::F));
        assert!(!has_timer(&actions, TimerName::E));
    }

    #[test]
    fn nict_timer_e_retransmits_and_doubles() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        assert_eq!(nict.timer_e_interval, Duration::from_millis(500));

        let actions = nict.process(NictEvent::TimerE);
        assert!(has_send(&actions));
        assert_eq!(nict.timer_e_interval, Duration::from_millis(1000));

        let actions = nict.process(NictEvent::TimerE);
        assert!(has_send(&actions));
        assert_eq!(nict.timer_e_interval, Duration::from_millis(2000));

        nict.process(NictEvent::TimerE);
        assert_eq!(nict.timer_e_interval, Duration::from_millis(4000)); // T2 cap

        nict.process(NictEvent::TimerE);
        assert_eq!(nict.timer_e_interval, Duration::from_millis(4000)); // stays at T2
    }

    #[test]
    fn nict_timer_f_timeout() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        let actions = nict.process(NictEvent::TimerF);
        assert_eq!(nict.state, NictState::Terminated);
        assert!(has_timeout(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn nict_provisional_to_proceeding() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        let actions = nict.process(NictEvent::Provisional(dummy_response(100, "Trying")));
        assert_eq!(nict.state, NictState::Proceeding);
        assert!(has_pass_to_tu(&actions));
    }

    #[test]
    fn nict_final_response_to_completed_udp() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        let actions = nict.process(NictEvent::FinalResponse(dummy_response(200, "OK")));
        assert_eq!(nict.state, NictState::Completed);
        assert!(has_pass_to_tu(&actions));
        assert!(has_timer(&actions, TimerName::K));
    }

    #[test]
    fn nict_final_response_tcp_immediate_terminate() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Reliable, TimerConfig::default());
        let actions = nict.process(NictEvent::FinalResponse(dummy_response(200, "OK")));
        assert_eq!(nict.state, NictState::Terminated);
        assert!(has_pass_to_tu(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn nict_timer_k_terminates() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        nict.process(NictEvent::FinalResponse(dummy_response(200, "OK")));
        let actions = nict.process(NictEvent::TimerK);
        assert_eq!(nict.state, NictState::Terminated);
        assert!(has_terminated(&actions));
    }

    #[test]
    fn nict_completed_absorbs_retransmit() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        nict.process(NictEvent::FinalResponse(dummy_response(200, "OK")));
        let actions = nict.process(NictEvent::FinalResponse(dummy_response(200, "OK")));
        assert!(actions.is_empty());
    }

    #[test]
    fn nict_proceeding_timer_e_uses_t2() {
        let (mut nict, _) = Nict::new(dummy_request(), Transport::Udp, TimerConfig::default());
        nict.process(NictEvent::Provisional(dummy_response(100, "Trying")));
        let actions = nict.process(NictEvent::TimerE);
        // In Proceeding, Timer E fires at T2 interval
        assert!(has_send(&actions));
        assert!(has_action(&actions, |a| matches!(a, Action::StartTimer(TimerName::E, d) if *d == Duration::from_secs(4))));
    }

    // =======================================================================
    // ICT tests
    // =======================================================================

    #[test]
    fn ict_new_sends_invite_and_starts_timers() {
        let (ict, actions) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        assert_eq!(ict.state, IctState::Calling);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::B));
        assert!(has_timer(&actions, TimerName::A));
    }

    #[test]
    fn ict_tcp_no_timer_a() {
        let (_, actions) = Ict::new(dummy_invite(), Transport::Reliable, TimerConfig::default());
        assert!(has_timer(&actions, TimerName::B));
        assert!(!has_timer(&actions, TimerName::A));
    }

    #[test]
    fn ict_timer_a_retransmits_and_doubles() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        assert_eq!(ict.timer_a_interval, Duration::from_millis(500));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(1000));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(2000));
    }

    #[test]
    fn ict_timer_b_timeout() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        let actions = ict.process(IctEvent::TimerB);
        assert_eq!(ict.state, IctState::Terminated);
        assert!(has_timeout(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ict_provisional_to_proceeding() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        let actions = ict.process(IctEvent::Provisional(dummy_response(180, "Ringing")));
        assert_eq!(ict.state, IctState::Proceeding);
        assert!(has_pass_to_tu(&actions));
    }

    #[test]
    fn ict_2xx_terminates() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        let actions = ict.process(IctEvent::Response2xx(dummy_response(200, "OK")));
        assert_eq!(ict.state, IctState::Terminated);
        assert!(has_pass_to_tu(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ict_non2xx_to_completed_udp() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        let actions = ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        assert_eq!(ict.state, IctState::Completed);
        assert!(has_pass_to_tu(&actions));
        assert!(has_timer(&actions, TimerName::D));
    }

    #[test]
    fn ict_non2xx_tcp_immediate_terminate() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Reliable, TimerConfig::default());
        let actions = ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        assert_eq!(ict.state, IctState::Terminated);
        assert!(has_pass_to_tu(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ict_timer_d_terminates() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        let actions = ict.process(IctEvent::TimerD);
        assert_eq!(ict.state, IctState::Terminated);
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ict_completed_absorbs_retransmit() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        let actions = ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        assert!(actions.is_empty());
    }

    #[test]
    fn ict_proceeding_2xx_terminates() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        ict.process(IctEvent::Provisional(dummy_response(180, "Ringing")));
        let actions = ict.process(IctEvent::Response2xx(dummy_response(200, "OK")));
        assert_eq!(ict.state, IctState::Terminated);
        assert!(has_pass_to_tu(&actions));
        assert!(has_terminated(&actions));
    }

    #[test]
    fn ict_proceeding_non2xx_to_completed() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        ict.process(IctEvent::Provisional(dummy_response(180, "Ringing")));
        let actions = ict.process(IctEvent::ResponseNon2xx(dummy_response(603, "Decline")));
        assert_eq!(ict.state, IctState::Completed);
        assert!(has_pass_to_tu(&actions));
    }

    // =======================================================================
    // ICT RFC 3261 §17.1.1.2 bug fix tests
    // =======================================================================

    /// Verify Timer A interval is capped at T2 (4000ms) and does not grow
    /// beyond it, per RFC 3261 §17.1.1.2.
    #[test]
    fn ict_timer_a_capped_at_t2() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        // Default T1=500ms, T2=4000ms
        // Intervals: 500 → 1000 → 2000 → 4000 → 4000 (capped)
        assert_eq!(ict.timer_a_interval, Duration::from_millis(500));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(1000));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(2000));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(4000)); // T2 cap

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(4000)); // stays at T2

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(4000)); // still capped
    }

    /// Verify Timer A fires in Proceeding state: retransmits the INVITE
    /// and restarts Timer A with a T2-capped interval.
    #[test]
    fn ict_proceeding_timer_a_retransmits() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());
        assert_eq!(ict.timer_a_interval, Duration::from_millis(500));

        // Enter Proceeding
        ict.process(IctEvent::Provisional(dummy_response(180, "Ringing")));
        assert_eq!(ict.state, IctState::Proceeding);

        // Timer A should retransmit in Proceeding
        let actions = ict.process(IctEvent::TimerA);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::A));
        // Interval doubled: 500 → 1000
        assert_eq!(ict.timer_a_interval, Duration::from_millis(1000));

        // Fire again — should still retransmit
        let actions = ict.process(IctEvent::TimerA);
        assert!(has_send(&actions));
        assert!(has_timer(&actions, TimerName::A));
        assert_eq!(ict.timer_a_interval, Duration::from_millis(2000));

        // Verify T2 capping works in Proceeding too
        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(4000));

        ict.process(IctEvent::TimerA);
        assert_eq!(ict.timer_a_interval, Duration::from_millis(4000)); // capped at T2
    }

    /// Verify Timer A is cancelled when a non-2xx final response arrives
    /// in Proceeding state (RFC 3261 §17.1.1.2).
    #[test]
    fn ict_proceeding_non2xx_cancels_timer_a() {
        let (mut ict, _) = Ict::new(dummy_invite(), Transport::Udp, TimerConfig::default());

        // Enter Proceeding
        ict.process(IctEvent::Provisional(dummy_response(180, "Ringing")));
        assert_eq!(ict.state, IctState::Proceeding);

        // Receive non-2xx final
        let actions = ict.process(IctEvent::ResponseNon2xx(dummy_response(486, "Busy Here")));
        assert_eq!(ict.state, IctState::Completed);

        // Both Timer A and Timer B must be cancelled
        assert!(has_cancel_timer(&actions, TimerName::A));
        assert!(has_cancel_timer(&actions, TimerName::B));
        assert!(has_pass_to_tu(&actions));
    }
}
