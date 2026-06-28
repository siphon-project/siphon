"use strict";
//
// SIP-over-WebSocket two-UA call test for SIPhon flow-based MT routing.
//
// Two real sip.js User Agents (Alice, Bob) connect over WS, REGISTER, and call
// each other in BOTH directions:
//   - call#1 Alice -> Bob : Alice is MO (originating from a WebRTC leg),
//                           Bob is MT  (terminating to a WebRTC leg) <-- the fix
//   - call#2 Bob   -> Alice: the mirror, so each leg is exercised both ways.
//
// The sip.js Contact is `sip:<id>@<uuid>.invalid;transport=ws` — an
// unresolvable host — so the only way the INVITE reaches the callee is RFC 5626
// §5.3 connection reuse over its captured inbound WebSocket flow. Pre-fix the
// INVITE never arrived; the callee-received assertion is the regression guard.
//
// Signaling-only: a stub SessionDescriptionHandler returns canned SDP (Node has
// no WebRTC stack, and siphon just relays the body). Exit 0 = pass, 1 = fail.

global.WebSocket = require("ws");
const { UserAgent, Registerer, Inviter, SessionState, RegistererState } = require("sip.js");

const WS_SERVER = process.env.WS_SERVER || "ws://172.20.0.80:8080";
const DOMAIN = process.env.SIP_DOMAIN || "example.com";
const STEP_TIMEOUT_MS = Number(process.env.STEP_TIMEOUT_MS || 15000);
const OVERALL_TIMEOUT_MS = Number(process.env.OVERALL_TIMEOUT_MS || 60000);

const FAKE_SDP = [
  "v=0",
  "o=- 0 0 IN IP4 127.0.0.1",
  "s=siphon-webrtc-test",
  "c=IN IP4 127.0.0.1",
  "t=0 0",
  "m=audio 9 RTP/AVP 0",
  "a=rtpmap:0 PCMU/8000",
  "a=sendrecv",
  "",
].join("\r\n");

// Minimal SessionDescriptionHandler — canned SDP, no media. siphon only relays
// the body, so this is sufficient to drive offer/answer signaling end to end.
class StubSDH {
  getDescription() {
    return Promise.resolve({ body: FAKE_SDP, contentType: "application/sdp" });
  }
  setDescription() {
    return Promise.resolve();
  }
  hasDescription(contentType) {
    return contentType === "application/sdp";
  }
  close() {}
  sendDtmf() {
    return false;
  }
}

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

function makeUA(user, onInvite) {
  const uri = UserAgent.makeURI(`sip:${user}@${DOMAIN}`);
  if (!uri) throw new Error(`could not build URI for ${user}`);
  return new UserAgent({
    uri,
    transportOptions: { server: WS_SERVER },
    sessionDescriptionHandlerFactory: () => new StubSDH(),
    delegate: { onInvite },
    logLevel: "warn",
  });
}

function withTimeout(promise, ms, label) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

function waitForRegistered(registerer) {
  return new Promise((resolve, reject) => {
    registerer.stateChange.addListener((state) => {
      if (state === RegistererState.Registered) resolve();
    });
    registerer.register().catch(reject);
  });
}

function placeCall(ua, toUser) {
  return new Promise((resolve, reject) => {
    const target = UserAgent.makeURI(`sip:${toUser}@${DOMAIN}`);
    const inviter = new Inviter(ua, target);
    inviter.stateChange.addListener((state) => {
      if (state === SessionState.Established) resolve(inviter);
      else if (state === SessionState.Terminated) reject(new Error("terminated before established (no 200)"));
    });
    inviter.invite().catch(reject);
  });
}

function waitTerminated(session) {
  return new Promise((resolve) => {
    if (session.state === SessionState.Terminated) return resolve();
    session.stateChange.addListener((state) => {
      if (state === SessionState.Terminated) resolve();
    });
  });
}

// Send BYE and resolve with the actual response status code. Crucial: the
// session reaches Terminated on ANY final response (incl. 502), so waiting on
// termination alone hides a failed teardown — we must assert the BYE got 200,
// which only happens if the in-dialog request actually reached the far UE.
function sendByeAndAwaitResponse(session) {
  return new Promise((resolve, reject) => {
    session
      .bye({
        requestDelegate: {
          onAccept: (response) => resolve(response.message.statusCode),
          onReject: (response) => resolve(response.message.statusCode),
        },
      })
      .catch(reject);
  });
}

async function callAndHangup(label, fromUA, fromUser, toUser, calleeFlag) {
  log(`${label}: ${fromUser} -> ${toUser} INVITE`);
  calleeFlag.got = false;
  const session = await withTimeout(placeCall(fromUA, toUser), STEP_TIMEOUT_MS, `${label} establish`);
  if (!calleeFlag.got) {
    throw new Error(`${label}: callee ${toUser} never received the INVITE — MT routing over the WS flow failed`);
  }
  log(`${label}: established (callee received INVITE); sending BYE`);
  const byeCode = await withTimeout(sendByeAndAwaitResponse(session), STEP_TIMEOUT_MS, `${label} bye`);
  if (byeCode !== 200) {
    throw new Error(`${label}: BYE got ${byeCode} (expected 200) — in-dialog routing to the WS UE failed`);
  }
  await withTimeout(waitTerminated(session), STEP_TIMEOUT_MS, `${label} terminate`);
  log(`${label}: PASS (full INVITE/200/ACK/BYE over WS, BYE 200)`);
}

async function main() {
  const aliceGot = { got: false };
  const bobGot = { got: false };
  const accept = (flag) => (invitation) => {
    flag.got = true;
    invitation.accept().catch((error) => log("accept error:", error.message || error));
  };

  const alice = makeUA("alice", accept(aliceGot));
  const bob = makeUA("bob", accept(bobGot));

  await withTimeout(alice.start(), STEP_TIMEOUT_MS, "alice transport connect");
  await withTimeout(bob.start(), STEP_TIMEOUT_MS, "bob transport connect");
  log("both WS transports connected to", WS_SERVER);

  const aliceReg = new Registerer(alice);
  const bobReg = new Registerer(bob);
  await withTimeout(waitForRegistered(aliceReg), STEP_TIMEOUT_MS, "alice register");
  await withTimeout(waitForRegistered(bobReg), STEP_TIMEOUT_MS, "bob register");
  log("both UAs registered over WS (Contact host is .invalid — connection reuse only)");

  // MO from Alice / MT toward Bob — the regression-critical direction.
  await callAndHangup("call#1 alice->bob", alice, "alice", "bob", bobGot);
  // Mirror: MO from Bob / MT toward Alice.
  await callAndHangup("call#2 bob->alice", bob, "bob", "alice", aliceGot);

  log("ALL CALLS PASSED — MT and MO over WebRTC (WS) legs both directions");
  await aliceReg.unregister().catch(() => {});
  await bobReg.unregister().catch(() => {});
  await alice.stop().catch(() => {});
  await bob.stop().catch(() => {});
}

const watchdog = setTimeout(() => {
  log("FAIL: overall timeout");
  process.exit(1);
}, OVERALL_TIMEOUT_MS);

main()
  .then(() => {
    clearTimeout(watchdog);
    log("SUCCESS");
    process.exit(0);
  })
  .catch((error) => {
    clearTimeout(watchdog);
    log("FAIL:", error.message || error);
    process.exit(1);
  });
