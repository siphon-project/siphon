"""
SIPhon IMS P-CSCF script — first contact point for UEs.

Handles VoLTE/IMS registration with IPsec and media anchoring.

Flow (3GPP TS 33.203 / TS 24.229):
  1. UE sends initial REGISTER with Security-Client header (unprotected, port 5060)
  2. P-CSCF sends 401 with AKA challenge + Security-Server header
  3. UE establishes IPsec SAs, re-sends REGISTER over protected path (port 5064/5066)
  4. P-CSCF verifies credentials, creates server-side SAs, returns 200 OK
  5. Subsequent requests flow over IPsec-protected ports

Equivalent to: opensips_ims_pcscf/opensips.cfg from docker_open5gs

Config: examples/ims_pcscf.yaml
"""
from siphon import proxy, registrar, auth, diameter, log

REALM = "ims.example.com"
PCSCF_URI = f"sip:{REALM};lr"

# Track Rx sessions per dialog (call_id -> rx_session_id).
# Used to release QoS resources on BYE.
rx_sessions = {}


def on_invite_reply(request, reply):
    """Called when an INVITE response arrives (on_reply callback).

    On 200 OK with SDP, request dedicated bearer via Rx AAR to PCRF.
    The PCRF provisions a dedicated EPS bearer through the PGW (Gx).
    """
    if reply.status_code != 200:
        return

    if diameter.peer_count() == 0:
        return

    # Extract media info from SDP for the Rx flow description.
    # For now, request a generic audio bearer.
    call_id = request.call_id
    source_ip = request.source_ip

    result = diameter.rx_aar(
        media_type="audio",
        framed_ip=source_ip,
        flow_description=f"permit in 17 from {source_ip} to any",
    )
    if result:
        rx_sessions[call_id] = result["session_id"]
        log.info(f"Rx AAR success: session={result['session_id']} "
                 f"result_code={result['result_code']}")
    else:
        log.warn(f"Rx AAR failed for call {call_id}")


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"REGISTER from {request.from_uri} via {request.transport}")

    # Force UE to use security agreement (IPsec): reject REGISTER without
    # Security-Client header (3GPP TS 33.203 sec 6.1, RFC 3329).
    if not request.has_header("Security-Client"):
        request.set_header("Require", "sec-agree")
        request.reply(421, "Extension Required")
        log.info(f"rejected {request.from_uri}: no Security-Client (IPsec required)")
        return

    # Add Path header so subsequent requests route through P-CSCF (RFC 3327).
    request.add_path(PCSCF_URI)

    # Add P-Visited-Network-ID (3GPP TS 24.229 sec 5.2.2.2).
    request.set_header("P-Visited-Network-ID", REALM)

    # Challenge with AKA digest auth (401 WWW-Authenticate with AKAv1-MD5).
    # Uses locally-configured Milenage credentials (K, OP, AMF) — no HSS needed.
    # The nonce contains base64(RAND || AUTN) per 3GPP TS 33.203.
    # CK/IK are derived and stored for IPsec SA creation.
    if not auth.require_aka_digest(request, realm=REALM):
        # 401 challenge includes Security-Server header with our IPsec params.
        # The Rust-side auth handler injects Security-Server automatically when
        # AKA credentials are configured and CK/IK are derived.
        log.info(f"sent 401 AKA challenge to {request.from_uri}")
        return

    # Authenticated — save the registration.
    registrar.save(request)

    # Add P-Associated-URI for the authenticated user (3GPP TS 24.229 sec 5.2.2.4).
    public_id = f"sip:{request.auth_user}"
    if "@" not in public_id:
        public_id = f"{public_id}@{REALM}"
    request.set_header("P-Associated-URI", f"<{public_id}>")

    # Add Service-Route so subsequent requests from this UE route through us.
    request.set_header("Service-Route", f"<{PCSCF_URI}>")

    request.reply(200, "OK")
    log.info(f"registered {request.from_uri}")


@proxy.on_request("SUBSCRIBE|PUBLISH")
def handle_presence(request):
    """Forward presence requests (reg event, presence) toward the S-CSCF."""
    if request.in_dialog:
        if request.loose_route():
            request.record_route()
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    request.record_route()
    request.relay()


@proxy.on_request("OPTIONS")
def handle_options(request):
    if request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    request.relay()


@proxy.on_request
def handle_request(request):
    if request.method in ("REGISTER", "OPTIONS", "SUBSCRIBE", "PUBLISH"):
        return  # handled above

    # In-dialog requests (re-INVITE, BYE, UPDATE, PRACK, etc.)
    if request.in_dialog:
        if not request.loose_route():
            request.reply(404, "Not Here")
            return

        request.record_route()

        # Strip security headers from mid-dialog requests (topology hiding).
        request.remove_header("Security-Verify")

        # BYE — release Rx QoS resources (dedicated bearer teardown).
        if request.method == "BYE":
            rx_session = rx_sessions.pop(request.call_id, None)
            if rx_session and diameter.peer_count() > 0:
                result = diameter.rx_str(rx_session)
                log.info(f"Rx STR for call {request.call_id}: "
                         f"result_code={result}")

        request.relay()
        return

    # Initial INVITE — add P-Visited-Network-ID and route.
    if request.method == "INVITE":
        request.ensure_header("P-Visited-Network-ID", REALM)

    # Look up registered contacts for terminating calls.
    contacts = registrar.lookup(str(request.ruri))
    if not contacts:
        # Not registered locally — relay toward S-CSCF / I-CSCF.
        request.record_route()
        # Use on_reply to trigger Rx AAR on 200 OK (QoS reservation).
        if request.method == "INVITE":
            request.relay(on_reply=on_invite_reply)
        else:
            request.relay()
        return

    request.record_route()
    if len(contacts) == 1:
        if request.method == "INVITE":
            request.relay(contacts[0].uri, on_reply=on_invite_reply)
        else:
            request.relay(contacts[0].uri)
    else:
        request.fork([c.uri for c in contacts])
