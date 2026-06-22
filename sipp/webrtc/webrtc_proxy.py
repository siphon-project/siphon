"""WebRTC (SIP-over-WebSocket) call test — minimal flow-routing proxy.

Two sip.js WS user agents register and call each other.  Routing to a
WS-registered UE uses ``request.fork(contacts)`` so the INVITE is delivered over
the callee's captured inbound WebSocket connection (RFC 7118 §5 / RFC 5626 §5.3)
— the Contact URI is an unresolvable ``<uuid>.invalid`` host, so connection
reuse is the only way back.  Auth is intentionally omitted so the test isolates
the WebSocket MT-routing path (the digest path is covered by the http-auth
profile).
"""
from siphon import proxy, registrar, log


@proxy.on_request
def route(request):
    # Local OPTIONS keepalive (also answers the docker UDP healthcheck probe).
    if request.method == "OPTIONS" and not request.ruri.user:
        request.reply(200, "OK")
        return

    # In-dialog requests (2xx ACK, BYE, re-INVITE) follow the dialog route set.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "REGISTER":
        registrar.save(request)
        return

    if request.method == "CANCEL":
        request.relay()
        return

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    # INVITE / MESSAGE / etc. → route to the registered WS contact.
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    log.info(
        f"routing {request.method} {request.ruri} over "
        f"{len(contacts)} contact(s); "
        f"flow={'yes' if contacts[0].flow else 'no'} "
        f"local={contacts[0].is_local}"
    )
    request.record_route()
    # The fix: pass Contact objects so each is_local binding routes over its
    # captured inbound WebSocket flow instead of DNS-resolving the .invalid URI.
    request.fork(contacts)
