"""WebRTC B2BUA call test — minimal flow-routing B2BUA.

Two sip.js WS user agents register; an INVITE between them is bridged by the
B2BUA, which forks the B-leg INVITE over the callee's captured inbound WebSocket
flow (RFC 7118 §5 / RFC 5626 §5.3) — the Contact URI is an unresolvable
`<uuid>.invalid` host, so connection reuse is the only way to reach the callee.
Auth is omitted so the test isolates the B2BUA WS dial/fork routing path.

REGISTER (and the docker OPTIONS healthcheck) are handled in the proxy plane;
the call itself is handled by the B2BUA plane.
"""
from siphon import proxy, registrar, b2bua, log


@proxy.on_request
def route(request):
    # Local OPTIONS keepalive (also answers the docker UDP healthcheck probe).
    if request.method == "OPTIONS" and not request.ruri.user:
        request.reply(200, "OK")
        return

    if request.method == "REGISTER":
        registrar.save(request)
        return


@b2bua.on_invite
def on_invite(call):
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return

    log.info(
        f"B2BUA bridging {call.from_uri} -> {len(contacts)} contact(s); "
        f"flow={'yes' if contacts[0].flow else 'no'} local={contacts[0].is_local}"
    )
    # Pass Contact objects: the B-leg INVITE routes over each is_local contact's
    # captured inbound WebSocket flow instead of DNS-resolving the .invalid URI.
    call.fork(contacts, strategy="parallel", timeout=30)


@b2bua.on_bye
def on_bye(call, initiator):
    log.info(f"B2BUA call ended (initiator: {initiator.side})")
    call.terminate()
