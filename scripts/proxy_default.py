"""
SIPhon default residential proxy script.

Handles:
- OPTIONS keepalive (local)
- REGISTER with digest auth
- In-dialog sequential requests (loose routing)
- INVITE / other requests via location lookup with parallel forking
"""
from siphon import proxy, registrar, auth, log, presence

DOMAIN = "example.com"


@proxy.on_request
def route(request):
    # Local OPTIONS ping (e.g. from SBC/gateway keepalive)
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # Sequential requests within an existing dialog
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        request.reply(200, "OK")
        return

    # PUBLISH — handle locally as Event State Compositor (RFC 3903)
    if request.method == "PUBLISH":
        body = request.body
        if body is not None:
            body = body.decode("utf-8") if isinstance(body, bytes) else body
        etag = presence.publish(
            str(request.ruri),
            body or "",
            expires=3600,
        )
        request.set_header("SIP-ETag", etag)
        request.reply(200, "OK")
        return

    # SUBSCRIBE/NOTIFY/MESSAGE — relay to registered contact like INVITE
    # (A real deployment would have a presence server; here we just proxy them.)

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.record_route()
    request.fork([c.uri for c in contacts])
