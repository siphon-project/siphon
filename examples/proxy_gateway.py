"""
SIPhon proxy gateway routing script for functional testing.

Routes INVITE requests to a gateway selected by gateway.select()
instead of looking up registered contacts.  Proves end-to-end gateway
wiring: YAML config -> Rust DispatcherManager -> Python API -> relay.
"""
from siphon import proxy, registrar, auth, gateway, log

DOMAIN = "siphon.test"


@proxy.on_request
def route(request):
    if request.max_forwards == 0:
        request.reply(483, "Too Many Hops")
        return

    # Local OPTIONS keepalive
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # In-dialog sequential requests
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "CANCEL":
        request.relay()
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        request.reply(200, "OK")
        return

    # For INVITE (and other out-of-dialog requests), use gateway dispatcher
    destination = gateway.select("gateways")
    if not destination:
        log.error("no healthy gateway in 'gateways' group")
        request.reply(503, "Service Unavailable")
        return

    log.info(f"gateway selected: {destination.uri}")
    request.record_route()
    request.relay(destination.uri)
