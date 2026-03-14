"""
Timer route examples — periodic housekeeping callbacks.

Timer handlers run on a Tokio interval in the Rust runtime.  They receive
no SIP request/call context but can use all other namespaces (registrar,
cache, gateway, log, presence, etc.).

Usage:
    @timer.every(seconds=N)                          # basic recurring timer
    @timer.every(seconds=N, name="my_timer")         # custom name for logs
    @timer.every(seconds=N, jitter=5)                # random 0-5s jitter per tick
"""
from siphon import proxy, timer, gateway, log, presence, registrar


# ── Proxy route (normal request handling) ────────────────────────────

@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    if request.method == "REGISTER":
        registrar.save(request)
        request.reply(200, "OK")
        return

    contacts = registrar.lookup(request.ruri)
    if contacts:
        request.fork([c.uri for c in contacts])
    else:
        request.reply(404, "Not Found")


# ── Timer routes ─────────────────────────────────────────────────────

@timer.every(seconds=30)
async def check_gateways():
    """Periodic health probe — log warnings for unhealthy gateways."""
    for dest in gateway.list("carriers"):
        if not dest.healthy:
            log.warn(f"Gateway {dest.uri} is down")


@timer.every(seconds=60)
def expire_presence():
    """Clean up expired presence documents and subscriptions."""
    presence.expire_stale()
    log.info(f"Presence docs: {presence.document_count()}, subs: {presence.subscription_count()}")


@timer.every(seconds=300, name="registration_audit", jitter=15)
async def audit_registrations():
    """Periodic audit of active registrations."""
    log.info("Running registration audit")
