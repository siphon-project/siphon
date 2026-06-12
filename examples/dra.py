"""SIPhon Diameter Routing Agent (DRA) dispatch script.

Routes inbound Diameter requests from authenticated peers to a backend peer
pool chosen from the per-tenant routing table in ``dra.yaml`` (surfaced to the
script via ``diameter.config``).

The two Rust-side auth gates (source-IP ACL + Origin-Host validation) have
already passed before ``@diameter.on_inbound_cer`` / ``@diameter.on_request``
run — a script bug cannot admit an unauthenticated peer.
"""

from siphon import diameter, log

# Diameter Result-Codes used here (RFC 6733 §7.1).
DIAMETER_UNABLE_TO_DELIVER = 3002
DIAMETER_REALM_NOT_SERVED = 3003

# Apps whose transactions should stick to one backend for a session.
STICKY_APPS = {"Cx", "Sh", "Gx", "Rx", "Ro", "Rf"}


@diameter.on_inbound_cer
def cer_received(peer_addr, peer_name, asserted_origin_host):
    """Advertise this tenant's identity back in the CEA."""
    tenant = _tenant_of(peer_name)
    identity = diameter.config["tenants"][tenant]["identity"]
    log.info(f"DRA CER from {peer_name}@{peer_addr} ({asserted_origin_host})")
    return identity["origin_host"], identity["origin_realm"]


@diameter.on_request
async def handle(req):
    """Route one inbound request to a backend pool and relay the answer."""
    tenant = req.peer.tenant
    route = _route_for(tenant, req.application_name, req.dest_realm)
    if route is None:
        log.warn(f"DRA: no route for {req.application_name} / {req.dest_realm}")
        return req.reject(DIAMETER_REALM_NOT_SERVED)

    destinations = route.get("destinations") or [route["destination"]]
    pool = diameter.peer_pool(tenant, destinations)

    if req.application_name in STICKY_APPS:
        peer = pool.pick_sticky(req.session_id or req.peer.name, ttl_secs=300)
    else:
        peer = pool.pick_round_robin()

    if peer is None:
        log.warn(f"DRA: no live backend for {req.application_name}")
        return req.reject(DIAMETER_UNABLE_TO_DELIVER)

    # forward_to handles Route-Record loop detection and synthesises an error
    # answer (3005/3002/3004) on loop / unreachable / timeout.
    return await req.forward_to(peer, timeout_secs=10)


@diameter.on_request_completed
def completed(req, answer, latency_us):
    """Emit a signalling event for every relayed request."""
    diameter.event_sink.emit(
        {
            "tenant": req.peer.tenant,
            "peer": req.peer.name,
            "application": req.application_name,
            "command": req.command_name,
            "session_id": req.session_id,
            "result_code": answer.result_code if answer else None,
            "latency_us": latency_us,
        }
    )


def _tenant_of(peer_name):
    """Find which tenant a client peer belongs to (single-tenant example)."""
    for name, tenant in diameter.config["tenants"].items():
        if any(client["name"] == peer_name for client in tenant.get("clients", [])):
            return name
    return "default"


def _route_for(tenant, application_name, dest_realm):
    """First matching route for (application, optional realm)."""
    routes = diameter.config["tenants"][tenant].get("routes", [])
    for route in routes:
        if route.get("application", "").lower() != (application_name or "").lower():
            continue
        realm = route.get("realm")
        if realm is not None and dest_realm is not None and realm != dest_realm:
            continue
        return route
    return None
