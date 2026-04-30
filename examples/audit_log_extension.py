"""
Companion script for examples/audit_log_extension.rs.

Demonstrates the script-side half of the extension contract: writing
into ``_siphon_registry`` directly under a custom kind that siphon-core
does not interpret. The host extension reads matching entries via
``ScriptHandle::handlers_for("audit.sink")`` and dispatches into them.

In a real extension, the registration call would be wrapped in a
decorator the extension's Python facade exports — e.g.

    from siphon_audit import audit
    @audit.sink(level="info")
    def on_event(event): ...

so script authors never see the raw _siphon_registry tuple format. This
example keeps the raw form visible for clarity.
"""

import _siphon_registry as _r
from siphon import audit, log, proxy

# Built-in handler — siphon-core dispatches these on incoming SIP requests.
@proxy.on_request
def route(request):
    request.relay()

# Custom-kind handler — siphon-core does not invoke these. The host
# extension (audit_log_extension.rs) reads them via
# ScriptHandle::handlers_for("audit.sink") and calls them directly.
def _audit_sink(event):
    """Receive an audit event from the host extension."""
    log.info(f"audit event: {event} (host has dispatched {audit.dispatched()})")


_r.register(
    "audit.sink",       # kind — opaque to siphon-core
    None,               # filter — unused for custom kinds
    _audit_sink,        # callable
    False,              # is_async
    {"level": "info"},  # metadata — read via handle.options(py)
)
