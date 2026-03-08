"""
_siphon_registry — internal handler registry.

Decorators in the `siphon` Python package write entries here.
The Rust engine reads them after script execution to build the handler table.

Each entry is a 4-tuple: (kind, filter, callable, is_async)
  - kind:     str — "proxy.on_request", "b2bua.on_invite", etc.
  - filter:   str | None — method filter for proxy.on_request (e.g. "REGISTER")
  - callable: the decorated function
  - is_async: bool — True if asyncio.iscoroutinefunction(callable)
"""

_handlers = []


def register(kind, filter, callable, is_async):
    """Add a handler to the registry."""
    _handlers.append((kind, filter, callable, is_async))


def entries():
    """Return all registered handlers."""
    return list(_handlers)


def clear():
    """Clear all registrations (called before each script load)."""
    _handlers.clear()
