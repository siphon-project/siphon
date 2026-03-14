"""Tests for the @timer.every() decorator — periodic timer callbacks."""

import asyncio

from siphon_sdk.mock_module import install, reset, get_registry


def setup_function():
    install()
    reset()


def test_timer_every_registers_handler():
    """@timer.every(seconds=N) registers a timer.every handler."""
    from siphon import timer

    @timer.every(seconds=30)
    def health_check():
        pass

    registry = get_registry()
    handlers = registry.handlers.get("timer.every", [])
    assert len(handlers) == 1
    _filter, fn, is_async, metadata = handlers[0]
    assert fn is health_check
    assert not is_async
    assert metadata["seconds"] == 30
    assert metadata["name"] == "health_check"
    assert metadata["jitter"] == 0


def test_timer_every_with_custom_name():
    """Custom name= overrides function name in metadata."""
    from siphon import timer

    @timer.every(seconds=300, name="stats_push")
    def push_stats():
        pass

    registry = get_registry()
    handlers = registry.handlers.get("timer.every", [])
    assert len(handlers) == 1
    _, _, _, metadata = handlers[0]
    assert metadata["name"] == "stats_push"
    assert metadata["seconds"] == 300


def test_timer_every_with_jitter():
    """Jitter param is stored in metadata."""
    from siphon import timer

    @timer.every(seconds=60, jitter=5)
    def check():
        pass

    registry = get_registry()
    handlers = registry.handlers.get("timer.every", [])
    _, _, _, metadata = handlers[0]
    assert metadata["jitter"] == 5


def test_timer_every_async_detected():
    """Async functions are correctly detected."""
    from siphon import timer

    @timer.every(seconds=10)
    async def async_check():
        pass

    registry = get_registry()
    handlers = registry.handlers.get("timer.every", [])
    assert len(handlers) == 1
    _, fn, is_async, _ = handlers[0]
    assert fn is async_check
    assert is_async


def test_timer_every_multiple_timers():
    """Multiple @timer.every decorators register multiple handlers."""
    from siphon import timer

    @timer.every(seconds=10)
    def fast():
        pass

    @timer.every(seconds=600, name="slow")
    async def slow():
        pass

    registry = get_registry()
    handlers = registry.handlers.get("timer.every", [])
    assert len(handlers) == 2
    assert handlers[0][3]["seconds"] == 10
    assert handlers[1][3]["seconds"] == 600
    assert handlers[1][3]["name"] == "slow"


def test_timer_coexists_with_proxy_handlers():
    """Timer handlers don't interfere with proxy handlers."""
    from siphon import proxy, timer

    @proxy.on_request
    def route(request):
        pass

    @timer.every(seconds=30)
    def check():
        pass

    registry = get_registry()
    proxy_handlers = registry.get("proxy.on_request")
    timer_handlers = registry.handlers.get("timer.every", [])
    assert len(proxy_handlers) == 1
    assert len(timer_handlers) == 1
