"""
Tests demonstrating inline script loading and async handlers.

Shows how to test scripts without separate files, useful for quick
validation during development.
"""

import pytest
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Contact


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestInlineScripts:
    """Load scripts from strings for quick testing."""

    def test_simple_echo(self, harness):
        harness.load_source("""
from siphon import proxy

@proxy.on_request
def route(request):
    request.reply(200, "OK")
""")
        result = harness.send_request("OPTIONS", "sip:example.com")
        assert result.status_code == 200

    def test_method_filter(self, harness):
        harness.load_source("""
from siphon import proxy

@proxy.on_request("REGISTER")
def handle_register(request):
    request.reply(200, "OK")

@proxy.on_request("INVITE")
def handle_invite(request):
    request.reply(404, "Not Found")
""")
        reg = harness.send_request("REGISTER", "sip:alice@example.com")
        assert reg.status_code == 200

        inv = harness.send_request("INVITE", "sip:bob@example.com")
        assert inv.status_code == 404

    def test_silent_drop(self, harness):
        harness.load_source("""
from siphon import proxy

@proxy.on_request
def route(request):
    # Intentional silent drop - no reply/relay/fork
    return
""")
        result = harness.send_request("INVITE", "sip:scanner@evil.com")
        assert result.was_dropped

    def test_rate_limiting(self, harness):
        harness.load_source("""
from siphon import proxy

@proxy.on_request
def route(request):
    if not proxy._utils.rate_limit(request, 60.0, 100):
        return  # silent drop
    request.relay()
""")
        # Default: rate limit allows
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.was_relayed

        # Simulate rate limit exceeded
        harness.proxy._utils._rate_limit_allow = False
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.was_dropped


class TestAsyncHandlers:
    """Test async handler support."""

    def test_async_handler(self, harness):
        harness.load_source("""
from siphon import proxy, rtpengine, log

@proxy.on_request
async def route(request):
    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile="srtp_to_rtp")
        log.info("RTPEngine offer sent")
    request.relay()
""")
        result = harness.send_request(
            "INVITE", "sip:bob@example.com",
            body=b"v=0\\r\\n...",
            content_type="application/sdp",
        )
        assert result.was_relayed
        assert harness.rtpengine.operations == [("offer", "srtp_to_rtp")]
        assert any("RTPEngine" in msg for _, msg in harness.log.messages)

    def test_async_reply_handler(self, harness):
        harness.load_source("""
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    request.relay()

@proxy.on_reply
async def reply_route(request, reply):
    if reply.status_code == 200 and reply.has_body("application/sdp"):
        await rtpengine.answer(reply, profile="wss_to_rtp")
    reply.relay()
""")
        harness.send_request("INVITE", "sip:bob@example.com")
        reply_result = harness.send_reply(
            status_code=200,
            reason="OK",
            body=b"v=0\\r\\n...",
            content_type="application/sdp",
        )
        assert reply_result.was_relayed
        assert ("answer", "wss_to_rtp") in harness.rtpengine.operations


class TestCacheIntegration:
    """Test cache namespace."""

    def test_cache_fetch(self, harness):
        harness.cache.set_data("cnam", {"msisdn_display:1234": "Sales Dept"})

        harness.load_source("""
from siphon import proxy, cache, log

@proxy.on_request
async def route(request):
    display = await cache.fetch("cnam", "msisdn_display:1234")
    if display:
        request.set_from_display(display)
        log.info(f"CNAM: {display}")
    request.relay()
""")
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.was_relayed
        assert any("Sales Dept" in msg for _, msg in harness.log.messages)


class TestHeaderManipulation:
    """Test header set/get/remove methods."""

    def test_set_and_check_header(self, harness):
        harness.load_source("""
from siphon import proxy

@proxy.on_request
def route(request):
    request.set_header("X-Custom", "test-value")
    request.ensure_header("X-Custom", "should-not-overwrite")
    request.ensure_header("X-New", "new-value")
    request.relay()
""")
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.request.get_header("X-Custom") == "test-value"
        assert result.request.get_header("X-New") == "new-value"

    def test_source_ip_in(self, harness):
        harness.load_source("""
from siphon import proxy, log

@proxy.on_request
def route(request):
    if request.source_ip_in(["10.0.0.0/8", "172.16.0.0/12"]):
        log.info("trusted")
    else:
        log.info("untrusted")
    request.relay()
""")
        harness.send_request("INVITE", "sip:bob@example.com",
                             source_ip="10.1.2.3")
        assert ("info", "trusted") in harness.log.messages

        harness.log.clear()
        harness.send_request("INVITE", "sip:bob@example.com",
                             source_ip="8.8.8.8")
        assert ("info", "untrusted") in harness.log.messages
