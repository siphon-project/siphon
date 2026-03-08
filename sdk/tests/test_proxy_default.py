"""
Tests for the default residential proxy script (proxy_default.py).

Demonstrates how to use SipTestHarness to test a real SIPhon script.
"""

import pytest
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Contact


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    h.load_script("../scripts/proxy_default.py")
    yield h
    h.reset()
    h.close()


class TestOptionsKeepalive:
    """Local OPTIONS without user part should get 200 OK."""

    def test_options_local(self, harness):
        result = harness.send_request("OPTIONS", "sip:example.com")
        assert result.action == "reply"
        assert result.status_code == 200

    def test_options_with_user_not_local(self, harness):
        """OPTIONS to a user should go through normal routing."""
        result = harness.send_request("OPTIONS", "sip:alice@example.com")
        # No contacts registered -> 404
        assert result.status_code == 404


class TestMaxForwards:
    """Max-Forwards == 0 should be rejected with 483."""

    def test_max_forwards_zero(self, harness):
        result = harness.send_request("INVITE", "sip:bob@example.com",
                                      max_forwards=0)
        assert result.status_code == 483


class TestRegister:
    """REGISTER should trigger digest auth challenge."""

    def test_register_no_auth(self, harness):
        result = harness.send_request("REGISTER", "sip:alice@example.com",
                                      from_uri="sip:alice@example.com")
        assert result.status_code == 401

    def test_register_with_auth(self, harness):
        harness.auth._allow = True
        result = harness.send_request("REGISTER", "sip:alice@example.com",
                                      from_uri="sip:alice@example.com")
        assert result.status_code == 200


class TestInviteRouting:
    """INVITE should look up contacts and fork."""

    def test_invite_not_found(self, harness):
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.status_code == 404

    def test_invite_with_contacts(self, harness):
        harness.registrar.add_contact(
            "sip:bob@example.com",
            Contact(uri="sip:bob@192.168.1.5:5060"),
        )
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.action == "fork"
        assert result.targets == ["sip:bob@192.168.1.5:5060"]
        assert result.record_routed

    def test_invite_multiple_contacts(self, harness):
        harness.registrar.add_contact(
            "sip:bob@example.com",
            Contact(uri="sip:bob@192.168.1.5:5060", q=0.8),
        )
        harness.registrar.add_contact(
            "sip:bob@example.com",
            Contact(uri="sip:bob@10.0.0.2:5060", q=1.0),
        )
        result = harness.send_request("INVITE", "sip:bob@example.com")
        assert result.was_forked
        assert len(result.targets) == 2

    def test_invite_address_incomplete(self, harness):
        """INVITE to domain without user part -> 484."""
        result = harness.send_request("INVITE", "sip:example.com")
        assert result.status_code == 484


class TestInDialog:
    """In-dialog requests should be loose-routed."""

    def test_in_dialog_relay(self, harness):
        result = harness.send_request(
            "BYE", "sip:bob@192.168.1.5:5060",
            from_tag="abc123",
            to_tag="def456",
        )
        assert result.was_relayed

    def test_cancel_relay(self, harness):
        result = harness.send_request("CANCEL", "sip:bob@example.com")
        assert result.was_relayed
