"""
Tests for the default B2BUA script (b2bua_default.py).
"""

import pytest
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Contact


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    h.load_script("../scripts/b2bua_default.py")
    yield h
    h.reset()
    h.close()


class TestB2buaInvite:
    def test_invite_no_contacts(self, harness):
        result = harness.send_invite(
            ruri="sip:bob@example.com",
            from_uri="sip:alice@example.com",
        )
        assert result.was_rejected
        assert result.status_code == 404

    def test_invite_with_contacts(self, harness):
        harness.registrar.add_contact(
            "sip:bob@example.com",
            Contact(uri="sip:bob@192.168.1.5:5060"),
        )
        result = harness.send_invite(
            ruri="sip:bob@example.com",
            from_uri="sip:alice@example.com",
        )
        assert result.action == "fork"
        assert result.targets == ["sip:bob@192.168.1.5:5060"]

    def test_invite_logs(self, harness):
        harness.registrar.add_contact(
            "sip:bob@example.com",
            Contact(uri="sip:bob@192.168.1.5:5060"),
        )
        harness.send_invite(
            ruri="sip:bob@example.com",
            from_uri="sip:alice@example.com",
        )
        assert any("Forking" in msg for _, msg in harness.log.messages)


class TestB2buaAnswer:
    def test_answer_logged(self, harness):
        from siphon_sdk.call import Call
        call = Call(state="answered", call_id="test-123")
        harness.send_answer(call)
        assert any("answered" in msg for _, msg in harness.log.messages)


class TestB2buaFailure:
    def test_failure_rejects(self, harness):
        result = harness.send_failure(code=486, reason="Busy Here")
        assert result.was_rejected
        assert result.status_code == 486


class TestB2buaBye:
    def test_bye_terminates(self, harness):
        result = harness.send_bye(initiator_side="a")
        assert result.was_terminated
        assert any("ended" in msg for _, msg in harness.log.messages)
