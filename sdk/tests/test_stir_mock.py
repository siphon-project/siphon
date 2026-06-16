"""
Tests for the MockStir class in siphon_sdk.mock_module.

Verifies sign/sign_div/verify/apply_verstat behavior and reset.
"""

import pytest
from siphon_sdk.mock_module import install, reset, get_stir, MockStirResult


@pytest.fixture(autouse=True)
def setup_siphon():
    install()
    yield
    reset()


class _FakeUri:
    def __init__(self, user):
        self.user = user


class FakeRequest:
    """Minimal request stub exposing the bits MockStir reads."""

    def __init__(self, from_user="12155550112", to_user="12025550100"):
        self.from_uri = _FakeUri(from_user)
        self.to_uri = _FakeUri(to_user)
        self.ruri = _FakeUri(to_user)
        self._headers = {}

    def set_header(self, name, value):
        self._headers[name] = value

    def get_header(self, name):
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return None


class TestSign:
    def test_sign_adds_identity_header_and_returns_origid(self):
        stir = get_stir()
        request = FakeRequest()
        origid = stir.sign(request, attestation="A")
        assert origid
        identity = request.get_header("Identity")
        assert identity is not None
        assert "ppt=shaken" in identity
        assert stir.signed[0]["attestation"] == "A"
        assert stir.signed[0]["orig_tn"] == "12155550112"
        assert stir.signed[0]["dest_tn"] == "12025550100"

    def test_sign_honours_explicit_origid_and_tns(self):
        stir = get_stir()
        request = FakeRequest()
        origid = stir.sign(
            request,
            attestation="B",
            origid="fixed-origid",
            orig_tn="18005550000",
            dest_tn="18005551111",
        )
        assert origid == "fixed-origid"
        assert stir.signed[0]["orig_tn"] == "18005550000"

    def test_sign_invalid_attestation_raises(self):
        stir = get_stir()
        with pytest.raises(ValueError):
            stir.sign(FakeRequest(), attestation="Z")

    def test_sign_disabled_raises(self):
        stir = get_stir()
        stir.signing_enabled = False
        with pytest.raises(RuntimeError):
            stir.sign(FakeRequest())

    def test_sign_missing_orig_tn_raises(self):
        stir = get_stir()
        request = FakeRequest(from_user=None)
        with pytest.raises(ValueError):
            stir.sign(request)


class TestSignDiv:
    def test_sign_div_adds_div_identity(self):
        stir = get_stir()
        request = FakeRequest()
        stir.sign_div(request, div_tn="12155550199")
        identity = request.get_header("Identity")
        assert "ppt=div" in identity
        assert stir.signed[0]["div_tn"] == "12155550199"

    def test_sign_div_requires_div_tn(self):
        stir = get_stir()
        with pytest.raises(ValueError):
            stir.sign_div(FakeRequest())


class TestVerify:
    def test_verify_passes_when_identity_present(self):
        stir = get_stir()
        request = FakeRequest()
        stir.sign(request)
        result = stir.verify(request)
        assert result.verstat == "TN-Validation-Passed"
        assert result.passed is True
        assert result.attestation == "A"

    def test_verify_no_identity_is_no_validation(self):
        stir = get_stir()
        result = stir.verify(FakeRequest())
        assert result.verstat == "No-TN-Validation"
        assert result.passed is False

    def test_set_verify_result_pins_outcome(self):
        stir = get_stir()
        stir.set_verify_result(
            verstat="TN-Validation-Failed", passed=False, reason="bad sig"
        )
        request = FakeRequest()
        stir.sign(request)
        result = stir.verify(request)
        assert result.verstat == "TN-Validation-Failed"
        assert result.reason == "bad sig"

    def test_verify_disabled_raises(self):
        stir = get_stir()
        stir.verification_enabled = False
        with pytest.raises(RuntimeError):
            stir.verify(FakeRequest())


class TestApplyVerstat:
    def test_apply_verstat_records(self):
        stir = get_stir()
        result = MockStirResult(verstat="TN-Validation-Passed", passed=True)
        stir.apply_verstat(FakeRequest(), result)
        assert stir.applied_verstats == ["TN-Validation-Passed"]


class TestReset:
    def test_clear_resets_state(self):
        stir = get_stir()
        request = FakeRequest()
        stir.sign(request)
        stir.set_verify_result(verstat="TN-Validation-Failed")
        stir.clear()
        assert stir.signed == []
        assert stir._next_result is None
        assert stir.signing_enabled is True
