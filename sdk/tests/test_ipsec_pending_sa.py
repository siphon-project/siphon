"""Tests for ``ipsec.PendingSA`` mock — focused on the
``activate(hard_lifetime_secs=…)`` kwarg, which re-pins the kernel SA
hard-lifetime so it tracks the registrar's grant (3GPP TS 33.203 §7.4)
instead of the placeholder installed at ``ipsec.allocate`` time.
"""
import asyncio

import pytest

from siphon_sdk import mock_module
from siphon_sdk.mock_module import (
    MockAuthVectorHandle,
    MockSecurityOffer,
    _TransformEnum,
)


def _fresh_ipsec():
    mock_module.install()
    ipsec = mock_module.get_ipsec()
    ipsec.clear()
    return ipsec


def _allocate(ipsec, *, expires_secs=600_000, protocol="udp"):
    av = MockAuthVectorHandle(ck=bytes(16), ik=bytes(16))
    offer = MockSecurityOffer(
        mechanism="ipsec-3gpp",
        alg="hmac-sha-1-96",
        ealg="null",
        spi_c=11111, spi_s=22222,
        port_c=50000, port_s=50001,
        ue_addr="10.0.0.1",
    )
    return asyncio.run(
        ipsec.allocate(
            av, offer, _TransformEnum.HmacSha1_96Null,
            expires_secs=expires_secs, protocol=protocol,
        )
    )


def test_activate_without_kwarg_preserves_allocation_lifetime():
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec, expires_secs=600_000)
    assert pending.expires_secs == 600_000

    pending.activate()  # no kwarg
    assert pending.is_active
    assert pending.expires_secs == 600_000, (
        "activate() with no kwarg must not touch expires_secs"
    )


def test_activate_with_hard_lifetime_secs_repins_to_grant():
    """The fix path: 401 installed an SA with the UE's 600000 s ask, the
    200 OK arrives with grant=3600, script calls
    activate(hard_lifetime_secs=grant+32) to tighten the kernel SA so
    its expiry tracks the registrar's grant."""
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec, expires_secs=600_000)

    pending.activate(hard_lifetime_secs=3632)
    assert pending.is_active
    assert pending.expires_secs == 3632


def test_activate_kwarg_must_be_keyword_only():
    """The Rust signature is ``def activate(*, hard_lifetime_secs=None)``
    — positional usage must raise so scripts can't accidentally pass an
    arbitrary first argument."""
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec)

    with pytest.raises(TypeError):
        pending.activate(3632)  # type: ignore[misc]


def test_activate_after_cleanup_rejects_lifetime_kwarg():
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec)
    asyncio.run(pending.cleanup())

    with pytest.raises(ValueError, match="cleaned up"):
        pending.activate(hard_lifetime_secs=3632)
