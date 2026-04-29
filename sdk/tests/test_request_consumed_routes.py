"""Unit tests for ``request.consumed_routes`` / ``consumed_route_user``.

Mirrors the production behaviour added in [src/script/api/request.rs]:
``loose_route()`` records the URIs it consumes so scripts can recover
service-case metadata (the ``orig``/``term`` user-part the P-CSCF
preloads on the IMS service-route) after the framework strips the
local entry per RFC 3261 §16.4.
"""
from siphon_sdk.request import Request


def _request_with_route(route_value: str) -> Request:
    return Request(
        method="INVITE",
        ruri="sip:bob@ims.example.com",
        from_uri="sip:alice@ims.example.com",
        to_uri="sip:bob@ims.example.com",
        from_tag="alice-tag",
        to_tag="bob-tag",  # in-dialog so the no-Route fallback would say True
        headers={"Route": route_value},
    )


def test_consumed_routes_empty_before_loose_route():
    request = _request_with_route("<sip:orig@scscf.ims.example.com:6060;lr>")
    assert request.consumed_routes == []
    assert request.consumed_route_user is None


def test_loose_route_records_popped_orig_route():
    """The IMS S-CSCF orig-leg case the user reported — the P-CSCF
    preloads ``<sip:orig@scscf...;lr>`` as the topmost Route, the script
    calls ``loose_route()``, and now needs the user-part to drive
    sescase logic."""
    request = _request_with_route("<sip:orig@scscf.ims.example.com:6060;lr>")
    assert request.loose_route() is True
    assert request.consumed_route_user == "orig"
    assert len(request.consumed_routes) == 1
    # And the wire-state Route is now empty.
    assert request.get_header("Route") is None


def test_loose_route_records_popped_term_route():
    request = _request_with_route("<sip:term@scscf.ims.example.com:6060;lr>")
    assert request.loose_route() is True
    assert request.consumed_route_user == "term"


def test_loose_route_with_strict_route_does_not_pop():
    """Strict-routed Routes (no ;lr) are not consumed, and nothing is
    recorded as consumed."""
    request = _request_with_route("<sip:strict@old-proxy.example.com>")
    assert request.loose_route() is False
    assert request.consumed_routes == []
    assert request.consumed_route_user is None
    # Route header preserved.
    assert request.get_header("Route") is not None


def test_loose_route_with_double_record_route_pops_one_at_a_time():
    """The mock pops the topmost entry per call — successive calls walk
    further into a multi-RR list, so scripts can drain it."""
    request = _request_with_route(
        "<sip:orig@scscf.ims.example.com:6060;lr>, "
        "<sip:scscf.ims.example.com:6060;lr;transport=tcp>"
    )
    assert request.loose_route() is True
    assert request.consumed_route_user == "orig"
    # Second pop drains the remaining local entry.
    assert request.loose_route() is True
    assert len(request.consumed_routes) == 2


def test_route_user_reflects_current_state_after_loose_route():
    """Documenting the contrast: ``route_user`` always reads the *current*
    top-of-Route, ``consumed_route_user`` always reads the *first popped*
    entry — they are observably different after loose_route()."""
    request = _request_with_route(
        "<sip:orig@scscf.ims.example.com:6060;lr>, "
        "<sip:next-hop@otherproxy.example.com;lr>"
    )
    # Before loose_route(), route_user is "orig".
    assert request.route_user == "orig"
    request.loose_route()
    # After: route_user reads the next entry, consumed_route_user keeps
    # the popped one.
    assert request.route_user == "next-hop"
    assert request.consumed_route_user == "orig"


def test_loose_route_no_route_header_falls_back_to_in_dialog():
    """Pre-existing mock contract: when no Route is set, return
    in_dialog (used pervasively in the example IMS scripts under
    ``examples/``)."""
    request = Request(
        method="BYE",
        ruri="sip:bob@example.com",
        from_tag="a",
        to_tag="b",
    )
    assert "Route" not in request._headers
    assert request.loose_route() is True
    assert request.consumed_routes == []
