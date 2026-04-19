"""
Mock SIP Request object — mirrors ``PyRequest`` from the Rust engine.

This is the primary object passed to ``@proxy.on_request`` handlers.
Every property and method is documented with types for LLM consumption.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Callable, Optional, Union

from siphon_sdk.types import Action, Contact, SipUri


def _parse_uri(value: Union[str, SipUri, None]) -> Optional[SipUri]:
    """Parse a string into a SipUri, or pass through if already one."""
    if value is None:
        return None
    if isinstance(value, SipUri):
        return value
    # Minimal parser: sip:user@host:port or sip:host:port
    s = str(value)
    scheme = "sip"
    if s.startswith("sips:"):
        scheme = "sips"
        s = s[5:]
    elif s.startswith("sip:"):
        s = s[4:]
    elif s.startswith("tel:"):
        return SipUri(scheme="tel", user=s[4:], host="")
    user = None
    if "@" in s:
        user, s = s.split("@", 1)
    port = None
    if ":" in s:
        host, port_str = s.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host = s
    else:
        host = s
    return SipUri(scheme=scheme, user=user, host=host, port=port)


class Request:
    """A SIP request message.

    This object is passed to ``@proxy.on_request`` handlers.  It provides
    read-only access to parsed SIP headers and methods to reply, relay,
    fork, and manipulate the message before forwarding.

    In the real SIPhon engine this is backed by a Rust ``PyRequest`` with
    an ``Arc<Mutex<SipMessage>>`` inside.  The mock version stores
    everything in plain Python attributes.

    Example::

        @proxy.on_request
        def route(request):
            if request.method == "REGISTER":
                request.reply(200, "OK")
                return
            request.relay()
    """

    def __init__(
        self,
        method: str = "INVITE",
        ruri: Union[str, SipUri] = "sip:bob@example.com",
        from_uri: Union[str, SipUri, None] = "sip:alice@example.com",
        to_uri: Union[str, SipUri, None] = "sip:bob@example.com",
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        call_id: Optional[str] = None,
        cseq: Optional[tuple[int, str]] = None,
        max_forwards: int = 70,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        transport: str = "udp",
        source_ip: str = "127.0.0.1",
        user_agent: Optional[str] = None,
        auth_user: Optional[str] = None,
        contact_expires: Optional[int] = None,
        event: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._method = method
        self._ruri = _parse_uri(ruri) or SipUri()
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._from_tag = from_tag or uuid.uuid4().hex[:8]
        self._to_tag = to_tag
        self._call_id = call_id or f"{uuid.uuid4().hex[:16]}@{source_ip}"
        self._cseq = cseq or (1, method)
        self._max_forwards = max_forwards
        self._body = body
        self._content_type = content_type
        self._transport = transport
        self._source_ip = source_ip
        self._user_agent = user_agent
        self._auth_user = auth_user
        self._contact_expires = contact_expires
        self._event = event
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._actions: list[Action] = []

    # -- Read-only properties --------------------------------------------------

    @property
    def method(self) -> str:
        """SIP method string (e.g. ``"INVITE"``, ``"REGISTER"``, ``"BYE"``)."""
        return self._method

    @property
    def ruri(self) -> SipUri:
        """Request-URI as a :class:`SipUri` object."""
        return self._ruri

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From header URI as a :class:`SipUri`, or ``None``."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To header URI as a :class:`SipUri`, or ``None``."""
        return self._to_uri

    @property
    def from_tag(self) -> Optional[str]:
        """From-tag parameter (always present for outgoing requests)."""
        return self._from_tag

    @property
    def to_tag(self) -> Optional[str]:
        """To-tag parameter.  ``None`` for initial (out-of-dialog) requests."""
        return self._to_tag

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def cseq(self) -> Optional[tuple[int, str]]:
        """CSeq as ``(sequence_number, method)`` tuple."""
        return self._cseq

    @property
    def in_dialog(self) -> bool:
        """``True`` if both From-tag and To-tag are present (mid-dialog request)."""
        return self._from_tag is not None and self._to_tag is not None

    @property
    def max_forwards(self) -> int:
        """Max-Forwards header value."""
        return self._max_forwards

    @property
    def body(self) -> Optional[bytes]:
        """Message body (SDP, etc.), or ``None`` if empty."""
        return self._body

    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value (e.g. ``"application/sdp"``)."""
        return self._content_type

    @property
    def transport(self) -> str:
        """Transport protocol: ``"udp"``, ``"tcp"``, ``"tls"``, ``"ws"``, ``"wss"``."""
        return self._transport

    @property
    def source_ip(self) -> str:
        """Source IP address of the sender."""
        return self._source_ip

    @property
    def user_agent(self) -> Optional[str]:
        """User-Agent header value."""
        return self._user_agent

    @property
    def auth_user(self) -> Optional[str]:
        """Authenticated username (set after digest auth succeeds)."""
        return self._auth_user

    @auth_user.setter
    def auth_user(self, value: Optional[str]) -> None:
        self._auth_user = value

    @property
    def contact_expires(self) -> Optional[int]:
        """Contact expires value from Contact ``expires=`` param or Expires header."""
        return self._contact_expires

    @property
    def event(self) -> Optional[str]:
        """Event header value (e.g. ``"reg"``, ``"presence"``)."""
        return self._event

    @property
    def route_user(self) -> Optional[str]:
        """User part of the top Route header URI, or ``None``."""
        route = self._headers.get("Route")
        if route:
            uri = _parse_uri(route.strip("<>").split(">")[0])
            return uri.user if uri else None
        return None

    # -- Response & forwarding -------------------------------------------------

    def reply(self, code: int, reason: str) -> None:
        """Send a SIP response.

        Args:
            code: SIP status code (e.g. 200, 401, 404, 486).
            reason: Reason phrase (e.g. ``"OK"``, ``"Not Found"``).

        Example::

            request.reply(200, "OK")
            request.reply(486, "Busy Here")
        """
        self._actions.append(Action(
            kind="reply",
            status_code=code,
            reason=reason,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
        ))

    def relay(
        self,
        next_hop: Optional[str] = None,
        on_reply: Optional[Callable] = None,
        on_failure: Optional[Callable] = None,
    ) -> None:
        """Forward the request to its destination.

        Args:
            next_hop: Optional explicit next-hop URI.  If ``None``, the
                      Request-URI is used as the destination.
            on_reply: Optional callback ``(request, reply)`` invoked when any
                      response arrives for this relay.
            on_failure: Optional callback ``(request, code, reason)`` invoked
                        when an error response (4xx+) arrives.

        Example::

            request.relay()                           # default routing
            request.relay("sip:proxy@10.0.0.2:5060")  # explicit next-hop
            request.relay(on_reply=my_reply_handler)   # per-relay callback
        """
        self._actions.append(Action(
            kind="relay",
            next_hop=next_hop,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
        ))
        self._on_reply_callback = on_reply
        self._on_failure_callback = on_failure

    def fork(
        self,
        targets: list[Union[str, Contact]],
        strategy: str = "parallel",
    ) -> None:
        """Fork the request to multiple targets.

        Args:
            targets: List of URI strings or :class:`Contact` objects.
            strategy: ``"parallel"`` (all at once, first 2xx wins) or
                      ``"sequential"`` (try in q-value order, next on failure).

        Example::

            contacts = registrar.lookup(request.ruri)
            request.fork([c.uri for c in contacts])
            request.fork(["sip:a@host", "sip:b@host"], strategy="sequential")
        """
        uris = [t.uri if isinstance(t, Contact) else str(t) for t in targets]
        self._actions.append(Action(
            kind="fork",
            targets=uris,
            strategy=strategy,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
        ))

    def record_route(self) -> None:
        """Insert a Record-Route header so that subsequent in-dialog requests
        traverse this proxy.

        Must be called **before** ``relay()`` or ``fork()``.
        """
        self._actions.append(Action(kind="record_route"))

    def loose_route(self) -> bool:
        """Perform RFC 3261 section 16.12 loose routing.

        If the top Route header has an ``lr`` parameter and matches a local
        domain, strip it and return ``True``.  Otherwise return ``False``.

        In the mock, this returns ``True`` if ``in_dialog`` is ``True``
        (simulating that the proxy previously Record-Routed).

        Example::

            if request.in_dialog:
                if request.loose_route():
                    request.relay()
                else:
                    request.reply(404, "Not Here")
        """
        return self.in_dialog

    # -- Header access ---------------------------------------------------------

    def get_header(self, name: str) -> Optional[str]:
        """Get the first value of a header by name (case-insensitive).

        Args:
            name: Header name (e.g. ``"Via"``, ``"Contact"``).

        Returns:
            Header value string or ``None`` if not present.
        """
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def header(self, name: str) -> Optional[str]:
        """Alias for :meth:`get_header`.

        Example::

            ua = request.header("User-Agent")
        """
        return self.get_header(name)

    def set_header(self, name: str, value: str) -> None:
        """Set (replace) a header value.

        Args:
            name: Header name.
            value: New header value.

        Example::

            request.set_header("X-Custom", "my-value")
        """
        self._headers[name] = value

    def set_reply_header(self, name: str, value: str) -> None:
        """Set an extra header to include in the response.

        Unlike :meth:`set_header` which modifies the request, this stores
        headers that the dispatcher injects into the reply built by
        ``request.reply()`` or ``registrar.save()``.  Multiple calls with
        the same name append (multi-value headers like P-Associated-URI).

        Args:
            name: Header name.
            value: Header value.

        Example::

            registrar.save(request)
            request.set_reply_header("P-Associated-URI", "<sip:user@ims.net>")
            request.set_reply_header("Service-Route", "<sip:orig@scscf:6060;lr>")
        """
        if not hasattr(self, "_reply_headers"):
            self._reply_headers = []
        self._reply_headers.append((name, value))

    def get_reply_header(self, name: str) -> Optional[str]:
        """Return the reply header value set by :meth:`set_reply_header`, or
        ``None`` if not set.  Joins multi-value headers with ``, ``.

        Test-only convenience — matches what the dispatcher would inject
        into the outgoing response.
        """
        reply_headers = getattr(self, "_reply_headers", [])
        values = [v for (n, v) in reply_headers if n.lower() == name.lower()]
        return ", ".join(values) if values else None

    @property
    def reply_headers(self) -> list[tuple[str, str]]:
        """All ``(name, value)`` pairs set via :meth:`set_reply_header`."""
        return list(getattr(self, "_reply_headers", []))

    def set_body(self, body, content_type: str | None = None) -> None:
        """Replace the body of the incoming request message.

        Args:
            body: ``str`` or ``bytes`` — the new body.
            content_type: Optional Content-Type to set alongside the body.

        Example::

            request.set_body(pidf_lo_xml, "application/pidf+xml")
        """
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._body = body
        if content_type is not None:
            self._headers["Content-Type"] = content_type
        self._headers["Content-Length"] = str(len(body))

    def set_reply_body(self, body, content_type: str) -> None:
        """Attach a body to the response built by :meth:`reply`.

        The dispatcher copies this body and sets ``Content-Type`` /
        ``Content-Length`` on the outgoing response.

        Args:
            body: ``str`` or ``bytes`` — the response body.
            content_type: ``Content-Type`` header value.

        Example::

            request.set_reply_body(pidf_lo_xml, "application/pidf+xml")
            request.reply(200, "OK")
        """
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._reply_body = (body, content_type)

    def remove_header(self, name: str) -> None:
        """Remove a header entirely.

        Args:
            name: Header name to remove.
        """
        self._headers = {
            k: v for k, v in self._headers.items()
            if k.lower() != name.lower()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header exists (case-insensitive).

        Args:
            name: Header name.

        Returns:
            ``True`` if the header is present.
        """
        return any(k.lower() == name.lower() for k in self._headers)

    def has_body(self, content_type: str) -> bool:
        """Check if the request has a body matching the given content type.

        Args:
            content_type: MIME type to match (e.g. ``"application/sdp"``).

        Returns:
            ``True`` if a body is present and Content-Type matches.
        """
        return self._body is not None and self._content_type == content_type

    # -- Header manipulation ---------------------------------------------------

    def ensure_header(self, name: str, value: str) -> None:
        """Set a header only if it is not already present.

        Args:
            name: Header name.
            value: Value to set if header is missing.
        """
        if not self.has_header(name):
            self.set_header(name, value)

    def remove_from_header_list(self, name: str, value: str) -> None:
        """Remove one value from a comma-separated multi-value header.

        If the header has values ``"A, B, C"`` and you remove ``"B"``,
        the result is ``"A, C"``.

        Args:
            name: Header name.
            value: The specific value to remove.
        """
        current = self.get_header(name)
        if current is None:
            return
        parts = [p.strip() for p in current.split(",")]
        parts = [p for p in parts if p != value]
        if parts:
            self.set_header(name, ", ".join(parts))
        else:
            self.remove_header(name)

    # -- R-URI mutation --------------------------------------------------------

    def set_ruri(self, value: Union[str, SipUri]) -> None:
        """Replace the entire Request-URI.

        Args:
            value: New URI as a string or :class:`SipUri`.
        """
        self._ruri = _parse_uri(value) or self._ruri

    def set_ruri_user(self, value: Optional[str]) -> None:
        """Set the user part of the Request-URI.

        Args:
            value: New user part, or ``None`` to clear.

        Example::

            request.set_ruri_user("bob")
        """
        self._ruri.user = value

    def set_ruri_host(self, value: str) -> None:
        """Set the host part of the Request-URI.

        Args:
            value: New host/domain string.
        """
        self._ruri.host = value

    # -- Display name / path / route -------------------------------------------

    def set_from_display(self, display_name: str) -> None:
        """Rewrite the From header display name.

        Args:
            display_name: New display name (e.g. ``"Alice Smith"``).
        """
        self.set_header("From-Display", display_name)

    def set_to_display(self, display_name: str) -> None:
        """Rewrite the To header display name.

        Args:
            display_name: New display name.
        """
        self.set_header("To-Display", display_name)

    def add_path(self, uri: str) -> None:
        """Prepend a ``Path`` header (P-CSCF registration path).

        Args:
            uri: URI to prepend (e.g. ``"sip:pcscf.ims.example.com;lr"``).
        """
        existing = self.get_header("Path")
        if existing:
            self.set_header("Path", f"<{uri};lr>, {existing}")
        else:
            self.set_header("Path", f"<{uri};lr>")

    def prepend_route(self, uri: str) -> None:
        """Prepend a ``Route`` header.

        Args:
            uri: URI to prepend (e.g. ``"sip:scscf.ims.example.com;lr"``).
        """
        existing = self.get_header("Route")
        if existing:
            self.set_header("Route", f"<{uri};lr>, {existing}")
        else:
            self.set_header("Route", f"<{uri};lr>")

    def add_contact_alias(self) -> None:
        """Append ``;alias`` to the Contact URI (NAT traversal)."""
        contact = self.get_header("Contact")
        if contact and ";alias" not in contact:
            self.set_header("Contact", f"{contact};alias")

    # -- NAT fixup -------------------------------------------------------------

    def fix_nated_register(self) -> None:
        """Add ``received=`` and ``rport=`` to top Via using source IP:port.

        Used by edge proxies / P-CSCFs for NAT traversal on REGISTER.
        """
        via = self.get_header("Via")
        if via:
            self.set_header("Via", f"{via};received={self._source_ip};rport=5060")

    def fix_nated_contact(self) -> None:
        """Rewrite Contact URI host:port with source IP:port.

        Used for NAT traversal — ensures replies route back through the
        actual transport address rather than the Contact address the UA
        advertised.
        """
        pass  # Mock: no-op (Contact rewriting is transport-layer)

    # -- Transport control -----------------------------------------------------

    def force_send_via(self, transport: str, target: str) -> None:
        """Override Via header transport and target for outgoing message.

        Args:
            transport: Protocol (``"udp"``, ``"tcp"``, ``"tls"``).
            target: Target address (e.g. ``"10.0.0.2:5060"``).
        """
        self.set_header("X-Force-Via", f"{transport}:{target}")

    # -- Utilities -------------------------------------------------------------

    def generate_icid(self) -> str:
        """Generate a unique ICID (IMS Charging ID) for ``P-Charging-Vector``.

        Returns:
            UUID string suitable for the ``icid-value`` parameter.
        """
        return str(uuid.uuid4())

    def source_ip_in(self, cidr_list: list[str]) -> bool:
        """Check if the source IP is within any of the given CIDR ranges.

        Args:
            cidr_list: List of CIDR strings (e.g. ``["10.0.0.0/8"]``).

        Returns:
            ``True`` if ``source_ip`` falls within any range.

        Example::

            if request.source_ip_in(["10.0.0.0/8", "172.16.0.0/12"]):
                log.info("Trusted network")
        """
        try:
            addr = ipaddress.ip_address(self._source_ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidr_list)

    # -- Internal helpers (not part of the public API) -------------------------

    def _pending_headers(self) -> dict[str, str]:
        return dict(self._headers)

    def _pending_removed(self) -> list[str]:
        return []

    @property
    def actions(self) -> list[Action]:
        """All actions recorded by this request (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """The last (most recent) action, or ``None``."""
        return self._actions[-1] if self._actions else None
