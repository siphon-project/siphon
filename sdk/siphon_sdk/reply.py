"""
Mock SIP Reply object — mirrors ``PyReply`` from the Rust engine.

Passed to ``@proxy.on_reply``, ``@proxy.on_failure``,
``@proxy.on_register_reply``, ``@b2bua.on_early_media``,
and ``@b2bua.on_answer`` handlers.
"""

from __future__ import annotations

from typing import Optional, Union

from siphon_sdk.types import Action, SipUri
from siphon_sdk.request import _parse_uri


class Reply:
    """A SIP response message.

    This object is passed as the second argument to reply handlers:

    - ``@proxy.on_reply`` — all responses
    - ``@proxy.on_failure`` — aggregated failure response
    - ``@proxy.on_register_reply`` — REGISTER responses

    Example::

        @proxy.on_reply
        async def reply_route(request, reply):
            if reply.status_code == 200 and reply.has_body("application/sdp"):
                await rtpengine.answer(reply)
            reply.relay()
    """

    def __init__(
        self,
        status_code: int = 200,
        reason: str = "OK",
        from_uri: Union[str, SipUri, None] = None,
        to_uri: Union[str, SipUri, None] = None,
        call_id: Optional[str] = None,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._status_code = status_code
        self._reason = reason
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._call_id = call_id
        self._body = body
        self._content_type = content_type
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._actions: list[Action] = []

    @property
    def status_code(self) -> int:
        """SIP status code (e.g. 200, 404, 503)."""
        return self._status_code

    @property
    def reason(self) -> str:
        """Reason phrase (e.g. ``"OK"``, ``"Not Found"``)."""
        return self._reason

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From header URI."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To header URI."""
        return self._to_uri

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def body(self) -> Optional[bytes]:
        """Response body (e.g. SDP), or ``None``."""
        return self._body

    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value."""
        return self._content_type

    # -- Header access ---------------------------------------------------------

    def get_header(self, name: str) -> Optional[str]:
        """Get the first value of a header (case-insensitive)."""
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def header(self, name: str) -> Optional[str]:
        """Alias for :meth:`get_header`."""
        return self.get_header(name)

    def set_header(self, name: str, value: str) -> None:
        """Set (replace) a header value."""
        self._headers[name] = value

    def remove_header(self, name: str) -> None:
        """Remove a header entirely."""
        self._headers = {
            k: v for k, v in self._headers.items()
            if k.lower() != name.lower()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header exists (case-insensitive)."""
        return any(k.lower() == name.lower() for k in self._headers)

    def has_body(self, content_type: str) -> bool:
        """Check if the reply has a body matching the given content type.

        Args:
            content_type: MIME type (e.g. ``"application/sdp"``).
        """
        return self._body is not None and self._content_type == content_type

    # -- IPsec / 3GPP TS 33.203 ------------------------------------------------

    def take_av(self):
        """Extract IMS-AKA CK/IK from auth headers and strip ``ck=``/``ik=``.

        Scans ``WWW-Authenticate``, ``Proxy-Authenticate`` and
        ``Authentication-Info`` (in that order).  Returns a
        :class:`MockAuthVectorHandle` only when **both** ``ck`` and ``ik``
        parsed cleanly; otherwise leaves the headers untouched and returns
        ``None``.

        Idempotent: after stripping, a second call returns ``None`` because
        no header still carries ``ck``/``ik``.
        """
        from siphon_sdk.mock_module import MockAuthVectorHandle

        for header_name in ("WWW-Authenticate", "Proxy-Authenticate", "Authentication-Info"):
            value = self.get_header(header_name)
            if value is None:
                continue
            rewritten, parsed = _strip_ck_ik(value)
            if parsed is not None:
                ck, ik = parsed
                self.set_header(header_name, rewritten)
                return MockAuthVectorHandle(ck=ck, ik=ik)
        return None

    # -- Forwarding ------------------------------------------------------------

    def relay(self) -> None:
        """Forward the reply upstream to the UAC.

        Example::

            @proxy.on_reply
            def handle_reply(request, reply):
                reply.relay()
        """
        self._actions.append(Action(kind="relay"))

    def forward(self) -> None:
        """Alias for :meth:`relay`."""
        self.relay()

    # -- Test helpers ----------------------------------------------------------

    @property
    def actions(self) -> list[Action]:
        """All actions recorded (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """Most recent action, or ``None``."""
        return self._actions[-1] if self._actions else None


def _split_top_level_commas(value: str) -> list[str]:
    """Split a header parameter list on top-level commas, respecting
    double-quoted strings and backslash escapes inside them."""
    out: list[str] = []
    start = 0
    in_quote = False
    escaped = False
    for i, ch in enumerate(value):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
        elif ch == "," and not in_quote:
            out.append(value[start:i])
            start = i + 1
    out.append(value[start:])
    return out


def _parse_hex_param(raw: str) -> Optional[bytes]:
    """Parse ``"hex…"`` or ``hex…`` into 16 bytes; ``None`` on length
    mismatch (IMS-AKA AV components are always 128-bit)."""
    trimmed = raw.strip()
    if len(trimmed) >= 2 and trimmed.startswith('"') and trimmed.endswith('"'):
        body = trimmed[1:-1]
    else:
        body = trimmed
    if len(body) != 32:
        return None
    try:
        return bytes.fromhex(body)
    except ValueError:
        return None


def _strip_ck_ik(value: str) -> tuple[str, Optional[tuple[bytes, bytes]]]:
    """Conservative strip — mirrors the Rust ``strip_ck_ik`` logic.

    Returns ``(rewritten, (ck, ik))`` only when both params parsed; the
    original string is returned unchanged with ``None`` otherwise.
    """
    parts = value.split(None, 1)
    if len(parts) < 2:
        return value, None
    scheme, rest = parts[0], parts[1]
    tokens = _split_top_level_commas(rest)
    kept: list[str] = []
    ck: Optional[bytes] = None
    ik: Optional[bytes] = None
    for token in tokens:
        trimmed = token.strip()
        if not trimmed:
            continue
        if "=" not in trimmed:
            kept.append(trimmed)
            continue
        name, raw = trimmed.split("=", 1)
        name_lower = name.strip().lower()
        if name_lower == "ck":
            ck = _parse_hex_param(raw)
            continue
        if name_lower == "ik":
            ik = _parse_hex_param(raw)
            continue
        kept.append(trimmed)
    if ck is None or ik is None:
        return value, None
    rewritten = f"{scheme} {', '.join(kept)}"
    return rewritten, (ck, ik)
