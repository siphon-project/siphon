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
