"""
Mock B2BUA Call object — mirrors ``PyCall`` from the Rust engine.

Passed to ``@b2bua.on_invite``, ``@b2bua.on_answer``, ``@b2bua.on_failure``,
and ``@b2bua.on_bye`` handlers.
"""

from __future__ import annotations

import uuid
from typing import Optional, Union

from siphon_sdk.types import Action, Contact, MediaHandle, SipUri
from siphon_sdk.request import _parse_uri


class Call:
    """A B2BUA call with two legs (A-leg = caller, B-leg = callee).

    The call object is the primary interface for B2BUA scripts.  It tracks
    call state and provides methods to dial, fork, reject, and terminate.

    Example::

        @b2bua.on_invite
        def new_call(call):
            contacts = registrar.lookup(call.ruri)
            if not contacts:
                call.reject(404, "Not Found")
                return
            call.fork([c.uri for c in contacts], strategy="parallel")

        @b2bua.on_bye
        def call_ended(call, initiator):
            log.info(f"Call ended by {initiator.side}-leg")
            call.terminate()
    """

    def __init__(
        self,
        call_id: Optional[str] = None,
        from_uri: Union[str, SipUri, None] = "sip:alice@example.com",
        to_uri: Union[str, SipUri, None] = "sip:bob@example.com",
        ruri: Union[str, SipUri, None] = "sip:bob@example.com",
        source_ip: str = "127.0.0.1",
        state: str = "calling",
        body: Optional[bytes] = None,
        headers: Optional[dict[str, str]] = None,
        refer_to: Optional[str] = None,
        refer_replaces: Optional[dict] = None,
    ) -> None:
        self._id = call_id or str(uuid.uuid4())
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._ruri = _parse_uri(ruri)
        self._source_ip = source_ip
        self._state = state
        self._body = body
        self._call_id = call_id or self._id
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._actions: list[Action] = []
        self._media = MediaHandle()
        self._refer_to = refer_to
        self._refer_replaces = refer_replaces

    # -- Properties ------------------------------------------------------------

    @property
    def id(self) -> str:
        """Unique call identifier (UUID)."""
        return self._id

    @property
    def state(self) -> str:
        """Call state: ``"calling"``, ``"ringing"``, ``"answered"``, ``"terminated"``."""
        return self._state

    @property
    def source_ip(self) -> str:
        """Source IP address of the A-leg caller."""
        return self._source_ip

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From URI of the A-leg INVITE."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To URI of the A-leg INVITE."""
        return self._to_uri

    @property
    def ruri(self) -> Optional[SipUri]:
        """Request-URI of the A-leg INVITE."""
        return self._ruri

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def body(self) -> Optional[bytes]:
        """SDP body content, or ``None``."""
        return self._body

    @property
    def media(self) -> MediaHandle:
        """Handle for media anchoring operations.

        Example::

            call.media.anchor(engine="rtpengine", profile="wss_to_rtp")
            call.media.release()
        """
        return self._media

    @property
    def refer_to(self) -> Optional[str]:
        """Refer-To URI from an incoming REFER request.

        Available in ``@b2bua.on_refer`` handlers.  Returns the URI the
        remote party wants to transfer the call to, or ``None`` if no
        REFER is pending.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                log.info(f"Transfer to {call.refer_to}")
                call.accept_refer()
        """
        return self._refer_to

    @property
    def refer_replaces(self) -> Optional[dict]:
        """Parsed Replaces parameter from the Refer-To header.

        Returns a dict with ``call_id``, ``from_tag``, and ``to_tag`` if
        the REFER includes a Replaces header (attended transfer), or
        ``None`` for a blind transfer.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                repl = call.refer_replaces
                if repl:
                    log.info(f"Attended transfer, replaces {repl['call_id']}")
        """
        return self._refer_replaces

    # -- Call control ----------------------------------------------------------

    def reject(self, code: int, reason: str) -> None:
        """Reject the call with an error response.

        Args:
            code: SIP status code (e.g. 404, 486, 503).
            reason: Reason phrase.

        Example::

            call.reject(486, "Busy Here")
        """
        self._state = "terminated"
        self._actions.append(Action(kind="reject", status_code=code, reason=reason))

    def dial(self, uri: str, timeout: int = 30) -> None:
        """Dial a single B-leg target.

        Args:
            uri: Destination SIP URI.
            timeout: INVITE timeout in seconds.

        Example::

            call.dial("sip:bob@10.0.0.2:5060", timeout=30)
        """
        self._actions.append(Action(
            kind="dial",
            targets=[uri],
            timeout=timeout,
        ))

    def fork(
        self,
        targets: list[Union[str, Contact]],
        strategy: str = "parallel",
        timeout: int = 30,
    ) -> None:
        """Fork to multiple B-leg targets.

        Args:
            targets: List of URI strings or :class:`Contact` objects.
            strategy: ``"parallel"`` (ring all, first answer wins) or
                      ``"sequential"`` (try in order).
            timeout: Per-branch INVITE timeout in seconds.

        Example::

            contacts = registrar.lookup(call.ruri)
            call.fork([c.uri for c in contacts], strategy="parallel", timeout=30)
        """
        uris = [t.uri if isinstance(t, Contact) else str(t) for t in targets]
        self._actions.append(Action(
            kind="fork",
            targets=uris,
            strategy=strategy,
            timeout=timeout,
        ))

    def terminate(self) -> None:
        """Terminate the call (send BYE to both legs).

        Example::

            @b2bua.on_bye
            def call_ended(call, initiator):
                call.terminate()
        """
        self._state = "terminated"
        self._actions.append(Action(kind="terminate"))

    def accept_refer(self) -> None:
        """Accept an incoming REFER and initiate the transfer.

        Call this from a ``@b2bua.on_refer`` handler to proceed with the
        call transfer.  The B2BUA will send 202 Accepted to the REFER
        originator and initiate a new INVITE to the Refer-To target.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                call.accept_refer()
        """
        self._actions.append(Action(kind="accept_refer"))

    def reject_refer(self, code: int, reason: str) -> None:
        """Reject an incoming REFER.

        Args:
            code: SIP status code (e.g. 403, 603).
            reason: Reason phrase.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                call.reject_refer(403, "Forbidden")
        """
        self._actions.append(Action(kind="reject_refer", status_code=code, reason=reason))

    def session_timer(self, expires: int, min_se: int = 90,
                      refresher: str = "uac") -> None:
        """Configure session timer (RFC 4028) for this call.

        Args:
            expires: Session-Expires value in seconds.
            min_se: Min-SE value in seconds (default 90).
            refresher: Who refreshes: ``"uac"`` or ``"uas"`` (default ``"uac"``).

        Example::

            @b2bua.on_invite
            def new_call(call):
                call.session_timer(1800, min_se=90, refresher="uac")
                call.dial("sip:bob@example.com")
        """
        self._actions.append(Action(
            kind="session_timer",
            extras={"expires": expires, "min_se": min_se, "refresher": refresher},
        ))

    def record(self, srs_uri: str) -> None:
        """Start SIPREC recording (RFC 7866) for this call.

        Args:
            srs_uri: URI of the Session Recording Server.

        Example::

            @b2bua.on_answer
            def call_answered(call):
                call.record("sip:recorder@srs.example.com")
        """
        self._actions.append(Action(kind="record", extras={"srs_uri": srs_uri}))

    def stop_recording(self) -> None:
        """Stop SIPREC recording for this call.

        Example::

            @b2bua.on_bye
            def call_ended(call, initiator):
                call.stop_recording()
                call.terminate()
        """
        self._actions.append(Action(kind="stop_recording"))

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
        """Check if a header exists."""
        return any(k.lower() == name.lower() for k in self._headers)

    def remove_headers_matching(self, prefix: str) -> None:
        """Remove all headers whose name starts with a prefix.

        Args:
            prefix: Prefix string (e.g. ``"X-"`` removes all custom headers).

        Example::

            call.remove_headers_matching("X-")
        """
        self._headers = {
            k: v for k, v in self._headers.items()
            if not k.startswith(prefix)
        }

    # -- Test helpers ----------------------------------------------------------

    @property
    def actions(self) -> list[Action]:
        """All actions recorded (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """Most recent action, or ``None``."""
        return self._actions[-1] if self._actions else None
