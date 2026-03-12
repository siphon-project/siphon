"""SRS (Session Recording Server) types for SIPhon scripts.

These types are passed to ``@srs.on_invite`` and ``@srs.on_session_end``
handlers by the Rust runtime.  The SDK mock provides identical interfaces
for offline testing.

Example::

    from siphon import srs, log

    @srs.on_invite
    async def on_recording(metadata):
        log.info(f"Recording: {metadata.session_id}")
        for p in metadata.participants:
            log.info(f"  participant: {p.aor}")
        return True  # accept

    @srs.on_session_end
    async def on_recording_end(session):
        log.info(f"Recording {session.session_id} done, {session.duration}s")
"""

from __future__ import annotations


class SrsParticipant:
    """A participant in the recorded call.

    Attributes:
        participant_id: Unique identifier for this participant.
        aor: Address of Record (SIP URI, e.g. ``"sip:alice@example.com"``).
        name: Optional display name.
    """

    def __init__(
        self,
        participant_id: str,
        aor: str,
        name: str | None = None,
    ) -> None:
        self._participant_id = participant_id
        self._aor = aor
        self._name = name

    @property
    def participant_id(self) -> str:
        """Participant identifier from the recording metadata."""
        return self._participant_id

    @property
    def aor(self) -> str:
        """Address of Record (SIP URI)."""
        return self._aor

    @property
    def name(self) -> str | None:
        """Optional display name."""
        return self._name

    def __repr__(self) -> str:
        return f"SrsParticipant(aor='{self._aor}')"


class SrsStreamInfo:
    """A media stream being recorded.

    Attributes:
        stream_id: Unique identifier for this stream.
        label: Stream label (correlates with SDP ``a=label``).
    """

    def __init__(self, stream_id: str, label: str) -> None:
        self._stream_id = stream_id
        self._label = label

    @property
    def stream_id(self) -> str:
        """Stream identifier from the recording metadata."""
        return self._stream_id

    @property
    def label(self) -> str:
        """Stream label (e.g. ``"main-audio"``, ``"caller-audio"``)."""
        return self._label

    def __repr__(self) -> str:
        return f"SrsStreamInfo(label='{self._label}')"


class RecordingMetadata:
    """Parsed RFC 7866 recording metadata from a SIPREC INVITE.

    Passed to ``@srs.on_invite`` handlers so the script can inspect
    participants, streams, and the session ID before accepting/rejecting.

    Example::

        @srs.on_invite
        async def on_recording(metadata):
            if any(p.aor == "sip:vip@example.com" for p in metadata.participants):
                return True   # always record VIP calls
            return False      # reject others
    """

    def __init__(
        self,
        session_id: str,
        participants: list[SrsParticipant] | None = None,
        streams: list[SrsStreamInfo] | None = None,
    ) -> None:
        self._session_id = session_id
        self._participants = participants or []
        self._streams = streams or []

    @property
    def session_id(self) -> str:
        """Recording session ID from the SIPREC metadata."""
        return self._session_id

    @property
    def participants(self) -> list[SrsParticipant]:
        """List of participants in the recorded call."""
        return list(self._participants)

    @property
    def streams(self) -> list[SrsStreamInfo]:
        """List of media streams being recorded."""
        return list(self._streams)

    def __repr__(self) -> str:
        return (
            f"RecordingMetadata(session_id='{self._session_id}', "
            f"participants={len(self._participants)}, "
            f"streams={len(self._streams)})"
        )


class SrsSession:
    """Completed recording session info.

    Passed to ``@srs.on_session_end`` handlers after the recording
    finishes (BYE from SRC or timeout).

    Example::

        @srs.on_session_end
        async def on_recording_end(session):
            log.info(f"Recording {session.session_id} complete")
            log.info(f"Duration: {session.duration}s")
            if session.recording_dir:
                log.info(f"Files in: {session.recording_dir}")
    """

    def __init__(
        self,
        session_id: str,
        recording_call_id: str,
        original_call_id: str | None = None,
        participants: list[SrsParticipant] | None = None,
        duration_secs: int = 0,
        recording_dir: str | None = None,
    ) -> None:
        self._session_id = session_id
        self._recording_call_id = recording_call_id
        self._original_call_id = original_call_id
        self._participants = participants or []
        self._duration_secs = duration_secs
        self._recording_dir = recording_dir

    @property
    def session_id(self) -> str:
        """SRS session identifier."""
        return self._session_id

    @property
    def recording_call_id(self) -> str:
        """Call-ID of the SIPREC INVITE (the recording dialog)."""
        return self._recording_call_id

    @property
    def original_call_id(self) -> str | None:
        """Call-ID of the original call being recorded (from metadata)."""
        return self._original_call_id

    @property
    def participants(self) -> list[SrsParticipant]:
        """Participants in the recorded call."""
        return list(self._participants)

    @property
    def duration(self) -> int:
        """Recording duration in seconds."""
        return self._duration_secs

    @property
    def recording_dir(self) -> str | None:
        """Directory where RTPEngine wrote the recording files."""
        return self._recording_dir

    def __repr__(self) -> str:
        return f"SrsSession(session_id='{self._session_id}', duration={self._duration_secs}s)"
