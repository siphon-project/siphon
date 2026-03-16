"""
siphon — Python scripting API for SIPhon.

This module is injected into sys.modules by the Rust engine before any user
script runs.  It exposes the decorator-based API that scripts use:

    from siphon import proxy, registrar, b2bua, auth, log, cache
"""
import asyncio as _asyncio
import sys as _sys

# Ensure the registry is available.
import _siphon_registry as _registry


# ---------------------------------------------------------------------------
# Proxy namespace
# ---------------------------------------------------------------------------

class _ProxyNamespace:
    """Namespace for stateful/stateless proxy event handlers."""

    def on_request(self, fn_or_filter=None):
        """
        Register a handler for incoming SIP requests.

        Usage:
            @proxy.on_request              # all methods
            @proxy.on_request("REGISTER")  # single method
            @proxy.on_request("INVITE|SUBSCRIBE")  # pipe-separated
        """
        if fn_or_filter is None or callable(fn_or_filter):
            # @proxy.on_request or @proxy.on_request without parens
            fn = fn_or_filter
            if fn is not None:
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn
            # @proxy.on_request() — called with no args, return decorator
            def decorator(fn):
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn
            return decorator

        if isinstance(fn_or_filter, str):
            # @proxy.on_request("REGISTER")
            method_filter = fn_or_filter
            def decorator(fn):
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", method_filter, fn, is_async)
                return fn
            return decorator

        raise TypeError(
            f"proxy.on_request expects a callable or method filter string, "
            f"got {type(fn_or_filter).__name__}"
        )

    @staticmethod
    def on_reply(fn):
        """
        Register a handler for SIP replies (responses).

        Usage:
            @proxy.on_reply
            def handle_reply(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_reply", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn):
        """
        Register a handler for proxy failure (all branches failed).

        Usage:
            @proxy.on_failure
            def failure_route(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_register_reply(fn):
        """
        Register a handler for REGISTER replies.

        Usage:
            @proxy.on_register_reply
            def handle_register_reply(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_register_reply", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# B2BUA namespace
# ---------------------------------------------------------------------------

class _B2buaNamespace:
    """Namespace for B2BUA call event handlers."""

    @staticmethod
    def on_invite(fn):
        """Register handler for new INVITE (new call)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_invite", None, fn, is_async)
        return fn

    @staticmethod
    def on_early_media(fn):
        """Register handler for provisional response with SDP (183/180).

        Called when the B-leg sends a provisional response containing SDP
        (early media).  Use this to process the SDP through RTPEngine so
        early media is anchored correctly.

        Usage:
            @b2bua.on_early_media
            async def early_media(call, reply):
                await rtpengine.answer(reply)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_early_media", None, fn, is_async)
        return fn

    @staticmethod
    def on_answer(fn):
        """Register handler for call answered (200 OK on B leg)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_answer", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn):
        """Register handler for B leg failure."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_bye(fn):
        """Register handler for BYE (call ended)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_bye", None, fn, is_async)
        return fn

    @staticmethod
    def on_refer(fn):
        """Register handler for REFER (call transfer, RFC 3515)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_refer", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# Registrar namespace (stubs — wired to Rust in Phase 4)
# ---------------------------------------------------------------------------

class _RegistrarNamespace:
    """Namespace for registrar operations."""

    def save(self, request, force=False):
        raise NotImplementedError("registrar.save() not yet wired to Rust backend")

    def lookup(self, uri):
        raise NotImplementedError("registrar.lookup() not yet wired to Rust backend")

    def is_registered(self, uri):
        raise NotImplementedError("registrar.is_registered() not yet wired to Rust backend")

    @staticmethod
    def on_change(fn):
        """Register a handler for registration state changes.

        The handler receives (aor, event_type, contacts) where:
          - aor: str — Address of Record (e.g. "sip:alice@example.com")
          - event_type: str — "registered", "refreshed", "deregistered", or "expired"
          - contacts: list[Contact] — current contact bindings

        Usage:
            @registrar.on_change
            def on_reg_change(aor, event_type, contacts):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("registrar.on_change", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# Auth namespace (stubs — wired to Rust in Phase 4)
# ---------------------------------------------------------------------------

class _AuthNamespace:
    """Namespace for authentication operations."""

    def require_www_digest(self, request, realm=None):
        raise NotImplementedError("auth.require_www_digest() not yet wired")

    def require_proxy_digest(self, request, realm=None):
        raise NotImplementedError("auth.require_proxy_digest() not yet wired")

    def require_digest(self, request, realm=None):
        """Convenience: same as require_www_digest (backward compat)."""
        return self.require_www_digest(request, realm=realm)

    def verify_digest(self, request, realm=None):
        raise NotImplementedError("auth.verify_digest() not yet wired")


# ---------------------------------------------------------------------------
# Log namespace
# ---------------------------------------------------------------------------

class _LogNamespace:
    """Logging — bridges to Rust tracing."""

    def debug(self, msg):
        print(f"[DEBUG] {msg}")

    def info(self, msg):
        print(f"[INFO] {msg}")

    def warn(self, msg):
        print(f"[WARN] {msg}")

    def error(self, msg):
        print(f"[ERROR] {msg}")


# ---------------------------------------------------------------------------
# Cache namespace (stub)
# ---------------------------------------------------------------------------

class _CacheNamespace:
    """Named cache connections (stub — wired to Redis in later phase)."""

    async def fetch(self, name, key):
        raise NotImplementedError("cache.fetch() not yet wired to Redis backend")


# ---------------------------------------------------------------------------
# RTPEngine namespace (stub — replaced by Rust when media.rtpengine configured)
# ---------------------------------------------------------------------------

class _RtpEngineNamespace:
    """RTPEngine media proxy operations (stub)."""

    async def offer(self, request, profile=None):
        raise NotImplementedError("rtpengine.offer() not available — no media.rtpengine in config")

    async def answer(self, reply, profile=None):
        raise NotImplementedError("rtpengine.answer() not available — no media.rtpengine in config")

    async def delete(self, request):
        raise NotImplementedError("rtpengine.delete() not available — no media.rtpengine in config")

    async def ping(self):
        raise NotImplementedError("rtpengine.ping() not available — no media.rtpengine in config")


# ---------------------------------------------------------------------------
# Gateway namespace (stub — replaced by Rust when gateway is configured)
# ---------------------------------------------------------------------------

class _GatewayNamespace:
    """Gateway dispatcher operations (stub)."""

    def select(self, group, key=None, attrs=None):
        raise NotImplementedError("gateway.select() not available — no gateway in config")

    def list(self, group):
        raise NotImplementedError("gateway.list() not available — no gateway in config")

    def groups(self):
        raise NotImplementedError("gateway.groups() not available — no gateway in config")

    def add_group(self, name, destinations, algorithm="weighted"):
        raise NotImplementedError("gateway.add_group() not available — no gateway in config")

    def remove_group(self, name):
        raise NotImplementedError("gateway.remove_group() not available — no gateway in config")

    def mark_down(self, group, uri):
        raise NotImplementedError("gateway.mark_down() not available — no gateway in config")

    def mark_up(self, group, uri):
        raise NotImplementedError("gateway.mark_up() not available — no gateway in config")

    def status(self, group):
        raise NotImplementedError("gateway.status() not available — no gateway in config")


# ---------------------------------------------------------------------------
# LI namespace (stub — replaced by Rust when lawful_intercept is configured)
# ---------------------------------------------------------------------------

class _LiNamespace:
    """Lawful Intercept operations (stub)."""

    def is_target(self, request):
        raise NotImplementedError("li.is_target() not available — no lawful_intercept in config")

    def intercept(self, request):
        raise NotImplementedError("li.intercept() not available — no lawful_intercept in config")

    def record(self, request):
        raise NotImplementedError("li.record() not available — no lawful_intercept in config")

    def stop_intercept(self, request):
        raise NotImplementedError("li.stop_intercept() not available — no lawful_intercept in config")

    def stop_recording(self, request):
        raise NotImplementedError("li.stop_recording() not available — no lawful_intercept in config")

    @property
    def is_enabled(self):
        return False


# ---------------------------------------------------------------------------
# Registration namespace (stub — replaced by Rust when registrant is configured)
# ---------------------------------------------------------------------------

class _RegistrationNamespace:
    """Outbound registration operations (stub)."""

    def add(self, aor, registrar, *, user, password, interval=None, realm=None, contact=None, transport=None):
        raise NotImplementedError("registration.add() not available — no registrant in config")

    def remove(self, aor):
        raise NotImplementedError("registration.remove() not available — no registrant in config")

    def refresh(self, aor):
        raise NotImplementedError("registration.refresh() not available — no registrant in config")

    def list(self):
        raise NotImplementedError("registration.list() not available — no registrant in config")

    def status(self, aor):
        raise NotImplementedError("registration.status() not available — no registrant in config")

    def count(self):
        raise NotImplementedError("registration.count() not available — no registrant in config")


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

proxy = _ProxyNamespace()
registrar = _RegistrarNamespace()
b2bua = _B2buaNamespace()
auth = _AuthNamespace()
log = _LogNamespace()
cache = _CacheNamespace()
rtpengine = _RtpEngineNamespace()
gateway = _GatewayNamespace()
registration = _RegistrationNamespace()
li = _LiNamespace()


# ---------------------------------------------------------------------------
# Presence namespace (stub — replaced by Rust when presence store is active)
# ---------------------------------------------------------------------------

class _PresenceNamespace:
    """Namespace for SIP presence operations (stub)."""

    def publish(self, entity, pidf_xml, expires=3600):
        raise NotImplementedError("presence.publish() not available — presence store not initialized")

    def lookup(self, entity):
        raise NotImplementedError("presence.lookup() not available — presence store not initialized")

    def subscribe(self, subscriber, resource, event="presence", expires=3600):
        raise NotImplementedError("presence.subscribe() not available — presence store not initialized")

    def unsubscribe(self, subscription_id):
        raise NotImplementedError("presence.unsubscribe() not available — presence store not initialized")

    def subscribers(self, resource):
        raise NotImplementedError("presence.subscribers() not available — presence store not initialized")


presence = _PresenceNamespace()


# ---------------------------------------------------------------------------
# SRS namespace (Session Recording Server — accepts SIPREC INVITEs)
# ---------------------------------------------------------------------------

class _SrsNamespace:
    """Namespace for SRS (Session Recording Server) event handlers."""

    @staticmethod
    def on_invite(fn):
        """Register handler for incoming SIPREC INVITE (recording request).

        The handler receives (request, metadata) where:
          - request: Request object (the SIPREC INVITE)
          - metadata: RecordingMetadata (parsed XML — participants, streams, session_id)

        Return True to accept the recording, False to reject (403).

        Usage:
            @srs.on_invite
            async def on_recording(request, metadata):
                log.info(f"Recording: {metadata.session_id}")
                return True
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("srs.on_invite", None, fn, is_async)
        return fn

    @staticmethod
    def on_session_end(fn):
        """Register handler called when a recording session ends.

        The handler receives (session,) where:
          - session: SrsSession (session_id, participants, duration, recording_dir)

        Usage:
            @srs.on_session_end
            async def on_recording_end(session):
                log.info(f"Recording {session.session_id} done, {session.duration}s")
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("srs.on_session_end", None, fn, is_async)
        return fn


srs = _SrsNamespace()


# ---------------------------------------------------------------------------
# Timer namespace — periodic callbacks (like OpenSIPS timer_route)
# ---------------------------------------------------------------------------

class _TimerNamespace:
    """Namespace for periodic timer callbacks.

    Timer handlers run on a Tokio interval in the Rust runtime.
    They receive no SIP request/call context but can use all other
    namespaces (registrar, cache, gateway, log, etc.).
    """

    def every(self, seconds, name=None, jitter=0):
        """Register a periodic timer callback.

        Usage:
            @timer.every(seconds=30)
            async def health_check():
                ...

            @timer.every(seconds=300, name="stats", jitter=10)
            def push_stats():
                ...

        Args:
            seconds: Interval between invocations.
            name: Optional name for logging (defaults to function name).
            jitter: Random jitter in seconds added to each interval (default 0).
        """
        def decorator(fn):
            timer_name = name if name is not None else fn.__name__
            is_async = _asyncio.iscoroutinefunction(fn)
            metadata = {"seconds": seconds, "name": timer_name, "jitter": jitter}
            _registry.register("timer.every", None, fn, is_async, metadata)
            return fn
        return decorator


timer = _TimerNamespace()


# ---------------------------------------------------------------------------
# Metrics namespace (stub — replaced by Rust at startup)
# ---------------------------------------------------------------------------

class _MetricsNamespace:
    """Custom Prometheus metrics from Python scripts (stub).

    Usage:
        from siphon import metrics

        counter = metrics.counter("my_total", "My counter")
        counter.inc()
    """

    def counter(self, name, help, labels=None):
        raise NotImplementedError("metrics.counter() not available — metrics not initialized")

    def gauge(self, name, help, labels=None):
        raise NotImplementedError("metrics.gauge() not available — metrics not initialized")

    def histogram(self, name, help, labels=None, buckets=None):
        raise NotImplementedError("metrics.histogram() not available — metrics not initialized")


metrics = _MetricsNamespace()
