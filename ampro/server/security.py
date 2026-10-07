"""Security policy for the reference server's native AMP route.

Implements the request pipeline of WIRE-BINDING Appendix D for
``POST /agent/message``: size limit, authentication, rate limiting,
envelope validation, sender binding, recipient check, loop detection,
deduplication (with response replay), concurrency limiting and a
handler timeout.

Every stateful piece is a small protocol with a bounded in-memory
default, so production deployments with several workers can plug in a
shared store (Redis, a database) without touching the pipeline.

PURE — zero platform-specific imports.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from ampro.security.concurrency_limiter import ConcurrencyLimiter
from ampro.security.rate_limiter import RateLimiter
from ampro.server.auth import Authenticator
from ampro.wire.config import WireConfig

#: Marker stored while the first copy of a message is still being handled.
_PENDING = object()


@dataclass(frozen=True)
class CachedResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class ResponseCache(Protocol):
    """Dedup store that remembers the response for each message id."""

    async def reserve(self, key: str) -> CachedResponse | bool:
        """Claim *key*.

        Returns ``True`` if the caller should process the message,
        ``False`` if another copy is still in flight, or the stored
        :class:`CachedResponse` for a completed duplicate.
        """
        ...

    async def complete(self, key: str, response: CachedResponse) -> None: ...

    async def release(self, key: str) -> None:
        """Forget a reservation whose processing failed before a response."""
        ...


class InMemoryResponseCache:
    """Bounded TTL response cache (single process)."""

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 100_000) -> None:
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("ttl_seconds and max_entries must be > 0")
        self._ttl = ttl_seconds
        self._max = max_entries
        self._entries: OrderedDict[str, tuple[float, object]] = OrderedDict()
        self._lock = asyncio.Lock()

    def _expire(self, now: float) -> None:
        while self._entries:
            key, (stamp, _) = next(iter(self._entries.items()))
            if now - stamp <= self._ttl:
                break
            del self._entries[key]

    async def reserve(self, key: str) -> CachedResponse | bool:
        async with self._lock:
            now = time.monotonic()
            self._expire(now)
            entry = self._entries.get(key)
            if entry is not None:
                value = entry[1]
                return False if value is _PENDING else value  # type: ignore[return-value]
            if len(self._entries) >= self._max:
                # Full of live entries: evict the oldest.  Keys are scoped
                # to an authenticated or rate-limited sender, so a flood
                # costs the attacker its own quota first.
                self._entries.popitem(last=False)
            self._entries[key] = (now, _PENDING)
            return True

    async def complete(self, key: str, response: CachedResponse) -> None:
        async with self._lock:
            self._entries[key] = (time.monotonic(), response)
            self._entries.move_to_end(key)

    async def release(self, key: str) -> None:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry[1] is _PENDING:
                del self._entries[key]


@dataclass
class SecurityPolicy:
    """Knobs for the native AMP route's security pipeline.

    The defaults are safe for local development (anonymous callers are
    admitted at the ``EXTERNAL`` tier but rate-, size- and
    concurrency-limited).  For an internet-facing deployment use
    :meth:`production`, which requires authentication.
    """

    authenticators: Sequence[Authenticator] = ()
    require_auth: bool = False
    #: Reject envelopes whose ``sender`` differs from a principal that is
    #: cryptographically bound to an agent address.
    enforce_sender_binding: bool = True
    #: Reject envelopes addressed to another agent.
    enforce_recipient: bool = True
    rate_limiter: RateLimiter | None = None
    concurrency: ConcurrencyLimiter | None = None
    dedup: ResponseCache | None = None
    handler_timeout_seconds: float | None = None
    max_visited_agents: int = 20
    #: Extra identifiers this agent answers to (besides ``agent_id`` and
    #: the identifiers in its agent.json).
    aliases: Sequence[str] = field(default_factory=tuple)
    #: Browser origins allowed to make state-changing requests.  Requests
    #: carrying any other ``Origin`` header are refused with 403 (CSRF and
    #: DNS-rebinding protection).  Loopback origins and the origin of the
    #: agent's own endpoint are always allowed.  Agent-to-agent calls
    #: send no ``Origin`` and are unaffected.
    allowed_origins: Sequence[str] = field(default_factory=tuple)

    @classmethod
    def from_config(cls, config: WireConfig, **overrides: object) -> SecurityPolicy:
        policy = cls(
            rate_limiter=RateLimiter(
                rpm=config.rate_limit_rpm,
                max_senders=config.rate_limiter_max_senders,
            ),
            concurrency=ConcurrencyLimiter(max_total=config.max_concurrent_tasks),
            dedup=InMemoryResponseCache(
                ttl_seconds=config.dedup_window_seconds,
                max_entries=config.dedup_max_entries,
            ),
            handler_timeout_seconds=float(config.default_timeout_seconds),
        )
        for key, value in overrides.items():
            if not hasattr(policy, key):
                raise TypeError(f"Unknown SecurityPolicy field {key!r}")
            setattr(policy, key, value)
        return policy

    @classmethod
    def production(
        cls,
        authenticators: Sequence[Authenticator],
        config: WireConfig | None = None,
        **overrides: object,
    ) -> SecurityPolicy:
        """Authentication required, every limit on."""
        if not authenticators:
            raise ValueError("production() needs at least one authenticator")
        from ampro.wire.config import DEFAULTS

        return cls.from_config(
            config or DEFAULTS,
            authenticators=tuple(authenticators),
            require_auth=True,
            **overrides,
        )


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` of *url*, lower-cased; ``None`` if unparsable."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def origin_allowed(origin: str, allowed: Sequence[str]) -> bool:
    """True if a browser *origin* may call this server."""
    from urllib.parse import urlsplit

    normalized = origin.strip().lower()
    if normalized in {o.rstrip("/").lower() for o in allowed}:
        return True
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname or ""
    return host in _LOOPBACK_HOSTS or f"[{host}]" in _LOOPBACK_HOSTS
