"""Persistence seams for PACT.

Every piece of state the Provider keeps sits behind a small
:class:`typing.Protocol` so operators can plug a database.  The in-memory
defaults are **bounded** (LRU size cap) and **expire** (TTL), so a flood of
requests can never grow memory without limit — but they are per-process:
run several workers and you need a shared implementation.

Secrets are never stored in the clear: device codes, refresh tokens and
consent sessions are keyed by their SHA-256 (see :func:`secret_key`).

Each mutating method is specified as a single atomic step (compare-and-set)
so a database implementation can map it onto one conditional ``UPDATE``.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from ampro.interop.pact._jwt import sha256_b64url

Clock = Callable[[], float]


def secret_key(secret: str) -> str:
    """Storage key for a bearer secret (SHA-256, base64url)."""
    return sha256_b64url(secret)


class BoundedTTLMap:
    """An LRU map whose entries also expire after a per-entry deadline."""

    def __init__(self, max_items: int, default_ttl: float | None, clock: Clock = time.time) -> None:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        self.max_items = max_items
        self.default_ttl = default_ttl
        self._clock = clock
        self._data: OrderedDict[Any, tuple[float | None, Any]] = OrderedDict()

    def get(self, key: Any) -> Any:
        item = self._data.get(key)
        if item is None:
            return None
        deadline, value = item
        if deadline is not None and self._clock() >= deadline:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: Any, value: Any, ttl: float | None = None) -> None:
        ttl = self.default_ttl if ttl is None else ttl
        deadline = None if ttl is None else self._clock() + ttl
        self._data[key] = (deadline, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)

    def pop(self, key: Any) -> Any:
        item = self._data.pop(key, None)
        return None if item is None else item[1]

    def values(self) -> list[Any]:
        now = self._clock()
        for k in [k for k, (d, _) in self._data.items() if d is not None and now >= d]:
            del self._data[k]
        return [v for _, v in self._data.values()]

    def __contains__(self, key: Any) -> bool:
        return self.get(key) is not None

    def __len__(self) -> int:
        return len(self._data)


# ---------------------------------------------------------------------------
# Single-use values (JWT ``jti``, Brand login assertions)
# ---------------------------------------------------------------------------


@runtime_checkable
class NonceStore(Protocol):
    async def use(self, namespace: str, value: str, expires_at: float) -> bool:
        """Record *value*; ``True`` the first time, ``False`` if already used."""


class InMemoryNonceStore:
    def __init__(self, *, max_items: int = 100_000, clock: Clock = time.time) -> None:
        self._clock = clock
        self._seen = BoundedTTLMap(max_items, None, clock)
        self._lock = asyncio.Lock()

    async def use(self, namespace: str, value: str, expires_at: float) -> bool:
        key = (namespace, value)
        async with self._lock:
            if self._seen.get(key) is not None:
                return False
            ttl = max(1.0, expires_at - self._clock())
            self._seen.set(key, True, ttl=ttl)
            return True


# ---------------------------------------------------------------------------
# Conversations (PACT §4.2 ownership, §5.5 sub binding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContextRecord:
    context_id: str
    brand_id: str
    owner: str  # Principal id: "pact:{iss}#{sub}"
    brand_user: str | None = None  # set once a delegated turn ran (§5.5)
    closed: bool = False


@runtime_checkable
class ContextStore(Protocol):
    async def get(self, context_id: str) -> ContextRecord | None: ...

    async def bind(self, record: ContextRecord) -> ContextRecord:
        """Insert *record* unless the id exists; returns the stored record."""

    async def set_brand_user(self, context_id: str, brand_user: str) -> bool:
        """Set ``brand_user`` if unset; ``False`` if it is set to another user."""

    async def close(self, context_id: str) -> None: ...


class InMemoryContextStore:
    def __init__(
        self, *, max_items: int = 100_000, ttl_seconds: float = 7 * 24 * 3600,
        clock: Clock = time.time,
    ) -> None:
        self._data = BoundedTTLMap(max_items, ttl_seconds, clock)
        self._lock = asyncio.Lock()

    async def get(self, context_id: str) -> ContextRecord | None:
        return self._data.get(context_id)

    async def bind(self, record: ContextRecord) -> ContextRecord:
        async with self._lock:
            current = self._data.get(record.context_id)
            if current is not None:
                return current
            self._data.set(record.context_id, record)
            return record

    async def set_brand_user(self, context_id: str, brand_user: str) -> bool:
        async with self._lock:
            current = self._data.get(context_id)
            if current is None:
                return False
            if current.brand_user is None:
                self._data.set(context_id, replace(current, brand_user=brand_user))
                return True
            return current.brand_user == brand_user

    async def close(self, context_id: str) -> None:
        async with self._lock:
            current = self._data.get(context_id)
            if current is not None:
                self._data.set(context_id, replace(current, closed=True))


# ---------------------------------------------------------------------------
# Delegation (§5): device authorizations, grants, refresh tokens, consent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code_hash: str
    user_code: str
    brand_id: str
    client_id: str  # PA issuer
    pa_subject: str  # PA-JWT ``sub`` that asked (informational)
    scopes: tuple[str, ...]
    interval: int
    expires_at: float
    status: str = "pending"  # pending | approved | denied | consumed
    last_polled_at: float | None = None
    brand_user: str | None = None
    grant_id: str | None = None


@runtime_checkable
class DeviceAuthorizationStore(Protocol):
    async def create(self, record: DeviceAuthorization) -> None: ...

    async def by_device_code(self, device_code_hash: str) -> DeviceAuthorization | None: ...

    async def by_user_code(self, brand_id: str, user_code: str) -> DeviceAuthorization | None: ...

    async def touch_poll(self, device_code_hash: str, at: float) -> float | None:
        """Set ``last_polled_at``; returns the previous value."""

    async def transition(
        self, device_code_hash: str, expected: str, new: str, **changes: Any
    ) -> DeviceAuthorization | None:
        """Move from *expected* to *new* status atomically; ``None`` if not in *expected*."""


class InMemoryDeviceAuthorizationStore:
    def __init__(self, *, max_items: int = 50_000, clock: Clock = time.time) -> None:
        self._by_hash = BoundedTTLMap(max_items, None, clock)
        self._by_user_code = BoundedTTLMap(max_items, None, clock)
        self._clock = clock
        self._lock = asyncio.Lock()

    async def create(self, record: DeviceAuthorization) -> None:
        ttl = max(1.0, record.expires_at - self._clock()) + 300  # keep briefly for expired_token
        async with self._lock:
            self._by_hash.set(record.device_code_hash, record, ttl=ttl)
            self._by_user_code.set((record.brand_id, record.user_code), record.device_code_hash, ttl=ttl)

    async def by_device_code(self, device_code_hash: str) -> DeviceAuthorization | None:
        return self._by_hash.get(device_code_hash)

    async def by_user_code(self, brand_id: str, user_code: str) -> DeviceAuthorization | None:
        h = self._by_user_code.get((brand_id, user_code))
        return None if h is None else self._by_hash.get(h)

    async def touch_poll(self, device_code_hash: str, at: float) -> float | None:
        async with self._lock:
            rec = self._by_hash.get(device_code_hash)
            if rec is None:
                return None
            self._by_hash.set(device_code_hash, replace(rec, last_polled_at=at),
                              ttl=max(1.0, rec.expires_at - self._clock()) + 300)
            return rec.last_polled_at

    async def transition(
        self, device_code_hash: str, expected: str, new: str, **changes: Any
    ) -> DeviceAuthorization | None:
        async with self._lock:
            rec = self._by_hash.get(device_code_hash)
            if rec is None or rec.status != expected:
                return None
            updated = replace(rec, status=new, **changes)
            self._by_hash.set(device_code_hash, updated,
                              ttl=max(1.0, rec.expires_at - self._clock()) + 300)
            return updated


@dataclass(frozen=True)
class Grant:
    grant_id: str
    brand_id: str
    client_id: str
    brand_user: str
    scopes: tuple[str, ...]
    created_at: float
    expires_at: float
    revoked: bool = False


@runtime_checkable
class GrantStore(Protocol):
    async def create(self, grant: Grant) -> None: ...

    async def get(self, grant_id: str) -> Grant | None: ...

    async def revoke(self, grant_id: str) -> None: ...


class InMemoryGrantStore:
    def __init__(self, *, max_items: int = 100_000, clock: Clock = time.time) -> None:
        self._data = BoundedTTLMap(max_items, None, clock)
        self._clock = clock

    async def create(self, grant: Grant) -> None:
        self._data.set(grant.grant_id, grant, ttl=max(1.0, grant.expires_at - self._clock()))

    async def get(self, grant_id: str) -> Grant | None:
        return self._data.get(grant_id)

    async def revoke(self, grant_id: str) -> None:
        g = self._data.get(grant_id)
        if g is not None:
            self._data.set(grant_id, replace(g, revoked=True),
                           ttl=max(1.0, g.expires_at - self._clock()))


@dataclass(frozen=True)
class RefreshToken:
    token_hash: str
    grant_id: str
    expires_at: float
    used: bool = False


@runtime_checkable
class RefreshTokenStore(Protocol):
    async def create(self, token: RefreshToken) -> None: ...

    async def consume(self, token_hash: str) -> RefreshToken | None:
        """Mark used atomically and return the record *as it was before*.

        ``None`` if unknown.  A returned record with ``used=True`` means the
        token was presented before: refresh-token reuse.
        """


class InMemoryRefreshTokenStore:
    def __init__(self, *, max_items: int = 100_000, clock: Clock = time.time) -> None:
        self._data = BoundedTTLMap(max_items, None, clock)
        self._clock = clock
        self._lock = asyncio.Lock()

    async def create(self, token: RefreshToken) -> None:
        self._data.set(token.token_hash, token, ttl=max(1.0, token.expires_at - self._clock()))

    async def consume(self, token_hash: str) -> RefreshToken | None:
        async with self._lock:
            rec = self._data.get(token_hash)
            if rec is None:
                return None
            if not rec.used:
                self._data.set(token_hash, replace(rec, used=True),
                               ttl=max(1.0, rec.expires_at - self._clock()))
            return rec


@dataclass(frozen=True)
class ConsentSession:
    session_hash: str
    brand_id: str
    user_code: str
    brand_user: str
    display_name: str
    expires_at: float


@runtime_checkable
class ConsentSessionStore(Protocol):
    async def create(self, session: ConsentSession) -> None: ...

    async def take(self, session_hash: str) -> ConsentSession | None:
        """Remove and return the session (single use)."""


class InMemoryConsentSessionStore:
    def __init__(self, *, max_items: int = 50_000, clock: Clock = time.time) -> None:
        self._data = BoundedTTLMap(max_items, None, clock)
        self._clock = clock
        self._lock = asyncio.Lock()

    async def create(self, session: ConsentSession) -> None:
        self._data.set(session.session_hash, session,
                       ttl=max(1.0, session.expires_at - self._clock()))

    async def take(self, session_hash: str) -> ConsentSession | None:
        async with self._lock:
            rec = self._data.get(session_hash)
            self._data.pop(session_hash)
            return rec


# ---------------------------------------------------------------------------
# Attempt limiting (user_code brute force, JWKS refetch, ...)
# ---------------------------------------------------------------------------


@runtime_checkable
class AttemptLimiter(Protocol):
    async def hit(self, key: str) -> bool:
        """Count one attempt; ``False`` once *key* is over its budget."""


class InMemoryAttemptLimiter:
    """Fixed-window counter: at most *limit* hits per *window* seconds per key."""

    def __init__(
        self, limit: int, window: float, *, max_keys: int = 100_000, clock: Clock = time.time,
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._data = BoundedTTLMap(max_keys, window, clock)
        self._lock = asyncio.Lock()

    async def hit(self, key: str) -> bool:
        async with self._lock:
            count = self._data.get(key)
            if count is None:
                self._data.set(key, 1)
                return True
            # keep the original window deadline: re-set with remaining ttl
            deadline, _ = self._data._data[key]
            remaining = (deadline or self._clock()) - self._clock()
            self._data.set(key, count + 1, ttl=max(0.001, remaining))
            return count + 1 <= self.limit


@dataclass
class DelegationStores:
    """Every store the delegated profile needs, swappable as a unit."""

    devices: DeviceAuthorizationStore = field(default_factory=InMemoryDeviceAuthorizationStore)
    grants: GrantStore = field(default_factory=InMemoryGrantStore)
    refresh_tokens: RefreshTokenStore = field(default_factory=InMemoryRefreshTokenStore)
    consent_sessions: ConsentSessionStore = field(default_factory=InMemoryConsentSessionStore)
    nonces: NonceStore = field(default_factory=InMemoryNonceStore)
    user_code_attempts: AttemptLimiter = field(
        default_factory=lambda: InMemoryAttemptLimiter(limit=10, window=600)
    )


__all__ = [
    "AttemptLimiter",
    "BoundedTTLMap",
    "ConsentSession",
    "ConsentSessionStore",
    "ContextRecord",
    "ContextStore",
    "DelegationStores",
    "DeviceAuthorization",
    "DeviceAuthorizationStore",
    "Grant",
    "GrantStore",
    "InMemoryAttemptLimiter",
    "InMemoryConsentSessionStore",
    "InMemoryContextStore",
    "InMemoryDeviceAuthorizationStore",
    "InMemoryGrantStore",
    "InMemoryNonceStore",
    "InMemoryRefreshTokenStore",
    "NonceStore",
    "RefreshToken",
    "RefreshTokenStore",
    "secret_key",
]
