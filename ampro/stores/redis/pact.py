"""Redis stores for PACT (delegation, contexts, receipts, registry).

Records are Redis hashes whose fields hold JSON-encoded values, so a
compare-and-set (device-code status, refresh-token use) is a short Lua
script over plain strings.  Secrets are already hashed by the caller
(:func:`ampro.interop.pact.stores.secret_key`).
"""
from __future__ import annotations

import dataclasses
import json
import logging
import time
from typing import Any, TypeVar

from ampro.interop.pact.jwks import JSONFetcher
from ampro.interop.pact.registry import (
    MAX_ISSUER_LEN,
    InMemoryPersonalAgentRegistry,
    PersonalAgentRegistration,
)
from ampro.interop.pact.stores import (
    Clock,
    ConsentSession,
    ContextRecord,
    DeviceAuthorization,
    Grant,
    RefreshToken,
)
from ampro.stores.redis._base import Keyspace, dumps, loads, ms, pairs, text

logger = logging.getLogger("ampro.stores.redis.pact")

T = TypeVar("T")


def _to_fields(record: Any) -> dict[str, str]:
    return {f.name: json.dumps(getattr(record, f.name)) for f in dataclasses.fields(record)}


def _from_fields(cls: type[T], fields: dict[str, str]) -> T | None:
    if not fields:
        return None
    values: dict[str, Any] = {}
    for f in dataclasses.fields(cls):  # type: ignore[arg-type]
        if f.name not in fields:
            continue
        value = json.loads(fields[f.name])
        if isinstance(value, list):
            value = tuple(value)
        values[f.name] = value
    return cls(**values)


class _Store:
    namespace = "pact"

    def __init__(self, client: Any, *, prefix: str = "ampro", clock: Clock = time.time) -> None:
        self.client = client
        self.keys = Keyspace(prefix)
        self.clock = clock

    def _key(self, *parts: Any) -> str:
        return self.keys.key(self.namespace, *parts)

    def _ttl(self, expires_at: float, extra: float = 0.0) -> int:
        return ms(max(1.0, expires_at - self.clock()) + extra)


# ---------------------------------------------------------------------------
# Single-use values and attempt limits
# ---------------------------------------------------------------------------


class RedisNonceStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.NonceStore` (``SET NX``)."""

    async def use(self, namespace: str, value: str, expires_at: float) -> bool:
        return bool(await self.client.set(self._key("nonce", namespace, value), b"1",
                                          nx=True, px=self._ttl(expires_at)))


_HIT = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return c
"""


class RedisAttemptLimiter(_Store):
    """Shared :class:`~ampro.interop.pact.stores.AttemptLimiter` (fixed window)."""

    def __init__(self, client: Any, limit: int, window: float, *, prefix: str = "ampro",
                 name: str = "attempts", clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self.limit = limit
        self.window = window
        self.name = name
        self._hit = client.register_script(_HIT)

    async def hit(self, key: str) -> bool:
        count = await self._hit(keys=[self._key("hits", self.name, key)], args=[ms(self.window)])
        return int(count) <= self.limit


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

_BIND = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  for i = 2, #ARGV, 2 do redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1]) end
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return redis.call('HGETALL', KEYS[1])
"""

_SET_BRAND_USER = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local cur = redis.call('HGET', KEYS[1], 'brand_user')
if (not cur) or cur == 'null' then
  redis.call('HSET', KEYS[1], 'brand_user', ARGV[1])
  return 1
end
if cur == ARGV[1] then return 1 end
return 0
"""

_SET_IF_EXISTS = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 1
"""


class RedisPactContextStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.ContextStore`."""

    def __init__(self, client: Any, *, prefix: str = "ampro", ttl_seconds: float = 7 * 24 * 3600,
                 clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self.ttl_seconds = ttl_seconds
        self._bind = client.register_script(_BIND)
        self._brand_user = client.register_script(_SET_BRAND_USER)
        self._set = client.register_script(_SET_IF_EXISTS)

    async def get(self, context_id: str) -> ContextRecord | None:
        return _from_fields(ContextRecord, pairs(await self.client.hgetall(self._key("ctx", context_id))))

    async def bind(self, record: ContextRecord) -> ContextRecord:
        flat: list[str] = []
        for k, v in _to_fields(record).items():
            flat += [k, v]
        stored = await self._bind(keys=[self._key("ctx", record.context_id)],
                                  args=[ms(self.ttl_seconds), *flat])
        return _from_fields(ContextRecord, pairs(stored)) or record

    async def set_brand_user(self, context_id: str, brand_user: str) -> bool:
        return bool(int(await self._brand_user(keys=[self._key("ctx", context_id)],
                                                args=[json.dumps(brand_user)])))

    async def close(self, context_id: str) -> None:
        await self._set(keys=[self._key("ctx", context_id)], args=["closed", "true"])


# ---------------------------------------------------------------------------
# Device authorizations (RFC 8628) — status transitions are compare-and-set
# ---------------------------------------------------------------------------

_TRANSITION = """
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
if redis.call('HGET', KEYS[1], 'status') ~= ARGV[1] then return false end
redis.call('HSET', KEYS[1], 'status', ARGV[2])
for i = 3, #ARGV, 2 do redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1]) end
return redis.call('HGETALL', KEYS[1])
"""

_TOUCH = """
if redis.call('EXISTS', KEYS[1]) == 0 then return {0} end
local prev = redis.call('HGET', KEYS[1], 'last_polled_at')
redis.call('HSET', KEYS[1], 'last_polled_at', ARGV[1])
return {1, prev}
"""


class RedisDeviceAuthorizationStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.DeviceAuthorizationStore`.

    ``transition`` is atomic across workers, so an approved device code is
    redeemed (``approved -> consumed``) exactly once wherever it is polled.
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self._transition = client.register_script(_TRANSITION)
        self._touch = client.register_script(_TOUCH)

    async def create(self, record: DeviceAuthorization) -> None:
        ttl = self._ttl(record.expires_at, 300)
        key = self._key("dev", record.device_code_hash)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            pipe.hset(key, mapping=_to_fields(record))
            pipe.pexpire(key, ttl)
            pipe.set(self._key("uc", record.brand_id, record.user_code),
                     record.device_code_hash, px=ttl)
            await pipe.execute()

    async def by_device_code(self, device_code_hash: str) -> DeviceAuthorization | None:
        return _from_fields(DeviceAuthorization,
                            pairs(await self.client.hgetall(self._key("dev", device_code_hash))))

    async def by_user_code(self, brand_id: str, user_code: str) -> DeviceAuthorization | None:
        h = text(await self.client.get(self._key("uc", brand_id, user_code)))
        return None if h is None else await self.by_device_code(h)

    async def touch_poll(self, device_code_hash: str, at: float) -> float | None:
        result = await self._touch(keys=[self._key("dev", device_code_hash)], args=[json.dumps(at)])
        if not int(result[0]) or len(result) < 2 or result[1] is None:
            return None
        return json.loads(text(result[1]))  # type: ignore[arg-type]

    async def transition(self, device_code_hash: str, expected: str, new: str,
                         **changes: Any) -> DeviceAuthorization | None:
        flat: list[str] = []
        for k, v in changes.items():
            flat += [k, json.dumps(v)]
        result = await self._transition(keys=[self._key("dev", device_code_hash)],
                                        args=[json.dumps(expected), json.dumps(new), *flat])
        if not result:
            return None
        return _from_fields(DeviceAuthorization, pairs(result))


# ---------------------------------------------------------------------------
# Grants, refresh tokens, consent sessions, receipts
# ---------------------------------------------------------------------------


class RedisGrantStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.GrantStore`."""

    def __init__(self, client: Any, *, prefix: str = "ampro", clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self._set = client.register_script(_SET_IF_EXISTS)

    async def create(self, grant: Grant) -> None:
        key = self._key("grant", grant.grant_id)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=_to_fields(grant))
            pipe.pexpire(key, self._ttl(grant.expires_at))
            await pipe.execute()

    async def get(self, grant_id: str) -> Grant | None:
        return _from_fields(Grant, pairs(await self.client.hgetall(self._key("grant", grant_id))))

    async def revoke(self, grant_id: str) -> None:
        await self._set(keys=[self._key("grant", grant_id)], args=["revoked", "true"])


_CONSUME = """
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
local before = redis.call('HGETALL', KEYS[1])
redis.call('HSET', KEYS[1], 'used', 'true')
return before
"""


class RedisRefreshTokenStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.RefreshTokenStore`.

    ``consume`` marks the token used and returns the record *as it was*
    in one script: the second presentation — on any worker — sees
    ``used=True`` and triggers reuse detection (grant revocation).
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self._consume = client.register_script(_CONSUME)

    async def create(self, token: RefreshToken) -> None:
        key = self._key("rt", token.token_hash)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=_to_fields(token))
            pipe.pexpire(key, self._ttl(token.expires_at))
            await pipe.execute()

    async def consume(self, token_hash: str) -> RefreshToken | None:
        result = await self._consume(keys=[self._key("rt", token_hash)])
        if not result:
            return None
        return _from_fields(RefreshToken, pairs(result))


class RedisConsentSessionStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.ConsentSessionStore` (``GETDEL``)."""

    async def create(self, session: ConsentSession) -> None:
        await self.client.set(self._key("consent", session.session_hash),
                              dumps(dataclasses.asdict(session)), px=self._ttl(session.expires_at))

    async def take(self, session_hash: str) -> ConsentSession | None:
        raw = await self.client.getdel(self._key("consent", session_hash))
        if raw is None:
            return None
        return ConsentSession(**loads(raw))


_PUT_IF_ABSENT = """
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then return ARGV[1] end
return redis.call('GET', KEYS[1])
"""


class RedisReceiptStore(_Store):
    """Shared :class:`~ampro.interop.pact.stores.ReceiptStore`."""

    def __init__(self, client: Any, *, prefix: str = "ampro", ttl_seconds: float = 24 * 3600,
                 clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self.ttl_seconds = ttl_seconds
        self._put = client.register_script(_PUT_IF_ABSENT)

    async def get(self, key: str) -> dict[str, Any] | None:
        return loads(await self.client.get(self._key("receipt", key)))

    async def put_if_absent(self, key: str, receipt: dict[str, Any]) -> dict[str, Any]:
        stored = await self._put(keys=[self._key("receipt", key)],
                                 args=[dumps(receipt), ms(self.ttl_seconds)])
        return loads(stored)


# ---------------------------------------------------------------------------
# Personal-agent registry
# ---------------------------------------------------------------------------


class RedisPersonalAgentRegistry(_Store):
    """Shared :class:`~ampro.interop.pact.registry.PersonalAgentRegistry`.

    Registrations live in one Redis hash, so enabling, disabling or
    removing a personal agent on any worker (or from an admin script)
    applies everywhere at once.  The admin methods are ``async``.  In
    *open_mode* OIDC discovery results are cached per process (they are
    public data re-derivable from the issuer).
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", open_mode: bool = False,
                 fetcher: JSONFetcher | None = None, max_registrations: int = 10_000,
                 discovery_ttl: float = 3600.0, clock: Clock = time.time) -> None:
        super().__init__(client, prefix=prefix, clock=clock)
        self.max_registrations = max_registrations
        self.open_mode = open_mode
        # Reuse the in-memory registry's discovery logic and cache.
        self._discovery = InMemoryPersonalAgentRegistry(
            open_mode=open_mode, fetcher=fetcher, discovery_ttl=discovery_ttl, clock=clock)

    @staticmethod
    def _encode(reg: PersonalAgentRegistration) -> str:
        return dumps({"issuer": reg.issuer, "jwks_uri": reg.jwks_uri, "audience": reg.audience,
                      "enabled": reg.enabled, "name": reg.name, "jwks": reg.jwks}, limit=262_144)

    async def register(self, registration: PersonalAgentRegistration) -> None:
        key = self._key("pa")
        if not await self.client.hexists(key, registration.issuer):
            if await self.client.hlen(key) >= self.max_registrations:
                raise ValueError("registry is full")
        await self.client.hset(key, registration.issuer, self._encode(registration))

    async def set_enabled(self, issuer: str, enabled: bool) -> None:
        reg = await self._get(issuer)
        if reg is None:
            raise KeyError(issuer)
        await self.register(dataclasses.replace(reg, enabled=enabled))

    async def remove(self, issuer: str) -> None:
        await self.client.hdel(self._key("pa"), issuer)

    async def _get(self, issuer: str) -> PersonalAgentRegistration | None:
        raw = await self.client.hget(self._key("pa"), issuer)
        if raw is None:
            return None
        return PersonalAgentRegistration(**loads(raw))

    async def lookup(self, issuer: str) -> PersonalAgentRegistration | None:
        if not isinstance(issuer, str) or not issuer or len(issuer) > MAX_ISSUER_LEN:
            return None
        reg = await self._get(issuer)
        if reg is not None or not self.open_mode:
            return reg
        return await self._discovery.lookup(issuer)


__all__ = [
    "RedisAttemptLimiter",
    "RedisConsentSessionStore",
    "RedisDeviceAuthorizationStore",
    "RedisGrantStore",
    "RedisNonceStore",
    "RedisPactContextStore",
    "RedisPersonalAgentRegistry",
    "RedisReceiptStore",
    "RedisRefreshTokenStore",
]
