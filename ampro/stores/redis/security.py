"""Redis implementations of the synchronous security stores.

These protocols are called from synchronous code paths (signature
verification, rate-limit checks), so they use the *sync* ``redis``
client.  Each operation is one round trip and atomic: ``SET NX PX`` for
single-use values, Lua for sliding windows and leases.  Time comes from
the Redis server (``TIME``), so workers with skewed clocks still agree.
"""
from __future__ import annotations

import hashlib
import math
import secrets
from typing import Any

from ampro.security.rate_limit import RateLimitInfo
from ampro.security.sender_tracker import SenderState
from ampro.stores.redis._base import LUA_NOW_MS, Keyspace, ms, text


class _SyncStore:
    namespace = "x"

    def __init__(self, client: Any, *, prefix: str = "ampro") -> None:
        self.client = client
        self.keys = Keyspace(prefix)

    def _key(self, *parts: Any) -> str:
        return self.keys.key(self.namespace, *parts)

    def _count(self) -> int:
        """Keys in this namespace (``SCAN``; for tests and diagnostics)."""
        pattern = self.keys.key(self.namespace) + ":*"
        return sum(1 for _ in self.client.scan_iter(match=pattern, count=1000))


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


class RedisNonceTracker(_SyncStore):
    """Shared :class:`~ampro.security.nonce_tracker.ReplayCache`.

    ``is_replay`` is a single ``SET key 1 NX PX window``: exactly one
    worker ever sees a given nonce as new.
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "nonce",
                 window_seconds: float = 3600) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        super().__init__(client, prefix=prefix)
        self.namespace = namespace
        self.window_seconds = window_seconds

    def is_replay(self, nonce: str) -> bool:
        created = self.client.set(self._key(nonce), b"1", nx=True, px=ms(self.window_seconds))
        return not created

    def seen_count(self) -> int:
        return self._count()


class RedisFederationNonceCache(_SyncStore):
    """Shared :class:`~ampro.registry.federation.FederationNonceCache`."""

    namespace = "fednonce"

    def check_and_add(self, key: str, ttl_seconds: float) -> bool:
        return bool(self.client.set(self._key(key), b"1", nx=True, px=ms(ttl_seconds)))


# ---------------------------------------------------------------------------
# Rate limiting (sliding-window log in a sorted set)
# ---------------------------------------------------------------------------

_RATE_LIMIT = LUA_NOW_MS + """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local reset = now + window
  if oldest[2] then reset = tonumber(oldest[2]) + window end
  return {0, count, reset}
end
redis.call('ZADD', key, now, ARGV[3])
redis.call('PEXPIRE', key, window)
return {1, count + 1, now + window}
"""


class RedisRateLimiter(_SyncStore):
    """Shared :class:`~ampro.security.rate_limiter.RateLimiterBackend`.

    At most *rpm* requests per *window_seconds* per key, counted across
    every worker.  Memory is bounded per key (the sorted set never holds
    more than *rpm* entries) and keys expire after one idle window.
    """

    namespace = "rl"

    def __init__(self, client: Any, *, prefix: str = "ampro", rpm: int = 60,
                 window_seconds: float = 60) -> None:
        if rpm <= 0:
            raise ValueError("rpm must be > 0")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        super().__init__(client, prefix=prefix)
        self.rpm = rpm
        self.window_seconds = window_seconds
        self._script = client.register_script(_RATE_LIMIT)

    def check(self, sender: str) -> tuple[bool, RateLimitInfo]:
        allowed, count, reset_ms = self._script(
            keys=[self._key(sender)],
            args=[ms(self.window_seconds), self.rpm, secrets.token_hex(8)],
        )
        reset = math.ceil(int(reset_ms) / 1000)
        info = RateLimitInfo(limit=self.rpm, remaining=max(0, self.rpm - int(count)), reset=reset)
        return bool(int(allowed)), info

    def sender_count(self) -> int:
        return self._count()


# ---------------------------------------------------------------------------
# Concurrency (leased slots, global + per sender)
# ---------------------------------------------------------------------------

_ACQUIRE = LUA_NOW_MS + """
local g, s = KEYS[1], KEYS[2]
local ttl = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', g, '-inf', now)
redis.call('ZREMRANGEBYSCORE', s, '-inf', now)
if ARGV[4] == 'check' then
  if redis.call('ZCARD', g) >= tonumber(ARGV[2]) then return 0 end
  if redis.call('ZCARD', s) >= tonumber(ARGV[3]) then return 0 end
  return 1
end
if redis.call('ZCARD', g) >= tonumber(ARGV[2]) then return 0 end
if redis.call('ZCARD', s) >= tonumber(ARGV[3]) then return 0 end
redis.call('ZADD', g, now + ttl, ARGV[4])
redis.call('ZADD', s, now + ttl, ARGV[4])
redis.call('PEXPIRE', g, ttl)
redis.call('PEXPIRE', s, ttl)
return 1
"""

_RELEASE = """
local m = redis.call('ZPOPMIN', KEYS[2])
if m[1] then redis.call('ZREM', KEYS[1], m[1]) end
return 1
"""

_COUNT = LUA_NOW_MS + """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
return redis.call('ZCARD', KEYS[1])
"""


class RedisConcurrencyLimiter(_SyncStore):
    """Shared :class:`~ampro.security.concurrency_limiter.ConcurrencyBackend`.

    Each slot is a lease that expires after *slot_ttl_seconds*, so a
    worker that crashes mid-request cannot leak capacity forever.
    """

    namespace = "conc"

    def __init__(self, client: Any, *, prefix: str = "ampro", max_total: int = 50,
                 per_sender_pct: float = 0.5, slot_ttl_seconds: float = 600.0) -> None:
        if max_total <= 0:
            raise ValueError("max_total must be > 0")
        if not (0.0 < per_sender_pct <= 1.0):
            raise ValueError("per_sender_pct must be in (0, 1]")
        if slot_ttl_seconds <= 0:
            raise ValueError("slot_ttl_seconds must be > 0 for a shared limiter")
        super().__init__(client, prefix=prefix)
        self.max_total = max_total
        self.per_sender_max = max(1, int(max_total * per_sender_pct))
        self.slot_ttl_seconds = slot_ttl_seconds
        self._acquire = client.register_script(_ACQUIRE)
        self._release = client.register_script(_RELEASE)
        self._count_script = client.register_script(_COUNT)

    def _keys(self, sender: str) -> list[str]:
        return [self._key("all"), self._key("s", sender)]

    def acquire(self, sender: str) -> bool:
        return bool(int(self._acquire(keys=self._keys(sender), args=[
            ms(self.slot_ttl_seconds), self.max_total, self.per_sender_max,
            secrets.token_hex(12)])))

    def can_accept(self, sender: str) -> bool:
        return bool(int(self._acquire(keys=self._keys(sender), args=[
            ms(self.slot_ttl_seconds), self.max_total, self.per_sender_max, "check"])))

    def release(self, sender: str) -> None:
        self._release(keys=self._keys(sender))

    def sender_active(self, sender: str) -> int:
        return int(self._count_script(keys=[self._key("s", sender)]))

    @property
    def total_active(self) -> int:
        return int(self._count_script(keys=[self._key("all")]))


# ---------------------------------------------------------------------------
# Poison-message escalation
# ---------------------------------------------------------------------------

_RECORD_FAILURE = LUA_NOW_MS + """
local st, fl = KEYS[1], KEYS[2]
local window, threshold = tonumber(ARGV[1]), tonumber(ARGV[2])
local state = redis.call('GET', st)
if state == 'blocked' then return 'blocked' end
if state == 'throttled' then
  redis.call('SET', st, 'blocked', 'PX', ARGV[4])
  redis.call('DEL', fl)
  return 'blocked'
end
redis.call('ZREMRANGEBYSCORE', fl, '-inf', now - window)
redis.call('ZADD', fl, now, ARGV[5])
redis.call('PEXPIRE', fl, window)
if redis.call('ZCARD', fl) >= threshold then
  redis.call('SET', st, 'throttled', 'PX', ARGV[3])
  redis.call('DEL', fl)
  return 'throttled'
end
return 'normal'
"""


class RedisSenderTracker(_SyncStore):
    """Shared :class:`~ampro.security.sender_tracker.SenderTrackerBackend`."""

    namespace = "sender"

    def __init__(self, client: Any, *, prefix: str = "ampro", failure_threshold: int = 3,
                 failure_window: int = 300, throttle_duration: int = 900,
                 block_duration: int = 3600) -> None:
        super().__init__(client, prefix=prefix)
        self.failure_threshold = failure_threshold
        self.failure_window = failure_window
        self.throttle_duration = throttle_duration
        self.block_duration = block_duration
        self._record = client.register_script(_RECORD_FAILURE)

    def get_state(self, sender: str) -> SenderState:
        raw = text(self.client.get(self._key("st", sender)))
        return SenderState(raw) if raw else SenderState.NORMAL

    def record_failure(self, sender: str) -> SenderState:
        result = self._record(
            keys=[self._key("st", sender), self._key("f", sender)],
            args=[ms(self.failure_window), self.failure_threshold,
                  ms(self.throttle_duration), ms(self.block_duration), secrets.token_hex(8)],
        )
        return SenderState(text(result))

    def record_success(self, sender: str) -> None:
        self.client.zpopmin(self._key("f", sender))

    def is_allowed(self, sender: str) -> bool:
        return self.get_state(sender) == SenderState.NORMAL


# ---------------------------------------------------------------------------
# Key revocation and API keys
# ---------------------------------------------------------------------------


class RedisRevocationStore(_SyncStore):
    """Shared :class:`~ampro.security.key_revocation.RevocationStore`.

    Register with :func:`ampro.security.key_revocation.register_revocation_store`.
    A revocation written by any worker (or an admin tool) is seen by all.
    """

    namespace = "revoked"

    def is_revoked(self, key_id: str) -> bool:
        return bool(self.client.exists(self._key(key_id)))

    def revoke(self, key_id: str, reason: str = "key_compromise",
               ttl_seconds: float | None = None) -> None:
        """Record *key_id* as revoked (forever unless *ttl_seconds*)."""
        px = ms(ttl_seconds) if ttl_seconds else None
        self.client.set(self._key(key_id), reason.encode("utf-8")[:64], px=px)

    def unrevoke(self, key_id: str) -> None:
        self.client.delete(self._key(key_id))


_API_KEY_FAILURE = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if c >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
  redis.call('DEL', KEYS[1])
end
return c
"""


class RedisApiKeyFailureTracker(_SyncStore):
    """Shared :class:`~ampro.transport.api_key_store.ApiKeyFailureTracker`.

    *max_failures* bad keys from one address within *window_seconds* block
    that address for *block_seconds* on every worker.
    """

    namespace = "apikeyfail"

    def __init__(self, client: Any, *, prefix: str = "ampro", max_failures: int = 10,
                 block_seconds: int = 900, window_seconds: int = 60) -> None:
        super().__init__(client, prefix=prefix)
        self.max_failures = max_failures
        self.block_seconds = block_seconds
        self.window_seconds = window_seconds
        self._fail = client.register_script(_API_KEY_FAILURE)

    def is_blocked(self, ip: str) -> bool:
        return bool(self.client.exists(self._key("b", ip)))

    def record_failure(self, ip: str) -> None:
        self._fail(keys=[self._key("f", ip), self._key("b", ip)],
                   args=[ms(self.window_seconds), self.max_failures, ms(self.block_seconds)])

    def reset_failures(self, ip: str) -> None:
        self.client.delete(self._key("f", ip), self._key("b", ip))


class RedisApiKeyValidator(_SyncStore):
    """Shared :class:`~ampro.trust.resolver.ApiKeyValidator` (hashes only).

    Register with :func:`ampro.trust.resolver.register_api_key_store`; keys
    added or removed by any worker take effect everywhere.
    """

    namespace = "apikeys"

    @staticmethod
    def _digest(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def add_key(self, key: str, agent_id: str) -> None:
        if not key:
            raise ValueError("API key must be non-empty")
        self.client.hset(self._key("h"), self._digest(key), agent_id.encode("utf-8"))

    def remove_key(self, key: str) -> None:
        self.client.hdel(self._key("h"), self._digest(key))

    def validate(self, key: str) -> str | None:
        return text(self.client.hget(self._key("h"), self._digest(key)))


# ---------------------------------------------------------------------------
# Stream channels
# ---------------------------------------------------------------------------

_REGISTER_CHANNEL = """
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then return 1 end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"""


class RedisChannelRegistry(_SyncStore):
    """Shared :class:`~ampro.streaming.channel.ChannelRegistryBackend`."""

    namespace = "chan"

    def __init__(self, client: Any, *, prefix: str = "ampro", max_per_session: int = 16,
                 ttl_seconds: float = 24 * 3600) -> None:
        super().__init__(client, prefix=prefix)
        self.max_per_session = max_per_session
        self.ttl_seconds = ttl_seconds
        self._register = client.register_script(_REGISTER_CHANNEL)

    def register_channel(self, session_id: str, channel_id: str) -> None:
        from ampro.streaming.channel import ChannelQuotaExceededError

        ok = self._register(keys=[self._key(session_id)],
                            args=[channel_id, self.max_per_session, ms(self.ttl_seconds)])
        if not int(ok):
            raise ChannelQuotaExceededError(session_id, self.max_per_session)

    def release_channel(self, session_id: str, channel_id: str) -> None:
        self.client.srem(self._key(session_id), channel_id)

    def count(self, session_id: str) -> int:
        return int(self.client.scard(self._key(session_id)))


__all__ = [
    "RedisApiKeyFailureTracker",
    "RedisApiKeyValidator",
    "RedisChannelRegistry",
    "RedisConcurrencyLimiter",
    "RedisFederationNonceCache",
    "RedisNonceTracker",
    "RedisRateLimiter",
    "RedisRevocationStore",
    "RedisSenderTracker",
]
