"""Unit tests of the synchronous Redis stores (fakeredis + real redis)."""
from __future__ import annotations

import pytest

from ampro.registry.federation import FederationNonceCache
from ampro.security.concurrency_limiter import ConcurrencyBackend
from ampro.security.nonce_tracker import ReplayCache
from ampro.security.rate_limiter import RateLimiterBackend
from ampro.security.sender_tracker import SenderState, SenderTrackerBackend
from ampro.stores.redis import (
    RedisApiKeyFailureTracker,
    RedisApiKeyValidator,
    RedisChannelRegistry,
    RedisConcurrencyLimiter,
    RedisFederationNonceCache,
    RedisNonceTracker,
    RedisRateLimiter,
    RedisRevocationStore,
    RedisSenderTracker,
)
from ampro.stores.redis._base import Keyspace, dumps, key_part
from ampro.streaming.channel import ChannelQuotaExceededError, ChannelRegistryBackend
from ampro.transport.api_key_store import ApiKeyFailureTracker


def test_key_parts_are_bounded_and_collision_free():
    assert key_part("abc-1.2@x") == "abc-1.2@x"
    hashed = key_part("a:b")
    assert hashed.startswith("~") and ":" not in hashed
    assert key_part("a" * 500) != key_part("a" * 501)
    assert len(key_part("x" * 10_000)) == 41
    ks = Keyspace("p")
    assert ks.key("ns", "a:b", "c") != ks.key("ns", "a", "b:c")
    with pytest.raises(ValueError):
        Keyspace("bad prefix")


def test_values_are_json_and_bounded():
    assert dumps({"a": 1}) == '{"a":1}'
    with pytest.raises(ValueError):
        dumps("x" * 100, limit=10)
    with pytest.raises(TypeError):
        dumps(object())  # never pickled


def test_nonce_tracker_is_single_use(redis_backend):
    t = RedisNonceTracker(redis_backend.client, prefix=redis_backend.prefix)
    assert isinstance(t, ReplayCache)
    assert t.is_replay("n1") is False
    assert t.is_replay("n1") is True
    assert t.is_replay("n2") is False
    assert t.seen_count() == 2
    other = RedisNonceTracker(redis_backend.client, prefix=redis_backend.prefix)
    assert other.is_replay("n1") is True  # a second "worker" sees it too
    with pytest.raises(ValueError):
        RedisNonceTracker(redis_backend.client, window_seconds=0)


def test_rate_limiter_counts_globally(redis_backend):
    a = RedisRateLimiter(redis_backend.client, prefix=redis_backend.prefix, rpm=3)
    b = RedisRateLimiter(redis_backend.client, prefix=redis_backend.prefix, rpm=3)
    assert isinstance(a, RateLimiterBackend)
    results = [a.check("s")[0], b.check("s")[0], a.check("s")[0], b.check("s")[0]]
    assert results == [True, True, True, False]
    allowed, info = a.check("s")
    assert not allowed and info.limit == 3 and info.remaining == 0 and info.reset > 0
    assert a.check("other")[0] is True
    assert a.sender_count() == 2


def test_concurrency_leases_are_shared(redis_backend):
    kw = {"prefix": redis_backend.prefix, "max_total": 4}
    a = RedisConcurrencyLimiter(redis_backend.client, **kw)
    b = RedisConcurrencyLimiter(redis_backend.client, **kw)
    assert isinstance(a, ConcurrencyBackend)
    assert a.acquire("s") and b.acquire("s")
    assert not a.acquire("s")  # per-sender cap (50%) reached across workers
    assert not b.can_accept("s") and b.can_accept("t")
    assert a.acquire("t") and b.acquire("t")
    assert not a.acquire("u")  # global cap
    assert a.total_active == 4
    b.release("s")
    assert a.sender_active("s") == 1 and a.acquire("u")
    a.release("nobody")  # harmless


def test_concurrency_leases_expire(redis_backend):
    import time

    lim = RedisConcurrencyLimiter(redis_backend.client, prefix=redis_backend.prefix,
                                  max_total=2, per_sender_pct=1.0, slot_ttl_seconds=0.05)
    assert lim.acquire("s") and lim.acquire("s") and not lim.acquire("s")
    time.sleep(0.1)
    assert lim.acquire("s")  # crashed holders cannot leak capacity


def test_sender_tracker_escalates_across_workers(redis_backend):
    a = RedisSenderTracker(redis_backend.client, prefix=redis_backend.prefix)
    b = RedisSenderTracker(redis_backend.client, prefix=redis_backend.prefix)
    assert isinstance(a, SenderTrackerBackend)
    assert a.record_failure("p") == SenderState.NORMAL
    assert b.record_failure("p") == SenderState.NORMAL
    a.record_success("p")  # decays one failure, never resets
    assert b.record_failure("p") == SenderState.NORMAL
    assert a.record_failure("p") == SenderState.THROTTLED
    assert not b.is_allowed("p") and b.get_state("p") == SenderState.THROTTLED
    assert b.record_failure("p") == SenderState.BLOCKED
    assert a.record_failure("p") == SenderState.BLOCKED
    assert a.is_allowed("q")


def test_revocation_store(redis_backend):
    s = RedisRevocationStore(redis_backend.client, prefix=redis_backend.prefix)
    assert not s.is_revoked("k1")
    s.revoke("k1")
    assert s.is_revoked("k1")
    s.unrevoke("k1")
    assert not s.is_revoked("k1")


def test_api_key_failure_tracker_and_validator(redis_backend):
    t = RedisApiKeyFailureTracker(redis_backend.client, prefix=redis_backend.prefix, max_failures=3)
    assert isinstance(t, ApiKeyFailureTracker)
    for _ in range(2):
        t.record_failure("1.2.3.4")
    assert not t.is_blocked("1.2.3.4")
    t.record_failure("1.2.3.4")
    assert t.is_blocked("1.2.3.4")
    t.reset_failures("1.2.3.4")
    assert not t.is_blocked("1.2.3.4")

    v = RedisApiKeyValidator(redis_backend.client, prefix=redis_backend.prefix)
    v.add_key("secret-key", "agent://a")
    assert v.validate("secret-key") == "agent://a"
    assert v.validate("wrong") is None
    raw = {k for k in redis_backend.client.hkeys(v._key("h"))}
    assert b"secret-key" not in raw  # only digests are stored
    v.remove_key("secret-key")
    assert v.validate("secret-key") is None


def test_federation_nonce_cache(redis_backend):
    c = RedisFederationNonceCache(redis_backend.client, prefix=redis_backend.prefix)
    assert isinstance(c, FederationNonceCache)
    assert c.check_and_add("r\x00n", 60) is True
    assert c.check_and_add("r\x00n", 60) is False


def test_channel_registry_quota_is_global(redis_backend):
    a = RedisChannelRegistry(redis_backend.client, prefix=redis_backend.prefix, max_per_session=2)
    b = RedisChannelRegistry(redis_backend.client, prefix=redis_backend.prefix, max_per_session=2)
    assert isinstance(a, ChannelRegistryBackend)
    a.register_channel("s", "c1")
    b.register_channel("s", "c2")
    b.register_channel("s", "c2")  # idempotent
    with pytest.raises(ChannelQuotaExceededError):
        a.register_channel("s", "c3")
    a.release_channel("s", "c1")
    b.register_channel("s", "c3")
    assert a.count("s") == 2
