"""Unit tests of the asyncio Redis stores (fakeredis + real redis)."""
from __future__ import annotations

import asyncio
import time

import pytest

from ampro.interop.a2a.store import (
    CANCEL,
    PENDING,
    TIMEOUT,
    ContextStore,
    IdempotencyStore,
    TaskBroker,
    TaskStore,
)
from ampro.interop.a2a.types import Task, TaskState, TaskStatus
from ampro.interop.mcp.server import SessionStore
from ampro.security.dedup import DedupStore
from ampro.server.security import CachedResponse, ResponseCache
from ampro.stores.redis import (
    RedisContextStore,
    RedisDedupStore,
    RedisIdempotencyStore,
    RedisResponseCache,
    RedisTaskBroker,
    RedisTaskStore,
)
from ampro.stores.redis.mcp import RedisSessionStore


def _task(tid: str, ctx: str = "c1", state: TaskState = TaskState.WORKING) -> Task:
    return Task(id=tid, context_id=ctx, status=TaskStatus(state=state))


async def test_response_cache_reserve_complete_release(redis_backend):
    a = RedisResponseCache(redis_backend.async_client, prefix=redis_backend.prefix)
    b = RedisResponseCache(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(a, ResponseCache)
    assert await a.reserve("k") is True
    assert await b.reserve("k") is False  # in flight on the other worker
    await a.complete("k", CachedResponse(202, {"content-type": "application/json"}, b'{"x":1}'))
    cached = await b.reserve("k")
    assert cached == CachedResponse(202, {"content-type": "application/json"}, b'{"x":1}')
    assert await a.reserve("k2") is True
    await a.release("k2")
    assert await b.reserve("k2") is True


async def test_response_cache_oversized_reply_is_not_cached(redis_backend):
    c = RedisResponseCache(redis_backend.async_client, prefix=redis_backend.prefix,
                           max_response_bytes=64)
    assert await c.reserve("k") is True
    await c.complete("k", CachedResponse(202, {}, b"x" * 1000))
    assert await c.reserve("k") is True


async def test_dedup_store(redis_backend):
    d = RedisDedupStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(d, DedupStore)
    assert await d.is_duplicate("m") is False
    assert await d.is_duplicate("m") is True
    await d.mark_seen("m2")
    assert await d.is_duplicate("m2") is True


async def test_task_store_scopes_by_owner_and_lists(redis_backend):
    s = RedisTaskStore(redis_backend.async_client, prefix=redis_backend.prefix,
                       max_tasks_per_owner=3)
    assert isinstance(s, TaskStore)
    await s.save_task(_task("t1"), "alice")
    await s.save_task(_task("t2", "c2", TaskState.COMPLETED), "alice")
    assert (await s.get_task("t1", "alice")).id == "t1"
    assert await s.get_task("t1", "mallory") is None
    with pytest.raises(PermissionError):
        await s.save_task(_task("t1"), "mallory")
    assert [t.id for t in await s.list_tasks("alice")] == ["t2", "t1"]
    assert [t.id for t in await s.list_tasks("alice", context_id="c1")] == ["t1"]
    assert [t.id for t in await s.list_tasks("alice", state=TaskState.COMPLETED)] == ["t2"]
    assert await s.list_tasks("mallory") == []
    for i in range(3, 7):
        await s.save_task(_task(f"t{i}"), "alice")
    assert len(await s.list_tasks("alice")) == 3  # per-owner index is capped
    with pytest.raises(ValueError):
        big = RedisTaskStore(redis_backend.async_client, prefix=redis_backend.prefix,
                             max_task_bytes=100)
        await big.save_task(_task("t9", "c" * 200), "alice")


async def test_context_store_claims_atomically(redis_backend):
    s = RedisContextStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(s, ContextStore)
    assert await s.claim_context("c", "alice", create=False) is False
    results = await asyncio.gather(*(s.claim_context("c", f"u{i}") for i in range(10)))
    assert sum(results) == 1  # exactly one claimant wins
    winner = f"u{results.index(True)}"
    assert await s.claim_context("c", winner, create=False) is True
    assert not await s.is_context_closed("c")
    await s.close_context("c")
    assert await s.is_context_closed("c")


async def test_idempotency_store(redis_backend):
    s = RedisIdempotencyStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(s, IdempotencyStore)
    assert await s.begin_message("c", "m") is None
    assert await s.begin_message("c", "m") is PENDING
    await s.finish_message("c", "m", {"task": {"id": "t"}})
    assert await s.begin_message("c", "m") == {"task": {"id": "t"}}
    assert await s.begin_message("c", "m2") is None
    await s.finish_message("c", "m2", None)
    assert await s.begin_message("c", "m2") is None


async def test_task_broker_fan_out_cancel_lock_liveness(redis_backend):
    a = RedisTaskBroker(redis_backend.async_client, prefix=redis_backend.prefix)
    b = RedisTaskBroker(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(a, TaskBroker) and a.distributed
    assert not await b.is_live("t")
    await a.set_live("t")
    assert await b.is_live("t")
    async with b.subscribe("t") as sub:
        assert await sub.get(0.05) is TIMEOUT
        await a.publish("t", {"statusUpdate": {"n": 1}})
        await a.publish("t", None)
        assert await sub.get(2) == {"statusUpdate": {"n": 1}}
        assert await sub.get(2) is None
    await a.clear_live("t")
    assert not await b.is_live("t")

    # A cancel requested before the runner's watcher subscribes is not lost.
    await b.request_cancel("t2")
    async with a.subscribe("t2") as sub:
        assert await sub.get(1) == CANCEL

    assert await a.try_lock("t") is True
    assert await b.try_lock("t") is False
    await a.unlock("t")
    assert await b.try_lock("t") is True


async def test_mcp_session_store(redis_backend):
    kw = {"prefix": redis_backend.prefix, "max_sessions_per_owner": 2, "max_sessions": 3}
    a = RedisSessionStore(redis_backend.async_client, **kw)
    b = RedisSessionStore(redis_backend.async_client, **kw)
    assert isinstance(a, SessionStore)
    s1 = await a.create("2025-06-18", "alice", {"name": "c"})
    got = await b.get(s1.id, "alice")
    assert got is not None and got.protocol_version == "2025-06-18" and got.client_info == {"name": "c"}
    assert await b.get(s1.id, "mallory") is None  # owned by someone else == unknown
    got.initialized = True
    await b.save(got)
    assert (await a.get(s1.id, "alice")).initialized is True
    # Per-owner cap evicts that owner's least recently used session.
    s2 = await a.create("2025-06-18", "alice")
    s3 = await b.create("2025-06-18", "alice")
    assert await a.get(s1.id, "alice") is None
    assert await a.get(s2.id, "alice") and await a.get(s3.id, "alice")
    # Global cap refuses new sessions instead of evicting other callers'.
    assert await a.create("2025-06-18", "bob") is not None
    assert await a.create("2025-06-18", "carol") is None
    assert await b.delete(s2.id, "mallory") is False
    assert await b.delete(s2.id, "alice") is True
    assert await a.get(s2.id, "alice") is None
    assert await a.create("2025-06-18", "carol") is not None
    # Oversized client info is dropped, not stored.
    big = await a.create("2025-06-18", "dave", {"x": "y" * 100_000}, quota_key="dave")
    assert big is None or big.client_info == {}


async def test_mcp_session_lifetime(redis_backend):
    s = RedisSessionStore(redis_backend.async_client, prefix=redis_backend.prefix, max_lifetime=0.05)
    sess = await s.create("2025-06-18", None)
    assert await s.get(sess.id, None) is not None
    await asyncio.sleep(0.1)
    assert await s.get(sess.id, None) is None


# ---------------------------------------------------------------------------
# PACT
# ---------------------------------------------------------------------------


@pytest.fixture
def pact():
    pytest.importorskip("jwt")
    from ampro.interop.pact import stores
    from ampro.stores.redis import pact as rp

    return stores, rp


async def test_pact_nonce_and_attempts(redis_backend, pact):
    stores, rp = pact
    n = rp.RedisNonceStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(n, stores.NonceStore)
    assert await n.use("jti", "x", time.time() + 60) is True
    assert await n.use("jti", "x", time.time() + 60) is False
    lim = rp.RedisAttemptLimiter(redis_backend.async_client, 2, 60, prefix=redis_backend.prefix)
    assert isinstance(lim, stores.AttemptLimiter)
    assert [await lim.hit("k") for _ in range(3)] == [True, True, False]


async def test_pact_context_store(redis_backend, pact):
    stores, rp = pact
    s = rp.RedisPactContextStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(s, stores.ContextStore)
    rec = stores.ContextRecord("c1", "shop", "pact:iss#u")
    assert await s.bind(rec) == rec
    assert await s.bind(stores.ContextRecord("c1", "shop", "pact:iss#other")) == rec
    assert await s.set_brand_user("c1", "cust-1") is True
    assert await s.set_brand_user("c1", "cust-1") is True
    assert await s.set_brand_user("c1", "cust-2") is False
    assert await s.set_brand_user("missing", "x") is False
    await s.close("c1")
    assert (await s.get("c1")).closed is True and (await s.get("c1")).brand_user == "cust-1"
    assert await s.get("missing") is None


async def test_pact_device_flow_is_compare_and_set(redis_backend, pact):
    stores, rp = pact
    s = rp.RedisDeviceAuthorizationStore(redis_backend.async_client, prefix=redis_backend.prefix)
    assert isinstance(s, stores.DeviceAuthorizationStore)
    rec = stores.DeviceAuthorization("h1", "BCDF-GHJK", "shop", "https://pa", "u",
                                     ("orders:read",), 5, time.time() + 600)
    await s.create(rec)
    assert await s.by_device_code("h1") == rec
    assert await s.by_user_code("shop", "BCDF-GHJK") == rec
    assert await s.touch_poll("h1", 1.5) is None
    assert await s.touch_poll("h1", 2.5) == 1.5
    approved = await s.transition("h1", "pending", "approved", brand_user="cust", grant_id="g1")
    assert approved.status == "approved" and approved.grant_id == "g1"
    assert approved.scopes == ("orders:read",)
    results = await asyncio.gather(*(s.transition("h1", "approved", "consumed") for _ in range(5)))
    assert sum(r is not None for r in results) == 1  # redeemable exactly once
    assert await s.transition("missing", "pending", "approved") is None


async def test_pact_grants_refresh_consent_receipts(redis_backend, pact):
    stores, rp = pact
    c, p = redis_backend.async_client, redis_backend.prefix
    g = rp.RedisGrantStore(c, prefix=p)
    grant = stores.Grant("g1", "shop", "https://pa", "cust", ("a", "b"), time.time(), time.time() + 60)
    await g.create(grant)
    assert await g.get("g1") == grant
    await g.revoke("g1")
    assert (await g.get("g1")).revoked is True
    await g.revoke("missing")
    assert await g.get("missing") is None

    r = rp.RedisRefreshTokenStore(c, prefix=p)
    await r.create(stores.RefreshToken("th", "g1", time.time() + 60))
    first, second = await asyncio.gather(r.consume("th"), r.consume("th"))
    assert sorted([first.used, second.used]) == [False, True]  # reuse detected
    assert await r.consume("missing") is None

    cs = rp.RedisConsentSessionStore(c, prefix=p)
    sess = stores.ConsentSession("sh", "shop", "BCDF-GHJK", "cust", "Cust", time.time() + 60)
    await cs.create(sess)
    assert await cs.take("sh") == sess
    assert await cs.take("sh") is None

    rs = rp.RedisReceiptStore(c, prefix=p)
    assert isinstance(rs, stores.ReceiptStore)
    assert await rs.get("k") is None
    assert await rs.put_if_absent("k", {"r": 1}) == {"r": 1}
    assert await rs.put_if_absent("k", {"r": 2}) == {"r": 1}


async def test_pact_registry(redis_backend, pact):
    from ampro.interop.pact.registry import PersonalAgentRegistration, PersonalAgentRegistry

    _, rp = pact
    reg = rp.RedisPersonalAgentRegistry(redis_backend.async_client, prefix=redis_backend.prefix,
                                        max_registrations=1)
    assert isinstance(reg, PersonalAgentRegistry)
    entry = PersonalAgentRegistration(issuer="https://pa.example", jwks={"keys": []}, name="PA")
    await reg.register(entry)
    assert await reg.lookup("https://pa.example") == entry
    other = rp.RedisPersonalAgentRegistry(redis_backend.async_client, prefix=redis_backend.prefix)
    await other.set_enabled("https://pa.example", False)
    assert (await reg.lookup("https://pa.example")).enabled is False  # seen by every worker
    with pytest.raises(ValueError):
        await reg.register(PersonalAgentRegistration(issuer="https://x", jwks={"keys": []}))
    await reg.remove("https://pa.example")
    assert await other.lookup("https://pa.example") is None
