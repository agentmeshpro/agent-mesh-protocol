"""Bounded, expiring default stores."""
from __future__ import annotations

from ampro.interop.pact.stores import (
    BoundedTTLMap,
    ContextRecord,
    DeviceAuthorization,
    InMemoryAttemptLimiter,
    InMemoryContextStore,
    InMemoryDeviceAuthorizationStore,
    InMemoryNonceStore,
    InMemoryRefreshTokenStore,
    RefreshToken,
    secret_key,
)

from .conftest import FakeClock


def test_bounded_map_evicts_lru_and_expires():
    clock = FakeClock(1000)
    m = BoundedTTLMap(2, 10, clock)
    m.set("a", 1)
    m.set("b", 2)
    m.get("a")
    m.set("c", 3)
    assert m.get("b") is None and m.get("a") == 1 and len(m) == 2
    clock.advance(11)
    assert m.get("a") is None and m.values() == []


async def test_nonce_store_single_use_and_expiry():
    clock = FakeClock(1000)
    s = InMemoryNonceStore(clock=clock)
    assert await s.use("ns", "j", 1060)
    assert not await s.use("ns", "j", 1060)
    assert await s.use("other", "j", 1060)
    clock.advance(61)
    assert await s.use("ns", "j", 1200)


async def test_attempt_limiter_window():
    clock = FakeClock(1000)
    lim = InMemoryAttemptLimiter(limit=2, window=60, clock=clock)
    assert await lim.hit("k") and await lim.hit("k")
    assert not await lim.hit("k")
    assert await lim.hit("other")
    clock.advance(61)
    assert await lim.hit("k")


async def test_refresh_consume_reports_reuse():
    s = InMemoryRefreshTokenStore()
    h = secret_key("rt_x")
    assert h != "rt_x"
    await s.create(RefreshToken(token_hash=h, grant_id="g", expires_at=10**12))
    assert (await s.consume(h)).used is False
    assert (await s.consume(h)).used is True
    assert await s.consume(secret_key("nope")) is None


async def test_device_transition_is_compare_and_set():
    clock = FakeClock(1000)
    s = InMemoryDeviceAuthorizationStore(clock=clock)
    rec = DeviceAuthorization(device_code_hash="h", user_code="BBBB-CCCC", brand_id="b", client_id="c",
                              pa_subject="s", scopes=("x",), interval=5, expires_at=1600)
    await s.create(rec)
    assert (await s.by_user_code("b", "BBBB-CCCC")).device_code_hash == "h"
    assert await s.by_user_code("other", "BBBB-CCCC") is None
    assert await s.transition("h", "pending", "approved", grant_id="g")
    assert await s.transition("h", "pending", "denied") is None
    assert (await s.by_device_code("h")).status == "approved"


async def test_context_store_sub_binding_and_close():
    s = InMemoryContextStore()
    rec = await s.bind(ContextRecord("c1", "b", "owner"))
    assert (await s.bind(ContextRecord("c1", "b", "intruder"))).owner == rec.owner
    assert await s.set_brand_user("c1", "u1")
    assert await s.set_brand_user("c1", "u1")
    assert not await s.set_brand_user("c1", "u2")
    await s.close("c1")
    assert (await s.get("c1")).closed
