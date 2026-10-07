"""Several workers behind a load balancer, simulated as independent servers.

Each "worker" is a separate :class:`AgentServer` object (its own adapters,
in-memory defaults, background tasks); the only thing they share is one
Redis (fakeredis, or a real ``redis-server`` when available).  Every test
sends a request to worker 1 and a follow-up to worker 2, which is exactly
what a round-robin balancer does.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption as _NoEnc

from ampro.ampi.app import AgentApp
from ampro.interop.a2a import A2AAdapter, InvalidToken, Principal
from ampro.interop.mcp import MCPAdapter
from ampro.security.nonce_tracker import NonceTracker
from ampro.security.rate_limiter import RateLimiter
from ampro.security.rfc9421 import sign_request
from ampro.server import AgentServer
from ampro.server.auth import SignatureAuthenticator
from ampro.server.http import HTTPRequest
from ampro.server.security import SecurityPolicy
from ampro.stores.redis import configure
from ampro.trust.tiers import TrustTier
from ampro.wire.config import DEFAULTS

BASE = "https://agent.example"
AGENT = "agent://agent.example"
CALLER = "agent://caller.example"


def shared(backend: Any, server: AgentServer, **kw: Any) -> AgentServer:
    configure(server, client=backend.client, async_client=backend.async_client,
              prefix=backend.prefix, **kw)
    return server


def envelope(msg_id: str | None = None, sender: str = CALLER) -> dict[str, Any]:
    return {"sender": sender, "recipient": AGENT, "id": msg_id or str(uuid.uuid4()),
            "body_type": "task.create", "body": {"description": "hello"}}


def post(server: AgentServer, env: dict[str, Any], headers: dict[str, str] | None = None):
    return server.handle(HTTPRequest(
        method="POST", path="/agent/message",
        headers={"content-type": "application/json", **(headers or {})},
        body=json.dumps(env).encode(), client="203.0.113.7"))


def counting_app(calls: list[str]) -> AgentApp:
    app = AgentApp(AGENT, BASE)

    @app.on("task.create")
    async def create(msg, ctx):
        calls.append(msg.id)
        return {"handled": len(calls)}

    return app


# ---------------------------------------------------------------------------
# Native AMP route: replay, rate limits, dedup
# ---------------------------------------------------------------------------


class _Keys:
    def __init__(self) -> None:
        key = Ed25519PrivateKey.generate()
        self.private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, _NoEnc())
        self.public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def authenticator(self) -> SignatureAuthenticator:
        # Each worker process has its own replay cache.
        return SignatureAuthenticator(
            BASE, key_resolver=lambda kid: self.public if kid == "k1" else None,
            key_owner=lambda kid: CALLER, nonce_tracker=NonceTracker())

    def signed(self, env: dict[str, Any]) -> dict[str, str]:
        body = json.dumps(env).encode()
        headers = {"content-type": "application/json"}
        sig = sign_request(self.private, "k1", "POST", f"{BASE}/agent/message", headers, body,
                           nonce=uuid.uuid4().hex)
        return {k.lower(): v for k, v in {**headers, **sig}.items()}


def signed_worker(keys: _Keys, calls: list[str]) -> AgentServer:
    policy = SecurityPolicy.production([keys.authenticator()])
    return AgentServer.from_app(counting_app(calls), security=policy)


async def test_in_memory_workers_accept_a_replayed_signature(redis_backend):
    """The bug this backend fixes: per-process nonce caches."""
    keys, calls = _Keys(), []
    w1, w2 = signed_worker(keys, calls), signed_worker(keys, calls)
    env = envelope()
    headers = keys.signed(env)
    assert (await post(w1, env, headers)).status == 202
    assert (await post(w2, env, headers)).status == 202  # replay accepted


async def test_signed_request_replayed_to_other_worker_is_rejected(redis_backend):
    keys, calls = _Keys(), []
    w1 = shared(redis_backend, signed_worker(keys, calls))
    w2 = shared(redis_backend, signed_worker(keys, calls))
    env = envelope()
    headers = keys.signed(env)
    assert (await post(w1, env, headers)).status == 202
    replay = await post(w2, env, headers)
    assert replay.status == 401
    assert calls == [env["id"]]
    # A fresh signature for a new message still works on worker 2.
    env2 = envelope()
    assert (await post(w2, env2, keys.signed(env2))).status == 202


async def test_rate_limit_is_global(redis_backend):
    def worker() -> AgentServer:
        policy = SecurityPolicy.from_config(DEFAULTS, rate_limiter=RateLimiter(rpm=3))
        return shared(redis_backend, AgentServer.from_app(counting_app([]), security=policy))

    w1, w2 = worker(), worker()
    statuses = [(await post(w, envelope())).status for w in (w1, w2, w1, w2)]
    assert statuses == [202, 202, 202, 429]
    limited = await post(w1, envelope())
    assert limited.status == 429 and int(limited.headers["retry-after"]) >= 1


async def test_dedup_returns_the_cached_reply_from_the_other_worker(redis_backend):
    calls: list[str] = []
    w1 = shared(redis_backend, AgentServer.from_app(counting_app(calls)))
    w2 = shared(redis_backend, AgentServer.from_app(counting_app(calls)))
    env = envelope("msg-dup-1")
    first = await post(w1, env)
    second = await post(w2, env)
    assert first.status == second.status == 202
    assert json.loads(second.body) == json.loads(first.body) == {"handled": 1}
    assert calls == ["msg-dup-1"]  # the handler ran once, on worker 1


# ---------------------------------------------------------------------------
# A2A: tasks, cancel, subscribe, ownership
# ---------------------------------------------------------------------------


class TokenAuth:
    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        header = request.header("authorization")
        if not header:
            return None
        if not header.startswith("Bearer user:"):
            raise InvalidToken("bad token")
        name = header.split(":", 1)[1]
        return Principal(id=f"user://{name}", trust_tier=TrustTier.VERIFIED, auth_method="jwt")


def a2a_worker(backend: Any, state: dict[str, Any]) -> AgentServer:
    app = AgentApp(AGENT, BASE)

    @app.on("task.create")
    async def create(msg, ctx):
        text = msg.body["text"]
        if text == "gate":
            await state["gate"].wait()
            await ctx.emit_event("progress", {"pct": 50})
            return "released"
        if text == "forever":
            state["started"].set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise
            return "never"
        if text == "ask":
            return {"body_type": "task.input_required",
                    "body": {"task_id": msg.body["task_id"], "reason": "need", "prompt": "Which?"}}
        return f"echo: {text}"

    server = AgentServer.from_app(app)
    server.mount(A2AAdapter.for_server(server, authenticators=[TokenAuth()]))
    return shared(backend, server)


def client(server: AgentServer, user: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()), base_url=BASE,
                             headers={"Authorization": f"Bearer user:{user}"})


def user_message(text: str, **config: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                                        "parts": [{"text": text}]}}
    if config:
        body["configuration"] = config
    return body


def sse(text: str) -> list[dict[str, Any]]:
    return [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]


@pytest.fixture
def a2a_state() -> dict[str, Any]:
    return {"gate": asyncio.Event(), "started": asyncio.Event()}


async def test_a2a_task_from_worker1_is_visible_on_worker2_with_ownership(redis_backend, a2a_state):
    w1, w2 = a2a_worker(redis_backend, a2a_state), a2a_worker(redis_backend, a2a_state)
    async with client(w1, "alice") as a1, client(w2, "alice") as a2, client(w2, "bob") as b2:
        task = (await a1.post("/a2a/message:send", json=user_message("ask"))).json()["task"]
        got = await a2.get(f"/a2a/tasks/{task['id']}")
        assert got.status_code == 200 and got.json()["status"]["state"] == "TASK_STATE_INPUT_REQUIRED"
        assert (await b2.get(f"/a2a/tasks/{task['id']}")).status_code == 404
        assert (await b2.post(f"/a2a/tasks/{task['id']}:cancel")).status_code == 404
        assert (await b2.post(f"/a2a/tasks/{task['id']}:subscribe")).status_code == 404
        listed = (await a2.get("/a2a/tasks")).json()["tasks"]
        assert [t["id"] for t in listed] == [task["id"]]
        assert (await b2.get("/a2a/tasks")).json()["tasks"] == []
        # The conversation (contextId) created on worker 1 continues on worker 2.
        follow = user_message("hello again")
        follow["message"]["contextId"] = task["contextId"]
        assert (await a2.post("/a2a/message:send", json=follow)).status_code == 200
        stolen = user_message("hijack")
        stolen["message"]["contextId"] = task["contextId"]
        assert (await b2.post("/a2a/message:send", json=stolen)).status_code == 400
        # Idempotent retry of the same messageId on the other worker.
        body = user_message("once")
        body["message"]["contextId"] = task["contextId"]
        r1 = (await a1.post("/a2a/message:send", json=body)).json()
        r2 = (await a2.post("/a2a/message:send", json=body)).json()
        assert r1 == r2


async def test_a2a_cancel_on_worker2_stops_the_run_on_worker1(redis_backend, a2a_state):
    w1, w2 = a2a_worker(redis_backend, a2a_state), a2a_worker(redis_backend, a2a_state)
    adapter1 = w1.adapters[0]
    async with client(w1, "alice") as a1, client(w2, "alice") as a2:
        task = (await a1.post("/a2a/message:send",
                              json=user_message("forever", returnImmediately=True))).json()["task"]
        await asyncio.wait_for(a2a_state["started"].wait(), 5)
        r = await a2.post(f"/a2a/tasks/{task['id']}:cancel")
        assert r.status_code == 200 and r.json()["status"]["state"] == "TASK_STATE_CANCELED"
        for _ in range(200):
            if not adapter1._live and not any(not t.done() for t in adapter1._background):
                break
            await asyncio.sleep(0.01)
        assert a2a_state.get("cancelled") is True  # the handler on worker 1 was cancelled
        assert adapter1._live == {}
        state = (await a1.get(f"/a2a/tasks/{task['id']}")).json()["status"]["state"]
        assert state == "TASK_STATE_CANCELED"
        assert not await adapter1.broker.is_live(task["id"])


async def test_a2a_subscribe_on_worker2_streams_events_from_worker1(redis_backend, a2a_state):
    w1, w2 = a2a_worker(redis_backend, a2a_state), a2a_worker(redis_backend, a2a_state)
    async with client(w1, "alice") as a1, client(w2, "alice") as a2:
        task = (await a1.post("/a2a/message:send",
                              json=user_message("gate", returnImmediately=True))).json()["task"]
        sub = asyncio.ensure_future(a2.post(f"/a2a/tasks/{task['id']}:subscribe"))
        await asyncio.sleep(0.2)  # let worker 2 subscribe
        a2a_state["gate"].set()
        resp = await asyncio.wait_for(sub, 10)
        events = sse(resp.text)
        assert events[0]["task"]["id"] == task["id"]
        assert events[-1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"
        progress = [e for e in events if "statusUpdate" in e
                    and (e["statusUpdate"].get("metadata") or {}).get("amp.topic") == "progress"]
        assert progress and progress[0]["statusUpdate"]["status"]["state"] == "TASK_STATE_WORKING"
        done = (await a2.get(f"/a2a/tasks/{task['id']}")).json()
        assert done["status"]["state"] == "TASK_STATE_COMPLETED"


async def test_a2a_busy_lock_is_shared(redis_backend, a2a_state):
    w1, w2 = a2a_worker(redis_backend, a2a_state), a2a_worker(redis_backend, a2a_state)
    a1, a2 = w1.adapters[0], w2.adapters[0]
    assert await a1.broker.try_lock("t") is True
    assert await a2.broker.try_lock("t") is False


# ---------------------------------------------------------------------------
# MCP sessions
# ---------------------------------------------------------------------------


async def test_mcp_session_from_worker1_is_valid_on_worker2(redis_backend):
    from tests.interop.mcp._support import Wire, make_app

    def worker() -> AgentServer:
        server = AgentServer.from_app(make_app())
        server.mount(MCPAdapter.for_server(server))
        return shared(redis_backend, server)

    w1, w2 = worker(), worker()
    wire = Wire(w1)
    await wire.initialize("2025-06-18")
    wire.server = w2
    body = await wire.call("add", {"a": 2, "b": 3})
    assert body["result"]["structuredContent"] == {"sum": 5}
    # DELETE on worker 2 ends it for worker 1 too.
    assert (await wire.http("DELETE")).status in (200, 204)
    wire.server = w1
    resp, _ = await wire.rpc("tools/list")
    assert resp.status == 404


# ---------------------------------------------------------------------------
# PACT delegation: device codes and refresh tokens across workers
# ---------------------------------------------------------------------------


@pytest.fixture
def pact_env():
    pytest.importorskip("jwt")
    from tests.interop.pact import test_delegation as td
    from tests.interop.pact.conftest import FakeClock, PAKey

    return td, FakeClock(), PAKey()


def pact_worker(backend: Any, td: Any, clock: Any, pa: Any, brand: Any, jwk: dict) -> Any:
    from ampro.interop.pact import (
        Brand,
        InMemoryPersonalAgentRegistry,
        JWTBrandLogin,
        PACTProvider,
        PersonalAgentRegistration,
        ProviderKeySet,
        Scope,
    )

    registry = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=td.ISSUER,
                                                                        jwks=pa.jwks)])
    provider = PACTProvider(public_url=td.PUBLIC, registry=registry, audience=td.AUDIENCE,
                            keys=ProviderKeySet.from_jwks(jwk), clock=clock)
    login = JWTBrandLogin(login_page=f"{td.BRAND_ISS}/login", issuer=td.BRAND_ISS,
                          jwks=brand.jwks, clock=clock)
    provider.add_brand(Brand("shop", td.shop_app(), name="Shop", scopes=[
        Scope("orders:read", "Look up orders"), Scope("orders:cancel", "Cancel orders")],
        login=login))
    server = shared(backend, provider.as_server())
    return provider, httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()),
                                       base_url=td.PUBLIC)


async def test_pact_device_code_and_refresh_token_across_workers(redis_backend, pact_env):
    from ampro.interop.pact._jwt import generate_es256_jwk

    td, clock, pa = pact_env
    brand = td.FakeBrand(clock)
    jwk = generate_es256_jwk()  # the shared provider key (same config on every worker)
    p1, h1 = pact_worker(redis_backend, td, clock, pa, brand, jwk)
    p2, h2 = pact_worker(redis_backend, td, clock, pa, brand, jwk)
    async with h1, h2:
        f1, f2 = td.Flow(h1, pa, clock, brand), td.Flow(h2, pa, clock, brand)
        auth = (await f1.start("orders:read")).json()
        page = await f1.consent(auth["user_code"])  # Brand login lands on worker 1
        assert page.status_code == 200, page.text
        decided = await f2.decide(td.session_of(page), ["orders:read"])  # browser hits worker 2
        assert decided.status_code in (200, 302, 303), decided.text
        clock.advance(10)
        redeemed = await f2.poll(auth["device_code"])
        assert redeemed.status_code == 200, redeemed.text
        tokens = redeemed.json()
        again = await f1.poll(auth["device_code"])  # single use, on any worker
        assert again.status_code == 400

        # The delegation token minted on worker 2 is honoured by worker 1.
        sent = await f1.send("my orders", token=tokens["access_token"])
        assert sent.status_code == 200, sent.text
        reply = sent.json()["message"]
        assert "orders for" in reply["parts"][0]["text"]
        assert reply["metadata"]["pact.receipt"]

        rotated = await f1.token({"grant_type": "refresh_token",
                                  "refresh_token": tokens["refresh_token"]})
        assert rotated.status_code == 200, rotated.text
        reuse = await f2.token({"grant_type": "refresh_token",
                                "refresh_token": tokens["refresh_token"]})
        assert reuse.status_code == 400 and reuse.json()["error"] == "invalid_grant"
        # Reuse revoked the grant everywhere: the rotated token is dead too.
        newer = await f1.token({"grant_type": "refresh_token",
                                "refresh_token": rotated.json()["refresh_token"]})
        assert newer.status_code == 400


async def test_configure_refuses_ephemeral_pact_keys(redis_backend):
    pytest.importorskip("jwt")
    from ampro.interop.pact import InMemoryPersonalAgentRegistry, PACTProvider, ProviderKeySet

    provider = PACTProvider(public_url="https://p.example", registry=InMemoryPersonalAgentRegistry(),
                            audience="aud", keys=ProviderKeySet.generate())
    with pytest.raises(ValueError, match="ephemeral"):
        shared(redis_backend, provider.as_server())
    shared(redis_backend, provider.as_server(), allow_ephemeral_keys=True)


# ---------------------------------------------------------------------------
# Readiness and graceful shutdown
# ---------------------------------------------------------------------------


async def test_readiness_reflects_redis_and_draining(redis_backend):
    server = shared(redis_backend, AgentServer.from_app(counting_app([])))
    status, _, body = await server.route("GET", "/agent/ready")
    assert status == 200 and json.loads(body)["status"] == "ready"

    async def down() -> bool:
        raise ConnectionError("redis down")

    server.readiness_checks.append(down)
    status, _, body = await server.route("GET", "/agent/ready")
    assert status == 503 and json.loads(body)["reason"] == "dependency unavailable"
    server.readiness_checks.pop()
    await server.aclose()
    status, _, body = await server.route("GET", "/agent/ready")
    assert status == 503 and json.loads(body)["reason"] == "draining"
    # Liveness is unaffected by dependencies or draining.
    assert (await server.route("GET", "/agent/health"))[0] == 200


async def test_graceful_shutdown_leaves_no_task_stuck_working(redis_backend, a2a_state):
    w1, w2 = a2a_worker(redis_backend, a2a_state), a2a_worker(redis_backend, a2a_state)
    async with client(w1, "alice") as a1, client(w2, "alice") as a2:
        task = (await a1.post("/a2a/message:send",
                              json=user_message("forever", returnImmediately=True))).json()["task"]
        await asyncio.wait_for(a2a_state["started"].wait(), 5)
        await w1.adapters[0].aclose(grace=0.1)  # what lifespan shutdown does on worker 1
        state = (await a2.get(f"/a2a/tasks/{task['id']}")).json()["status"]["state"]
        assert state == "TASK_STATE_CANCELED"
        assert not await w2.adapters[0].broker.is_live(task["id"])
