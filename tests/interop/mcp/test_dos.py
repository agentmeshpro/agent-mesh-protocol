"""Regression tests for MCP resource-exhaustion findings.

* Session exhaustion: one caller must not be able to fill the session
  store (per-owner cap with LRU eviction, and ``initialize`` is metered).
* Concurrency: ``tools/call`` (including ``amp_task``) is bounded by the
  server's concurrency limiter.
"""
from __future__ import annotations

import asyncio
import json

from ampro.ampi.app import AgentApp
from ampro.interop.mcp import InMemorySessionStore, MCPAdapter
from ampro.security.concurrency_limiter import ConcurrencyLimiter
from ampro.security.rate_limiter import RateLimiter
from ampro.server.auth import Principal
from ampro.server.core import AgentServer
from ampro.server.http import HTTPRequest

from ._support import body_of

INIT = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
).encode()
H = {"content-type": "application/json", "accept": "application/json"}


class Tok:
    async def authenticate(self, request: HTTPRequest):
        a = request.header("authorization") or ""
        return Principal(id=a[7:]) if a.startswith("Bearer ") else None


def _server(app: AgentApp, **kw) -> AgentServer:
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, **kw))
    return server


async def _init(server: AgentServer, who: str | None, client: str = "1.1.1.1"):
    headers = dict(H)
    if who:
        headers["authorization"] = f"Bearer {who}"
    return await server.handle(HTTPRequest("POST", "/mcp", headers, body=INIT, client=client))


async def _call(server: AgentServer, sid: str, who: str | None, name: str, arguments: dict, client="1.1.1.1"):
    headers = dict(H, **{"mcp-session-id": sid})
    if who:
        headers["authorization"] = f"Bearer {who}"
    msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return await server.handle(
        HTTPRequest("POST", "/mcp", headers, body=json.dumps(msg).encode(), client=client)
    )


# ---------------------------------------------------------------------------
# Session exhaustion (poc6)
# ---------------------------------------------------------------------------


async def test_poc6_one_caller_cannot_exhaust_sessions(app: AgentApp):
    """The original PoC with rate limiting off: the per-owner cap alone holds."""
    server = _server(app, authenticators=[Tok()], require_auth=True, rate_limiter=None)
    first = None
    for i in range(1024):
        r = await _init(server, "mallory", "6.6.6.6")
        assert r.status == 200
        if i == 0:
            first = r.headers["mcp-session-id"]
    store = server.adapters[0].sessions
    assert len(store) == 8
    r = await _init(server, "alice")
    assert r.status == 200
    # Mallory's oldest session was evicted; the client would re-initialize.
    r = await _call(server, first, "mallory", "add", {"a": 1, "b": 1}, "6.6.6.6")
    assert r.status == 404


async def test_initialize_is_rate_limited(app: AgentApp):
    server = _server(app, authenticators=[Tok()], rate_limiter=RateLimiter(rpm=3))
    statuses = [(await _init(server, "mallory")).status for _ in range(5)]
    assert statuses == [200, 200, 200, 429, 429]
    r = await _init(server, "mallory")
    assert "retry-after" in r.headers
    assert body_of(r)["error"]["message"] == "Rate limit exceeded"
    assert (await _init(server, "alice")).status == 200


async def test_anonymous_session_quota_is_per_peer(app: AgentApp):
    server = _server(app, rate_limiter=None, max_sessions_per_owner=2)
    sids = [(await _init(server, None, "6.6.6.6")).headers["mcp-session-id"] for _ in range(5)]
    victim = (await _init(server, None, "7.7.7.7")).headers["mcp-session-id"]
    for _ in range(5):
        await _init(server, None, "6.6.6.6")
    # The other peer's session survives; the flooding peer keeps only 2.
    assert (await _call(server, victim, None, "add", {"a": 1, "b": 1}, "7.7.7.7")).status == 200
    assert (await _call(server, sids[0], None, "add", {"a": 1, "b": 1}, "6.6.6.6")).status == 404


async def test_store_per_owner_cap_evicts_lru():
    store = InMemorySessionStore(max_sessions_per_owner=2)
    a = await store.create("2025-11-25", "u", quota_key="u")
    b = await store.create("2025-11-25", "u", quota_key="u")
    assert await store.get(a.id, "u") is a  # a becomes most recently used
    c = await store.create("2025-11-25", "u", quota_key="u")
    assert await store.get(b.id, "u") is None
    assert await store.get(a.id, "u") is a and await store.get(c.id, "u") is c
    other = await store.create("2025-11-25", "v", quota_key="v")
    assert other is not None and len(store) == 3


# ---------------------------------------------------------------------------
# Concurrency limiter
# ---------------------------------------------------------------------------


def _blocking_app(app: AgentApp) -> asyncio.Event:
    gate = asyncio.Event()

    @app.tool("wait")
    async def wait() -> str:
        await gate.wait()
        return "done"

    @app.on("task.create")
    async def task(msg, ctx):
        await gate.wait()
        return {"ok": True}

    return gate


async def _session(server: AgentServer, who: str) -> str:
    return (await _init(server, who)).headers["mcp-session-id"]


async def test_tools_call_bounded_by_concurrency(app: AgentApp):
    gate = _blocking_app(app)
    limiter = ConcurrencyLimiter(max_total=2, per_sender_pct=0.5)  # 1 per caller, 2 total
    server = _server(app, authenticators=[Tok()], concurrency=limiter, rate_limiter=None)
    s_m = await _session(server, "mallory")
    s_a = await _session(server, "alice")
    s_b = await _session(server, "bob")
    first = asyncio.create_task(_call(server, s_m, "mallory", "wait", {}))
    await asyncio.sleep(0.01)
    assert limiter.total_active == 1
    # Same caller over its share: 503.
    r = await _call(server, s_m, "mallory", "add", {"a": 1, "b": 1})
    assert r.status == 503 and r.headers["retry-after"] == "1"
    # amp_task is limited too.
    r = await _call(server, s_m, "mallory", "amp_task", {"description": "x"})
    assert r.status == 503
    # Another caller still gets in until the global cap is reached.
    second = asyncio.create_task(_call(server, s_a, "alice", "amp_task", {"description": "x"}))
    await asyncio.sleep(0.01)
    assert limiter.total_active == 2
    assert (await _call(server, s_b, "bob", "add", {"a": 1, "b": 1})).status == 503
    gate.set()
    assert (await first).status == 200 and (await second).status == 200
    # Slots are released, including after failures.
    assert limiter.total_active == 0
    r = await _call(server, s_m, "mallory", "boom", {})
    assert r.status == 200 and body_of(r)["result"]["isError"] is True
    assert limiter.total_active == 0


async def test_concurrency_inherited_from_server_policy(app: AgentApp):
    server = AgentServer.from_app(app)
    adapter = MCPAdapter.for_server(server)
    assert adapter.concurrency is server.security.concurrency
    assert adapter.concurrency is not None
