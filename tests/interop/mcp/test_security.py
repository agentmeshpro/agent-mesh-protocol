"""MCPAdapter — Origin validation, authentication and scope enforcement."""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.mcp import MCPAdapter
from ampro.server.core import AgentServer
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

from ._support import Wire, body_of

# ---------------------------------------------------------------------------
# Origin (DNS rebinding)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    ["https://evil.example", "null", "http://localhost.evil.example", "file://localhost", "http://10.0.0.1"],
)
async def test_foreign_origin_rejected_by_default(wire: Wire, origin: str):
    resp, body = await wire.rpc(
        "initialize",
        {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}},
        headers={"origin": origin},
    )
    assert resp.status == 403
    assert "mcp-session-id" not in resp.headers


async def test_origin_checked_before_anything_else(wire: Wire):
    for method in ("GET", "DELETE", "POST"):
        resp = await wire.http(method, body={}, headers={"origin": "https://evil.example"})
        assert resp.status == 403


@pytest.mark.parametrize(
    "origin", [None, "http://localhost:6274", "http://127.0.0.1", "https://[::1]:8443"]
)
async def test_local_or_missing_origin_allowed(wire: Wire, origin):
    await wire.initialize(headers={"origin": origin})


async def test_allowed_origins_configurable(app: AgentApp):
    server = AgentServer.from_app(app)
    adapter = MCPAdapter.for_server(
        server, allowed_origins=["https://app.example.com", "http://dev.example.com:*"]
    )
    server.mount(adapter)
    assert adapter.origin_allowed("https://app.example.com")
    assert adapter.origin_allowed("http://dev.example.com:3000")
    assert not adapter.origin_allowed("http://localhost:3000")  # explicit list replaces default
    assert not adapter.origin_allowed("https://app.example.com.evil.io")
    assert adapter.origin_allowed(None)
    await Wire(server).initialize(headers={"origin": "https://app.example.com"})


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@dataclass
class Principal:
    id: str
    scopes: set[str] = field(default_factory=set)
    trust_tier: TrustTier = TrustTier.VERIFIED


TOKENS = {
    "alice-token": Principal("user:alice", {"admin"}),
    "bob-token": Principal("user:bob", set(), TrustTier.EXTERNAL),
}


async def bearer(request: HTTPRequest):
    header = request.header("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or token not in TOKENS:
        raise PermissionError("bad token")
    return TOKENS[token]


def secured(app: AgentApp, **kw) -> AgentServer:
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, authenticator=bearer, **kw))
    return server


def auth(token: str) -> dict:
    return {"authorization": f"Bearer {token}"}


async def test_rejected_credentials_are_401(app: AgentApp):
    w = Wire(secured(app))
    resp, _ = await w.rpc("initialize", {"protocolVersion": "2025-11-25"}, headers=auth("forged"))
    assert resp.status == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


async def test_require_auth_rejects_anonymous(app: AgentApp):
    w = Wire(secured(app, require_auth=True))
    resp, _ = await w.rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert resp.status == 401
    assert "www-authenticate" in resp.headers
    await w.initialize(headers=auth("bob-token"))


async def test_scoped_tool_visible_and_callable_with_scope(app: AgentApp):
    w = Wire(secured(app))
    await w.initialize(headers=auth("alice-token"))
    _, body = await w.rpc("tools/list", headers=auth("alice-token"))
    assert "admin_reset" in {t["name"] for t in body["result"]["tools"]}
    result = (await w.call("admin_reset", headers=auth("alice-token")))["result"]
    assert result["structuredContent"] == {"reset": True}


async def test_scoped_tool_forbidden_without_scope(app: AgentApp):
    w = Wire(secured(app))
    await w.initialize(headers=auth("bob-token"))
    _, body = await w.rpc("tools/list", headers=auth("bob-token"))
    assert "admin_reset" not in {t["name"] for t in body["result"]["tools"]}
    resp, body = await w.rpc(
        "tools/call", {"name": "admin_reset", "arguments": {}}, headers=auth("bob-token")
    )
    assert resp.status == 403
    assert 'error="insufficient_scope"' in resp.headers["www-authenticate"]
    assert 'scope="admin"' in resp.headers["www-authenticate"]


async def test_scoped_tool_anonymous_is_401(app: AgentApp):
    w = Wire(secured(app))
    await w.initialize()
    resp, _ = await w.rpc("tools/call", {"name": "admin_reset", "arguments": {}})
    assert resp.status == 401


async def test_scoped_tool_unusable_without_authenticator(wire: Wire):
    await wire.initialize()
    resp, _ = await wire.rpc("tools/call", {"name": "admin_reset", "arguments": {}})
    assert resp.status == 403


async def test_amp_task_scopes_via_tool_meta(app: AgentApp):
    app.tool_meta["amp_task"] = {"scopes": ["tasks"]}
    w = Wire(secured(app))
    await w.initialize(headers=auth("alice-token"))
    resp, _ = await w.rpc(
        "tools/call", {"name": "amp_task", "arguments": {"description": "x"}}, headers=auth("alice-token")
    )
    assert resp.status == 403


async def test_session_bound_to_principal(app: AgentApp):
    server = secured(app)
    w = Wire(server)
    await w.initialize(headers=auth("alice-token"))
    resp, _ = await w.rpc("tools/list", headers=auth("bob-token"))
    assert resp.status == 404
    resp, _ = await w.rpc("tools/list")
    assert resp.status == 404
    resp = await w.http("DELETE", headers=auth("bob-token"))
    assert resp.status == 404
    resp, _ = await w.rpc("tools/list", headers=auth("alice-token"))
    assert resp.status == 200


async def test_principal_flows_into_context(app: AgentApp):
    w = Wire(secured(app))
    await w.initialize(headers=auth("alice-token"))
    await w.call("add", {"a": 1, "b": 1}, headers=auth("alice-token"))
    ctx = app.state["calls"][-1]
    assert ctx.trust_tier == TrustTier.VERIFIED
    assert ctx.sender_address == "user:alice"
    await w.call("amp_task", {"description": "go"}, headers=auth("alice-token"))
    assert app.state["task_ctx"].sender_address == "user:alice"


async def test_dict_principal_with_string_scopes(app: AgentApp):
    async def authn(request):
        return {"id": "svc", "scopes": "admin other", "trust_tier": "verified"}

    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, authenticator=authn))
    w = Wire(server)
    await w.initialize()
    result = (await w.call("admin_reset"))["result"]
    assert result["isError"] is False


async def test_auth_runs_on_every_request(app: AgentApp):
    w = Wire(secured(app))
    await w.initialize(headers=auth("alice-token"))
    resp, _ = await w.rpc("tools/list", headers=auth("forged"))
    assert resp.status == 401


async def test_error_responses_are_jsonrpc_shaped(wire: Wire):
    resp = await wire.http(body={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"origin": "https://x.io"})
    body = body_of(resp)
    assert body["jsonrpc"] == "2.0" and body["id"] is None and "error" in body


# ---------------------------------------------------------------------------
# Canonical server auth contract, policy inheritance, rate limiting
# ---------------------------------------------------------------------------


class TokenAuthenticator:
    """Implements ampro.server.auth.Authenticator."""

    async def authenticate(self, request: HTTPRequest):
        from ampro.server.auth import Principal as CanonicalPrincipal
        from ampro.server.auth import Unauthorized

        header = request.header("authorization")
        if header is None:
            return None
        if header != "Bearer ops":
            raise Unauthorized("bad token")
        return CanonicalPrincipal(
            id="svc:ops", trust_tier=TrustTier.VERIFIED, scopes=frozenset({"admin"}), auth_method="bearer"
        )


async def test_canonical_authenticators(app: AgentApp):
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, authenticators=[TokenAuthenticator()], require_auth=True))
    w = Wire(server)
    resp, _ = await w.rpc("initialize", {"protocolVersion": "2025-11-25"}, headers=auth("nope"))
    assert resp.status == 401
    resp, _ = await w.rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert resp.status == 401
    hdr = {"authorization": "Bearer ops"}
    await w.initialize(headers=hdr)
    result = (await w.call("admin_reset", headers=hdr))["result"]
    assert result["structuredContent"] == {"reset": True}
    await w.call("add", {"a": 1, "b": 2}, headers=hdr)
    assert app.state["calls"][-1].sender_address == "svc:ops"


async def test_inherits_server_security_policy(app: AgentApp):
    from ampro.server.security import SecurityPolicy

    policy = SecurityPolicy.production([TokenAuthenticator()])
    server = AgentServer.from_app(app)
    server.security = policy
    adapter = MCPAdapter.for_server(server)
    server.mount(adapter)
    assert adapter.require_auth is True
    assert adapter.rate_limiter is policy.rate_limiter
    assert adapter.tool_timeout == policy.handler_timeout_seconds
    resp, _ = await Wire(server).rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert resp.status == 401


async def test_require_auth_without_authenticators_fails_closed(app: AgentApp):
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, authenticators=(), require_auth=True))
    resp, _ = await Wire(server).rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert resp.status == 401


async def test_crashing_authenticator_fails_closed(app: AgentApp):
    class Broken:
        async def authenticate(self, request):
            raise RuntimeError("bug")

    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, authenticators=[Broken()]))
    resp, _ = await Wire(server).rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert resp.status == 401


async def test_tools_call_rate_limited_per_caller(app: AgentApp):
    from ampro.security.rate_limiter import RateLimiter

    server = AgentServer.from_app(app)
    # initialize is metered too: 1 initialize + 2 calls fill a budget of 3.
    server.mount(MCPAdapter.for_server(server, authenticator=bearer, rate_limiter=RateLimiter(rpm=3)))
    w = Wire(server)
    await w.initialize(headers=auth("alice-token"))
    for _ in range(2):
        await w.call("add", {"a": 1, "b": 1}, headers=auth("alice-token"))
    resp, body = await w.rpc(
        "tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}, auth("alice-token")
    )
    assert resp.status == 429
    assert int(resp.headers["retry-after"]) >= 1
    assert body["error"]["code"] == -32600
    # tools/list is not metered; another principal has its own budget.
    resp, _ = await w.rpc("tools/list", headers=auth("alice-token"))
    assert resp.status == 200
    other = Wire(server)
    await other.initialize(headers=auth("bob-token"))
    await other.call("add", {"a": 1, "b": 1}, headers=auth("bob-token"))


async def test_anonymous_rate_limit_keyed_by_peer(app: AgentApp):
    import json as _json

    from ampro.security.rate_limiter import RateLimiter

    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, rate_limiter=RateLimiter(rpm=1)))
    w = Wire(server)
    await w.initialize()  # Wire sends no client address: counts against "ip:None"

    async def call_from(ip: str) -> int:
        msg = {
            "jsonrpc": "2.0",
            "id": w.next_id(),
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 1, "b": 1}},
        }
        hdrs = {
            "accept": "application/json",
            "content-type": "application/json",
            "mcp-session-id": w.session_id,
            "mcp-protocol-version": w.version,
        }
        req = HTTPRequest("POST", "/mcp", hdrs, body=_json.dumps(msg).encode(), client=ip)
        return (await server.handle(req)).status

    assert await call_from("10.0.0.1") == 200
    assert await call_from("10.0.0.1") == 429
    assert await call_from("10.0.0.2") == 200


async def test_timeout_defaults_to_policy_handler_timeout(app: AgentApp):
    import asyncio

    @app.tool("slow")
    async def slow() -> str:
        await asyncio.sleep(5)
        return "late"

    server = AgentServer.from_app(app)
    server.security.handler_timeout_seconds = 0.05
    server.mount(MCPAdapter.for_server(server))
    w = Wire(server)
    await w.initialize()
    result = (await w.call("slow"))["result"]
    assert result["isError"] is True and "timed out" in result["content"][0]["text"]
