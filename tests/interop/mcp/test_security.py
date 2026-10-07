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
