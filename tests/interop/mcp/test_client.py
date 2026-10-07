"""MCPToolSource — consuming MCP servers (our own, in-process via ASGI)."""
from __future__ import annotations

import json

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.mcp import MCPAdapter, MCPClientError, MCPToolError, MCPToolSource
from ampro.interop.mcp.client import _parse_sse
from ampro.server.core import AgentServer

from ._support import Wire, make_app

URL = "http://127.0.0.1:8000/mcp"


def asgi_client(server: AgentServer) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()))


@pytest.fixture
def remote() -> AgentServer:
    app = make_app()
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server))
    return server


async def test_handshake_and_list(remote: AgentServer):
    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        assert source.protocol_version == "2025-11-25"
        assert source.session_id
        assert source.server_info["name"] == "agent://mcp-test.example.com"
        names = {t["name"] for t in await source.list_tools()}
        assert {"add", "greet", "search", "amp_task"} <= names
        result = await source.call_tool("add", {"a": 4, "b": 5})
        assert result["structuredContent"] == {"sum": 9}


async def test_close_deletes_session(remote: AgentServer):
    async with asgi_client(remote) as http:
        source = MCPToolSource(URL, http_client=http)
        await source.connect()
        sid = source.session_id
        await source.close()
        w = Wire(remote)
        w.session_id = sid
        resp, _ = await w.rpc("tools/list")
        assert resp.status == 404


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18"])
async def test_older_versions(remote: AgentServer, version: str):
    async with asgi_client(remote) as http, MCPToolSource(
        URL, http_client=http, protocol_version=version
    ) as source:
        assert source.protocol_version == version
        assert await source.list_tools()


async def test_register_into_and_proxy(remote: AgentServer):
    local = AgentApp("agent://local", "http://x")
    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        names = await source.register_into(local, prefix="remote.")
        assert "remote.add" in names and "remote.admin_reset" not in names
        assert local.tool_meta["remote.add"]["input_schema"]["required"] == ["a", "b"]
        assert local.tool_meta["remote.add"]["description"] == "Add two integers."
        assert await local.tools["remote.add"](a=1, b=2) == {"sum": 3}
        assert await local.tools["remote.greet"](name="Bo") == "Hello, Bo!"
        with pytest.raises(MCPToolError) as info:
            await local.tools["remote.boom"]()
        assert "hunter2" not in str(info.value)
        result = await local.tools["remote.amp_task"](description="Porto")
        assert result["plan"] == "done: Porto"


async def test_register_does_not_overwrite_by_default(remote: AgentServer):
    local = AgentApp("agent://local", "http://x")

    @local.tool("add")
    def mine():
        return "local"

    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        names = await source.register_into(local)
        assert "add" not in names and local.tools["add"] is mine
        await source.register_into(local, overwrite=True)
        assert local.tools["add"] is not mine


async def test_reexport_remote_tools_over_mcp(remote: AgentServer):
    """A gateway agent re-exports a remote MCP server's tools over its own MCP endpoint."""
    gateway = AgentApp("agent://gateway", "http://x")
    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        await source.register_into(gateway, prefix="r_")
        gw_server = AgentServer.from_app(gateway)
        gw_server.mount(MCPAdapter.for_server(gw_server))
        w = Wire(gw_server)
        await w.initialize()
        _, body = await w.rpc("tools/list")
        tools = {t["name"]: t for t in body["result"]["tools"]}
        assert tools["r_add"]["inputSchema"]["required"] == ["a", "b"]
        result = (await w.call("r_add", {"a": 20, "b": 22}))["result"]
        assert result["structuredContent"] == {"sum": 42}
        bad = (await w.call("r_add", {"a": 1}))["result"]
        assert bad["isError"] is True


async def test_auth_headers_and_401(remote: AgentServer):
    app = make_app()
    server = AgentServer.from_app(app)

    async def authn(request):
        if request.header("authorization") != "Bearer good":
            raise PermissionError
        return {"id": "client", "scopes": ["admin"]}

    server.mount(MCPAdapter.for_server(server, authenticator=authn, require_auth=True))
    async with asgi_client(server) as http:
        with pytest.raises(MCPClientError) as info:
            await MCPToolSource(URL, http_client=http).connect()
        assert info.value.status == 401
        async with MCPToolSource(URL, http_client=http, headers={"Authorization": "Bearer good"}) as src:
            assert "admin_reset" in {t["name"] for t in await src.list_tools()}


async def test_reinitializes_after_session_loss(remote: AgentServer):
    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        old = source.session_id
        adapter = remote.adapters[0]
        await adapter.sessions.delete(old, None)
        assert await source.list_tools()
        assert source.session_id != old


async def test_jsonrpc_error_surfaces(remote: AgentServer):
    async with asgi_client(remote) as http, MCPToolSource(URL, http_client=http) as source:
        with pytest.raises(MCPClientError) as info:
            await source.call_tool("does-not-exist")
        assert info.value.code == -32602


# ---------------------------------------------------------------------------
# Transport hardening (mock transport)
# ---------------------------------------------------------------------------


def _init_reply(request: httpx.Request) -> httpx.Response:
    msg = json.loads(request.content)
    if "id" not in msg:
        return httpx.Response(202)
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-11-25", "capabilities": {}}},
        headers={"mcp-session-id": "s1"},
    )


async def test_cross_origin_redirect_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://attacker.example/mcp"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as http:
        with pytest.raises(MCPClientError, match="cross-origin"):
            await MCPToolSource(URL, http_client=http).connect()


async def test_same_origin_redirect_followed():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/mcp":
            return httpx.Response(308, headers={"location": "/v2/mcp"})
        return _init_reply(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        source = MCPToolSource(URL, http_client=http)
        await source.connect()
        assert "/v2/mcp" in seen


async def test_302_not_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/elsewhere"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(MCPClientError, match="redirect"):
            await MCPToolSource(URL, http_client=http).connect()


async def test_response_size_cap():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000, headers={"content-type": "application/json"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(MCPClientError, match="too large"):
            await MCPToolSource(URL, http_client=http, max_response_bytes=1000).connect()


async def test_timeout():
    import asyncio

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(2)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(MCPClientError, match="timed out"):
            await MCPToolSource(URL, http_client=http, timeout=0.05).connect()


async def test_rejects_unknown_negotiated_version():
    def handler(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "1.0"}}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(MCPClientError, match="unsupported protocol version"):
            await MCPToolSource(URL, http_client=http).connect()


async def test_sse_response_parsing():
    def handler(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if "id" not in msg:
            return httpx.Response(202)
        payload = {"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18"}}
        body = (
            ": keepalive\n\n"
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
            f"event: message\nid: 1\ndata: {json.dumps(payload)}\n\n"
        )
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/event-stream"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        source = MCPToolSource(URL, http_client=http)
        await source.connect()
        assert source.protocol_version == "2025-06-18"


def test_parse_sse_multiline_and_crlf():
    text = "event: message\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\nevent: other\r\ndata: {}\r\n\r\n"
    assert _parse_sse(text) == [{"a": 1}]


def test_constructor_rejects_modern_version():
    with pytest.raises(ValueError):
        MCPToolSource(URL, protocol_version="2026-07-28")


# ---------------------------------------------------------------------------
# SSRF guard (owned client only)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/mcp",
        "https://10.1.2.3/mcp",
        "https://127.0.0.1/mcp",
        "https://[::1]/mcp",
        "http://93.184.216.34/mcp",  # plain http to a public host needs allow_http
        "https://user:pw@93.184.216.34/mcp",
    ],
)
async def test_ssrf_guard_rejects(url: str):
    source = MCPToolSource(url)
    with pytest.raises(MCPClientError, match="not allowed"):
        await source.connect()
    await source.close()


async def test_allow_private_opt_out_reaches_transport():
    # Port 9 on loopback is closed: the guard lets it through and the
    # failure is a transport error, not an SSRF rejection.
    source = MCPToolSource("http://127.0.0.1:9/mcp", allow_private=True, timeout=5)
    with pytest.raises(MCPClientError) as info:
        await source.connect()
    assert "not allowed" not in str(info.value)
    await source.close()
