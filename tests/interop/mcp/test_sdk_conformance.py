"""Conformance against the official MCP Python SDK (used only as a test oracle).

Skipped when the ``mcp`` SDK is not installed.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket

import httpx
import pytest

mcp = pytest.importorskip("mcp")
httpx2 = pytest.importorskip("httpx2")
pytest.importorskip("mcp.client.client")

from mcp.client.client import Client  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402

from ampro.interop.mcp import MCPAdapter, MCPToolSource  # noqa: E402
from ampro.server.core import AgentServer  # noqa: E402

from ._support import make_app  # noqa: E402

BASE = "http://127.0.0.1:8000"


@pytest.fixture
def ampro_server() -> AgentServer:
    app = make_app()
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server))
    return server


@contextlib.asynccontextmanager
async def sdk_client(server: AgentServer, mode: str):
    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=server.asgi()), base_url=BASE)
    async with http, Client(streamable_http_client(f"{BASE}/mcp", http_client=http), mode=mode) as client:
        yield client


@pytest.mark.parametrize(
    "mode, expected",
    [("legacy", "2025-11-25"), ("auto", "2026-07-28"), ("2026-07-28", "2026-07-28")],
)
async def test_sdk_client_round_trip(ampro_server: AgentServer, mode: str, expected: str):
    async with sdk_client(ampro_server, mode) as client:
        assert client.protocol_version == expected
        listed = await client.list_tools()
        tools = {t.name: t for t in listed.tools}
        assert {"add", "greet", "search", "amp_task", "boom"} <= set(tools)
        assert tools["add"].input_schema["required"] == ["a", "b"]
        assert tools["add"].description == "Add two integers."

        ok = await client.call_tool("add", {"a": 2, "b": 3})
        assert ok.is_error is False
        assert ok.structured_content == {"sum": 5}
        assert ok.content[0].type == "text"

        text = await client.call_tool("greet", {"name": "Ada"})
        assert text.content[0].text == "Hello, Ada!"

        failed = await client.call_tool("boom", {})
        assert failed.is_error is True
        assert "hunter2" not in failed.content[0].text

        invalid = await client.call_tool("add", {"a": "x"})
        assert invalid.is_error is True

        task = await client.call_tool("amp_task", {"description": "Kyoto"})
        assert task.structured_content["plan"] == "done: Kyoto"


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_sdk_client_unknown_tool_is_protocol_error(ampro_server: AgentServer, mode: str):
    async with sdk_client(ampro_server, mode) as client:
        with pytest.raises(MCPError) as info:
            await client.session.call_tool("nope", {})
        assert info.value.code == -32602


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_sdk_client_paginates(mode: str):
    app = make_app()
    for i in range(7):
        app.tool(f"extra_{i}")(lambda: None)
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, page_size=3))
    async with sdk_client(server, mode) as client:
        names, cursor = [], None
        while True:
            page = await client.list_tools(cursor=cursor)
            names += [t.name for t in page.tools]
            cursor = page.next_cursor
            if not cursor:
                break
        # every tool except the scope-hidden admin_reset, plus amp_task
        assert len(names) == len(set(names)) == len(app.tools)
        assert "admin_reset" not in names and "extra_6" in names


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_real_uvicorn_server(ampro_server: AgentServer):
    """End to end over a real socket on 127.0.0.1, SDK client and our client."""
    uvicorn = pytest.importorskip("uvicorn")
    port = _free_port()
    config = uvicorn.Config(ampro_server.asgi(), host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    srv = uvicorn.Server(config)
    task = asyncio.create_task(srv.serve())
    try:
        for _ in range(200):
            if srv.started:
                break
            await asyncio.sleep(0.02)
        url = f"http://127.0.0.1:{port}/mcp"
        async with Client(url, mode="auto") as client:
            result = await client.call_tool("add", {"a": 40, "b": 2})
            assert result.structured_content == {"sum": 42}
        async with Client(url, mode="legacy") as client:
            result = await client.call_tool("add", {"a": 1, "b": 2})
            assert result.structured_content == {"sum": 3}
        async with MCPToolSource(url) as source:
            assert (await source.call_tool("add", {"a": 1, "b": 1}))["structuredContent"] == {"sum": 2}
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 10)


async def test_tool_source_consumes_sdk_server():
    """Our client against the SDK's own MCPServer (SSE responses, stateful sessions)."""
    from mcp.server.mcpserver import MCPServer

    sdk_server = MCPServer("sdk-oracle")

    @sdk_server.tool()
    def multiply(x: int, y: int) -> int:
        """Multiply two integers."""
        return x * y

    @sdk_server.tool()
    def shout(text: str) -> str:
        return text.upper()

    asgi = sdk_server.streamable_http_app()
    from ampro.ampi.app import AgentApp

    local = AgentApp("agent://consumer", "http://x")
    async with sdk_server.session_manager.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi)) as http:
            async with MCPToolSource(f"{BASE}/mcp", http_client=http) as source:
                assert source.protocol_version == "2025-11-25"
                names = await source.register_into(local, prefix="sdk.")
                assert set(names) == {"sdk.multiply", "sdk.shout"}
                assert local.tool_meta["sdk.multiply"]["description"] == "Multiply two integers."
                product = await local.tools["sdk.multiply"](x=6, y=7)
                assert product in (42, {"result": 42})
                assert await local.tools["sdk.shout"](text="hi") in ("HI", {"result": "HI"})
