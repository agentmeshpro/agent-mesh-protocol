"""Shared fixtures and helpers for the MCP interop tests."""
from __future__ import annotations

import json
from typing import Any

import pytest

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.ampi.errors import AMPError
from ampro.interop.mcp import MCPAdapter
from ampro.server.core import AgentServer
from ampro.server.http import HTTPRequest, HTTPResponse

AGENT_ID = "agent://mcp-test.example.com"


def make_app() -> AgentApp:
    app = AgentApp(AGENT_ID, "http://localhost:8000/agent/message")
    app.state["calls"] = []

    @app.tool("add")
    async def add(a: int, b: int, ctx: AMPContext) -> dict:
        """Add two integers."""
        app.state["calls"].append(ctx)
        return {"sum": a + b}

    @app.tool("greet", description="Say hello.")
    def greet(name: str, punctuation: str = "!") -> str:
        return f"Hello, {name}{punctuation}"

    @app.tool("boom")
    async def boom() -> dict:
        raise RuntimeError("secret database password is hunter2")

    @app.tool("refuse")
    async def refuse() -> dict:
        raise AMPError("quota_exceeded", "daily quota reached")

    @app.tool(
        "search",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search terms"}},
            "required": ["query"],
        },
    )
    async def search(query: str, limit: int = 5) -> list:
        return [f"{query}-{i}" for i in range(limit)]

    @app.tool("admin_reset", scopes=["admin"])
    async def admin_reset() -> dict:
        return {"reset": True}

    @app.on("task.create")
    async def handle_task(msg, ctx):
        """Plans trips."""
        app.state["task_ctx"] = ctx
        if msg.body["description"] == "explode":
            raise ValueError("internal detail")
        return {"plan": f"done: {msg.body['description']}", "priority": msg.body.get("priority")}

    return app


@pytest.fixture
def app() -> AgentApp:
    return make_app()


@pytest.fixture
def server(app: AgentApp) -> AgentServer:
    return AgentServer.from_app(app)


@pytest.fixture
def adapter(server: AgentServer) -> MCPAdapter:
    return server.mount(MCPAdapter.for_server(server))  # type: ignore[return-value]


class Wire:
    """Tiny raw-HTTP driver for an AgentServer with an MCP adapter."""

    def __init__(self, server: AgentServer, path: str = "/mcp") -> None:
        self.server = server
        self.path = path
        self.session_id: str | None = None
        self.version: str | None = None
        self._next = 0

    async def http(
        self,
        method: str = "POST",
        body: Any = None,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
    ) -> HTTPResponse:
        hdrs = {"accept": "application/json, text/event-stream", "content-type": "application/json"}
        if self.session_id:
            hdrs["mcp-session-id"] = self.session_id
        if self.version:
            hdrs["mcp-protocol-version"] = self.version
        for k, v in (headers or {}).items():
            if v is None:
                hdrs.pop(k.lower(), None)
            else:
                hdrs[k.lower()] = v
        data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        return await self.server.handle(HTTPRequest(method=method, path=self.path, headers=hdrs, body=data))

    def next_id(self) -> int:
        self._next += 1
        return self._next

    async def rpc(
        self, method: str, params: dict | None = None, headers: dict | None = None
    ) -> tuple[HTTPResponse, Any]:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self.next_id(), "method": method}
        if params is not None:
            msg["params"] = params
        resp = await self.http(body=msg, headers=headers)
        return resp, body_of(resp)

    async def initialize(self, version: str = "2025-11-25", headers: dict | None = None) -> dict:
        resp, body = await self.rpc(
            "initialize",
            {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
            headers=headers,
        )
        assert resp.status == 200, body
        self.session_id = resp.headers["mcp-session-id"]
        self.version = body["result"]["protocolVersion"]
        note = await self.http(body={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        assert note.status == 202
        return body["result"]

    async def call(self, name: str, arguments: dict | None = None, headers: dict | None = None) -> Any:
        resp, body = await self.rpc("tools/call", {"name": name, "arguments": arguments or {}}, headers)
        assert resp.status == 200, (resp.status, body)
        return body


def body_of(resp: HTTPResponse) -> Any:
    if not resp.body:
        return None
    return json.loads(resp.body)


MODERN = "2026-07-28"


def modern_params(extra: dict | None = None, version: str = MODERN) -> dict:
    params = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
        }
    }
    params.update(extra or {})
    return params


def modern_headers(method: str, name: str | None = None, version: str = MODERN) -> dict:
    h = {"mcp-protocol-version": version, "mcp-method": method}
    if name is not None:
        h["mcp-name"] = name
    return h


@pytest.fixture
def wire(server: AgentServer, adapter: MCPAdapter) -> Wire:
    return Wire(server)
