"""MCPAdapter — handshake-era Streamable HTTP behaviour (no SDK needed)."""
from __future__ import annotations

import json

import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.mcp import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
    InMemorySessionStore,
    MCPAdapter,
    SessionStore,
)
from ampro.server.core import AgentServer
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

from ._support import Wire, body_of, make_app

# ---------------------------------------------------------------------------
# Handshake & version negotiation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", HANDSHAKE_PROTOCOL_VERSIONS)
async def test_initialize_echoes_supported_version(wire: Wire, version: str):
    result = await wire.initialize(version)
    assert result["protocolVersion"] == version
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "agent://mcp-test.example.com"
    assert wire.session_id and len(wire.session_id) >= 32
    assert all(0x21 <= ord(c) <= 0x7E for c in wire.session_id)


async def test_initialize_unknown_version_counter_offers_latest(wire: Wire):
    result = await wire.initialize("1999-01-01")
    assert result["protocolVersion"] == LATEST_HANDSHAKE_VERSION


async def test_initialize_requires_protocol_version(wire: Wire):
    resp, body = await wire.rpc("initialize", {"capabilities": {}})
    assert body["error"]["code"] == -32602
    assert "mcp-session-id" not in resp.headers


async def test_each_initialize_gets_a_fresh_session(wire: Wire):
    await wire.initialize()
    first = wire.session_id
    other = Wire(wire.server)
    await other.initialize()
    assert other.session_id != first


async def test_ping(wire: Wire):
    await wire.initialize()
    resp, body = await wire.rpc("ping")
    assert body == {"jsonrpc": "2.0", "id": body["id"], "result": {}}
    assert resp.headers["mcp-session-id"] == wire.session_id


async def test_unknown_method_is_method_not_found(wire: Wire):
    await wire.initialize()
    resp, body = await wire.rpc("resources/list")
    assert body["error"]["code"] == -32601


async def test_server_discover_is_not_a_handshake_era_method(wire: Wire):
    await wire.initialize()
    _, body = await wire.rpc("server/discover")
    assert body["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# Session enforcement
# ---------------------------------------------------------------------------


async def test_request_without_session_is_400(wire: Wire):
    resp, body = await wire.rpc("tools/list")
    assert resp.status == 400
    assert body["error"]["code"] == -32600


async def test_unknown_session_is_404(wire: Wire):
    wire.session_id = "not-a-session"
    resp, _ = await wire.rpc("tools/list")
    assert resp.status == 404


async def test_delete_ends_session(wire: Wire):
    await wire.initialize()
    resp = await wire.http("DELETE")
    assert resp.status == 200
    resp, _ = await wire.rpc("tools/list")
    assert resp.status == 404
    assert (await wire.http("DELETE")).status == 404


async def test_delete_without_session_is_400(wire: Wire):
    assert (await wire.http("DELETE")).status == 400


async def test_version_header_must_match_negotiated(wire: Wire):
    await wire.initialize("2025-06-18")
    resp, _ = await wire.rpc("tools/list", headers={"mcp-protocol-version": "2025-11-25"})
    assert resp.status == 400


async def test_missing_version_header_is_tolerated(wire: Wire):
    await wire.initialize("2025-03-26")
    resp, body = await wire.rpc("tools/list", headers={"mcp-protocol-version": None})
    assert resp.status == 200 and "tools" in body["result"]


async def test_unknown_version_header_is_400(wire: Wire):
    await wire.initialize()
    resp, _ = await wire.rpc("tools/list", headers={"mcp-protocol-version": "2099-01-01"})
    assert resp.status == 400


async def test_session_store_is_bounded():
    app = make_app()
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, max_sessions=2))
    for _ in range(2):
        await Wire(server).initialize()
    resp, body = await Wire(server).rpc(
        "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}
    )
    assert resp.status == 503
    assert body["error"]["code"] == -32603


async def test_session_store_idle_expiry_frees_capacity():
    now = [0.0]
    store = InMemorySessionStore(max_sessions=1, idle_timeout=10, clock=lambda: now[0])
    assert isinstance(store, SessionStore)
    s = await store.create("2025-11-25", None)
    assert s is not None and await store.create("2025-11-25", None) is None
    now[0] = 11
    assert await store.get(s.id, None) is None
    assert await store.create("2025-11-25", None) is not None


async def test_session_store_max_lifetime():
    now = [0.0]
    store = InMemorySessionStore(idle_timeout=10, max_lifetime=25, clock=lambda: now[0])
    s = await store.create("2025-11-25", None)
    for t in (8, 16, 24):
        now[0] = t
        assert await store.get(s.id, None) is s
    now[0] = 26
    assert await store.get(s.id, None) is None


async def test_session_store_binds_owner():
    store = InMemorySessionStore()
    s = await store.create("2025-11-25", "alice")
    assert await store.get(s.id, "bob") is None
    assert await store.get(s.id, None) is None
    assert await store.delete(s.id, "bob") is False
    assert await store.get(s.id, "alice") is s


async def test_custom_session_store_is_used(app: AgentApp):
    class Recording(InMemorySessionStore):
        saved = 0

        async def save(self, session):
            Recording.saved += 1
            await super().save(session)

    store = Recording()
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, session_store=store))
    await Wire(server).initialize()
    assert len(store) == 1 and Recording.saved == 1


# ---------------------------------------------------------------------------
# HTTP-level rules
# ---------------------------------------------------------------------------


async def test_get_is_405_without_server_stream(wire: Wire):
    await wire.initialize()
    resp = await wire.http("GET")
    assert resp.status == 405
    assert "POST" in resp.headers["allow"]


async def test_other_methods_are_405(wire: Wire):
    assert (await wire.http("PUT", body={})).status == 405


async def test_notifications_and_responses_are_accepted_202(wire: Wire):
    await wire.initialize()
    resp = await wire.http(body={"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})
    assert resp.status == 202 and resp.body == b""
    resp = await wire.http(body={"jsonrpc": "2.0", "id": 99, "result": {}})
    assert resp.status == 202


async def test_parse_error(wire: Wire):
    resp = await wire.http(raw=b"{not json")
    assert resp.status == 400
    assert body_of(resp)["error"]["code"] == -32700
    assert body_of(resp)["id"] is None


@pytest.mark.parametrize(
    "msg",
    [
        {"id": 1, "method": "ping"},
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": None, "method": "ping"},
        {"jsonrpc": "2.0", "id": True, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1, "method": 5},
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]},
        "hello",
    ],
)
async def test_invalid_jsonrpc_is_400(wire: Wire, msg):
    resp = await wire.http(body=msg)
    assert resp.status == 400
    assert body_of(resp)["error"]["code"] == -32600


async def test_accept_must_allow_json(wire: Wire):
    resp, _ = await wire.rpc("ping", headers={"accept": "text/html"})
    assert resp.status == 406


async def test_content_type_must_be_json(wire: Wire):
    resp, _ = await wire.rpc("ping", headers={"content-type": "text/plain"})
    assert resp.status == 415


async def test_other_paths_fall_through_to_amp(wire: Wire, server: AgentServer):
    resp = await server.handle(HTTPRequest("GET", "/agent/health"))
    assert resp.status == 200
    wire.path = "/mcpx"
    assert (await wire.http(body={})).status != 202


async def test_custom_path(app: AgentApp):
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, path="/tools/mcp/"))
    w = Wire(server, "/tools/mcp")
    await w.initialize()


# ---------------------------------------------------------------------------
# Batches (2025-03-26 only)
# ---------------------------------------------------------------------------


async def test_batch_allowed_on_2025_03_26(wire: Wire):
    await wire.initialize("2025-03-26")
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "b": 2}}},
        {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
    ]
    resp = await wire.http(body=batch)
    assert resp.status == 200
    replies = {r["id"]: r for r in body_of(resp)}
    assert replies[1]["result"] == {}
    assert replies[2]["result"]["structuredContent"] == {"sum": 3}
    assert replies[3]["error"]["code"] == -32600


async def test_notification_only_batch_is_202(wire: Wire):
    await wire.initialize("2025-03-26")
    resp = await wire.http(body=[{"jsonrpc": "2.0", "method": "notifications/initialized"}])
    assert resp.status == 202


@pytest.mark.parametrize("version", ["2024-11-05", "2025-06-18", "2025-11-25"])
async def test_batch_rejected_on_other_versions(wire: Wire, version: str):
    await wire.initialize(version)
    resp = await wire.http(body=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
    assert resp.status == 400


async def test_empty_batch_is_400(wire: Wire):
    await wire.initialize("2025-03-26")
    assert (await wire.http(body=[])).status == 400


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------


async def _tools(wire: Wire) -> dict[str, dict]:
    _, body = await wire.rpc("tools/list")
    return {t["name"]: t for t in body["result"]["tools"]}


async def test_tools_list_schemas(wire: Wire):
    await wire.initialize()
    tools = await _tools(wire)
    add = tools["add"]
    assert add["description"] == "Add two integers."
    schema = add["inputSchema"]
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"a", "b"}  # ctx skipped
    assert schema["properties"]["a"]["type"] == "integer"
    assert sorted(schema["required"]) == ["a", "b"]
    assert schema["additionalProperties"] is False

    greet = tools["greet"]
    assert greet["description"] == "Say hello."
    assert greet["inputSchema"]["required"] == ["name"]
    assert greet["inputSchema"]["properties"]["punctuation"]["default"] == "!"


async def test_explicit_input_schema_wins(wire: Wire):
    await wire.initialize()
    tools = await _tools(wire)
    assert tools["search"]["inputSchema"] == {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "Search terms"}},
        "required": ["query"],
    }


async def test_scoped_tool_hidden_without_principal(wire: Wire):
    await wire.initialize()
    assert "admin_reset" not in await _tools(wire)


async def test_task_tool_listed(wire: Wire):
    await wire.initialize()
    task = (await _tools(wire))["amp_task"]
    assert "agent://mcp-test.example.com" in task["description"]
    assert "Plans trips." in task["description"]
    assert task["inputSchema"]["required"] == ["description"]


async def test_tools_list_pagination():
    app = AgentApp("agent://p", "http://x")
    for i in range(5):
        app.tool(f"t{i}")(lambda: i)
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, page_size=2))
    w = Wire(server)
    await w.initialize()
    names, cursor, pages = [], None, 0
    while True:
        _, body = await w.rpc("tools/list", {"cursor": cursor} if cursor else {})
        names += [t["name"] for t in body["result"]["tools"]]
        pages += 1
        cursor = body["result"].get("nextCursor")
        if not cursor:
            break
    assert names == [f"t{i}" for i in range(5)] and pages == 3


@pytest.mark.parametrize("cursor", ["!!!", 5, "eyJvIjogLTF9", "eyJvIjogOTl9"])
async def test_tools_list_invalid_cursor(wire: Wire, cursor):
    await wire.initialize()
    _, body = await wire.rpc("tools/list", {"cursor": cursor})
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------


async def test_call_returns_structured_and_text(wire: Wire, app: AgentApp):
    await wire.initialize()
    result = (await wire.call("add", {"a": 2, "b": 40}))["result"]
    assert result["isError"] is False
    assert result["structuredContent"] == {"sum": 42}
    assert json.loads(result["content"][0]["text"]) == {"sum": 42}
    ctx = app.state["calls"][-1]
    assert getattr(ctx, "protocol", None) == "mcp"
    assert ctx.trust_tier == TrustTier.EXTERNAL
    assert ctx.agent_address == "agent://mcp-test.example.com"


async def test_call_sync_tool_with_default(wire: Wire):
    await wire.initialize()
    result = (await wire.call("greet", {"name": "Ada"}))["result"]
    assert result["content"] == [{"type": "text", "text": "Hello, Ada!"}]
    assert "structuredContent" not in result


async def test_call_list_result_is_text(wire: Wire):
    await wire.initialize()
    result = (await wire.call("search", {"query": "q", "limit": 2}))["result"]
    assert json.loads(result["content"][0]["text"]) == ["q-0", "q-1"]


async def test_tool_exception_is_generic_error(wire: Wire, caplog):
    await wire.initialize()
    result = (await wire.call("boom"))["result"]
    assert result["isError"] is True
    assert "hunter2" not in json.dumps(result)
    text = result["content"][0]["text"]
    assert text.startswith("Tool execution failed (reference ")
    ref = text.rsplit(" ", 1)[-1].rstrip(")")
    assert any(ref in r.getMessage() and "boom" in r.getMessage() for r in caplog.records)


async def test_amp_error_message_is_returned(wire: Wire):
    await wire.initialize()
    result = (await wire.call("refuse"))["result"]
    assert result["isError"] is True
    assert "quota_exceeded" in result["content"][0]["text"]
    assert "daily quota" not in result["content"][0]["text"]


@pytest.mark.parametrize(
    "arguments, bad",
    [
        ({"a": 1}, "b"),
        ({"a": "x", "b": 1}, "a"),
        ({"a": "1", "b": 1}, "a"),  # strict: no string -> int coercion
        ({"a": 1.5, "b": 1}, "a"),
        ({"a": 1, "b": 2, "c": 3}, "c"),
    ],
)
async def test_argument_validation(wire: Wire, arguments, bad):
    await wire.initialize()
    result = (await wire.call("add", arguments))["result"]
    assert result["isError"] is True
    assert bad in result["content"][0]["text"]


async def test_explicit_schema_required_enforced(wire: Wire):
    await wire.initialize()
    result = (await wire.call("search", {}))["result"]
    assert result["isError"] is True and "query" in result["content"][0]["text"]


async def test_unknown_tool_is_invalid_params(wire: Wire):
    await wire.initialize()
    body = await wire.call("nope")
    assert body["error"]["code"] == -32602
    assert "nope" in body["error"]["message"]


@pytest.mark.parametrize("params", [{}, {"name": 3}, {"name": "add", "arguments": [1, 2]}])
async def test_malformed_call_params(wire: Wire, params):
    await wire.initialize()
    _, body = await wire.rpc("tools/call", params)
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# amp_task bridge
# ---------------------------------------------------------------------------


async def test_amp_task_dispatches_task_create(wire: Wire, app: AgentApp):
    seen = []

    @app.middleware
    async def record(msg, ctx, nxt):
        seen.append(msg.body_type)
        return await nxt(msg, ctx)

    await wire.initialize()
    result = (await wire.call("amp_task", {"description": "Lisbon", "priority": "high"}))["result"]
    assert result["structuredContent"] == {"plan": "done: Lisbon", "priority": "high"}
    assert seen == ["task.create"]
    assert getattr(app.state["task_ctx"], "protocol", None) == "mcp"


async def test_amp_task_handler_error_is_generic(wire: Wire):
    await wire.initialize()
    result = (await wire.call("amp_task", {"description": "explode"}))["result"]
    assert result["isError"] is True
    assert "internal detail" not in json.dumps(result)


async def test_amp_task_on_error_hook_runs(wire: Wire, app: AgentApp):
    @app.on_error
    async def recover(exc, msg, ctx):
        return {"recovered": True}

    await wire.initialize()
    result = (await wire.call("amp_task", {"description": "explode"}))["result"]
    assert result["structuredContent"] == {"recovered": True}


@pytest.mark.parametrize(
    "arguments", [{}, {"description": "x", "priority": "asap"}, {"description": "x", "rogue": 1}]
)
async def test_amp_task_validates_arguments(wire: Wire, arguments):
    await wire.initialize()
    result = (await wire.call("amp_task", arguments))["result"]
    assert result["isError"] is True


async def test_amp_task_can_be_disabled(app: AgentApp):
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, expose_tasks=False))
    w = Wire(server)
    await w.initialize()
    assert "amp_task" not in await _tools(w)


async def test_no_amp_task_without_handler():
    app = AgentApp("agent://x", "http://x")
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server))
    w = Wire(server)
    await w.initialize()
    assert await _tools(w) == {}


async def test_amp_task_on_plain_agent_server():
    server = AgentServer(agent_id="@plain", endpoint="http://x")

    @server.on("task.create")
    async def handle(msg):
        return {"echo": msg.body["description"], "sender": msg.sender}

    server.mount(MCPAdapter.for_server(server))
    w = Wire(server)
    await w.initialize()
    result = (await w.call("amp_task", {"description": "hi"}))["result"]
    assert result["structuredContent"] == {"echo": "hi", "sender": "mcp://anonymous"}


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_cli_mounts_mcp_adapter(app: AgentApp):
    from ampro.server.cli import build_server

    server = build_server(app, ["amp", "mcp"])
    assert [a.name for a in server.adapters] == ["mcp"]
    assert isinstance(server.adapters[0], MCPAdapter)


def test_app_tool_metadata_is_additive():
    app = AgentApp("agent://x", "http://x")

    @app.tool("plain")
    def plain():
        return 1

    @app.tool("rich", description="d", input_schema={"type": "object"}, scopes=["s1", "s2"])
    def rich():
        return 2

    assert app.tools == {"plain": plain, "rich": rich}
    assert "plain" not in app.tool_meta
    assert app.tool_meta["rich"] == {
        "description": "d",
        "input_schema": {"type": "object"},
        "scopes": ["s1", "s2"],
    }


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


async def test_tool_timeout(app: AgentApp):
    import asyncio
    import time as _time

    @app.tool("slow")
    async def slow() -> str:
        await asyncio.sleep(5)
        return "late"

    @app.tool("slow_sync")
    def slow_sync() -> str:
        _time.sleep(0.5)
        return "late"

    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, tool_timeout=0.05))
    w = Wire(server)
    await w.initialize()
    for name in ("slow", "slow_sync"):
        result = (await w.call(name))["result"]
        assert result["isError"] is True
        assert "timed out" in result["content"][0]["text"]


async def test_sync_tools_run_off_the_event_loop(wire: Wire, app: AgentApp):
    import threading

    main = threading.get_ident()

    @app.tool("where")
    def where() -> dict:
        return {"same_thread": threading.get_ident() == main}

    await wire.initialize()
    assert (await wire.call("where"))["result"]["structuredContent"] == {"same_thread": False}


async def test_argument_size_limit(app: AgentApp):
    server = AgentServer.from_app(app)
    server.mount(MCPAdapter.for_server(server, max_argument_bytes=64))
    w = Wire(server)
    await w.initialize()
    body = await w.call("greet", {"name": "x" * 100})
    assert body["error"]["code"] == -32602
    assert (await w.call("greet", {"name": "x"}))["result"]["isError"] is False
