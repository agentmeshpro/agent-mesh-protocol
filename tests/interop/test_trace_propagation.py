"""W3C trace context + hop count carried across every adapter and client.

Covers :mod:`ampro.interop.propagation` itself, the inbound side of the
A2A / MCP / native AMP routes, the outbound side of the A2A / MCP / AMP
clients, and an end-to-end A2A -> MCP -> A2A -> ... cycle that the hop
limit terminates while the trace id survives every protocol boundary.
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.delegation.tracing import parse_traceparent
from ampro.interop.a2a import AMP_EXTENSION_URI, A2AAdapter, A2AClient
from ampro.interop.mcp import MCPAdapter, MCPToolSource
from ampro.interop.propagation import (
    DEFAULT_MAX_HOPS,
    HOP_COUNT_HEADER,
    HOP_COUNT_METADATA_KEY,
    HopLimitExceeded,
    InboundTrace,
    Propagation,
    TracePropagationError,
    begin_span,
    check_max_hops,
    current_propagation,
    outbound_headers,
    outbound_hop_count,
    parse_hop_count,
    propagation_from_context,
    read_inbound,
    use_propagation,
)
from ampro.server import AgentServer
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

TID = "4bf92f3577b34da6a3ce929d0e0e4736"
PID = "00f067aa0ba902b7"
TP = f"00-{TID}-{PID}-01"
OTHER_TP = f"00-{'1' * 32}-{PID}-01"


def _out() -> dict[str, str] | None:
    """What an outbound call made by this handler would carry (None at the limit)."""
    try:
        return outbound_headers()
    except HopLimitExceeded:
        return None


# ---------------------------------------------------------------------------
# propagation module
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("0", 0), ("7", 7), (" 12\t", 12), ("9999", 9999), (3, 3), (0, 0),
])
def test_parse_hop_count_valid(value, expected):
    assert parse_hop_count(value) == expected


@pytest.mark.parametrize("value", [
    "", "-1", "+1", "1.0", "0x1", "10000", "1 2", "١", True, False, -1, 10000, 1.0, None,
    [1], "9" * 100,
])
def test_parse_hop_count_rejects(value):
    with pytest.raises(TracePropagationError):
        parse_hop_count(value)


@pytest.mark.parametrize("bad", [0, -1, 1001, True, 2.0, "5"])
def test_check_max_hops(bad):
    with pytest.raises(ValueError):
        check_max_hops(bad)


def test_hop_limit_from_policy_is_clamped():
    from types import SimpleNamespace

    from ampro.interop.propagation import MAX_HOPS_CEILING, hop_limit_from_policy

    assert hop_limit_from_policy(None) == DEFAULT_MAX_HOPS
    assert hop_limit_from_policy(SimpleNamespace(max_visited_agents=7)) == 7
    assert hop_limit_from_policy(SimpleNamespace(max_visited_agents=0)) == 1
    assert hop_limit_from_policy(SimpleNamespace(max_visited_agents=10**6)) == MAX_HOPS_CEILING
    assert hop_limit_from_policy(SimpleNamespace(max_visited_agents="x")) == DEFAULT_MAX_HOPS


def test_read_inbound_headers_case_insensitive():
    inbound = read_inbound({"Traceparent": TP, "TRACESTATE": "a=1", "amp-hop-count": "3"})
    assert inbound.traceparent is not None and inbound.traceparent.trace_id == TID
    assert inbound.tracestate == "a=1" and inbound.hop_count == 3


def test_read_inbound_nothing():
    assert read_inbound(None) == InboundTrace()
    assert read_inbound({}, metadata=(None, {})) == InboundTrace()


def test_read_inbound_tracestate_ignored_without_traceparent():
    assert read_inbound({"tracestate": "not valid at all"}).tracestate is None


@pytest.mark.parametrize("headers,metadata", [
    ({"traceparent": "00-bad"}, ()),
    ({"traceparent": TP.upper()}, ()),
    ({}, ({"traceparent": 5},)),
    ({}, ({"traceparent": "nope"},)),
    ({"traceparent": TP}, ({"traceparent": OTHER_TP},)),          # conflicting sources
    ({"traceparent": TP, "tracestate": "A=1"}, ()),                # malformed tracestate
    ({"traceparent": TP, "tracestate": "a=1"}, ({"tracestate": "b=2"},)),
    ({"traceparent": TP}, ({"tracestate": 7},)),
    ({HOP_COUNT_HEADER: "abc"}, ()),
    ({}, ({HOP_COUNT_METADATA_KEY: "1e3"},)),
    ({}, ({HOP_COUNT_METADATA_KEY: True},)),
])
def test_read_inbound_rejects(headers, metadata):
    with pytest.raises(TracePropagationError) as exc:
        read_inbound(headers, metadata=metadata)
    # Generic message: never echoes the offending value.
    assert "bad" not in str(exc.value) and "nope" not in str(exc.value)


def test_read_inbound_hop_limit_is_max_of_all_sources():
    inbound = read_inbound({HOP_COUNT_HEADER: "2"}, metadata=({HOP_COUNT_METADATA_KEY: 5},),
                           hop_floor=4)
    assert inbound.hop_count == 5  # a lower value never lowers the count
    assert read_inbound({}, hop_floor=7).hop_count == 7
    assert read_inbound({HOP_COUNT_HEADER: "20"}).hop_count == 20  # == max is fine
    with pytest.raises(HopLimitExceeded):
        read_inbound({HOP_COUNT_HEADER: "21"})
    with pytest.raises(HopLimitExceeded):
        read_inbound({HOP_COUNT_HEADER: "1"}, metadata=({HOP_COUNT_METADATA_KEY: 6},), max_hops=5)
    with pytest.raises(HopLimitExceeded):
        read_inbound({}, hop_floor=6, max_hops=5)


def test_begin_span_continues_inbound_trace():
    prop = begin_span(read_inbound({"traceparent": f"00-{TID}-{PID}-00", "tracestate": "a=1",
                                    HOP_COUNT_HEADER: "2"}), max_hops=9)
    assert prop.trace_id == TID and prop.parent_span_id == PID and prop.span_id != PID
    assert prop.trace_flags == 0 and prop.tracestate == "a=1" and prop.hop_count == 2
    headers = prop.outbound_headers()
    assert parse_traceparent(headers["traceparent"]).parent_id == prop.span_id
    assert headers["traceparent"].endswith("-00")
    assert headers["tracestate"] == "a=1" and headers[HOP_COUNT_HEADER] == "3"


def test_begin_span_root():
    prop = begin_span(None)
    assert len(prop.trace_id) == 32 and prop.parent_span_id is None and prop.hop_count == 0
    assert begin_span(None, trace_id="a" * 32, span_id="b" * 16).trace_id == "a" * 32
    assert begin_span(None, trace_id="not-hex").trace_id != "not-hex"


def test_outbound_outside_any_handler_starts_hop_1():
    assert current_propagation() is None
    h1, h2 = outbound_headers(), outbound_headers()
    assert h1[HOP_COUNT_HEADER] == "1" and "tracestate" not in h1
    assert parse_traceparent(h1["traceparent"]).trace_id != parse_traceparent(
        h2["traceparent"]).trace_id
    assert outbound_hop_count() == 1


def test_outbound_inside_handler_and_limits():
    prop = Propagation(trace_id=TID, span_id=PID, hop_count=4, max_hops=5)
    with use_propagation(prop):
        assert current_propagation() is prop
        assert outbound_headers()["traceparent"] == TP
        assert outbound_hop_count() == 5
        with pytest.raises(HopLimitExceeded):
            outbound_hop_count(max_hops=4)  # the stricter of the two limits wins
    assert current_propagation() is None
    with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=5, max_hops=5)):
        with pytest.raises(HopLimitExceeded):
            outbound_headers()


def test_propagation_from_context():
    ctx = AMPContext(agent_address="@a", sender_address="@b", request_id="r",
                     trust_tier=TrustTier.EXTERNAL, trace_id="custom-id", span_id=PID,
                     visited_agents=["@x", "@y", "@z"], hop_count=1)
    prop = propagation_from_context(ctx, max_hops=DEFAULT_MAX_HOPS)
    assert prop.trace_id != "custom-id" and len(prop.trace_id) == 32  # not W3C-shaped
    assert prop.span_id == PID and prop.hop_count == 3  # Visited-Agents count wins


# ---------------------------------------------------------------------------
# A2A inbound
# ---------------------------------------------------------------------------

BASE = "https://agent.example"


def trace_app(seen: list[AMPContext]) -> AgentApp:
    app = AgentApp("@demo", BASE)

    @app.on("task.create")
    async def create(msg, ctx):
        seen.append(ctx)
        return {"out": _out()}

    return app


def a2a_server(seen: list[AMPContext], **kw: Any) -> AgentServer:
    server = AgentServer.from_app(trace_app(seen))
    server.mount(A2AAdapter.for_server(server, **kw))
    return server


def a2a_body(**meta: Any) -> dict[str, Any]:
    msg: dict[str, Any] = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                           "parts": [{"text": "hi"}]}
    if meta:
        msg["metadata"] = meta
    return {"message": msg}


def a2a_http(server: AgentServer) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()), base_url=BASE)


def reason(resp: httpx.Response) -> str:
    return resp.json()["error"]["details"][0]["reason"]


async def test_a2a_traceparent_populates_context():
    seen: list[AMPContext] = []
    async with a2a_http(a2a_server(seen)) as c:
        r = await c.post("/a2a/message:send", json=a2a_body(),
                         headers={"traceparent": TP, "tracestate": "v=1",
                                  HOP_COUNT_HEADER: "2"})
    assert r.status_code == 200, r.text
    ctx = seen[0]
    assert ctx.trace_id == TID and ctx.parent_span_id == PID and ctx.span_id != PID
    assert ctx.trace_state == "v=1" and ctx.hop_count == 2
    assert ctx.metadata["amp.parentSpanId"] == PID
    out = r.json()["message"]["parts"][0]["data"]["out"]
    assert out["traceparent"] == f"00-{TID}-{ctx.span_id}-01"
    assert out["tracestate"] == "v=1" and out[HOP_COUNT_HEADER] == "3"


async def test_a2a_traceparent_from_message_metadata():
    seen: list[AMPContext] = []
    async with a2a_http(a2a_server(seen)) as c:
        r = await c.post("/a2a/message:send",
                         json=a2a_body(traceparent=TP, **{HOP_COUNT_METADATA_KEY: 4}))
    assert r.status_code == 200, r.text
    assert seen[0].trace_id == TID and seen[0].hop_count == 4


async def test_a2a_no_trace_context_starts_fresh():
    seen: list[AMPContext] = []
    async with a2a_http(a2a_server(seen)) as c:
        r = await c.post("/a2a/message:send", json=a2a_body())
    assert r.status_code == 200
    assert seen[0].hop_count == 0 and seen[0].parent_span_id is None
    assert r.json()["message"]["parts"][0]["data"]["out"][HOP_COUNT_HEADER] == "1"


@pytest.mark.parametrize("headers,meta", [
    ({"traceparent": "00-zz"}, {}),
    ({"traceparent": TP.upper()}, {}),
    ({"traceparent": f"00-{'0' * 32}-{PID}-01"}, {}),
    ({"traceparent": TP}, {"traceparent": OTHER_TP}),
    ({"traceparent": TP, "tracestate": "BAD=1"}, {}),
    ({HOP_COUNT_HEADER: "-1"}, {}),
    ({}, {HOP_COUNT_METADATA_KEY: "x"}),
    ({HOP_COUNT_HEADER: "21"}, {}),
    ({}, {HOP_COUNT_METADATA_KEY: 21}),
    ({HOP_COUNT_HEADER: "1"}, {HOP_COUNT_METADATA_KEY: 21}),  # never trust the lower one
])
async def test_a2a_rejects_bad_trace_or_hops(headers, meta):
    seen: list[AMPContext] = []
    async with a2a_http(a2a_server(seen)) as c:
        r = await c.post("/a2a/message:send", json=a2a_body(**meta), headers=headers)
        assert r.status_code == 400 and reason(r) == "INVALID_PARAMS"
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": a2a_body(**meta)}
        r = await c.post("/a2a", json=rpc, headers={"A2A-Version": "1.0", **headers})
        assert r.json()["error"]["code"] == -32602
    assert seen == []  # the handler never ran


async def test_a2a_max_hops_option_and_policy_default():
    seen: list[AMPContext] = []
    server = a2a_server(seen, max_hops=3)
    async with a2a_http(server) as c:
        assert (await c.post("/a2a/message:send", json=a2a_body(),
                             headers={HOP_COUNT_HEADER: "3"})).status_code == 200
        r = await c.post("/a2a/message:send", json=a2a_body(), headers={HOP_COUNT_HEADER: "4"})
        assert reason(r) == "INVALID_PARAMS" and "Hop limit" in r.text
    other = AgentServer.from_app(trace_app(seen))
    other.security.max_visited_agents = 7
    assert A2AAdapter.for_server(other).max_hops == 7
    with pytest.raises(ValueError):
        A2AAdapter.for_server(other, max_hops=0)


async def test_a2a_visited_agents_count_is_a_hop_floor():
    seen: list[AMPContext] = []
    ext = {AMP_EXTENSION_URI: {"visitedAgents": [f"@a{i}" for i in range(4)]}}
    async with a2a_http(a2a_server(seen, max_hops=3)) as c:
        r = await c.post("/a2a/message:send", json=a2a_body(**ext),
                         headers={"A2A-Extensions": AMP_EXTENSION_URI, HOP_COUNT_HEADER: "0"})
        assert reason(r) == "INVALID_PARAMS"
    async with a2a_http(a2a_server(seen, max_hops=10)) as c:
        r = await c.post("/a2a/message:send", json=a2a_body(**ext),
                         headers={"A2A-Extensions": AMP_EXTENSION_URI})
        assert r.status_code == 200 and seen[-1].hop_count == 4


async def test_a2a_extension_trace_must_agree_with_traceparent():
    seen: list[AMPContext] = []
    hdrs = {"A2A-Extensions": AMP_EXTENSION_URI, "traceparent": TP}
    async with a2a_http(a2a_server(seen)) as c:
        ok = a2a_body(**{AMP_EXTENSION_URI: {"traceId": TID, "spanId": PID}})
        assert (await c.post("/a2a/message:send", json=ok, headers=hdrs)).status_code == 200
        for amp in ({"traceId": "a" * 32}, {"spanId": "b" * 16}, {"traceId": "custom"}):
            r = await c.post("/a2a/message:send", json=a2a_body(**{AMP_EXTENSION_URI: amp}),
                             headers=hdrs)
            assert reason(r) == "INVALID_PARAMS" and "Conflicting" in r.text
    assert len(seen) == 1


# ---------------------------------------------------------------------------
# A2A outbound (client)
# ---------------------------------------------------------------------------


async def test_a2a_client_emits_trace_and_hop_count():
    seen: list[AMPContext] = []
    server = a2a_server(seen)
    async with a2a_http(server) as h:
        client = A2AClient(BASE, http_client=h, extensions=[])
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=2,
                                         tracestate="v=1")):
            await client.send_message("hi")
        ctx = seen[-1]
        assert ctx.trace_id == TID and ctx.parent_span_id == PID
        assert ctx.hop_count == 3 and ctx.trace_state == "v=1"
        raw = ctx.metadata["a2a.message"]
        assert raw.metadata[HOP_COUNT_METADATA_KEY] == 3
        # A caller cannot lower the hop count through metadata.
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=5)):
            await client.send_message("hi", metadata={HOP_COUNT_METADATA_KEY: 1})
        assert seen[-1].hop_count == 6
        # At the limit the client refuses to send at all.
        before = len(seen)
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=20)):
            with pytest.raises(HopLimitExceeded):
                await client.send_message("hi")
        assert len(seen) == before
        with pytest.raises(HopLimitExceeded):
            with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=1)):
                await A2AClient(BASE, http_client=h, extensions=[], max_hops=1).send_message("x")


async def test_a2a_client_traceparent_follows_amp_extension_ids():
    seen: list[AMPContext] = []
    async with a2a_http(a2a_server(seen)) as h:
        client = A2AClient(BASE, http_client=h)  # AMP extension active
        await client.send_message("hi", amp={"traceId": "c" * 32, "spanId": "d" * 16})
        assert seen[-1].trace_id == "c" * 32 and seen[-1].parent_span_id == "d" * 16
        # A non-W3C trace id suppresses traceparent instead of contradicting it.
        await client.send_message("hi", amp={"traceId": "custom-trace"})
        assert seen[-1].trace_id == "custom-trace" and seen[-1].hop_count == 1


# ---------------------------------------------------------------------------
# MCP inbound + outbound
# ---------------------------------------------------------------------------

MCP_URL = "http://127.0.0.1:8000/mcp"


def mcp_app(seen: list[AMPContext]) -> AgentApp:
    app = AgentApp("agent://mcp.example", "http://localhost:8000/agent/message")

    @app.tool("probe")
    async def probe(ctx: AMPContext) -> dict:
        seen.append(ctx)
        return {"out": _out()}

    return app


def mcp_server(seen: list[AMPContext], **kw: Any) -> AgentServer:
    server = AgentServer.from_app(mcp_app(seen))
    server.mount(MCPAdapter.for_server(server, **kw))
    return server


async def test_mcp_inbound_trace_and_outbound_client():
    seen: list[AMPContext] = []
    server = mcp_server(seen)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi())) as h:
        source = MCPToolSource(MCP_URL, http_client=h)
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=6,
                                         tracestate="v=1")):
            result = await source.call_tool("probe", {})
        await source.close()
    ctx = seen[-1]
    assert ctx.protocol == "mcp" and ctx.trace_id == TID and ctx.parent_span_id == PID
    assert ctx.hop_count == 7 and ctx.trace_state == "v=1"
    out = result["structuredContent"]["out"]
    assert out[HOP_COUNT_HEADER] == "8" and out["traceparent"] == f"00-{TID}-{ctx.span_id}-01"


async def test_mcp_client_refuses_past_limit():
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as h:
        source = MCPToolSource(MCP_URL, http_client=h, max_hops=2)
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=2)):
            with pytest.raises(HopLimitExceeded):
                await source.call_tool("probe", {})
    assert sent == []  # refused locally, nothing went on the wire


@pytest.mark.parametrize("headers", [
    {"traceparent": "garbage"},
    {"traceparent": TP, "tracestate": "a=1,a=2"},
    {HOP_COUNT_HEADER: "1.5"},
    {HOP_COUNT_HEADER: "21"},
])
async def test_mcp_rejects_bad_trace_or_hops(headers):
    seen: list[AMPContext] = []
    server = mcp_server(seen)
    hdrs = {"accept": "application/json, text/event-stream",
            "content-type": "application/json", **{k.lower(): v for k, v in headers.items()}}
    body = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}'
    resp = await server.handle(HTTPRequest(method="POST", path="/mcp", headers=hdrs, body=body))
    assert resp.status == 400
    assert b"Bad Request" in resp.body and b"garbage" not in resp.body  # type: ignore[operator]
    assert seen == []


def test_mcp_max_hops_from_policy():
    server = AgentServer.from_app(mcp_app([]))
    server.security.max_visited_agents = 6
    assert MCPAdapter.for_server(server).max_hops == 6
    assert MCPAdapter.for_server(server, max_hops=2).max_hops == 2
    with pytest.raises(ValueError):
        MCPAdapter.for_server(server, max_hops=0)


# ---------------------------------------------------------------------------
# Native AMP route + AMP client
# ---------------------------------------------------------------------------


def native_server(seen: list[AMPContext]) -> AgentServer:
    app = AgentApp("agent://native.example", "https://native.example")

    @app.on("task.create")
    async def create(msg, ctx):
        seen.append(ctx)
        return {"out": _out()}

    return AgentServer.from_app(app)


def envelope(**headers: str) -> bytes:
    import json

    return json.dumps({"sender": "agent://caller.example", "recipient": "agent://native.example",
                       "body_type": "task.create", "headers": headers,
                       "body": {"description": "x", "task_id": "t1"}}).encode()


async def native_post(server: AgentServer, body: bytes, **headers: str):
    hdrs = {"content-type": "application/json", **{k.lower(): v for k, v in headers.items()}}
    return await server.handle(HTTPRequest(method="POST", path="/agent/message",
                                           headers=hdrs, body=body))


async def test_native_route_reads_trace_and_hops():
    seen: list[AMPContext] = []
    server = native_server(seen)
    resp = await native_post(server, envelope(), traceparent=TP, **{HOP_COUNT_HEADER: "5"})
    assert resp.status == 202, resp.body
    ctx = seen[-1]
    assert ctx.trace_id == TID and ctx.parent_span_id == PID and ctx.hop_count == 5


async def test_native_route_visited_agents_is_hop_floor():
    seen: list[AMPContext] = []
    server = native_server(seen)
    visited = ",".join(f"agent://a{i}.example" for i in range(3))
    resp = await native_post(server, envelope(**{"Visited-Agents": visited}),
                             **{HOP_COUNT_HEADER: "1"})
    assert resp.status == 202
    assert seen[-1].hop_count == 3


@pytest.mark.parametrize("headers,status", [
    ({"traceparent": "00-nope"}, 400),
    ({"traceparent": TP, "tracestate": "=1"}, 400),
    ({HOP_COUNT_HEADER: "x"}, 400),
    ({HOP_COUNT_HEADER: "21"}, 409),
])
async def test_native_route_rejects(headers, status):
    seen: list[AMPContext] = []
    resp = await native_post(native_server(seen), envelope(), **headers)
    assert resp.status == status and seen == []


async def test_native_route_hop_limit_follows_policy():
    seen: list[AMPContext] = []
    server = native_server(seen)
    server.security.max_visited_agents = 2
    assert (await native_post(server, envelope(), **{HOP_COUNT_HEADER: "2"})).status == 202
    assert (await native_post(server, envelope(), **{HOP_COUNT_HEADER: "3"})).status == 409


async def test_amp_client_emits_trace_headers(monkeypatch):
    from ampro.client import core as client_core

    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(200, json={"sender": "agent://b", "recipient": "agent://a",
                                         "body_type": "message", "body": {}})

    async def fake_client(url: str, **kw: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(client_core, "_guarded_client", fake_client)
    from ampro.core.envelope import AgentMessage

    msg = AgentMessage(sender="agent://a", recipient="agent://b", body_type="message", body={})
    with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=3)):
        await client_core._post_message("https://b.example", msg)
    assert captured["traceparent"] == TP and captured["amp-hop-count"] == "4"
    with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=20)):
        with pytest.raises(HopLimitExceeded):
            await client_core._post_message("https://b.example", msg)


# ---------------------------------------------------------------------------
# End to end: an A2A <-> MCP cycle is cut by the hop limit, trace intact
# ---------------------------------------------------------------------------


async def test_cross_protocol_cycle_terminated_by_hop_limit():
    hops: list[tuple[str, int, str, str | None, str]] = []
    a_app = AgentApp("@agent-a", BASE)
    b_app = AgentApp("agent://b.example", "http://localhost:8000/agent/message")
    a_server = AgentServer.from_app(a_app)
    b_server = AgentServer.from_app(b_app)
    a_server.mount(A2AAdapter.for_server(a_server, max_hops=4))
    b_server.mount(MCPAdapter.for_server(b_server, max_hops=4))
    a_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=a_server.asgi()),
                               base_url=BASE)
    b_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=b_server.asgi()))

    @a_app.on("task.create")
    async def a_handler(msg, ctx):
        hops.append(("a2a", ctx.hop_count, ctx.trace_id, ctx.parent_span_id, ctx.span_id))
        source = MCPToolSource(MCP_URL, http_client=b_http)
        try:
            return await source.call_tool("bounce", {})
        finally:
            await source.close()

    @b_app.tool("bounce")
    async def bounce(ctx: AMPContext) -> dict:
        hops.append(("mcp", ctx.hop_count, ctx.trace_id, ctx.parent_span_id, ctx.span_id))
        reply = await A2AClient(BASE, http_client=a_http, extensions=[]).send_message("again")
        return {"reply": str(reply)}

    root = Propagation(trace_id=TID, span_id=PID)
    try:
        with use_propagation(root):
            await A2AClient(BASE, http_client=a_http, extensions=[]).send_message("start")
    finally:
        await a_http.aclose()
        await b_http.aclose()

    assert [(p, h) for p, h, *_ in hops] == [("a2a", 1), ("mcp", 2), ("a2a", 3), ("mcp", 4)]
    assert {t for _, _, t, _, _ in hops} == {TID}  # one trace across every boundary
    parents = [parent for *_, parent, _ in hops]
    spans = [span for *_, span in hops]
    assert parents == [PID, *spans[:-1]]  # each hop's parent is the previous hop's span
