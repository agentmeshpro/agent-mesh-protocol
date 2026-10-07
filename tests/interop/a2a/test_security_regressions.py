"""Regression tests from the security review of the A2A adapter and client."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.a2a import A2AAdapter, A2AClient, A2AClientError
from ampro.server import AgentServer
from ampro.server.http import HTTPRequest
from ampro.server.security import SecurityPolicy
from ampro.wire.config import WireConfig

# ---------------------------------------------------------------------------
# returnImmediately must not escape the concurrency limiter
# ---------------------------------------------------------------------------


def _bg_server(max_tasks: int, **adapter_kw):
    app = AgentApp("agent://x", "https://x.example")
    running = {"now": 0, "peak": 0}
    gate = asyncio.Event()

    @app.on("task.create")
    async def handler(msg, ctx):
        running["now"] += 1
        running["peak"] = max(running["peak"], running["now"])
        try:
            await gate.wait()
        finally:
            running["now"] -= 1
        return "done"

    cfg = WireConfig(max_concurrent_tasks=max_tasks, rate_limit_rpm=1000)
    server = AgentServer.from_app(app, security=SecurityPolicy.from_config(cfg), config=cfg)
    adapter = A2AAdapter.for_server(server, **adapter_kw)
    server.mount(adapter)
    return server, adapter, running, gate


def _bg_request(i: int, client: str) -> HTTPRequest:
    body = {"message": {"role": "ROLE_USER", "messageId": f"m{i}", "parts": [{"text": "hi"}]},
            "configuration": {"returnImmediately": True}}
    return HTTPRequest("POST", "/a2a/message:send", {"content-type": "application/json"},
                       body=json.dumps(body).encode(), client=client)


async def test_background_runs_hold_the_concurrency_lease():
    server, adapter, running, gate = _bg_server(max_tasks=2)
    statuses = [(await server.handle(_bg_request(i, "1.1.1.1"))).status for i in range(20)]
    await asyncio.sleep(0.01)
    assert statuses[0] == 200
    assert set(statuses[1:]) == {503}  # per-sender limit is 1 while the first one runs
    assert running["peak"] == 1
    gate.set()
    for _ in range(100):
        await asyncio.sleep(0.005)
        if not adapter._background:
            break
    assert server.security.concurrency.total_active == 0
    # capacity is back once the background run finished
    assert (await server.handle(_bg_request(99, "1.1.1.1"))).status == 200
    gate.set()


async def test_background_tasks_are_bounded_without_a_limiter():
    server, adapter, running, gate = _bg_server(max_tasks=2, max_background_tasks=3)
    server.security.concurrency = None
    statuses = [(await server.handle(_bg_request(i, f"10.0.0.{i}"))).status for i in range(6)]
    await asyncio.sleep(0.01)
    assert statuses == [200, 200, 200, 503, 503, 503]
    assert running["peak"] == 3
    gate.set()
    await asyncio.sleep(0.02)
    assert not adapter._background


# ---------------------------------------------------------------------------
# A2A client: bounded SSE reads, stream deadline, credential origin
# ---------------------------------------------------------------------------


CARD = {
    "name": "x",
    "supportedInterfaces": [{"url": "https://agent.example/a2a", "protocolBinding": "HTTP+JSON",
                             "protocolVersion": "1.0"}],
}


class Producer:
    def __init__(self, total: int, chunk: bytes, prefix: bytes = b"") -> None:
        self.total, self.chunk, self.prefix, self.produced = total, chunk, prefix, 0

    async def __aiter__(self):
        if self.prefix:
            yield self.prefix
        while self.produced < self.total:
            self.produced += len(self.chunk)
            yield self.chunk


def _sse_client(producer: Producer) -> httpx.AsyncClient:
    def handler(request):
        if request.url.path.endswith("agent-card.json"):
            return httpx.Response(200, json=CARD)
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              content=producer)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_sse_unterminated_comment_line_is_capped():
    producer = Producer(200 * 1024 * 1024, b"A" * 65536, prefix=b":")
    async with _sse_client(producer) as h:
        client = A2AClient("https://agent.example", http_client=h, max_response_bytes=1024 * 1024)
        with pytest.raises(A2AClientError, match="too large"):
            async for _ in client.stream_message("hi"):
                pass
    assert producer.produced < 2 * 1024 * 1024


async def test_sse_stream_deadline():
    producer = Producer(50 * 1024 * 1024, b": keepalive\n")
    async with _sse_client(producer) as h:
        client = A2AClient("https://agent.example", http_client=h, stream_timeout=0.05)
        with pytest.raises(A2AClientError, match="timed out"):
            async for _ in client.stream_message("hi"):
                pass


def _recording_client(card: dict, seen: list) -> httpx.AsyncClient:
    def handler(request):
        if request.url.path.endswith("agent-card.json"):
            return httpx.Response(200, json=card)
        seen.append((str(request.url), request.headers.get("authorization")))
        return httpx.Response(200, json={"message": {
            "messageId": "r", "role": "ROLE_AGENT", "parts": [{"text": "ok"}]}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_token_not_sent_to_foreign_interface_origin():
    card = {"name": "x", "supportedInterfaces": [
        {"url": "https://evil.example/a2a", "protocolBinding": "HTTP+JSON",
         "protocolVersion": "1.0"}]}
    seen: list = []
    async with _recording_client(card, seen) as h:
        client = A2AClient("https://good.example", http_client=h, auth="secret")
        await client.send_message("hi")
        assert seen == [("https://evil.example/a2a/message:send", None)]
        assert not client.credentials_allowed("https://evil.example/a2a")

        trusted = A2AClient("https://good.example", http_client=h, auth="secret",
                            trusted_origins=["https://evil.example"])
        await trusted.send_message("hi")
        assert seen[-1][1] == "Bearer secret"


async def test_token_sent_to_same_origin_interface():
    card = {"name": "x", "supportedInterfaces": [
        {"url": "https://good.example:443/a2a", "protocolBinding": "JSONRPC",
         "protocolVersion": "1.0"}]}
    seen: list = []

    def handler(request):
        if request.url.path.endswith("agent-card.json"):
            return httpx.Response(200, json=card)
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "1", "result": {"message": {
            "messageId": "r", "role": "ROLE_AGENT", "parts": [{"text": "ok"}]}}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as h:
        client = A2AClient("https://good.example", http_client=h, auth="secret")
        await client.send_message("hi")
    assert seen == ["Bearer secret"]


async def test_auth_object_also_origin_scoped():
    class Recorder(httpx.Auth):
        calls = 0

        def auth_flow(self, request):
            Recorder.calls += 1
            request.headers["Authorization"] = "Bearer via-auth"
            yield request

    card = {"name": "x", "supportedInterfaces": [
        {"url": "https://evil.example/a2a", "protocolBinding": "HTTP+JSON",
         "protocolVersion": "1.0"}]}
    seen: list = []
    async with _recording_client(card, seen) as h:
        await A2AClient("https://good.example", http_client=h, auth=Recorder()).send_message("hi")
    assert Recorder.calls == 0 and seen[0][1] is None
