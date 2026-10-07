"""Our A2AClient against our A2AAdapter (in-process), plus client hardening."""
from __future__ import annotations

import httpx
import pytest

from ampro.interop.a2a import (
    AMP_EXTENSION_URI,
    A2AClient,
    A2AClientError,
    A2AError,
    AgentCard,
    Message,
    Task,
    TaskState,
    discover_protocol,
)
from ampro.interop.a2a.types import BINDING_HTTP_JSON, BINDING_JSONRPC, AgentInterface

from .conftest import BASE, http_client, make_server


@pytest.fixture
def served():
    from .conftest import TokenAuth

    server, adapter = make_server(authenticators=[TokenAuth()])
    return server, adapter


@pytest.mark.parametrize("bindings", [(BINDING_HTTP_JSON,), (BINDING_JSONRPC,)])
async def test_round_trip_both_bindings(served, bindings):
    server, _ = served
    async with http_client(server) as h:
        client = A2AClient(BASE, http_client=h, bindings=bindings, auth="user:alice")
        reply = await client.send_message("hi")
        assert isinstance(reply, Message) and reply.text() == "echo: hi"
        task = await client.send_message("ask", context_id=reply.context_id)
        assert isinstance(task, Task) and task.status.state == TaskState.INPUT_REQUIRED
        assert task.context_id == reply.context_id
        done = await client.send_message("Paris", task_id=task.id, context_id=task.context_id)
        assert done.status.state == TaskState.COMPLETED
        assert (await client.get_task(task.id)).status.state == TaskState.COMPLETED
        listing = await client.list_tasks(pageSize=10)
        assert [t.id for t in listing.tasks] == [task.id]
        other = await client.send_message("ask")
        canceled = await client.cancel_task(other.id)
        assert canceled.status.state == TaskState.CANCELED
        with pytest.raises(A2AError) as err:
            await client.get_task("missing")
        assert err.value.reason == "TASK_NOT_FOUND"
        events = [e async for e in client.stream_message("stream")]
        assert events[0].task is not None
        assert events[-1].status_update.status.state == TaskState.COMPLETED


async def test_amp_extension_round_trip(served):
    server, _ = served
    async with http_client(server) as h:
        client = A2AClient(BASE, http_client=h)  # activates AMP ext from the card
        reply = await client.send_message("ctx", amp={"jurisdiction": "DE", "traceId": "c" * 32})
        assert client.activated_extensions == {AMP_EXTENSION_URI}
        data = reply.parts[0].data
        assert data["jurisdiction"] == "DE" and data["trace_id"] == "c" * 32
        ext = reply.metadata[AMP_EXTENSION_URI]
        assert ext["agentId"] == "@demo" and ext["traceId"] == "c" * 32
        # explicitly disabled
        plain = A2AClient(BASE, http_client=h, extensions=[])
        reply = await plain.send_message("ctx", amp={"jurisdiction": "DE"})
        assert reply.parts[0].data["jurisdiction"] is None
        assert plain.activated_extensions == frozenset()


async def test_interface_chosen_by_binding_not_position():
    card = AgentCard(name="x", supported_interfaces=[
        AgentInterface(url="https://x/grpc", protocol_binding="GRPC", protocol_version="1.0"),
        AgentInterface(url="https://x/old", protocol_binding="HTTP+JSON", protocol_version="0.3"),
        AgentInterface(url="https://x/rpc", protocol_binding="JSONRPC", protocol_version="1.0"),
        AgentInterface(url="https://x/rest", protocol_binding="HTTP+JSON", protocol_version="1.0"),
    ])
    assert (await A2AClient(card).interface()).url == "https://x/rest"
    only_rpc = AgentCard(name="x", supported_interfaces=[card.supported_interfaces[2]])
    assert (await A2AClient(only_rpc).interface()).url == "https://x/rpc"
    none = AgentCard(name="x", supported_interfaces=[card.supported_interfaces[1]])
    with pytest.raises(A2AClientError):
        await A2AClient(none).interface()


async def test_auth_header_and_errors():
    from .conftest import TokenAuth

    server, _ = make_server(authenticators=[TokenAuth()], require_auth=True)
    async with http_client(server) as h:
        client = A2AClient(BASE, http_client=h, auth="user:alice")
        reply = await client.send_message("ctx")
        assert reply.parts[0].data["sender"] == "user://alice"
        anon = A2AClient(BASE, http_client=h)
        with pytest.raises(A2AClientError) as err:
            await anon.send_message("hi")
        assert err.value.status == 401


def _mock(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_cross_origin_redirect_refused():
    def handler(request):
        return httpx.Response(302, headers={"location": "https://evil.example/card.json"})

    async with _mock(handler) as h:
        with pytest.raises(A2AClientError, match="cross-origin"):
            await A2AClient("https://good.example", http_client=h).fetch_card()


async def test_same_origin_redirect_followed():
    card = {"name": "r", "supportedInterfaces": []}

    def handler(request):
        if request.url.path == "/.well-known/agent-card.json":
            return httpx.Response(307, headers={"location": "/cards/r.json"})
        return httpx.Response(200, json=card)

    async with _mock(handler) as h:
        got = await A2AClient("https://good.example", http_client=h).fetch_card()
        assert got.name == "r"


async def test_response_size_cap():
    def handler(request):
        return httpx.Response(200, content=b"{" + b" " * 5000 + b"}")

    async with _mock(handler) as h:
        client = A2AClient("https://big.example", http_client=h, max_response_bytes=1000)
        with pytest.raises(A2AClientError, match="too large"):
            await client.fetch_card()


async def test_url_validator_and_ssrf_guard():
    def refuse(url):
        raise ValueError("nope")

    async with _mock(lambda r: httpx.Response(200, json={})) as h:
        with pytest.raises(ValueError):
            await A2AClient("https://x.example", http_client=h, url_validator=refuse).fetch_card()
    # Default (owned client): private / loopback targets and plain http are refused.
    for url in ("https://127.0.0.1", "https://10.0.0.1/a2a", "http://example.com"):
        client = A2AClient(url)
        with pytest.raises(A2AClientError, match="SSRF"):
            await client.fetch_card()
        await client.aclose()


async def test_timeout_is_client_error():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    async with _mock(handler) as h:
        with pytest.raises(A2AClientError, match="timed out"):
            await A2AClient("https://slow.example", http_client=h).fetch_card()


async def test_discover_protocol(served):
    server, _ = served
    async with http_client(server) as h:
        assert await discover_protocol(BASE, http_client=h) == "amp"

    def a2a_only(request):
        if request.url.path == "/.well-known/agent-card.json":
            return httpx.Response(200, json={"name": "x", "supportedInterfaces": []})
        return httpx.Response(404)

    async with _mock(a2a_only) as h:
        assert await discover_protocol("https://a2a.example/", http_client=h) == "a2a"

    async with _mock(lambda r: httpx.Response(404)) as h:
        with pytest.raises(LookupError):
            await discover_protocol("https://none.example", http_client=h)
