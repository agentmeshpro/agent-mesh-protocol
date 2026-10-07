"""Conformance: the official a2a-sdk (1.x) client and models against our server.

The SDK parses responses *without* ignoring unknown fields, so these tests
also prove our JSON carries only A2A 1.0 schema fields.
"""
from __future__ import annotations

import pytest

pytest.importorskip("a2a")
pytest.importorskip("google.protobuf")

from a2a.client import ClientConfig, ClientFactory  # noqa: E402
from a2a.client.card_resolver import parse_agent_card  # noqa: E402
from a2a.types import (  # noqa: E402
    CancelTaskRequest,
    GetTaskRequest,
    ListTasksRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    SendMessageResponse,
    StreamResponse,
    SubscribeToTaskRequest,
    Task,
    TaskState,
)
from a2a.utils.errors import (  # noqa: E402
    InvalidParamsError,
    PushNotificationNotSupportedError,
    TaskNotCancelableError,
    TaskNotFoundError,
    VersionNotSupportedError,
)
from google.protobuf.json_format import ParseDict  # noqa: E402

from ampro.interop.a2a import AMP_EXTENSION_URI  # noqa: E402

from .conftest import BASE, TokenAuth, http_client, make_server, user_message  # noqa: E402

BINDINGS = ["HTTP+JSON", "JSONRPC"]


def sdk_message(text: str, **kw) -> Message:
    return Message(message_id=f"m-{text}-{id(kw)}", role=Role.ROLE_USER,
                   parts=[Part(text=text)], **kw)


async def first_event(client, request) -> StreamResponse:
    events = [e async for e in client.send_message(request)]
    return events[0] if len(events) == 1 else events


@pytest.fixture
def server():
    return make_server(authenticators=[TokenAuth()])[0]


@pytest.fixture
async def httpx_client(server):
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as h:
        yield h


async def make_client(httpx_client, binding, streaming=False):
    config = ClientConfig(httpx_client=httpx_client, streaming=streaming,
                          supported_protocol_bindings=[binding])
    return await ClientFactory(config).create_from_url(BASE)


async def test_card_parses_with_sdk(httpx_client):
    data = (await httpx_client.get("/.well-known/agent-card.json")).json()
    card = parse_agent_card(dict(data))
    assert card.name == "@demo"
    assert {i.protocol_binding for i in card.supported_interfaces} == {"HTTP+JSON", "JSONRPC"}
    assert card.capabilities.streaming
    ext = card.capabilities.extensions[0]
    assert ext.uri == AMP_EXTENSION_URI and not ext.required
    assert ext.params["agent_id"] == "@demo"
    assert any(s.id == "task.create" for s in card.skills)


async def test_raw_responses_parse_strictly(httpx_client):
    for text in ("hi", "ask", "auth", "ack", "data", "complete-receipt"):
        r = await httpx_client.post("/a2a/message:send", json=user_message(text),
                                    headers={"A2A-Extensions": AMP_EXTENSION_URI})
        ParseDict(r.json(), SendMessageResponse())  # raises on unknown fields
    r = await httpx_client.post("/a2a/message:stream", json=user_message("stream"))
    import json

    for block in r.text.strip().split("\n\n"):
        data = block.split("data: ", 1)[1]
        ParseDict(json.loads(data), StreamResponse())


@pytest.mark.parametrize("binding", BINDINGS)
async def test_send_message_and_task_lifecycle(httpx_client, binding):
    client = await make_client(httpx_client, binding)
    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("hi")))]
    assert len(events) == 1 and events[0].HasField("message")
    reply = events[0].message
    assert reply.role == Role.ROLE_AGENT and reply.parts[0].text == "echo: hi"

    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("ask")))]
    task = events[0].task
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    follow = sdk_message("Lisbon", task_id=task.id, context_id=task.context_id)
    events = [e async for e in client.send_message(SendMessageRequest(message=follow))]
    done = events[0].task
    assert done.status.state == TaskState.TASK_STATE_COMPLETED
    assert done.artifacts[0].parts[0].data.struct_value["city"] == "Lisbon"

    got = await client.get_task(GetTaskRequest(id=task.id))
    assert isinstance(got, Task) and got.status.state == TaskState.TASK_STATE_COMPLETED

    listed = await client.list_tasks(ListTasksRequest(page_size=5))
    assert task.id in [t.id for t in listed.tasks]
    filtered = await client.list_tasks(ListTasksRequest(status=TaskState.TASK_STATE_COMPLETED))
    assert all(t.status.state == TaskState.TASK_STATE_COMPLETED for t in filtered.tasks)

    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("ask")))]
    other = events[0].task
    canceled = await client.cancel_task(CancelTaskRequest(id=other.id))
    assert canceled.status.state == TaskState.TASK_STATE_CANCELED
    with pytest.raises(TaskNotCancelableError):
        await client.cancel_task(CancelTaskRequest(id=other.id))


@pytest.mark.parametrize("binding", BINDINGS)
async def test_errors_map_to_sdk_exceptions(httpx_client, binding):
    client = await make_client(httpx_client, binding)
    with pytest.raises(TaskNotFoundError):
        await client.get_task(GetTaskRequest(id="missing"))
    with pytest.raises(TaskNotFoundError):
        await client.cancel_task(CancelTaskRequest(id="missing"))
    with pytest.raises(InvalidParamsError):
        await client.list_tasks(ListTasksRequest(page_size=500))
    with pytest.raises(InvalidParamsError):
        bad = sdk_message("hi", context_id="not-mine")
        _ = [e async for e in client.send_message(SendMessageRequest(message=bad))]
    from a2a.types import TaskPushNotificationConfig

    with pytest.raises(PushNotificationNotSupportedError):
        await client.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id="t", url="https://x.example/hook"))


async def test_version_error(server):
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as h:
        client = await make_client(h, "HTTP+JSON")
        h.headers["A2A-Version"] = "2.0"
        with pytest.raises(VersionNotSupportedError):
            await client.get_task(GetTaskRequest(id="x"))


@pytest.mark.parametrize("binding", BINDINGS)
async def test_streaming(httpx_client, binding):
    client = await make_client(httpx_client, binding, streaming=True)
    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("stream")))]
    assert events[0].HasField("task")
    assert events[0].task.status.state == TaskState.TASK_STATE_WORKING
    assert any(e.HasField("artifact_update") for e in events)
    last = events[-1]
    assert last.HasField("status_update")
    assert last.status_update.status.state == TaskState.TASK_STATE_COMPLETED

    # a reply without intermediate events streams as a single Message
    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("hi")))]
    assert len(events) == 1 and events[0].HasField("message")


@pytest.mark.parametrize("binding", BINDINGS)
async def test_subscribe(httpx_client, binding):
    client = await make_client(httpx_client, binding, streaming=True)
    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("ask")))]
    task = events[0].task
    sub = [e async for e in client.subscribe(SubscribeToTaskRequest(id=task.id))]
    assert sub[0].task.id == task.id


async def test_auth_required_task_parses(httpx_client):
    client = await make_client(httpx_client, "HTTP+JSON")
    events = [e async for e in client.send_message(SendMessageRequest(message=sdk_message("auth")))]
    task = events[0].task
    assert task.status.state == TaskState.TASK_STATE_AUTH_REQUIRED
    assert list(task.metadata["missingScopes"]) == ["refunds:issue"]
