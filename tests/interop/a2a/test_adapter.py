"""Integration tests: AgentServer + A2AAdapter over in-process ASGI."""
from __future__ import annotations

import asyncio
import json
import logging

from ampro.interop.a2a import AMP_EXTENSION_URI, PACT_AUTH_KEYS, TEXT_MODES, bearer_scheme

from .conftest import TokenAuth, http_client, make_server, user_message

A2A_CT = "application/a2a+json"


def sse_events(text: str) -> list[tuple[str, dict]]:
    events = []
    for block in text.strip().split("\n\n"):
        name, data = "message", None
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        if data is not None:
            events.append((name, data))
    return events


def reason(resp) -> str:
    body = resp.json()
    assert body["error"]["details"][0]["domain"] == "a2a-protocol.org"
    return body["error"]["details"][0]["reason"]


# ---------------------------------------------------------------------------
# Card & routing
# ---------------------------------------------------------------------------


async def test_agent_card_root_and_base(client):
    for path in ("/.well-known/agent-card.json", "/a2a/.well-known/agent-card.json"):
        r = await client.get(path)
        assert r.status_code == 200
        card = r.json()
        assert card["name"] == "@demo"
        bindings = {(i["protocolBinding"], i["protocolVersion"], i["url"])
                    for i in card["supportedInterfaces"]}
        assert ("HTTP+JSON", "1.0", "https://agent.example/a2a") in bindings
        assert ("JSONRPC", "1.0", "https://agent.example/a2a") in bindings
        assert card["capabilities"]["streaming"] is True
        ext = card["capabilities"]["extensions"][0]
        assert ext["uri"] == AMP_EXTENSION_URI and ext["required"] is False
        assert ext["params"]["agent_id"] == "@demo"
        assert ext["params"]["amp_endpoint"] == "https://agent.example"
        skill_ids = {s["id"] for s in card["skills"]}
        assert "task.create" in skill_ids and "tool:lookup" in skill_ids
        assert "task.response" not in skill_ids


async def test_card_needs_no_auth():
    server, _ = make_server(authenticators=[TokenAuth()], require_auth=True)
    async with http_client(server) as c:
        assert (await c.get("/.well-known/agent-card.json")).status_code == 200
        assert (await c.post("/.well-known/agent-card.json")).status_code == 405


async def test_card_options_security_and_brand_base_path():
    server, _ = make_server(
        base_path="/a2a/brand-42", public_url="https://provider.example",
        serve_root_card=False, name="Brand Support", description="Help",
        security_schemes={"paJwt": bearer_scheme()},
        security_requirements=[{"schemes": {"paJwt": {"list": []}}}],
        input_modes=TEXT_MODES, streaming=False,
    )
    async with http_client(server) as c:
        assert (await c.get("/.well-known/agent-card.json")).status_code != 200
        card = (await c.get("/a2a/brand-42/.well-known/agent-card.json")).json()
        assert card["name"] == "Brand Support"
        assert card["supportedInterfaces"][0]["url"] == "https://provider.example/a2a/brand-42"
        assert card["securitySchemes"]["paJwt"]["httpAuthSecurityScheme"]["scheme"] == "Bearer"
        assert card["securityRequirements"] == [{"schemes": {"paJwt": {"list": []}}}]
        assert card["defaultInputModes"] == ["text/plain"]
        assert card["capabilities"]["streaming"] is False
        r = await c.post("/a2a/brand-42/message:send", json=user_message("hi"))
        assert r.status_code == 200


async def test_unmatched_routes_have_no_body_even_without_token():
    server, _ = make_server(authenticators=[TokenAuth()], require_auth=True)
    async with http_client(server) as c:
        r = await c.get("/a2a/nope")
        assert r.status_code == 404 and r.content == b""
        r = await c.get("/a2a/message:send")
        assert r.status_code == 405 and r.content == b""
        r = await c.delete("/a2a/tasks")
        assert r.status_code == 405 and r.content == b""


async def test_amp_routes_still_served(client):
    r = await client.get("/.well-known/agent.json")
    assert r.status_code == 200
    r = await client.post("/agent/message", json={
        "sender": "@x", "recipient": "@demo", "body_type": "task.create",
        "body": {"description": "hello", "text": "hello", "task_id": "t1"}})
    assert r.status_code == 202
    assert r.json() == {"result": "echo: hello"}


# ---------------------------------------------------------------------------
# message:send
# ---------------------------------------------------------------------------


async def test_send_returns_message(client, state):
    r = await client.post("/a2a/message:send", json=user_message("hi"))
    assert r.status_code == 200
    assert r.headers["content-type"] == A2A_CT
    msg = r.json()["message"]
    assert msg["role"] == "ROLE_AGENT"
    assert msg["parts"] == [{"text": "echo: hi"}]
    assert msg["contextId"]
    ctx = state["last_ctx"]
    assert ctx.protocol == "a2a"
    assert ctx.sender_address == "user://alice"
    assert ctx.principal.claims == {"sub": "alice"}
    assert ctx.metadata["a2a.message"].message_id
    assert state["last_msg"].body_type == "task.create"


async def test_send_accepts_a2a_json_content_type(client):
    msg = user_message("hi")
    r = await client.post("/a2a/message:send", content=json.dumps(msg),
                          headers={"Content-Type": "application/a2a+json", "A2A-Version": "1.0"})
    assert r.status_code == 200


async def test_ctx_fields_and_parts(client):
    body = user_message("ctx")
    body["message"]["parts"] += [
        {"data": {"order": "A-1"}},
        {"url": "https://files.example/x.pdf", "mediaType": "application/pdf", "filename": "x.pdf"},
    ]
    r = await client.post("/a2a/message:send", json=body)
    data = r.json()["message"]["parts"][0]["data"]
    assert data["protocol"] == "a2a"
    assert data["sender"] == "user://alice"
    assert data["tier"] == "verified"
    assert data["has_raw"] is True
    assert data["session"] == r.json()["message"]["contextId"]
    assert data["data"] == {"order": "A-1"}
    assert data["attachments"] == [{"url": "https://files.example/x.pdf", "filename": "x.pdf",
                                    "media_type": "application/pdf"}]


async def test_scopes_reach_context(server, state):
    async with http_client(server, headers={"Authorization": "Bearer user:bob:orders:read,x"}) as c:
        r = await c.post("/a2a/message:send", json=user_message("ctx"))
        assert r.json()["message"]["parts"][0]["data"]["scopes"] == ["orders:read", "x"]


async def test_dict_result_is_data_part(client):
    r = await client.post("/a2a/message:send", json=user_message("data"))
    assert r.json()["message"]["parts"] == [{"data": {"answer": 42}}]


async def test_input_required_then_continue(client):
    r = await client.post("/a2a/message:send", json=user_message("ask"))
    task = r.json()["task"]
    assert task["status"]["state"] == "TASK_STATE_INPUT_REQUIRED"
    assert task["status"]["message"]["parts"] == [{"text": "Which city?"}]
    r = await client.post("/a2a/message:send", json=user_message(
        "Paris", taskId=task["id"], contextId=task["contextId"]))
    done = r.json()["task"]
    assert done["id"] == task["id"]
    assert done["status"]["state"] == "TASK_STATE_COMPLETED"
    assert done["artifacts"][0]["parts"] == [{"data": {"city": "Paris"}}]
    assert len(done["history"]) == 2
    # completed tasks accept no more messages
    r = await client.post("/a2a/message:send", json=user_message("again", taskId=task["id"]))
    assert r.status_code == 400 and reason(r) == "UNSUPPORTED_OPERATION"
    r = await client.get(f"/a2a/tasks/{task['id']}")
    assert r.json()["status"]["state"] == "TASK_STATE_COMPLETED"
    r = await client.get(f"/a2a/tasks/{task['id']}", params={"historyLength": 1})
    assert len(r.json()["history"]) == 1


async def test_task_state_mapping(client):
    expect = {"ack": "TASK_STATE_WORKING", "reject": "TASK_STATE_REJECTED",
              "error": "TASK_STATE_FAILED"}
    for text, state_name in expect.items():
        r = await client.post("/a2a/message:send", json=user_message(text))
        task = r.json()["task"]
        assert task["status"]["state"] == state_name, text
    r = await client.post("/a2a/message:send", json=user_message("error"))
    assert r.json()["task"]["status"]["message"]["parts"] == [{"text": "it broke"}]


async def test_unknown_task_id_is_task_not_found(client):
    r = await client.post("/a2a/message:send", json=user_message("x", taskId="nope"))
    assert r.status_code == 404 and reason(r) == "TASK_NOT_FOUND"


async def test_validation_errors(client):
    bad = [
        ({"message": {"messageId": "1", "role": "ROLE_AGENT", "parts": [{"text": "x"}]}},
         "INVALID_PARAMS"),
        ({"message": {"messageId": "1", "role": "ROLE_USER", "parts": [{"text": "  "}]}},
         "INVALID_PARAMS"),
        ({"message": {"messageId": "1", "role": "ROLE_USER", "parts": []}}, "INVALID_PARAMS"),
        ({"message": {"role": "ROLE_USER", "parts": [{"text": "x"}]}}, "INVALID_PARAMS"),
        ({"message": {"messageId": "1", "role": "ROLE_USER",
                      "parts": [{"text": "x", "data": {}}]}}, "INVALID_PARAMS"),
        ({"nope": 1}, "INVALID_PARAMS"),
        ({"message": {"messageId": "1", "role": "ROLE_USER", "parts": [{"text": "x" * 70_000}]}},
         "INVALID_PARAMS"),
        ({"message": {"messageId": "1", "role": "ROLE_USER", "parts": [{"text": "x"}],
                      "metadata": {"big": "y" * 20_000}}}, "INVALID_PARAMS"),
    ]
    for body, expected in bad:
        r = await client.post("/a2a/message:send", json=body)
        assert r.status_code == 400, body
        assert reason(r) == expected
    r = await client.post("/a2a/message:send", content=b"{not json")
    assert r.status_code == 400 and reason(r) == "INVALID_REQUEST"


async def test_text_only_input_modes():
    server, _ = make_server(input_modes=TEXT_MODES)
    async with http_client(server) as c:
        body = user_message("x")
        body["message"]["parts"].append({"data": {"a": 1}})
        r = await c.post("/a2a/message:send", json=body)
        assert r.status_code == 400 and reason(r) == "CONTENT_TYPE_NOT_SUPPORTED"
        body = user_message("x")
        body["message"]["parts"].append({"url": "https://x/y", "mediaType": "image/png"})
        r = await c.post("/a2a/message:send", json=body)
        assert reason(r) == "CONTENT_TYPE_NOT_SUPPORTED"


async def test_version_header(client):
    r = await client.post("/a2a/message:send", json=user_message(), headers={"A2A-Version": "0.3"})
    assert r.status_code == 400 and reason(r) == "VERSION_NOT_SUPPORTED"
    r = await client.post("/a2a/message:send", json=user_message(), headers={"A2A-Version": "1.0"})
    assert r.status_code == 200


async def test_handler_exception_is_not_leaked(client, caplog):
    with caplog.at_level(logging.ERROR, logger="ampro.interop.a2a.adapter"):
        r = await client.post("/a2a/message:send", json=user_message("fail"),
                              headers={"X-Request-Id": "req-123"})
    assert r.status_code == 500 and reason(r) == "INTERNAL_ERROR"
    assert "secret" not in r.text
    assert any("req-123" in rec.getMessage() for rec in caplog.records)


async def test_no_handler_is_unsupported():
    from ampro.ampi.app import AgentApp
    from ampro.interop.a2a import A2AAdapter
    from ampro.server import AgentServer

    app = AgentApp("@empty", "https://e.example")
    server = AgentServer.from_app(app)
    server.mount(A2AAdapter.for_server(server))
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("x"))
        assert reason(r) == "UNSUPPORTED_OPERATION"


async def test_message_handler_fallback_and_plain_server():
    from ampro.interop.a2a import A2AAdapter
    from ampro.server import AgentServer

    server = AgentServer(agent_id="@plain", endpoint="https://p.example")

    @server.on("message")
    async def on_message(msg):
        return {"body_type": "message", "body": {"text": msg.body["text"].upper()}}

    server.mount(A2AAdapter.for_server(server))
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("hey"))
        assert r.json()["message"]["parts"] == [{"text": "HEY"}]


async def test_handler_timeout_fails_task():
    server, _ = make_server(handler_timeout=0.01)
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("forever"))
        task = r.json()["task"]
        assert task["status"]["state"] == "TASK_STATE_FAILED"
        assert task["status"]["message"]["parts"] == [{"text": "The agent did not respond in time."}]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


async def test_require_auth_401_no_body():
    server, _ = make_server(authenticators=[TokenAuth()], require_auth=True)
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message())
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == 'Bearer realm="a2a"'
        assert r.content == b""
        # auth happens before the body is parsed
        r = await c.post("/a2a/message:send", content=b"garbage")
        assert r.status_code == 401
        r = await c.post("/a2a", content=b"garbage")
        assert r.status_code == 401


async def test_bad_credential_401_with_error():
    server, _ = make_server(authenticators=[TokenAuth()])
    async with http_client(server, headers={"Authorization": "Bearer bad"}) as c:
        r = await c.post("/a2a/message:send", json=user_message())
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == 'Bearer realm="a2a", error="invalid_token"'
        assert r.content == b""


async def test_anonymous_allowed_by_default(state):
    server, _ = make_server(state, authenticators=[TokenAuth()])
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("ctx"))
        data = r.json()["message"]["parts"][0]["data"]
        assert data["sender"] == "a2a://anonymous" and data["tier"] == "external"
        assert state["last_ctx"].principal is None
        r = await c.get("/a2a/tasks")
        assert r.json()["tasks"] == []


async def test_auth_required_task(client):
    r = await client.post("/a2a/message:send", json=user_message("auth"))
    task = r.json()["task"]
    assert task["status"]["state"] == "TASK_STATE_AUTH_REQUIRED"
    assert task["status"]["message"]["parts"] == [{"text": "I need permission to issue refunds."}]
    assert task["metadata"] == {"missingScopes": ["refunds:issue"],
                                "verificationUriComplete": "https://brand.example/login?x=1"}


async def test_auth_required_pact_keys_and_error_hook():
    server, _ = make_server(auth_required_keys=PACT_AUTH_KEYS)
    seen = []

    @server.app.on_error
    async def on_error(exc, msg, ctx):
        seen.append(exc)
        return "handled"

    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("auth"))
        meta = r.json()["task"]["metadata"]
        assert meta["pact.missingScopes"] == ["refunds:issue"]
        assert "pact.verificationUriComplete" in meta
        assert seen == []  # AuthRequired bypasses @on_error
        r = await c.post("/a2a/message:send", json=user_message("fail"))
        assert r.json()["message"]["parts"] == [{"text": "handled"}]


# ---------------------------------------------------------------------------
# Contexts & idempotency
# ---------------------------------------------------------------------------


async def test_context_ownership(server):
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as alice, \
            http_client(server, headers={"Authorization": "Bearer user:mallory"}) as mallory:
        r = await alice.post("/a2a/message:send", json=user_message("hi"))
        ctx_id = r.json()["message"]["contextId"]
        r = await alice.post("/a2a/message:send", json=user_message("again", contextId=ctx_id))
        assert r.json()["message"]["contextId"] == ctx_id
        r = await mallory.post("/a2a/message:send", json=user_message("hi", contextId=ctx_id))
        assert r.status_code == 400 and reason(r) == "INVALID_PARAMS"
        unknown = await mallory.post("/a2a/message:send", json=user_message("hi", contextId="nope"))
        assert unknown.json() == r.json()  # same answer: existence not revealed


async def test_unknown_context_allowed_when_configured():
    server, _ = make_server(accept_unknown_contexts=True)
    async with http_client(server) as c:
        r = await c.post("/a2a/message:send", json=user_message("hi", contextId="client-ctx"))
        assert r.json()["message"]["contextId"] == "client-ctx"


async def test_closed_context(client, server):
    r = await client.post("/a2a/message:send", json=user_message("close"))
    ctx_id = r.json()["message"]["contextId"]
    r = await client.post("/a2a/message:send", json=user_message("hi", contextId=ctx_id))
    assert r.status_code == 400 and reason(r) == "UNSUPPORTED_OPERATION"
    # adapter API
    r = await client.post("/a2a/message:send", json=user_message("hi"))
    ctx2 = r.json()["message"]["contextId"]
    await server.adapters[0].close_context(ctx2)
    r = await client.post("/a2a/message:send", json=user_message("hi", contextId=ctx2))
    assert reason(r) == "UNSUPPORTED_OPERATION"


async def test_idempotent_retry(client, state):
    r = await client.post("/a2a/message:send", json=user_message("hi"))
    first = r.json()
    ctx_id = first["message"]["contextId"]
    body = user_message("count", contextId=ctx_id)
    r1 = await client.post("/a2a/message:send", json=body)
    calls = state["calls"]
    r2 = await client.post("/a2a/message:send", json=body)
    assert r1.json() == r2.json()
    assert state["calls"] == calls


async def test_retry_while_in_flight_is_invalid_params(server):
    adapter = server.adapters[0]
    await adapter.replies.begin_message("c1", "m1")
    await adapter.contexts.claim_context("c1", "user://alice")
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as c:
        r = await c.post("/a2a/message:send",
                         json={"message": {"messageId": "m1", "contextId": "c1",
                                           "role": "ROLE_USER", "parts": [{"text": "x"}]}})
        assert reason(r) == "INVALID_PARAMS"


# ---------------------------------------------------------------------------
# Tasks: get / list / cancel
# ---------------------------------------------------------------------------


async def test_tasks_scoped_to_principal(server):
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as alice, \
            http_client(server, headers={"Authorization": "Bearer user:bob"}) as bob:
        task = (await alice.post("/a2a/message:send", json=user_message("ask"))).json()["task"]
        assert (await alice.get(f"/a2a/tasks/{task['id']}")).status_code == 200
        r = await bob.get(f"/a2a/tasks/{task['id']}")
        assert r.status_code == 404 and reason(r) == "TASK_NOT_FOUND"
        r = await bob.post(f"/a2a/tasks/{task['id']}:cancel")
        assert reason(r) == "TASK_NOT_FOUND"
        r = await bob.post("/a2a/message:send", json=user_message("x", taskId=task["id"]))
        assert reason(r) == "TASK_NOT_FOUND"
        assert (await bob.get("/a2a/tasks")).json()["tasks"] == []
        listing = (await alice.get("/a2a/tasks")).json()
        assert [t["id"] for t in listing["tasks"]] == [task["id"]]
        assert listing["pageSize"] == 50 and listing["totalSize"] == 1


async def test_list_tasks_pagination_and_filters(client):
    ids = []
    for _ in range(3):
        ids.append((await client.post("/a2a/message:send", json=user_message("ask"))).json()["task"]["id"])
    done = (await client.post("/a2a/message:send", json=user_message("reject"))).json()["task"]
    r = await client.get("/a2a/tasks", params={"pageSize": 2})
    page = r.json()
    assert len(page["tasks"]) == 2 and page["nextPageToken"] and page["totalSize"] == 4
    r2 = await client.get("/a2a/tasks", params={"pageSize": 2, "pageToken": page["nextPageToken"]})
    assert len(r2.json()["tasks"]) == 2 and r2.json()["nextPageToken"] == ""
    r = await client.get("/a2a/tasks", params={"status": "TASK_STATE_REJECTED"})
    assert [t["id"] for t in r.json()["tasks"]] == [done["id"]]
    r = await client.get("/a2a/tasks", params={"contextId": done["contextId"]})
    assert [t["id"] for t in r.json()["tasks"]] == [done["id"]]
    for bad in ({"pageSize": 0}, {"pageSize": 101}, {"pageSize": "x"}, {"pageToken": "zz"}):
        r = await client.get("/a2a/tasks", params=bad)
        assert r.status_code == 400 and reason(r) == "INVALID_PARAMS", bad


async def test_list_tasks_artifacts_only_when_requested(client):
    task = (await client.post("/a2a/message:send", json=user_message("complete-receipt"))).json()["task"]
    assert task["artifacts"]
    r = await client.get("/a2a/tasks")
    assert "artifacts" not in r.json()["tasks"][0]
    r = await client.get("/a2a/tasks", params={"includeArtifacts": "true"})
    assert r.json()["tasks"][0]["artifacts"]


async def test_cancel(client):
    task = (await client.post("/a2a/message:send", json=user_message("ask"))).json()["task"]
    r = await client.post(f"/a2a/tasks/{task['id']}:cancel")
    assert r.status_code == 200 and r.json()["status"]["state"] == "TASK_STATE_CANCELED"
    r = await client.post(f"/a2a/tasks/{task['id']}:cancel")
    assert r.status_code == 400 and reason(r) == "TASK_NOT_CANCELABLE"
    r = await client.post("/a2a/tasks/unknown:cancel")
    assert reason(r) == "TASK_NOT_FOUND"


async def test_return_immediately_and_cancel_running(client, server):
    body = user_message("forever")
    body["configuration"] = {"returnImmediately": True}
    task = (await client.post("/a2a/message:send", json=body)).json()["task"]
    assert task["status"]["state"] == "TASK_STATE_WORKING"
    r = await client.post(f"/a2a/tasks/{task['id']}:cancel")
    assert r.json()["status"]["state"] == "TASK_STATE_CANCELED"
    await asyncio.sleep(0.01)
    r = await client.get(f"/a2a/tasks/{task['id']}")
    assert r.json()["status"]["state"] == "TASK_STATE_CANCELED"
    assert server.adapters[0]._live == {}


async def test_return_immediately_completes_in_background(client):
    body = user_message("slow")
    body["configuration"] = {"returnImmediately": True}
    task = (await client.post("/a2a/message:send", json=body)).json()["task"]
    for _ in range(50):
        await asyncio.sleep(0.01)
        current = (await client.get(f"/a2a/tasks/{task['id']}")).json()
        if current["status"]["state"] == "TASK_STATE_COMPLETED":
            break
    assert current["status"]["state"] == "TASK_STATE_COMPLETED"
    assert current["status"]["message"]["parts"] == [{"text": "slow done"}]


async def test_push_and_extended_card_routes(client):
    for method, path in (("POST", "/a2a/tasks/t1/pushNotificationConfigs"),
                         ("GET", "/a2a/tasks/t1/pushNotificationConfigs"),
                         ("GET", "/a2a/tasks/t1/pushNotificationConfigs/c1"),
                         ("DELETE", "/a2a/tasks/t1/pushNotificationConfigs/c1")):
        r = await client.request(method, path)
        assert r.status_code == 400 and reason(r) == "PUSH_NOTIFICATION_NOT_SUPPORTED"
    r = await client.get("/a2a/extendedAgentCard")
    assert reason(r) == "EXTENDED_AGENT_CARD_NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


async def test_stream_events(client):
    r = await client.post("/a2a/message:stream", json=user_message("stream"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    events = sse_events(r.text)
    kinds = [next(iter(e)) for _, e in events]
    assert kinds[0] == "task"
    assert events[0][1]["task"]["status"]["state"] == "TASK_STATE_WORKING"
    assert kinds[-1] == "statusUpdate"
    final = events[-1][1]["statusUpdate"]
    assert final["status"]["state"] == "TASK_STATE_COMPLETED"
    deltas = [e["artifactUpdate"] for _, e in events
              if "artifactUpdate" in e and e["artifactUpdate"]["artifact"]["name"] == "response"]
    assert [d["artifact"]["parts"][0]["text"] for d in deltas] == ["Hel", "lo"]
    assert deltas[0]["append"] is False and deltas[1]["append"] is True
    working = [e["statusUpdate"] for _, e in events if "statusUpdate" in e][:-1]
    assert working[0]["metadata"]["amp.event"] == "thinking"
    assert working[1]["status"]["message"]["parts"][0]["data"] == {"topic": "progress",
                                                                    "data": {"pct": 50}}
    task_id = events[0][1]["task"]["id"]
    stored = (await client.get(f"/a2a/tasks/{task_id}")).json()
    assert stored["status"]["state"] == "TASK_STATE_COMPLETED"
    texts = [p.get("text") for a in stored["artifacts"] for p in a["parts"]]
    assert "Hello" in texts and "done" in texts


async def test_stream_without_emits_is_single_message(client):
    r = await client.post("/a2a/message:stream", json=user_message("hi"))
    events = sse_events(r.text)
    assert len(events) == 1 and events[0][1]["message"]["parts"] == [{"text": "echo: hi"}]


async def test_stream_plain_result_completes_task(client):
    r = await client.post("/a2a/message:stream", json=user_message("stream-plain"))
    events = sse_events(r.text)
    assert events[-1][1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"
    arts = [e["artifactUpdate"] for _, e in events if "artifactUpdate" in e]
    assert arts[-1]["artifact"]["parts"] == [{"text": "plain result"}]
    assert arts[-1]["lastChunk"] is True


async def test_stream_errors_before_first_event_are_http_errors(client):
    r = await client.post("/a2a/message:stream", json={"message": {"role": "ROLE_USER"}})
    assert r.status_code == 400 and reason(r) == "INVALID_PARAMS"
    r = await client.post("/a2a/message:stream", json=user_message("fail"))
    assert r.status_code == 500 and "secret" not in r.text


async def test_subscribe(client):
    task = (await client.post("/a2a/message:send", json=user_message("ask"))).json()["task"]
    r = await client.get(f"/a2a/tasks/{task['id']}:subscribe")
    events = sse_events(r.text)
    assert events[0][1]["task"]["id"] == task["id"]
    done = (await client.post("/a2a/message:send", json=user_message("reject"))).json()["task"]
    r = await client.post(f"/a2a/tasks/{done['id']}:subscribe")
    assert r.status_code == 400 and reason(r) == "UNSUPPORTED_OPERATION"


async def test_subscribe_receives_live_updates(client, server):
    body = user_message("slow")
    body["configuration"] = {"returnImmediately": True}
    task = (await client.post("/a2a/message:send", json=body)).json()["task"]
    r = await client.post(f"/a2a/tasks/{task['id']}:subscribe")
    events = sse_events(r.text)
    assert events[0][1]["task"]["id"] == task["id"]
    assert events[-1][1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"


async def test_streaming_disabled():
    server, _ = make_server(streaming=False)
    async with http_client(server) as c:
        r = await c.post("/a2a/message:stream", json=user_message("hi"))
        assert reason(r) == "UNSUPPORTED_OPERATION"


# ---------------------------------------------------------------------------
# JSON-RPC
# ---------------------------------------------------------------------------


async def rpc(c, method, params=None, rid=1, **kw):
    payload = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        payload["params"] = params
    return await c.post("/a2a", json=payload, **kw)


async def test_jsonrpc_send_get_list_cancel(client):
    r = await rpc(client, "SendMessage", user_message("ask"))
    assert r.status_code == 200
    body = r.json()
    assert body["jsonrpc"] == "2.0" and body["id"] == 1
    task = body["result"]["task"]
    r = await rpc(client, "GetTask", {"id": task["id"]})
    assert r.json()["result"]["id"] == task["id"]
    r = await rpc(client, "ListTasks", {"pageSize": 10})
    assert r.json()["result"]["tasks"][0]["id"] == task["id"]
    r = await rpc(client, "CancelTask", {"id": task["id"]})
    assert r.json()["result"]["status"]["state"] == "TASK_STATE_CANCELED"


async def test_jsonrpc_errors(client):
    r = await client.post("/a2a", content=b"{bad")
    assert r.status_code == 200 and r.json()["error"]["code"] == -32700
    r = await client.post("/a2a", json=[{"jsonrpc": "2.0"}])
    assert r.json()["error"]["code"] == -32600
    r = await client.post("/a2a", json={"jsonrpc": "1.0", "id": 3, "method": "GetTask"})
    assert r.json()["error"]["code"] == -32600 and r.json()["id"] == 3
    r = await rpc(client, "Nope")
    assert r.json()["error"]["code"] == -32601
    r = await rpc(client, "GetTask", {"id": "missing"})
    err = r.json()["error"]
    assert err["code"] == -32001 and err["data"][0]["reason"] == "TASK_NOT_FOUND"
    r = await rpc(client, "GetTask", {})
    assert r.json()["error"]["code"] == -32602
    r = await rpc(client, "CreateTaskPushNotificationConfig", {"taskId": "t"})
    assert r.json()["error"]["code"] == -32003
    r = await rpc(client, "GetExtendedAgentCard")
    assert r.json()["error"]["code"] == -32007
    r = await rpc(client, "SendMessage", user_message("fail"))
    assert r.json()["error"]["code"] == -32603 and "secret" not in r.text
    r = await rpc(client, "SendMessage", user_message("x"), headers={"A2A-Version": "2.0"})
    assert r.json()["error"]["code"] == -32009


async def test_jsonrpc_stream(client):
    r = await rpc(client, "SendStreamingMessage", user_message("stream"), rid="s1")
    events = sse_events(r.text)
    assert all(e["id"] == "s1" and "result" in e for _, e in events)
    assert events[-1][1]["result"]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"


# ---------------------------------------------------------------------------
# AMP extension (raw HTTP)
# ---------------------------------------------------------------------------


async def test_amp_extension_metadata_round_trip(client):
    amp = {"jurisdiction": "EU", "traceId": "a" * 32, "spanId": "b" * 16,
           "sender": "@spoofed",
           "delegationChain": [{"delegator": "@root", "delegate": "@demo", "scopes": ["x"],
                                "created_at": "2026-01-01T00:00:00Z",
                                "expires_at": "2027-01-01T00:00:00Z"}]}
    body = user_message("ctx", metadata={AMP_EXTENSION_URI: amp})
    r = await client.post("/a2a/message:send", json=body,
                          headers={"A2A-Extensions": f"{AMP_EXTENSION_URI}, urn:other"})
    assert r.headers["a2a-extensions"] == AMP_EXTENSION_URI
    msg = r.json()["message"]
    data = msg["parts"][0]["data"]
    assert data["jurisdiction"] == "EU" and data["trace_id"] == "a" * 32 and data["depth"] == 1
    assert data["sender"] == "user://alice"  # identity never taken from metadata
    ext = msg["metadata"][AMP_EXTENSION_URI]
    assert ext["agentId"] == "@demo" and ext["traceId"] == "a" * 32 and ext["jurisdiction"] == "EU"


async def test_amp_extension_ignored_unless_activated(client):
    body = user_message("ctx", metadata={AMP_EXTENSION_URI: {"jurisdiction": "EU"}})
    r = await client.post("/a2a/message:send", json=body)
    assert "a2a-extensions" not in r.headers
    msg = r.json()["message"]
    assert msg["parts"][0]["data"]["jurisdiction"] is None
    assert "metadata" not in msg


async def test_amp_extension_invalid_values(client):
    body = user_message("ctx", metadata={"amp": {"traceId": "bad id with spaces"}})
    r = await client.post("/a2a/message:send", json=body,
                          headers={"A2A-Extensions": AMP_EXTENSION_URI})
    assert reason(r) == "INVALID_PARAMS"


async def test_amp_extension_cost_receipt(client):
    r = await client.post("/a2a/message:send", json=user_message("complete-receipt"),
                          headers={"A2A-Extensions": AMP_EXTENSION_URI})
    ext = r.json()["task"]["metadata"][AMP_EXTENSION_URI]
    assert ext["costReceipt"] == {"agent_id": "@demo", "cost_usd": 0.01}


# ---------------------------------------------------------------------------
# Server security policy applies to A2A
# ---------------------------------------------------------------------------


async def test_rate_limit_applies():
    from ampro.security.rate_limiter import RateLimiter

    server, _ = make_server(authenticators=[TokenAuth()])
    server.security.rate_limiter = RateLimiter(rpm=2)
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as c:
        assert (await c.get("/a2a/tasks")).status_code == 200
        assert (await c.get("/a2a/tasks")).status_code == 200
        r = await c.get("/a2a/tasks")
        assert r.status_code == 429 and r.content == b"" and int(r.headers["retry-after"]) >= 1
        # the card is not rate limited
        assert (await c.get("/.well-known/agent-card.json")).status_code == 200
    async with http_client(server, headers={"Authorization": "Bearer user:bob"}) as c:
        assert (await c.get("/a2a/tasks")).status_code == 200


async def test_concurrency_limit_released_after_requests():
    from ampro.security.concurrency_limiter import ConcurrencyLimiter

    server, _ = make_server()
    server.security.concurrency = ConcurrencyLimiter(max_total=1)
    async with http_client(server) as c:
        for _ in range(3):
            assert (await c.post("/a2a/message:send", json=user_message("hi"))).status_code == 200
            r = await c.post("/a2a/message:stream", json=user_message("stream"))
            assert r.status_code == 200
        assert server.security.concurrency.total_active == 0
        server.security.concurrency.acquire("someone-else")
        r = await c.post("/a2a/message:send", json=user_message("hi"))
        assert r.status_code == 503 and r.content == b""


async def test_defaults_come_from_server_security():
    from ampro.interop.a2a import A2AAdapter
    from ampro.server import AgentServer

    from .conftest import build_app

    server = AgentServer.from_app(build_app({}))
    server.security.authenticators = [TokenAuth()]
    server.security.require_auth = True
    server.security.handler_timeout_seconds = 7.0
    adapter = A2AAdapter.for_server(server)
    assert adapter.require_auth is True and adapter.handler_timeout == 7.0
    assert len(adapter.authenticators) == 1
