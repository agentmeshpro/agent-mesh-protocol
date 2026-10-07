"""Unit tests: A2A types, AMP <-> A2A mapping, stores, errors, card."""
from __future__ import annotations

import base64
import time

import pytest
from pydantic import BaseModel, ValidationError

from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage
from ampro.interop.a2a import (
    PACT_AUTH_KEYS,
    AuthRequired,
    AuthRequiredKeys,
    InMemoryContextStore,
    InMemoryIdempotencyStore,
    InMemoryTaskStore,
    Principal,
    build_agent_card,
)
from ampro.interop.a2a.errors import A2AError
from ampro.interop.a2a.mapping import (
    DESCRIPTION_LIMIT,
    MAX_DELEGATION_LINKS,
    UNVERIFIED_DELEGATION_CHAIN_KEY,
    a2a_to_amp,
    amp_shape,
    apply_amp_metadata,
    auth_required_reply,
    result_to_reply,
    split_parts,
)
from ampro.interop.a2a.store import PENDING, BoundedTTLMap
from ampro.interop.a2a.types import (
    AgentCard,
    Message,
    Part,
    Role,
    SecurityRequirement,
    Task,
    TaskState,
    TaskStatus,
    dump,
)
from ampro.server import AgentServer
from ampro.trust.tiers import TrustTier


def msg(*parts, **kw) -> Message:
    return Message(message_id="m1", role=Role.USER, parts=list(parts), **kw)


# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------


def test_part_requires_exactly_one_content():
    with pytest.raises(ValidationError):
        Part()
    with pytest.raises(ValidationError):
        Part(text="a", data={"b": 1})
    with pytest.raises(ValidationError):
        Part(raw="***not base64***")
    assert Part.from_bytes(b"hi", media_type="text/plain").raw == base64.b64encode(b"hi").decode()
    assert Part(data=False).kind == "data"


def test_enum_parsing_is_lenient():
    m = Message.model_validate({"messageId": "x", "role": "user", "parts": [{"text": "a"}]})
    assert m.role == Role.USER
    assert Message.model_validate({"messageId": "x", "role": 2, "parts": []}).role == Role.AGENT
    for raw in ("TASK_STATE_COMPLETED", "completed", 3):
        assert TaskStatus.model_validate({"state": raw}).state == TaskState.COMPLETED
    assert TaskState.parse("cancelled") == TaskState.CANCELED
    assert TaskState.COMPLETED.is_terminal and not TaskState.INPUT_REQUIRED.is_terminal
    assert TaskState.AUTH_REQUIRED.is_interrupted


def test_unknown_fields_ignored_and_output_is_camel_case():
    m = Message.model_validate({"messageId": "x", "role": "ROLE_USER", "kind": "message",
                                "parts": [{"text": "a", "kind": "text"}], "contextId": ""})
    assert m.context_id is None
    out = dump(m)
    assert out == {"messageId": "x", "role": "ROLE_USER", "parts": [{"text": "a"}]}


def test_security_requirement_shape():
    assert dump(SecurityRequirement.of("jwt", ["a"])) == {"schemes": {"jwt": {"list": ["a"]}}}


def test_card_interface_selection():
    card = AgentCard.model_validate({"name": "x", "supportedInterfaces": [
        {"url": "u1", "protocolBinding": "HTTP+JSON", "protocolVersion": "0.3"},
        {"url": "u2", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.1"},
        {"url": "u3", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
    ]})
    assert card.interface("HTTP+JSON").url == "u3"
    assert card.interface("JSONRPC") is None


# ---------------------------------------------------------------------------
# inbound
# ---------------------------------------------------------------------------


def test_split_parts():
    text, data, atts = split_parts([
        Part(text="a"), Part(text="b"), Part(data={"k": 1}),
        Part(url="https://f/x", filename="x", media_type="image/png"),
        Part(raw=base64.b64encode(b"z").decode()),
    ])
    assert text == "a\nb" and data == {"k": 1}
    assert atts == [{"url": "https://f/x", "filename": "x", "media_type": "image/png"},
                    {"raw": "eg=="}]
    _, data, _ = split_parts([Part(data=[1]), Part(data={"a": 1})])
    assert data == {"parts": [[1], {"a": 1}]}


def test_a2a_to_amp_new_message():
    amp = a2a_to_amp(msg(Part(text="x" * (DESCRIPTION_LIMIT + 5))), agent_id="@me",
                     sender="user://a", context_id="c1", task_id="t1")
    assert amp.body_type == "task.create"
    assert amp.id == "m1" and amp.sender == "user://a" and amp.recipient == "@me"
    assert len(amp.body["description"]) == DESCRIPTION_LIMIT
    assert len(amp.body["text"]) == DESCRIPTION_LIMIT + 5
    assert amp.body["task_id"] == "t1"
    assert amp.headers == {"Session-Id": "c1"}


def test_a2a_to_amp_continuation():
    task = Task(id="t1", context_id="c1", status=TaskStatus(state=TaskState.INPUT_REQUIRED))
    amp = a2a_to_amp(msg(Part(text="Paris"), Part(data={"x": 1})), agent_id="@me",
                     sender="s", context_id="c1", task_id="t1", continuing=task)
    assert amp.body_type == "task.response"
    assert amp.body == {"task_id": "t1", "text": "Paris", "data": {"x": 1}}


# ---------------------------------------------------------------------------
# outbound
# ---------------------------------------------------------------------------


def reply_for(result, continuing=None):
    return result_to_reply(result, context_id="c1", task_id="t1",
                           user_message=msg(Part(text="q")), continuing=continuing)


class Model(BaseModel):
    a: int


def test_plain_results_become_messages():
    assert reply_for("hi").message.parts == [Part(text="hi")]
    assert reply_for({"a": 1}).message.parts == [Part(data={"a": 1})]
    assert reply_for(Model(a=2)).message.parts == [Part(data={"a": 2})]
    r = reply_for("hi")
    assert r.message.role == Role.AGENT and r.message.context_id == "c1" and not r.is_task


def test_none_result_completes_task():
    r = reply_for(None)
    assert r.task.status.state == TaskState.COMPLETED and r.task.artifacts is None


def test_amp_shape_detection():
    am = AgentMessage(sender="a", recipient="b", body_type="task.complete", body={"x": 1})
    assert amp_shape(am) == ("task.complete", {"x": 1})
    assert amp_shape({"body_type": "task.error", "reason": "r"}) == ("task.error", {"reason": "r"})
    assert amp_shape({"body_type": 3}) is None


@pytest.mark.parametrize("body_type, state", [
    ("task.complete", TaskState.COMPLETED),
    ("task.input_required", TaskState.INPUT_REQUIRED),
    ("task.error", TaskState.FAILED),
    ("task.reject", TaskState.REJECTED),
    ("task.acknowledge", TaskState.WORKING),
    ("task.progress", TaskState.WORKING),
])
def test_body_type_to_state(body_type, state):
    r = reply_for({"body_type": body_type, "body": {"task_id": "t1", "reason": "r",
                                                    "prompt": "p", "result": "ok"}})
    assert r.task.status.state == state
    assert r.task.id == "t1" and r.task.context_id == "c1"
    assert r.task.history[0].task_id == "t1"


def test_complete_artifacts_and_cost_receipt():
    r = reply_for({"body_type": "task.complete", "body": {
        "task_id": "t1", "result": {"v": 1},
        "attachments": [{"url": "https://f/x.pdf", "mime_type": "application/pdf"}],
        "cost_receipt": {"c": 1}, "cost_usd": 0.5}})
    parts = r.task.artifacts[0].parts
    assert parts[0] == Part(data={"v": 1})
    assert parts[1].url == "https://f/x.pdf" and parts[1].media_type == "application/pdf"
    assert r.amp == {"costReceipt": {"c": 1}, "costUsd": 0.5}


def test_input_required_prompt_and_options():
    r = reply_for({"body_type": "task.input_required", "body": {
        "task_id": "t1", "reason": "r", "prompt": "Which?", "options": ["a", "b"],
        "consent_url": "https://c"}})
    st = r.task.status.message
    assert st.parts == [Part(text="Which?"), Part(data={"options": ["a", "b"]})]
    assert r.task.metadata == {"amp.consentUrl": "https://c"}


def test_message_body_types():
    r = reply_for({"body_type": "task.response", "body": {"text": "t", "data": {"d": 1}}})
    assert r.message.parts == [Part(text="t"), Part(data={"d": 1})]
    r = reply_for({"body_type": "x.custom", "body": {"z": 1}})
    assert r.message.parts == [Part(data={"z": 1})]
    assert r.message.metadata == {"amp.bodyType": "x.custom"}


def test_continuation_plain_result_completes_existing_task():
    base = Task(id="t1", context_id="c1", status=TaskStatus(state=TaskState.INPUT_REQUIRED),
                history=[msg(Part(text="first"))])
    r = reply_for("answer", continuing=base)
    assert r.task.status.state == TaskState.COMPLETED
    assert r.task.artifacts[0].parts == [Part(text="answer")]
    assert len(r.task.history) == 2


def test_auth_required_reply_keys():
    exc = AuthRequired(["a:b"], "https://v", metadata={"extra": 1})
    for keys in (AuthRequiredKeys(), PACT_AUTH_KEYS):
        r = auth_required_reply(exc, context_id="c", task_id="t", user_message=msg(Part(text="q")),
                                keys=keys)
        assert r.task.status.state == TaskState.AUTH_REQUIRED
        assert r.task.metadata[keys.missing_scopes] == ["a:b"]
        assert r.task.metadata[keys.verification_uri] == "https://v"
        assert r.task.metadata["extra"] == 1


# ---------------------------------------------------------------------------
# AMP extension
# ---------------------------------------------------------------------------


def make_ctx() -> AMPContext:
    return AMPContext(agent_address="@me", sender_address="s", request_id="r",
                      trust_tier=TrustTier.EXTERNAL)


def test_apply_amp_metadata():
    ctx = make_ctx()
    apply_amp_metadata(ctx, {"jurisdiction": "EU", "data_residency": "eu-west",
                             "traceId": "abc123", "spanId": "s1", "visitedAgents": ["@a"],
                             "sender": "@claimed", "delegationChain": {"links": []}})
    assert ctx.jurisdiction == "EU" and ctx.data_residency == "eu-west"
    assert ctx.trace_id == "abc123" and ctx.metadata["amp.parentSpanId"] == "s1"
    assert ctx.visited_agents == ["@a"]
    assert ctx.sender_address == "s" and ctx.metadata["amp.claimedSender"] == "@claimed"
    # A chain from metadata is never exposed as ctx.delegation_chain here:
    # only the adapter's chain_verifier can promote it.
    assert ctx.delegation_chain is None
    assert ctx.metadata[UNVERIFIED_DELEGATION_CHAIN_KEY].depth == 0
    assert "delegationChain" not in ctx.metadata["amp.extension"]


def test_apply_amp_metadata_chain_bounded():
    link = {"delegator": "@a", "delegate": "@b", "scopes": ["x"],
            "created_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"}
    ctx = make_ctx()
    apply_amp_metadata(ctx, {"delegationChain": [link] * MAX_DELEGATION_LINKS})
    assert ctx.metadata[UNVERIFIED_DELEGATION_CHAIN_KEY].depth == MAX_DELEGATION_LINKS
    for bad in ([link] * (MAX_DELEGATION_LINKS + 1), "chain", {"links": "x"}, 5):
        with pytest.raises(A2AError):
            apply_amp_metadata(make_ctx(), {"delegationChain": bad})


@pytest.mark.parametrize("bad", [
    {"jurisdiction": 5}, {"jurisdiction": "x" * 300}, {"traceId": "a b"},
    {"visitedAgents": "x"}, {"delegationChain": [{"nope": 1}]},
])
def test_apply_amp_metadata_rejects_bad_values(bad):
    with pytest.raises(A2AError) as err:
        apply_amp_metadata(make_ctx(), bad)
    assert err.value.reason == "INVALID_PARAMS"


def test_context_has_optional_protocol_fields():
    ctx = make_ctx()
    assert ctx.principal is None and ctx.scopes == frozenset()
    assert ctx.protocol == "amp" and ctx.metadata == {}


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


def test_error_envelopes():
    e = A2AError("TASK_NOT_FOUND")
    rest = e.rest_payload()
    assert rest["error"]["code"] == 404 and rest["error"]["status"] == "NOT_FOUND"
    assert rest["error"]["details"][0] == {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "TASK_NOT_FOUND",
        "domain": "a2a-protocol.org", "metadata": {}}
    assert e.jsonrpc_error()["code"] == -32001
    back = A2AError.from_rest_payload(rest, 404)
    assert back.reason == "TASK_NOT_FOUND"
    assert A2AError.from_jsonrpc_error({"code": -32602, "message": "m"}).reason == "INVALID_PARAMS"
    assert A2AError.from_rest_payload("junk", 502).reason == "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# stores
# ---------------------------------------------------------------------------


def test_bounded_map_lru_and_ttl(monkeypatch):
    m = BoundedTTLMap(2, ttl=10)
    m.set("a", 1)
    m.set("b", 2)
    m.get("a")
    m.set("c", 3)
    assert m.get("b") is None and m.get("a") == 1
    now = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: now + 11)
    assert m.get("a") is None and m.values() == []


async def test_task_store_scoping():
    store = InMemoryTaskStore(max_tasks=10)
    t = Task(id="t", context_id="c", status=TaskStatus(state=TaskState.WORKING))
    await store.save_task(t, "alice")
    assert (await store.get_task("t", "alice")).id == "t"
    assert await store.get_task("t", "bob") is None
    with pytest.raises(PermissionError):
        await store.save_task(t, "bob")
    assert [x.id for x in await store.list_tasks("alice", state=TaskState.WORKING)] == ["t"]
    assert await store.list_tasks("alice", context_id="other") == []
    # returned copies are detached
    got = await store.get_task("t", "alice")
    got.status.state = TaskState.FAILED
    assert (await store.get_task("t", "alice")).status.state == TaskState.WORKING


async def test_context_store():
    store = InMemoryContextStore()
    assert await store.claim_context("c", "alice")
    assert await store.claim_context("c", "alice", create=False)
    assert not await store.claim_context("c", "bob")
    assert not await store.claim_context("new", "bob", create=False)
    assert not await store.is_context_closed("c")
    await store.close_context("c")
    assert await store.is_context_closed("c")


async def test_idempotency_store():
    store = InMemoryIdempotencyStore(pending_ttl_seconds=60)
    assert await store.begin_message("c", "m") is None
    assert await store.begin_message("c", "m") is PENDING
    await store.finish_message("c", "m", {"message": 1})
    assert await store.begin_message("c", "m") == {"message": 1}
    assert await store.begin_message("c", "m2") is None
    await store.finish_message("c", "m2", None)
    assert await store.begin_message("c", "m2") is None


# ---------------------------------------------------------------------------
# card
# ---------------------------------------------------------------------------


def test_build_card_from_plain_server_and_overrides():
    server = AgentServer(agent_id="@p", endpoint="https://p.example/")

    @server.on("task.create")
    async def h(msg):
        """Plan trips."""

    card = build_agent_card(server, base_path="/", skills=[{"id": "s", "name": "S"}],
                            include_amp_extension=False)
    assert card.supported_interfaces[0].url == "https://p.example"
    assert [s.id for s in card.skills] == ["s"]
    assert card.capabilities.extensions is None
    card = build_agent_card(server)
    assert card.skills[0].description == "Plan trips."


def test_principal_is_canonical():
    from ampro.server.auth import Principal as ServerPrincipal

    assert Principal is ServerPrincipal
