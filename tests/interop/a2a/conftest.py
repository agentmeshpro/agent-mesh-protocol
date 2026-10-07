"""Shared fixtures: an AMP app served over A2A through in-process ASGI."""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.a2a import (
    A2AAdapter,
    AuthRequired,
    InvalidToken,
    Principal,
)
from ampro.server import AgentServer
from ampro.server.http import HTTPRequest
from ampro.streaming.events import StreamingEvent
from ampro.trust.tiers import TrustTier

BASE = "https://agent.example"


def build_app(state: dict[str, Any]) -> AgentApp:
    app = AgentApp("@demo", BASE)

    @app.on("task.create")
    async def create(msg, ctx):
        """Demo agent that does many things."""
        text = msg.body["text"]
        tid = msg.body["task_id"]
        state["calls"] = state.get("calls", 0) + 1
        state["last_ctx"] = ctx
        state["last_msg"] = msg
        if text == "ask":
            return {"body_type": "task.input_required",
                    "body": {"task_id": tid, "reason": "need city", "prompt": "Which city?"}}
        if text == "auth":
            raise AuthRequired(["refunds:issue"], "https://brand.example/login?x=1",
                               message="I need permission to issue refunds.")
        if text == "fail":
            raise RuntimeError("secret internal detail")
        if text == "stream":
            await ctx.emit(StreamingEvent(type="thinking", data={"note": "hmm"}))
            await ctx.emit(StreamingEvent(type="text_delta", data={"text": "Hel"}))
            await ctx.emit(StreamingEvent(type="text_delta", data={"text": "lo"}))
            await ctx.emit_event("progress", {"pct": 50})
            return {"body_type": "task.complete", "body": {"task_id": tid, "result": "done"}}
        if text == "stream-plain":
            await ctx.emit(StreamingEvent(type="text_delta", data={"text": "x"}))
            return "plain result"
        if text == "slow":
            await asyncio.sleep(0.05)
            return "slow done"
        if text == "forever":
            await asyncio.sleep(30)
            return "never"
        if text == "ack":
            return {"body_type": "task.acknowledge", "body": {"task_id": tid, "message": "on it"}}
        if text == "reject":
            return {"body_type": "task.reject", "body": {"task_id": tid, "reason": "not allowed"}}
        if text == "error":
            return {"body_type": "task.error", "body": {"task_id": tid, "reason": "boom",
                                                        "detail": "it broke"}}
        if text == "data":
            return {"answer": 42}
        if text == "close":
            await ctx.close_session()
            return "bye"
        if text == "ctx":
            return {
                "protocol": ctx.protocol,
                "sender": ctx.sender_address,
                "tier": ctx.trust_tier.value,
                "scopes": sorted(ctx.scopes),
                "has_raw": ctx.metadata.get("a2a.message") is not None,
                "jurisdiction": ctx.jurisdiction,
                "trace_id": ctx.trace_id,
                "depth": ctx.delegation_chain.depth if ctx.delegation_chain else 0,
                "session": msg.headers.get("Session-Id"),
                "data": msg.body.get("data"),
                "attachments": msg.body.get("attachments"),
            }
        if text == "complete-receipt":
            return {"body_type": "task.complete",
                    "body": {"task_id": tid, "result": "ok",
                             "cost_receipt": {"agent_id": "@demo", "cost_usd": 0.01}}}
        return f"echo: {text}"

    @app.on("task.response")
    async def respond(msg, ctx):
        return {"body_type": "task.complete",
                "body": {"task_id": msg.body["task_id"], "result": {"city": msg.body["text"]}}}

    @app.tool("lookup")
    async def lookup(**kw):
        """Look something up."""
        return kw

    return app


class TokenAuth:
    """Fake bearer authenticator: ``Bearer user:<name>[:scope,scope]``; ``Bearer bad`` -> 401."""

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        header = request.header("authorization")
        if not header:
            return None
        if not header.startswith("Bearer user:"):
            raise InvalidToken("bad token")
        _, name, *rest = header[len("Bearer "):].split(":", 2)
        scopes = frozenset(rest[0].split(",")) if rest and rest[0] else frozenset()
        return Principal(id=f"user://{name}", trust_tier=TrustTier.VERIFIED, scopes=scopes,
                         claims={"sub": name}, auth_method="jwt")


def make_server(state: dict[str, Any] | None = None, **adapter_kw: Any) -> tuple[AgentServer, A2AAdapter]:
    state = state if state is not None else {}
    app = build_app(state)
    server = AgentServer.from_app(app)
    adapter = A2AAdapter.for_server(server, **adapter_kw)
    server.mount(adapter)
    return server, adapter


def http_client(server: AgentServer, **kw: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()), base_url=BASE, **kw)


def user_message(text: str = "hi", **extra: Any) -> dict[str, Any]:
    msg = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}
    msg.update(extra)
    return {"message": msg}


@pytest.fixture
def state() -> dict[str, Any]:
    return {}


@pytest.fixture
def server(state):
    return make_server(state, authenticators=[TokenAuth()])[0]


@pytest.fixture
async def client(server):
    async with http_client(server, headers={"Authorization": "Bearer user:alice"}) as c:
        yield c
