"""Delegation chains arriving over A2A are verified at the edge (fail closed)."""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.delegation.chain import DelegationChain
from ampro.interop.a2a import AMP_EXTENSION_URI, A2AAdapter
from ampro.interop.a2a.adapter import CHAIN_REJECTED_MESSAGE
from ampro.interop.a2a.mapping import UNVERIFIED_DELEGATION_CHAIN_KEY
from ampro.server import AgentServer

BASE = "https://agent.example"
LINK = {"delegator": "@root", "delegate": "@demo", "scopes": ["x"],
        "created_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"}
EXT = {"A2A-Extensions": AMP_EXTENSION_URI}


def build(seen: list[AMPContext], **kw: Any) -> AgentServer:
    app = AgentApp("@demo", BASE)

    @app.on("task.create")
    async def create(msg, ctx):
        seen.append(ctx)
        return "ok"

    server = AgentServer.from_app(app)
    server.mount(A2AAdapter.for_server(server, **kw))
    return server


def body(chain: Any = None, *, ext: dict[str, Any] | None = None) -> dict[str, Any]:
    amp = dict(ext or {})
    if chain is not None:
        amp["delegationChain"] = chain
    return {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                        "parts": [{"text": "hi"}], "metadata": {AMP_EXTENSION_URI: amp}}}


async def send(server: AgentServer, payload: dict[str, Any], jsonrpc: bool = False):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()),
                                 base_url=BASE) as c:
        if jsonrpc:
            rpc = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": payload}
            return await c.post("/a2a", json=rpc, headers={"A2A-Version": "1.0", **EXT})
        return await c.post("/a2a/message:send", json=payload, headers=EXT)


def assert_rejected(r: httpx.Response) -> None:
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["details"][0]["reason"] == "INVALID_PARAMS"
    assert err["message"] == CHAIN_REJECTED_MESSAGE


async def test_valid_chain_accepted_by_verifier():
    seen: list[AMPContext] = []
    calls: list[tuple[DelegationChain, AMPContext]] = []

    async def verifier(chain: DelegationChain, ctx: AMPContext) -> tuple[bool, str]:
        calls.append((chain, ctx))
        return chain.links[-1].delegate == ctx.agent_address, "ok"

    server = build(seen, chain_verifier=verifier)
    r = await send(server, body([LINK]))
    assert r.status_code == 200, r.text
    ctx = seen[-1]
    assert ctx.delegation_chain is not None and ctx.delegation_chain.depth == 1
    assert ctx.delegation_chain.links[0].delegator == "@root"
    assert UNVERIFIED_DELEGATION_CHAIN_KEY not in ctx.metadata
    assert calls and calls[0][0] is ctx.delegation_chain


async def test_invalid_chain_rejected_without_leaking_reason(caplog):
    seen: list[AMPContext] = []

    async def verifier(chain, ctx):
        return False, "signature invalid for secret-key-id-42"

    server = build(seen, chain_verifier=verifier)
    with caplog.at_level(logging.WARNING, logger="ampro.interop.a2a.adapter"):
        r = await send(server, body([LINK]))
    assert_rejected(r)
    assert "secret-key-id-42" not in r.text
    assert "secret-key-id-42" in caplog.text  # the detail is logged server-side
    assert seen == []
    r = await send(server, body([LINK]), jsonrpc=True)
    assert r.json()["error"]["code"] == -32602 and "secret" not in r.text
    assert seen == []


@pytest.mark.parametrize("behaviour", ["raise", "timeout", "none", "truthy", "triple", "sync-ok"])
async def test_verifier_failures_are_rejections(behaviour):
    seen: list[AMPContext] = []

    async def verifier(chain, ctx):
        if behaviour == "raise":
            raise RuntimeError("verifier exploded: internal detail")
        if behaviour == "timeout":
            await asyncio.sleep(10)
        if behaviour == "none":
            return None
        if behaviour == "truthy":
            return ("yes", "ok")  # not a bool: rejected
        return (True, "a", "b")

    def sync_verifier(chain, ctx):
        return True, "fine"

    if behaviour == "sync-ok":
        server = build(seen, chain_verifier=sync_verifier)
        r = await send(server, body([LINK]))
        assert r.status_code == 200 and seen[-1].delegation_chain is not None
        return
    server = build(seen, chain_verifier=verifier, chain_verifier_timeout=0.05)
    r = await send(server, body([LINK]))
    assert_rejected(r)
    assert "internal detail" not in r.text
    assert seen == []


async def test_no_verifier_never_exposes_chain():
    seen: list[AMPContext] = []
    server = build(seen)
    r = await send(server, body([LINK]))
    assert r.status_code == 200
    ctx = seen[-1]
    assert ctx.delegation_chain is None
    unverified = ctx.metadata[UNVERIFIED_DELEGATION_CHAIN_KEY]
    assert isinstance(unverified, DelegationChain) and unverified.depth == 1
    assert "delegationChain" not in ctx.metadata["amp.extension"]


async def test_no_chain_does_not_call_verifier():
    seen: list[AMPContext] = []
    called: list[Any] = []

    async def verifier(chain, ctx):
        called.append(chain)
        return False, "no"

    server = build(seen, chain_verifier=verifier)
    r = await send(server, body(ext={"jurisdiction": "EU"}))
    assert r.status_code == 200 and called == []
    assert seen[-1].delegation_chain is None
    assert UNVERIFIED_DELEGATION_CHAIN_KEY not in seen[-1].metadata


async def test_chain_ignored_unless_extension_active():
    seen: list[AMPContext] = []
    server = build(seen)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()),
                                 base_url=BASE) as c:
        r = await c.post("/a2a/message:send", json=body([LINK]))
    assert r.status_code == 200
    assert seen[-1].delegation_chain is None
    assert UNVERIFIED_DELEGATION_CHAIN_KEY not in seen[-1].metadata


async def test_malformed_chain_rejected_before_verifier():
    seen: list[AMPContext] = []
    called: list[Any] = []

    async def verifier(chain, ctx):
        called.append(chain)
        return True, "ok"

    server = build(seen, chain_verifier=verifier)
    for bad in ([{"nope": 1}], [LINK] * 51, "chain"):
        r = await send(server, body(bad))
        assert r.status_code == 400 and r.json()["error"]["details"][0]["reason"] == "INVALID_PARAMS"
    assert called == [] and seen == []


def test_verifier_option_validated():
    server = AgentServer.from_app(AgentApp("@demo", BASE))
    with pytest.raises(TypeError):
        A2AAdapter.for_server(server, chain_verifier="not callable")
    with pytest.raises(ValueError):
        A2AAdapter.for_server(server, chain_verifier=lambda c, x: (True, ""),
                              chain_verifier_timeout=0)
