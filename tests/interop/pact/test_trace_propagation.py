"""PACT carries W3C trace context and the hop count in both directions."""
from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.interop.pact import (
    Brand,
    InMemoryPersonalAgentRegistry,
    PACTProvider,
    PersonalAgentRegistration,
)
from ampro.interop.pact.client import BrandSession, PACTClient, PASigner
from ampro.interop.propagation import (
    HOP_COUNT_HEADER,
    HOP_COUNT_METADATA_KEY,
    HopLimitExceeded,
    Propagation,
    use_propagation,
)

from .conftest import AUDIENCE, ISSUER

PUBLIC = "https://provider.example"
TID = "4bf92f3577b34da6a3ce929d0e0e4736"
PID = "00f067aa0ba902b7"


@pytest.fixture
def seen() -> list[AMPContext]:
    return []


@pytest.fixture
def provider(pa_key, clock, seen) -> PACTProvider:
    app = AgentApp(agent_id="agent://brand.example", endpoint="https://brand.example")

    @app.on("task.create")
    async def turn(msg, ctx):
        seen.append(ctx)
        return "ok"

    registry = InMemoryPersonalAgentRegistry([
        PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks)])
    p = PACTProvider(public_url=PUBLIC, registry=registry, audience=AUDIENCE, clock=clock)
    p.add_brand(Brand("brand-a", app, name="Brand A"))
    return p


async def post(provider: PACTProvider, pa_key, clock, headers: dict[str, str],
               metadata: dict[str, Any] | None = None) -> httpx.Response:
    message: dict[str, Any] = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                               "parts": [{"text": "hi"}]}
    if metadata is not None:
        message["metadata"] = metadata
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=provider.asgi()),
                                 base_url=PUBLIC) as http:
        return await http.post("/a2a/brand-a/message:send", content=json.dumps({"message": message}),
                               headers={"A2A-Version": "1.0", "Content-Type": "application/json",
                                        "Authorization": f"Bearer {pa_key.token(clock)}",
                                        **headers})


async def test_provider_reads_traceparent_and_hops(provider, pa_key, clock, seen):
    r = await post(provider, pa_key, clock, {"traceparent": f"00-{TID}-{PID}-01",
                                             HOP_COUNT_HEADER: "4"})
    assert r.status_code == 200, r.text
    assert seen[-1].trace_id == TID and seen[-1].parent_span_id == PID
    assert seen[-1].hop_count == 4


@pytest.mark.parametrize("headers,metadata", [
    ({"traceparent": "00-broken"}, None),
    ({HOP_COUNT_HEADER: "21"}, None),
    ({}, {HOP_COUNT_METADATA_KEY: 21}),
])
async def test_provider_rejects_bad_trace_or_hops(provider, pa_key, clock, seen, headers, metadata):
    r = await post(provider, pa_key, clock, headers, metadata)
    assert r.status_code == 400
    assert r.json()["error"]["details"][0]["reason"] == "INVALID_PARAMS"
    assert seen == []


async def test_pact_client_emits_trace_and_hop_count(pa_key):
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"message": {"messageId": "m", "contextId": "c",
                                                     "role": "ROLE_AGENT",
                                                     "parts": [{"text": "ok"}]}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = PACTClient(PASigner(ISSUER, pa_key.jwk), AUDIENCE, http=http)
        brand = BrandSession(client, {}, "https://brand.example/a2a/brand-a")
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=2,
                                         tracestate="v=1")):
            reply = await brand.send("user-1", "hi")
        assert reply.text == "ok"
        req = sent[-1]
        assert req.headers["traceparent"] == f"00-{TID}-{PID}-01"
        assert req.headers["tracestate"] == "v=1" and req.headers["amp-hop-count"] == "3"
        assert json.loads(req.content)["message"]["metadata"] == {HOP_COUNT_METADATA_KEY: 3}

        limited = PACTClient(PASigner(ISSUER, pa_key.jwk), AUDIENCE, http=http, max_hops=2)
        with use_propagation(Propagation(trace_id=TID, span_id=PID, hop_count=2)):
            with pytest.raises(HopLimitExceeded):
                await BrandSession(limited, {}, "https://brand.example/a2a/x").send("u", "hi")
        assert len(sent) == 1
