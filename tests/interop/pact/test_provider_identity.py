"""PACT Identity profile (§2, §3.4, §4, §6) over HTTP via httpx.ASGITransport."""
from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.pact import (
    Brand,
    InMemoryPersonalAgentRegistry,
    PACTProvider,
    PersonalAgentRegistration,
    close_conversation,
    current_turn,
)
from ampro.security.rate_limiter import RateLimiter

from .conftest import AUDIENCE, ISSUER, PAKey

PUBLIC = "https://provider.example"
A2A = "application/a2a+json"


def make_app(calls: list[dict[str, Any]]) -> AgentApp:
    app = AgentApp(agent_id="agent://brand.example", endpoint="https://brand.example")

    @app.on("task.create")
    async def turn(msg, ctx):
        text = msg.body["text"]
        t = current_turn()
        calls.append({"text": text, "context": ctx.headers.get("Session-Id"),
                      "sender": ctx.sender_address, "pa_sub": t.pa_sub if t else None})
        if text == "boom":
            raise RuntimeError("secret database password is hunter2")
        if text == "bye":
            close_conversation()
            return "Goodbye."
        return f"echo: {text}"

    return app


@pytest.fixture
def calls() -> list[dict[str, Any]]:
    return []


@pytest.fixture
def provider(pa_key, clock, calls) -> PACTProvider:
    registry = InMemoryPersonalAgentRegistry([
        PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks),
        PersonalAgentRegistration(issuer=ISSUER + "/disabled", jwks=pa_key.jwks, enabled=False),
    ])
    p = PACTProvider(public_url=PUBLIC, registry=registry, audience=AUDIENCE, clock=clock)
    p.add_brand(Brand("brand-a", make_app(calls), name="Brand A", description="A",
                      skills=[{"id": "orders", "name": "Orders", "description": "x", "tags": ["o"]}]))
    p.add_brand(Brand("brand-b", make_app(calls), name="Brand B"))
    return p


@pytest.fixture
async def http(provider):
    transport = httpx.ASGITransport(app=provider.asgi())
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC) as client:
        yield client


class Caller:
    def __init__(self, http: httpx.AsyncClient, pa: PAKey, clock) -> None:
        self.http, self.pa, self.clock = http, pa, clock

    async def __call__(self, route: str, *, brand: str = "brand-a", method: str = "GET",
                       sub: str = "user-1", body: Any = None, token: Any = "default",
                       headers: dict[str, str] | None = None) -> httpx.Response:
        hdrs = {"A2A-Version": "1.0"}
        if token == "default":
            token = self.pa.token(self.clock, sub=sub)
        if token is not None:
            hdrs["Authorization"] = f"Bearer {token}"
        content = None
        if body is not None:
            hdrs["Content-Type"] = "application/json"
            content = body if isinstance(body, (str, bytes)) else json.dumps(body)
        hdrs.update(headers or {})
        return await self.http.request(method, f"/a2a/{brand}/{route}" if route else f"/a2a/{brand}",
                                       headers=hdrs, content=content)


@pytest.fixture
def call(http, pa_key, clock) -> Caller:
    return Caller(http, pa_key, clock)


def msg(text: str = "hello", **fields: Any) -> dict[str, Any]:
    m = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}
    m.update(fields)
    return {"message": m}


def assert_error(resp: httpx.Response, status: int, grpc: str, reason: str, message: str | None = None):
    assert resp.status_code == status
    assert resp.headers["content-type"] == A2A
    err = resp.json()["error"]
    assert err["code"] == status and err["status"] == grpc
    assert err["details"][0] == {"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                 "reason": reason, "domain": "a2a-protocol.org"}
    if message is not None:
        assert err["message"] == message


def assert_no_a2a_body(resp: httpx.Response):
    assert resp.headers.get("content-type") != A2A
    assert resp.content == b""


# -- §2.1 card ---------------------------------------------------------------


async def test_card_is_public_and_spec_shaped(http):
    resp = await http.get("/a2a/brand-a/.well-known/agent-card.json")
    assert resp.status_code == 200
    card = resp.json()
    assert card["supportedInterfaces"] == [
        {"url": f"{PUBLIC}/a2a/brand-a", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}]
    assert card["securitySchemes"]["paJwt"]["httpAuthSecurityScheme"]["scheme"] == "Bearer"
    assert card["securitySchemes"]["paJwt"]["httpAuthSecurityScheme"]["bearerFormat"] == "JWT"
    assert card["securityRequirements"] == [{"schemes": {"paJwt": {"list": []}}}]
    assert card["capabilities"] == {"streaming": False, "pushNotifications": False,
                                    "extendedAgentCard": False}
    assert card["name"] == "Brand A" and card["skills"][0]["id"] == "orders"
    assert "userDelegation" not in card["securitySchemes"]


async def test_unknown_brand_card_is_404_without_body(http):
    resp = await http.get("/a2a/nope/.well-known/agent-card.json")
    assert resp.status_code == 404
    assert_no_a2a_body(resp)


async def test_card_wrong_method_405(http):
    resp = await http.post("/a2a/brand-a/.well-known/agent-card.json")
    assert resp.status_code == 405


# -- §4 messages -------------------------------------------------------------


async def test_send_returns_agent_message_with_context(call, calls):
    resp = await call("message:send", method="POST", body=msg("hi"))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == A2A
    m = resp.json()["message"]
    assert m["role"] == "ROLE_AGENT" and m["parts"] == [{"text": "echo: hi"}]
    assert isinstance(m["contextId"], str) and "taskId" not in m
    assert calls[0]["sender"] == f"pact:{ISSUER}#user-1"
    assert calls[0]["pa_sub"] == "user-1"
    assert calls[0]["context"] == m["contextId"]


async def test_context_continues_for_same_user(call):
    first = (await call("message:send", method="POST", body=msg("one"))).json()["message"]
    second = await call("message:send", method="POST", body=msg("two", contextId=first["contextId"]))
    assert second.status_code == 200
    assert second.json()["message"]["contextId"] == first["contextId"]


@pytest.mark.parametrize("brand,sub", [("brand-a", "someone-else"), ("brand-b", "user-1")])
async def test_foreign_context_is_unknown(call, brand, sub):
    ctx = (await call("message:send", method="POST", body=msg())).json()["message"]["contextId"]
    resp = await call("message:send", brand=brand, sub=sub, method="POST", body=msg(contextId=ctx))
    assert_error(resp, 400, "INVALID_ARGUMENT", "INVALID_PARAMS", "Unknown contextId")


async def test_never_minted_context_is_unknown(call):
    resp = await call("message:send", method="POST", body=msg(contextId=str(uuid.uuid4())))
    assert_error(resp, 400, "INVALID_ARGUMENT", "INVALID_PARAMS", "Unknown contextId")


async def test_context_from_other_pa_same_sub_is_unknown(provider, http, call, clock):
    other = PAKey()
    provider.authenticator.registry.register(
        PersonalAgentRegistration(issuer="https://pa2.example", jwks=other.jwks))
    ctx = (await call("message:send", method="POST", body=msg())).json()["message"]["contextId"]
    resp = await call("message:send", method="POST", body=msg(contextId=ctx),
                      token=other.token(clock, iss="https://pa2.example"))
    assert_error(resp, 400, "INVALID_ARGUMENT", "INVALID_PARAMS", "Unknown contextId")


async def test_duplicate_message_id_returns_stored_reply(call, calls):
    body = msg("once")
    first = (await call("message:send", method="POST", body=body)).json()["message"]
    body["message"]["contextId"] = first["contextId"]
    retry = (await call("message:send", method="POST", body=body)).json()["message"]
    assert retry["messageId"] == first["messageId"]
    assert len(calls) == 1


async def test_closed_context_is_unsupported(call):
    ctx = (await call("message:send", method="POST", body=msg("bye"))).json()["message"]["contextId"]
    resp = await call("message:send", method="POST", body=msg("again", contextId=ctx))
    assert_error(resp, 400, "FAILED_PRECONDITION", "UNSUPPORTED_OPERATION")
    fresh = await call("message:send", method="POST", body=msg("new"))
    assert fresh.status_code == 200


async def test_task_id_on_send_is_task_not_found(call):
    resp = await call("message:send", method="POST", body=msg(taskId="task-1"))
    assert_error(resp, 404, "NOT_FOUND", "TASK_NOT_FOUND", "Task not found")


@pytest.mark.parametrize("body", [
    "{", "[]", {"message": "x"}, {"nomessage": {}},
    {"message": {"role": "ROLE_USER", "parts": [{"text": "x"}]}},                 # no messageId
    {"message": {"messageId": "", "role": "ROLE_USER", "parts": [{"text": "x"}]}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": []}},
    {"message": {"messageId": "m", "role": "ROLE_X", "parts": [{"text": "x"}]}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": 1}]}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "x", "raw": "aGk="}]}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "x", "evil": 1}]}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "x"}], "bogus": 1}},
    {"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "x"}]}, "metadata": 3},
    {"message": {"messageId": "m" * 300, "role": "ROLE_USER", "parts": [{"text": "x"}]}},
])
async def test_malformed_requests_are_invalid_params(call, body):
    resp = await call("message:send", method="POST", body=body)
    assert_error(resp, 400, "INVALID_ARGUMENT", "INVALID_PARAMS")


async def test_wrong_role_and_blank_text(call):
    assert_error(await call("message:send", method="POST", body=msg(role="ROLE_AGENT")),
                 400, "INVALID_ARGUMENT", "INVALID_PARAMS")
    assert_error(await call("message:send", method="POST", body=msg("   ")),
                 400, "INVALID_ARGUMENT", "INVALID_PARAMS")


@pytest.mark.parametrize("part", [{"raw": "aGVsbG8="}, {"url": "https://x/y"}, {"data": {"a": 1}}])
async def test_non_text_parts_not_supported(call, part):
    body = msg()
    body["message"]["parts"] = [{"text": "see attached"}, part]
    assert_error(await call("message:send", method="POST", body=body),
                 400, "INVALID_ARGUMENT", "CONTENT_TYPE_NOT_SUPPORTED")


async def test_overlong_text_rejected(call):
    assert_error(await call("message:send", method="POST", body=msg("x" * 20_000)),
                 400, "INVALID_ARGUMENT", "INVALID_PARAMS")


async def test_handler_failure_is_internal_without_details(call):
    resp = await call("message:send", method="POST", body=msg("boom"))
    assert_error(resp, 500, "INTERNAL", "INTERNAL", "Internal error")
    assert "hunter2" not in resp.text


# -- §2 transport ------------------------------------------------------------


async def test_a2a_json_accepted_and_version_optional(call):
    for headers in ({"Content-Type": "application/a2a+json"}, {"A2A-Version": "2.0"},
                    {"Content-Type": "text/plain"}):
        resp = await call("message:send", method="POST", body=msg(), headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == A2A
    resp = await call("message:send", method="POST", body=msg(), headers={"A2A-Version": ""})
    assert resp.status_code == 200


# -- §2.2 tasks and other operations ---------------------------------------


async def test_tasks_list_is_empty_and_validates_page_size(call):
    resp = await call("tasks?pageSize=20&contextId=ignored&status=ignored")
    assert resp.json() == {"tasks": [], "nextPageToken": "", "pageSize": 20, "totalSize": 0}
    assert resp.headers["content-type"] == A2A
    assert (await call("tasks")).json()["pageSize"] == 50
    assert (await call("tasks?pageSize=100")).json()["pageSize"] == 100
    for bad in ("0", "101", "-1", "abc", "1.5", "9999999999"):
        assert_error(await call(f"tasks?pageSize={bad}"), 400, "INVALID_ARGUMENT", "INVALID_PARAMS")


async def test_task_routes_are_task_not_found(call):
    tid = str(uuid.uuid4())
    assert_error(await call(f"tasks/{tid}"), 404, "NOT_FOUND", "TASK_NOT_FOUND", f"Task not found: {tid}")
    assert_error(await call(f"tasks/{tid}:cancel", method="POST"), 404, "NOT_FOUND",
                 "TASK_NOT_FOUND", f"Task not found: {tid}")


async def test_unsupported_operations(call):
    tid = str(uuid.uuid4())
    for method, route in (("POST", "message:stream"), ("POST", f"tasks/{tid}:subscribe"),
                          ("GET", "extendedAgentCard")):
        assert_error(await call(route, method=method), 400, "FAILED_PRECONDITION", "UNSUPPORTED_OPERATION")
    for method, route in (("GET", f"tasks/{tid}/pushNotificationConfigs"),
                          ("POST", f"tasks/{tid}/pushNotificationConfigs"),
                          ("GET", f"tasks/{tid}/pushNotificationConfigs/c1"),
                          ("DELETE", f"tasks/{tid}/pushNotificationConfigs/c1")):
        assert_error(await call(route, method=method), 400, "FAILED_PRECONDITION",
                     "PUSH_NOTIFICATION_NOT_SUPPORTED")


@pytest.mark.parametrize("method,route", [
    ("GET", "unknown"), ("GET", "message:send"), ("DELETE", "message:send"), ("PUT", "message:send"),
    ("POST", "tasks"), ("DELETE", "tasks/x/pushNotificationConfigs"),
    ("POST", "tasks/x/pushNotificationConfigs/c"), ("GET", ""), ("GET", "tasks/x/y"),
    ("GET", "oauth/.well-known/oauth-authorization-server"),
])
async def test_unmatched_routes_without_body_before_auth(call, method, route):
    resp = await call(route, method=method, token=None)
    assert resp.status_code in (404, 405)
    assert_no_a2a_body(resp)


async def test_paths_outside_a2a_are_not_ours(provider):
    from ampro.server.http import HTTPRequest

    assert await provider.handle(HTTPRequest("GET", "/agent/health")) is None


# -- §3.4 authentication failures ---------------------------------------


async def test_missing_token_401(call):
    resp = await call("tasks", token=None)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Bearer realm="a2a"'
    assert_no_a2a_body(resp)


async def test_auth_happens_before_body_parsing(call):
    resp = await call("message:send", method="POST", body="{", token=None)
    assert resp.status_code == 401
    assert_no_a2a_body(resp)


async def test_bad_tokens_401(call, clock):
    now = int(clock())
    other = PAKey()
    for token in (other.token(clock), PAKey(kid="x").token(clock),
                  call.pa.token(clock, aud=f"{PUBLIC}/a2a/brand-a"),
                  call.pa.token(clock, iat=now + 31, exp=now + 151),
                  call.pa.token(clock, iat=now - 200, exp=now - 100),
                  call.pa.token(clock, iss=ISSUER + "/disabled"), "garbage"):
        resp = await call("tasks", token=token)
        assert resp.status_code == 401, token
        assert resp.headers["www-authenticate"] == 'Bearer realm="a2a"'
        assert_no_a2a_body(resp)


async def test_token_reusable_across_brands_and_unknown_brand_404(call, clock):
    tok = call.pa.token(clock)
    assert (await call("tasks", token=tok)).status_code == 200
    assert (await call("tasks", brand="brand-b", token=tok)).status_code == 200
    resp = await call("tasks", brand="missing-brand", token=tok)
    assert resp.status_code == 404
    assert_no_a2a_body(resp)


async def test_unknown_brand_without_token_is_401(call):
    # authenticate before looking up the Brand (§3.4): no Brand enumeration
    assert (await call("tasks", brand="missing-brand", token=None)).status_code == 401


async def test_delegation_header_on_identity_brand_is_invalid_token(call):
    resp = await call("message:send", method="POST", body=msg(),
                      headers={"X-A2A-User-Delegation": "Bearer abc"})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Bearer realm="a2a", error="invalid_token"'


async def test_rate_limit_returns_429_with_retry_after(pa_key, clock, calls):
    registry = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks)])
    p = PACTProvider(public_url=PUBLIC, registry=registry, audience=AUDIENCE, clock=clock,
                     rate_limiter=RateLimiter(rpm=2))
    p.add_brand(Brand("brand-a", make_app(calls), name="A"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.asgi()), base_url=PUBLIC) as h:
        c = Caller(h, pa_key, clock)
        assert (await c("tasks")).status_code == 200
        assert (await c("tasks")).status_code == 200
        resp = await c("tasks")
        assert resp.status_code == 429 and int(resp.headers["retry-after"]) >= 1


def test_provider_config_validation(registry):
    with pytest.raises(ValueError):
        PACTProvider(public_url="provider.example", registry=registry, audience=AUDIENCE)
    with pytest.raises(ValueError):
        PACTProvider(public_url=PUBLIC, registry=registry, audience="")
    with pytest.raises(ValueError):
        Brand("bad id!", AgentApp("agent://x", "https://x"), name="x")
