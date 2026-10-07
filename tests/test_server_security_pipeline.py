"""Security pipeline of AgentServer's native POST /agent/message route."""
from __future__ import annotations

import asyncio
import json

import pytest

from ampro.ampi.app import AgentApp
from ampro.security.rate_limiter import RateLimiter
from ampro.server import AgentServer, HTTPRequest
from ampro.server.auth import Principal, Unauthorized
from ampro.server.security import InMemoryResponseCache, SecurityPolicy
from ampro.trust.tiers import TrustTier

AGENT = "agent://me.example.com"


class StaticAuth:
    """Accepts ``Authorization: Bearer good`` as a sender-bound principal."""

    def __init__(self, principal_id: str = "agent://caller.example.com") -> None:
        self.principal_id = principal_id

    async def authenticate(self, request):
        token = request.header("authorization")
        if token is None:
            return None
        if token != "Bearer good":
            raise Unauthorized("bad token")
        return Principal(
            id=self.principal_id,
            trust_tier=TrustTier.VERIFIED,
            scopes=frozenset({"orders:read"}),
            claims={"bound_sender": True},
            auth_method="test",
        )


def make_server(policy: SecurityPolicy | None = None, handler=None):
    app = AgentApp(AGENT, "https://me.example.com/agent/message")
    calls = []

    @app.on("task.create")
    async def handle(msg, ctx):
        calls.append(msg.id)
        if handler is not None:
            return await handler(msg, ctx)
        return {"tier": ctx.trust_tier.value, "principal": ctx.principal.id}

    server = AgentServer.from_app(app, security=policy)
    return server, calls


def envelope(**overrides):
    env = {
        "sender": "agent://caller.example.com",
        "recipient": AGENT,
        "id": "msg-1",
        "body_type": "task.create",
        "body": {"description": "hello"},
    }
    env.update(overrides)
    return env


def post(server, env, headers=None, client="203.0.113.7"):
    req = HTTPRequest(
        method="POST",
        path="/agent/message",
        headers={
            "content-type": "application/json",
            **{k.lower(): v for k, v in (headers or {}).items()},
        },
        body=json.dumps(env).encode(),
        client=client,
    )
    return server.handle(req)


async def test_anonymous_allowed_by_default_at_external_tier():
    server, _ = make_server()
    resp = await post(server, envelope())
    assert resp.status == 202
    assert json.loads(resp.body) == {"tier": "external", "principal": "anonymous"}


async def test_require_auth_rejects_anonymous_with_challenge():
    server, calls = make_server(SecurityPolicy.production([StaticAuth()]))
    resp = await post(server, envelope())
    assert resp.status == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")
    assert calls == []


async def test_invalid_credential_is_never_downgraded_to_anonymous():
    server, calls = make_server(SecurityPolicy(authenticators=[StaticAuth()]))
    resp = await post(server, envelope(), {"Authorization": "Bearer bad"})
    assert resp.status == 401
    assert calls == []


async def test_authenticated_principal_reaches_handler():
    server, _ = make_server(SecurityPolicy.production([StaticAuth()]))
    resp = await post(server, envelope(), {"Authorization": "Bearer good"})
    assert resp.status == 202
    assert json.loads(resp.body) == {"tier": "verified", "principal": "agent://caller.example.com"}


async def test_bound_principal_cannot_spoof_sender():
    server, calls = make_server(SecurityPolicy.production([StaticAuth()]))
    resp = await post(
        server, envelope(sender="agent://victim.example.com"), {"Authorization": "Bearer good"}
    )
    assert resp.status == 403
    assert calls == []


async def test_message_for_another_agent_is_rejected():
    server, calls = make_server()
    resp = await post(server, envelope(recipient="agent://someone-else.example.com"))
    assert resp.status == 400
    assert calls == []


async def test_rate_limit_returns_429_with_headers():
    server, _ = make_server(SecurityPolicy(rate_limiter=RateLimiter(rpm=2)))
    for i in range(2):
        assert (await post(server, envelope(id=f"m{i}"))).status == 202
    resp = await post(server, envelope(id="m3"))
    assert resp.status == 429
    assert "retry-after" in resp.headers
    assert resp.headers["x-ratelimit-remaining"] == "0"


async def test_rate_limit_is_per_peer_for_anonymous_callers():
    server, _ = make_server(SecurityPolicy(rate_limiter=RateLimiter(rpm=1)))
    assert (await post(server, envelope(id="a"), client="198.51.100.1")).status == 202
    assert (await post(server, envelope(id="b"), client="198.51.100.2")).status == 202
    assert (await post(server, envelope(id="c"), client="198.51.100.1")).status == 429


async def test_duplicate_message_replays_cached_response_without_rerunning():
    server, calls = make_server(SecurityPolicy(dedup=InMemoryResponseCache()))
    first = await post(server, envelope())
    second = await post(server, envelope())
    assert first.status == second.status == 202
    assert first.body == second.body
    assert calls == ["msg-1"]


async def test_dedup_is_scoped_to_the_caller():
    """A different caller reusing a message id must not read the cached reply."""
    policy = SecurityPolicy(authenticators=[StaticAuth()], dedup=InMemoryResponseCache())
    server, calls = make_server(policy)
    await post(server, envelope(), {"Authorization": "Bearer good"})
    resp = await post(server, envelope())  # anonymous, same sender/id
    assert json.loads(resp.body)["principal"] == "anonymous"
    assert len(calls) == 2


async def test_loop_detection():
    server, calls = make_server()
    env = envelope(headers={"Visited-Agents": "agent://a.example.com, " + AGENT})
    resp = await post(server, env)
    assert resp.status == 409
    assert calls == []


async def test_handler_timeout_returns_problem_not_hang():
    async def slow(msg, ctx):
        await asyncio.sleep(5)

    server, _ = make_server(SecurityPolicy(handler_timeout_seconds=0.05), handler=slow)
    resp = await post(server, envelope())
    assert resp.status == 408


async def test_handler_exception_text_is_not_leaked():
    async def boom(msg, ctx):
        raise RuntimeError("secret database password")

    server, _ = make_server(handler=boom)
    resp = await post(server, envelope())
    assert resp.status == 500
    assert b"secret" not in resp.body


async def test_oversized_body_rejected_before_parsing():
    from ampro.wire.config import WireConfig

    app = AgentApp(AGENT, "https://me.example.com")
    server = AgentServer.from_app(app, config=WireConfig(max_message_bytes=1024))
    req = HTTPRequest("POST", "/agent/message", body=b"x" * 2048)
    assert (await server.handle(req)).status == 413


def test_production_policy_requires_an_authenticator():
    with pytest.raises(ValueError):
        SecurityPolicy.production([])


async def test_cross_origin_browser_post_is_refused():
    server, calls = make_server()
    resp = await post(server, envelope(), {"Origin": "http://evil.example"})
    assert resp.status == 403
    assert calls == []


async def test_loopback_and_own_origin_allowed():
    server, _ = make_server()
    assert (await post(server, envelope(id="a"), {"Origin": "http://localhost:3000"})).status == 202
    assert (await post(server, envelope(id="b"), {"Origin": "https://me.example.com"})).status == 202


async def test_configured_origin_allowed():
    server, _ = make_server(SecurityPolicy(allowed_origins=["https://ui.example.org"]))
    assert (await post(server, envelope(), {"Origin": "https://ui.example.org"})).status == 202


async def test_non_json_content_type_rejected():
    server, calls = make_server()
    resp = await post(server, envelope(), {"Content-Type": "text/plain"})
    assert resp.status == 415
    assert calls == []


async def test_deeply_nested_json_is_a_400_not_a_crash():
    server, _ = make_server()
    req = HTTPRequest(
        "POST", "/agent/message",
        headers={"content-type": "application/json"},
        body=b"[" * 200_000,
    )
    assert (await server.handle(req)).status == 400


async def test_api_key_callers_get_distinct_bound_identities():
    from ampro.server.auth import TrustResolverAuthenticator
    from ampro.trust.resolver import _reset_api_keys_for_tests, register_api_key

    _reset_api_keys_for_tests()
    try:
        register_api_key("alice-key", "agent://alice.example.com")
        register_api_key("mallory-key", "agent://mallory.example.com")
        auth = TrustResolverAuthenticator(AGENT)
        server, calls = make_server(SecurityPolicy.production([auth]))

        alice = envelope(sender="agent://alice.example.com", id="shared-id")
        resp = await post(server, alice, {"Authorization": "ApiKey alice-key"})
        assert json.loads(resp.body)["principal"] == "agent://alice.example.com"

        # Mallory cannot send as Alice ...
        spoof = await post(server, alice, {"Authorization": "ApiKey mallory-key"})
        assert spoof.status == 403
        # ... nor read Alice's cached reply by reusing her message id.
        own = envelope(sender="agent://mallory.example.com", id="shared-id")
        resp = await post(server, own, {"Authorization": "ApiKey mallory-key"})
        assert json.loads(resp.body)["principal"] == "agent://mallory.example.com"
        assert len(calls) == 2
    finally:
        _reset_api_keys_for_tests()


async def test_encrypted_envelope_is_not_validated_as_plaintext():
    import json as _json
    from pathlib import Path

    vectors = _json.loads(
        (Path(__file__).parent / "vectors" / "encryption.json").read_text()
    )["vectors"]
    sample = next(v for v in vectors if v.get("valid"))["envelope"]
    server, calls = make_server()
    env = envelope(
        body_type="task.create",
        headers={"Content-Encryption": "A256GCM"},
        body=sample["body"],
    )
    resp = await post(server, env)
    assert resp.status == 202, resp.body
    bad = envelope(id="m-bad", headers={"Content-Encryption": "A256GCM"}, body={"nope": 1})
    assert (await post(server, bad)).status == 400
