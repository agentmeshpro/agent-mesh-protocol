"""Black-box conformance checks for any AMP implementation over HTTP.

Every check talks to the target only through HTTP, so the suite tests a Go,
Rust or TypeScript agent exactly as it tests the Python reference server.
Each check names the WIRE-BINDING section it verifies, its requirement
level (MUST / SHOULD) and the conformance level (0-5) it belongs to.

Usage::

    from ampro.conformance import run_conformance

    report = await run_conformance("https://agent.example.com", level=1)
    print(report.to_table())
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from ampro.conformance.model import (
    CheckFailed,
    CheckResult,
    CheckSkipped,
    CheckSpec,
    Report,
    Requirement,
)
from ampro.conformance.signing import Signer

TEN_MIB = 10 * 1024 * 1024
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
PROBLEM_CT = "application/problem+json"


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclass
class Context:
    base_url: str
    client: httpx.AsyncClient
    level: int
    signer: Signer | None = None
    sender: str = "agent://conformance.invalid"
    sender_bound: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)
    probe_rate_limit: int = 0
    skip_large: bool = False
    timeout: float = 15.0

    agent_json: dict[str, Any] | None = None
    baseline: httpx.Response | None = None
    observed_429: list[httpx.Response] = field(default_factory=list)
    _validators: dict[str, Any] = field(default_factory=dict)

    # -- helpers -----------------------------------------------------------

    @property
    def has_credentials(self) -> bool:
        return self.signer is not None or any(
            k.lower() == "authorization" for k in self.extra_headers
        )

    @property
    def message_url(self) -> str:
        return self.base_url + "/agent/message"

    @property
    def recipient(self) -> str:
        ids = (self.agent_json or {}).get("identifiers") or []
        if not ids or not isinstance(ids[0], str):
            raise CheckSkipped("agent.json has no identifiers; cannot address messages")
        return ids[0]

    def envelope(self, body_type: str = "message", body: Any = None, **fields: Any) -> dict[str, Any]:
        env: dict[str, Any] = {
            "sender": self.sender,
            "recipient": self.recipient,
            "id": str(uuid.uuid4()),
            "body_type": body_type,
            "headers": {},
            "body": {"text": "ampro-conformance ping"} if body is None else body,
        }
        env.update(fields)
        return env

    async def get(self, path: str, headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.client.get(
            self.base_url + path,
            headers={**self.extra_headers, **(headers or {})},
            timeout=self.timeout,
        )

    async def post(
        self,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
        content_type: str | None = "application/json",
        sign: bool = True,
        path: str = "/agent/message",
    ) -> httpx.Response:
        """POST *payload* (a dict, or raw bytes) and record any 429."""
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        hdrs = dict(self.extra_headers)
        if content_type is not None:
            hdrs["Content-Type"] = content_type
        hdrs.update(headers or {})
        url = self.base_url + path
        if sign and self.signer is not None:
            hdrs = self.signer.sign("POST", url, hdrs, body)
        resp = await self.client.post(url, content=body, headers=hdrs, timeout=self.timeout)
        if resp.status_code == 429:
            self.observed_429.append(resp)
        return resp

    def require_auth_ok(self, resp: httpx.Response) -> None:
        if resp.status_code == 401 and not self.has_credentials:
            raise CheckSkipped(
                "/agent/message requires authentication; pass --signing-key/--keyid or --header"
            )
        if resp.status_code == 429:
            raise CheckSkipped("rate limited by the target; rerun later or raise its limit")

    def validator(self, name: str) -> Any | None:
        """A JSON Schema validator for ``spec/schemas/<name>``; None without jsonschema."""
        if name not in self._validators:
            try:
                from ampro.wire.schemas import validator_for

                self._validators[name] = validator_for(name)
            except ImportError:
                self._validators[name] = None
        return self._validators[name]

    def schema_errors(self, name: str, instance: Any) -> list[str]:
        v = self.validator(name)
        if v is None:
            return []
        return [
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"[:160]
            for e in v.iter_errors(instance)
        ][:3]


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def _ct(resp: httpx.Response) -> str:
    return resp.headers.get("content-type", "").split(";")[0].strip().lower()


def _json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError as exc:
        raise CheckFailed(f"response body is not JSON: {resp.text[:80]!r}") from exc


def expect(cond: bool, message: str) -> None:
    if not cond:
        raise CheckFailed(message)


def expect_problem(
    ctx: Context, resp: httpx.Response, status: int | tuple[int, ...], urn: str | None = None
) -> dict[str, Any]:
    """Assert an RFC 7807 problem response (WIRE-BINDING 7.1)."""
    statuses = (status,) if isinstance(status, int) else status
    expect(
        resp.status_code in statuses,
        f"expected HTTP {'/'.join(map(str, statuses))}, got {resp.status_code}: {resp.text[:120]!r}",
    )
    expect(_ct(resp) == PROBLEM_CT, f"Content-Type {_ct(resp)!r}, expected {PROBLEM_CT}")
    body = _json(resp)
    expect(isinstance(body, dict), "problem body is not a JSON object")
    for key, typ in (("type", str), ("title", str), ("status", int)):
        expect(isinstance(body.get(key), typ), f"problem member {key!r} missing or not {typ.__name__}")
    expect(body["status"] == resp.status_code, f"problem status {body['status']} != HTTP {resp.status_code}")
    errs = ctx.schema_errors("problem-details.json", body)
    expect(not errs, f"problem does not match schema: {errs}")
    if urn is not None:
        expect(body["type"] == urn, f"problem type {body['type']!r}, expected {urn!r}")
    return body


def same_outcome(resp: httpx.Response, baseline: httpx.Response) -> bool:
    return resp.status_code == baseline.status_code or (
        200 <= resp.status_code < 300 and 200 <= baseline.status_code < 300
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

CheckFn = Callable[[Context], Awaitable[str | None]]
CHECKS: list[tuple[CheckSpec, CheckFn]] = []


def check(
    id: str, title: str, section: str, requirement: Requirement, level: int, *, needs_key: bool = False
) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        CHECKS.append((CheckSpec(id, title, section, requirement, level, needs_key), fn))
        return fn

    return deco


# ---------------------------------------------------------------------------
# Level 0 -- discovery
# ---------------------------------------------------------------------------


@check("discovery.agent-json", "agent.json is served and valid", "4.1.2", "MUST", 0)
async def _agent_json(ctx: Context) -> str:
    resp = await ctx.get("/.well-known/agent.json", {"Accept": "application/json"})
    expect(resp.status_code == 200, f"GET /.well-known/agent.json returned {resp.status_code}")
    expect(_ct(resp) == "application/json", f"Content-Type {_ct(resp)!r}, expected application/json")
    doc = _json(resp)
    expect(isinstance(doc, dict), "agent.json is not a JSON object")
    ctx.agent_json = doc
    for key, typ in (("protocol_version", str), ("identifiers", list), ("endpoint", str)):
        expect(isinstance(doc.get(key), typ), f"required field {key!r} missing or not {typ.__name__}")
    expect(bool(doc["identifiers"]), "identifiers is empty")
    expect(all(isinstance(i, str) for i in doc["identifiers"]), "identifiers must be strings")
    errs = ctx.schema_errors("agent-json.json", doc)
    expect(not errs, f"agent.json does not match schema: {errs}")
    return f"identifiers={doc['identifiers'][:2]}"


@check("discovery.protocol-version", "agent.json protocol_version is SemVer", "4.1.2", "MUST", 0)
async def _agent_json_version(ctx: Context) -> str:
    if ctx.agent_json is None:
        raise CheckSkipped("agent.json unavailable")
    v = ctx.agent_json.get("protocol_version", "")
    expect(isinstance(v, str) and bool(SEMVER.match(v)), f"protocol_version {v!r} is not SemVer")
    return v


@check("discovery.caching", "agent.json declares a cache lifetime", "4.1.5", "SHOULD", 0)
async def _agent_json_cache(ctx: Context) -> str:
    resp = await ctx.get("/.well-known/agent.json")
    ttl = (ctx.agent_json or {}).get("ttl_seconds")
    cc = resp.headers.get("cache-control")
    expect(isinstance(ttl, int) or bool(cc), "neither ttl_seconds nor Cache-Control present")
    return f"ttl_seconds={ttl} cache-control={cc!r}"


@check("discovery.health", "GET /agent/health returns a valid health object", "4.2.2", "MUST", 0)
async def _health(ctx: Context) -> str:
    resp = await ctx.get("/agent/health", {"Accept": "application/json"})
    expect(resp.status_code in (200, 503), f"GET /agent/health returned {resp.status_code}")
    expect(_ct(resp) == "application/json", f"Content-Type {_ct(resp)!r}, expected application/json")
    doc = _json(resp)
    expect(isinstance(doc, dict), "health response is not a JSON object")
    expect(doc.get("status") in ("healthy", "unhealthy"), f"status {doc.get('status')!r}")
    expect(isinstance(doc.get("protocol_version"), str), "protocol_version missing")
    errs = ctx.schema_errors("health-response.json", doc)
    expect(not errs, f"health response does not match schema: {errs}")
    expect(
        (resp.status_code == 200) == (doc["status"] == "healthy"),
        f"HTTP {resp.status_code} disagrees with status {doc['status']!r} (4.2.4)",
    )
    return f"{resp.status_code} {doc['status']}"


@check("errors.unknown-route", "Unknown paths get an RFC 7807 problem", "7.1", "MUST", 0)
async def _unknown_route(ctx: Context) -> str:
    resp = await ctx.get("/agent/conformance-no-such-path-" + secrets.token_hex(4))
    expect_problem(ctx, resp, (404, 405, 501))
    return str(resp.status_code)


# ---------------------------------------------------------------------------
# Level 1 -- messaging
# ---------------------------------------------------------------------------


@check("message.accepted", "A valid `message` envelope is accepted", "20.2", "MUST", 1)
async def _accepted(ctx: Context) -> str:
    resp = await ctx.post(ctx.envelope())
    ctx.require_auth_ok(resp)
    ctx.baseline = resp
    if resp.status_code == 501:
        expect_problem(ctx, resp, 501)
        return "501: the agent has no handler for `message` (allowed)"
    expect(200 <= resp.status_code < 300, f"HTTP {resp.status_code}: {resp.text[:120]!r}")
    return str(resp.status_code)


def _need_baseline(ctx: Context, success: bool = False) -> httpx.Response:
    if ctx.baseline is None:
        raise CheckSkipped("baseline message was not accepted")
    if success and not 200 <= ctx.baseline.status_code < 300:
        raise CheckSkipped(f"baseline message got HTTP {ctx.baseline.status_code}")
    return ctx.baseline


@check("message.response-envelope", "Success responses are AgentMessage envelopes", "20.2", "MUST", 1)
async def _response_envelope(ctx: Context) -> str:
    resp = _need_baseline(ctx, success=True)
    expect(_ct(resp) == "application/json", f"Content-Type {_ct(resp)!r}")
    doc = _json(resp)
    expect(isinstance(doc, dict), "response is not a JSON object")
    missing = [k for k in ("sender", "recipient", "id", "body_type") if k not in doc]
    expect(not missing, f"response is not an AgentMessage envelope (missing {missing})")
    errs = ctx.schema_errors("envelope.json", doc)
    expect(not errs, f"response envelope does not match schema: {errs}")
    return f"body_type={doc['body_type']}"


@check("message.content-type-default", "A request without Content-Type is treated as JSON", "3.2", "MUST", 1)
async def _ct_default(ctx: Context) -> str:
    base = _need_baseline(ctx)
    resp = await ctx.post(ctx.envelope(), content_type=None)
    ctx.require_auth_ok(resp)
    expect(resp.status_code != 415, "HTTP 415 for a request without Content-Type")
    expect(same_outcome(resp, base), f"HTTP {resp.status_code}, baseline was {base.status_code}")
    return str(resp.status_code)


@check("message.content-type-unsupported", "Unsupported Content-Type gets 415", "3.2", "MUST", 1)
async def _ct_unsupported(ctx: Context) -> str:
    resp = await ctx.post(json.dumps(ctx.envelope()).encode(), content_type="text/plain")
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 415, "urn:amp:error:content-type-mismatch")
    return "415"


@check("message.invalid-json", "Malformed JSON gets 400 invalid-message", "7.2.1", "MUST", 1)
async def _invalid_json(ctx: Context) -> str:
    resp = await ctx.post(b'{"sender": "agent://x", ')
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 400, "urn:amp:error:invalid-message")
    return "400"


@check("message.invalid-envelope", "An envelope without `sender` gets 400", "5.1.1", "MUST", 1)
async def _invalid_envelope(ctx: Context) -> str:
    env = ctx.envelope()
    del env["sender"]
    resp = await ctx.post(env)
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 400, "urn:amp:error:invalid-message")
    return "400"


@check("message.invalid-body", "A body that fails its body-type schema gets 400", "Appendix D.4", "MUST", 1)
async def _invalid_body(ctx: Context) -> str:
    resp = await ctx.post(ctx.envelope("task.create", {"priority": "normal"}))
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 400, "urn:amp:error:invalid-message")
    return "400 for task.create without description"


@check("message.unknown-body-type", "Unknown body types are not rejected with 400", "5.1.4", "MUST", 1)
async def _unknown_body_type(ctx: Context) -> str:
    resp = await ctx.post(ctx.envelope("org.example.conformance.unknown_type", {"anything": [1, 2]}))
    ctx.require_auth_ok(resp)
    expect(resp.status_code != 400, f"HTTP 400 for an unknown body type: {resp.text[:120]!r}")
    if resp.status_code >= 400:
        expect_problem(ctx, resp, resp.status_code)
    return str(resp.status_code)


@check("message.unknown-headers", "Unknown envelope headers are ignored", "5.1.5", "MUST", 1)
async def _unknown_headers(ctx: Context) -> str:
    base = _need_baseline(ctx)
    env = ctx.envelope(headers={"X-Conformance-Unknown": "1", "Future-Protocol-Header": "v9"})
    resp = await ctx.post(env)
    ctx.require_auth_ok(resp)
    expect(same_outcome(resp, base), f"HTTP {resp.status_code}, baseline was {base.status_code}")
    return str(resp.status_code)


@check("message.unknown-fields", "Unknown envelope fields are ignored", "PROTOCOL-CONTRACTS 2", "MUST", 1)
async def _unknown_fields(ctx: Context) -> str:
    base = _need_baseline(ctx)
    resp = await ctx.post(ctx.envelope(x_future_field={"nested": True}))
    ctx.require_auth_ok(resp)
    expect(same_outcome(resp, base), f"HTTP {resp.status_code}, baseline was {base.status_code}")
    return str(resp.status_code)


def _declared_limit(ctx: Context) -> int | None:
    limit = ((ctx.agent_json or {}).get("constraints") or {}).get("max_message_bytes")
    return limit if isinstance(limit, int) and limit > 0 else None


def _padded(ctx: Context, size: int) -> bytes:
    """A valid envelope of exactly *size* bytes (padding in an unknown field)."""
    env = ctx.envelope(x_padding="")
    raw = json.dumps(env).encode()
    env["x_padding"] = "a" * max(0, size - len(raw))
    return json.dumps(env).encode()


@check("message.size-limit", "Messages over the limit get 413", "3.4", "MUST", 1)
async def _size_limit(ctx: Context) -> str:
    if ctx.skip_large:
        raise CheckSkipped("--skip-large")
    declared = _declared_limit(ctx)
    limit = declared or TEN_MIB
    resp = await ctx.post(_padded(ctx, limit + 1024))
    ctx.require_auth_ok(resp)
    if resp.status_code != 413 and declared is None and resp.status_code < 400:
        return f"accepted {limit + 1024} bytes; no declared limit (larger limits are allowed)"
    expect_problem(ctx, resp, 413, "urn:amp:error:payload-too-large")
    return f"413 at {limit + 1024} bytes"


@check("message.size-minimum", "Messages up to 10 MiB are accepted", "3.4", "MUST", 1)
async def _size_minimum(ctx: Context) -> str:
    if ctx.skip_large:
        raise CheckSkipped("--skip-large")
    base = _need_baseline(ctx)
    resp = await ctx.post(_padded(ctx, TEN_MIB))
    ctx.require_auth_ok(resp)
    expect(resp.status_code != 413, "HTTP 413 for a 10 MiB message")
    expect(same_outcome(resp, base), f"HTTP {resp.status_code}, baseline was {base.status_code}")
    return str(resp.status_code)


@check("message.recipient-mismatch", "Envelopes for another agent are rejected", "5.1.3", "MUST", 1)
async def _recipient_mismatch(ctx: Context) -> str:
    resp = await ctx.post(ctx.envelope(recipient="agent://someone-else.conformance.invalid"))
    ctx.require_auth_ok(resp)
    body = expect_problem(ctx, resp, tuple(range(400, 500)))
    if resp.status_code != 400 or body["type"] != "urn:amp:error:invalid-message":
        return f"rejected with {resp.status_code} {body['type']} (Appendix D recommends 400 invalid-message)"
    return "400"


@check("message.loop-detected", "A message that already visited this agent gets 409", "Appendix D.7", "SHOULD", 1)
async def _loop(ctx: Context) -> str:
    env = ctx.envelope(headers={"Visited-Agents": f"agent://upstream.invalid,{ctx.recipient}"})
    resp = await ctx.post(env)
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 409, "urn:amp:error:loop-detected")
    return "409"


@check("message.loop-limit", "More than 20 Visited-Agents gets 409", "19", "SHOULD", 1)
async def _loop_limit(ctx: Context) -> str:
    visited = ",".join(f"agent://hop{i}.conformance.invalid" for i in range(21))
    resp = await ctx.post(ctx.envelope(headers={"Visited-Agents": visited}))
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 409, "urn:amp:error:loop-detected")
    return "409"


@check("message.duplicate-id", "A repeated message id returns the original response", "12.5", "SHOULD", 1)
async def _duplicate(ctx: Context) -> str:
    _need_baseline(ctx, success=True)
    env = ctx.envelope()
    first = await ctx.post(env)
    ctx.require_auth_ok(first)
    second = await ctx.post(env)
    expect(
        second.status_code == first.status_code,
        f"replay got HTTP {second.status_code}, first was {first.status_code}",
    )
    expect(second.content == first.content, "replayed message was reprocessed (response differs)")
    return f"{first.status_code}, identical body"


@check("ratelimit.headers", "Responses carry X-RateLimit-* headers", "12.4", "SHOULD", 1)
async def _rl_headers(ctx: Context) -> str:
    resp = _need_baseline(ctx)
    vals = {h: resp.headers.get(h) for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")}
    missing = [h for h, v in vals.items() if v is None]
    expect(not missing, f"missing {missing}")
    expect(all(v.isdigit() for v in vals.values() if v), f"non-integer values {vals}")
    return ", ".join(f"{k[12:]}={v}" for k, v in vals.items())


@check("version.protocol-version-header", "Responses carry Protocol-Version", "18.4", "MUST", 1)
async def _pv_header(ctx: Context) -> str:
    resp = _need_baseline(ctx)
    pv = resp.headers.get("protocol-version")
    expect(pv is not None, "no Protocol-Version response header")
    expect(bool(SEMVER.match(pv)), f"Protocol-Version {pv!r} is not SemVer")
    return pv


def _major(ctx: Context) -> int:
    v = (ctx.agent_json or {}).get("protocol_version", "1.0.0")
    try:
        return int(str(v).split(".")[0])
    except ValueError:
        return 1


def _with_version(ctx: Context, version: str) -> tuple[dict[str, Any], dict[str, str]]:
    return ctx.envelope(headers={"Accept-Version": version}), {"Accept-Version": version}


@check("version.same-major", "A same-MAJOR version is accepted", "18.4", "MUST", 1)
async def _same_major(ctx: Context) -> str:
    base = _need_baseline(ctx)
    major = _major(ctx)
    env, hdrs = _with_version(ctx, f"{major}.999.0")
    resp = await ctx.post(env, headers=hdrs)
    ctx.require_auth_ok(resp)
    expect(resp.status_code != 406, f"HTTP 406 for {major}.999.0")
    expect(same_outcome(resp, base), f"HTTP {resp.status_code}, baseline was {base.status_code}")
    pv = resp.headers.get("protocol-version", "")
    expect(pv.split(".")[0] == str(major), f"negotiated Protocol-Version {pv!r}, expected MAJOR {major}")
    return f"negotiated {pv}"


@check("version.unsupported-major", "An unsupported MAJOR gets 406", "18.4", "MUST", 1)
async def _bad_major(ctx: Context) -> str:
    env, hdrs = _with_version(ctx, "999.0.0")
    resp = await ctx.post(env, headers=hdrs)
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 406, "urn:amp:error:version-mismatch")
    return "406"


@check("version.malformed", "A malformed version gets 406", "18.4", "MUST", 1)
async def _malformed_version(ctx: Context) -> str:
    env, hdrs = _with_version(ctx, "not-a-version")
    resp = await ctx.post(env, headers=hdrs)
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 406, "urn:amp:error:version-mismatch")
    return "406"


# ---------------------------------------------------------------------------
# Level 1 -- RFC 9421 signatures (only with --signing-key / --keyid)
# ---------------------------------------------------------------------------


def _signer(ctx: Context) -> Signer:
    if ctx.signer is None:
        raise CheckSkipped("no --signing-key/--keyid given")
    return ctx.signer


async def _post_signed(ctx: Context, env: dict[str, Any], **sign_kw: Any) -> tuple[httpx.Response, dict, bytes]:
    signer = _signer(ctx)
    body = json.dumps(env).encode()
    hdrs = signer.sign(
        "POST", ctx.message_url, {**ctx.extra_headers, "Content-Type": "application/json"}, body, **sign_kw
    )
    resp = await ctx.client.post(ctx.message_url, content=body, headers=hdrs, timeout=ctx.timeout)
    return resp, hdrs, body


def _expect_401(ctx: Context, resp: httpx.Response) -> None:
    expect_problem(ctx, resp, 401, "urn:amp:error:unauthorized")


@check("auth.signed-request", "A valid RFC 9421 signature is accepted", "12.15.5", "MUST", 1, needs_key=True)
async def _signed_ok(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope())
    expect(resp.status_code not in (401, 403), f"HTTP {resp.status_code}: {resp.text[:160]!r}")
    expect(resp.status_code < 500 or resp.status_code == 501, f"HTTP {resp.status_code}")
    return str(resp.status_code)


@check("auth.signature-replay", "A replayed signature (same keyid+nonce) gets 401", "12.15.4", "MUST", 1, needs_key=True)
async def _signed_replay(ctx: Context) -> str:
    first, hdrs, body = await _post_signed(ctx, ctx.envelope())
    expect(first.status_code not in (401, 403), f"first request rejected with {first.status_code}")
    second = await ctx.client.post(ctx.message_url, content=body, headers=hdrs, timeout=ctx.timeout)
    _expect_401(ctx, second)
    return "401 on replay"


@check("auth.signature-tamper", "A body changed after signing gets 401", "12.15.2", "MUST", 1, needs_key=True)
async def _signed_tamper(ctx: Context) -> str:
    signer = _signer(ctx)
    env = ctx.envelope()
    body = json.dumps(env).encode()
    hdrs = signer.sign("POST", ctx.message_url, {**ctx.extra_headers, "Content-Type": "application/json"}, body)
    env["body"] = {"text": "tampered"}
    resp = await ctx.client.post(
        ctx.message_url, content=json.dumps(env).encode(), headers=hdrs, timeout=ctx.timeout
    )
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-stale", "A signature older than 300 s gets 401", "12.15.4", "MUST", 1, needs_key=True)
async def _signed_stale(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope(), created=int(time.time()) - 900)
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-future", "A signature created 300+ s in the future gets 401", "12.15.4", "MUST", 1, needs_key=True)
async def _signed_future(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope(), created=int(time.time()) + 900)
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-no-nonce", "A signature without nonce gets 401", "12.15.1", "MUST", 1, needs_key=True)
async def _signed_no_nonce(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope(), nonce=None)
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-alg", "A signature with alg other than ed25519 gets 401", "12.15.1", "MUST", 1, needs_key=True)
async def _signed_alg(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope(), alg="hmac-sha256")
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-unknown-key", "A signature by an unknown key gets 401", "12.15.5", "MUST", 1, needs_key=True)
async def _signed_unknown_key(ctx: Context) -> str:
    resp, _, _ = await _post_signed(
        ctx, ctx.envelope(), seed=secrets.token_bytes(32), keyid=_signer(ctx).keyid + "-conformance-unknown"
    )
    _expect_401(ctx, resp)
    return "401"


@check("auth.signature-wrong-key", "A signature by the wrong key for the keyid gets 401", "12.15.5", "MUST", 1, needs_key=True)
async def _signed_wrong_key(ctx: Context) -> str:
    resp, _, _ = await _post_signed(ctx, ctx.envelope(), seed=secrets.token_bytes(32))
    _expect_401(ctx, resp)
    return "401"


@check("auth.sender-binding", "A key bound to an agent cannot send as another", "12.15.5", "MUST", 1, needs_key=True)
async def _sender_binding(ctx: Context) -> str:
    _signer(ctx)
    if not ctx.sender_bound:
        raise CheckSkipped("pass --sender-bound when the key is bound to --sender")
    resp, _, _ = await _post_signed(ctx, ctx.envelope(sender="agent://impostor.conformance.invalid"))
    expect_problem(ctx, resp, 403)
    return "403"


# ---------------------------------------------------------------------------
# Rate limiting (run late: the probe exhausts the caller's quota)
# ---------------------------------------------------------------------------


@check("ratelimit.429", "429 responses carry Retry-After and a problem body", "7.2.10", "MUST", 1)
async def _rl_429(ctx: Context) -> str:
    sent = 0
    while not ctx.observed_429 and sent < ctx.probe_rate_limit:
        await ctx.post(ctx.envelope())
        sent += 1
    if not ctx.observed_429:
        raise CheckSkipped(
            "no 429 observed" + (f" after {sent} probe requests" if sent else "; use --probe-rate-limit N")
        )
    resp = ctx.observed_429[0]
    expect_problem(ctx, resp, 429, "urn:amp:error:rate-limited")
    retry = resp.headers.get("retry-after")
    expect(retry is not None and retry.strip().isdigit(), f"Retry-After missing or not seconds: {retry!r}")
    return f"Retry-After={retry}" + (f" after {sent} probe requests" if sent else "")


# ---------------------------------------------------------------------------
# Level 2 -- tools, Level 3 -- streaming and tasks
# ---------------------------------------------------------------------------


@check("tools.list", "GET /agent/tools returns JSON", "20.3", "MUST", 2)
async def _tools(ctx: Context) -> str:
    resp = await ctx.get("/agent/tools", {"Accept": "application/json"})
    expect(resp.status_code == 200, f"HTTP {resp.status_code}")
    expect(_ct(resp) == "application/json", f"Content-Type {_ct(resp)!r}")
    _json(resp)
    return "200"


@check("tools.unknown", "Invoking an unknown tool gets 404", "20.3", "MUST", 2)
async def _tools_unknown(ctx: Context) -> str:
    resp = await ctx.post({}, path="/agent/tools/conformance-unknown-tool-" + secrets.token_hex(3))
    ctx.require_auth_ok(resp)
    expect_problem(ctx, resp, 404)
    return "404"


@check("stream.events", "GET /agent/stream emits valid SSE events", "8.3", "MUST", 3)
async def _stream(ctx: Context) -> str:
    url = ctx.base_url + "/agent/stream"
    headers = {**ctx.extra_headers, "Accept": "text/event-stream"}
    async with ctx.client.stream("GET", url, headers=headers, timeout=ctx.timeout) as resp:
        expect(resp.status_code == 200, f"HTTP {resp.status_code}")
        expect(_ct(resp) == "text/event-stream", f"Content-Type {_ct(resp)!r}")
        event: dict[str, Any] = {}
        buf = ""

        async def first_event() -> None:
            nonlocal buf
            async for chunk in resp.aiter_text():
                buf += chunk
                if "\n\n" in buf.replace("\r\n", "\n"):
                    return

        try:
            await asyncio.wait_for(first_event(), ctx.timeout)
        except TimeoutError as exc:
            raise CheckFailed(f"no complete event within {ctx.timeout}s") from exc
    block = buf.replace("\r\n", "\n").split("\n\n", 1)[0]
    data_lines = []
    for line in block.split("\n"):
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "data":
            data_lines.append(value)
        elif name in ("event", "id"):
            event[name] = value
    expect("event" in event, "event has no `event:` field")
    try:
        event["data"] = json.loads("\n".join(data_lines))
    except ValueError as exc:
        raise CheckFailed("event data is not JSON") from exc
    errs = ctx.schema_errors("stream/event.json", event)
    expect(not errs, f"event does not match schema: {errs}")
    expect(isinstance(event["data"].get("seq"), int), "event data has no integer `seq` (8.3.1)")
    from ampro.streaming.events import StreamingEventType

    known = {e.value for e in StreamingEventType}
    expect(event["event"] in known, f"event type {event['event']!r} is not defined in 8.4")
    return f"event={event['event']}"


@check("tasks.unknown", "Polling an unknown task gets 404", "20.4", "MUST", 3)
async def _tasks_unknown(ctx: Context) -> str:
    resp = await ctx.get("/agent/tasks/conformance-unknown-" + secrets.token_hex(4))
    expect_problem(ctx, resp, 404)
    return "404"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _tool_version() -> str:
    try:
        from importlib.metadata import version

        return version("ampro")
    except Exception:  # pragma: no cover - not installed as a distribution
        return "unknown"


async def run_conformance(
    url: str,
    *,
    level: int | None = None,
    signer: Signer | None = None,
    sender: str | None = None,
    sender_bound: bool = False,
    headers: dict[str, str] | None = None,
    probe_rate_limit: int = 0,
    skip_large: bool = False,
    only: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 15.0,
    verify: bool | str = True,
) -> Report:
    """Run the suite against the AMP agent at *url* and return a :class:`Report`.

    Args:
        url: Origin of the agent (``https://agent.example.com``).  Paths are
            appended; signatures cover ``url + "/agent/message"``, so pass
            the externally visible origin.
        level: Highest conformance level to test.  Defaults to the level the
            agent declares in agent.json (at least 1).
        signer: Enables the RFC 9421 checks; every request is then signed.
        sender: Envelope ``sender``.  Defaults to the keyid's agent address
            (the part before ``#``) or ``agent://conformance.invalid``.
        sender_bound: The key is bound to *sender*; enables the 403 check.
        headers: Extra HTTP headers for every request (e.g. Authorization).
        probe_rate_limit: Send up to this many messages to provoke a 429.
        skip_large: Skip the 10 MiB size checks.
        only: Run only checks whose id starts with one of these prefixes.
        transport: An httpx transport (e.g. ``httpx.ASGITransport(app)``).
    """
    from ampro.core.versioning import CURRENT_VERSION

    base = url.rstrip("/")
    if sender is None:
        sender = "agent://conformance.invalid"
        if signer is not None and signer.keyid.startswith("agent://"):
            sender = signer.keyid.split("#", 1)[0]
    report = Report(
        target=base,
        level=level if level is not None else -1,
        protocol_version=CURRENT_VERSION,
        tool_version=_tool_version(),
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    async with httpx.AsyncClient(transport=transport, verify=verify, follow_redirects=False) as client:
        ctx = Context(
            base_url=base,
            client=client,
            level=level if level is not None else 1,
            signer=signer,
            sender=sender,
            sender_bound=sender_bound,
            extra_headers=dict(headers or {}),
            probe_rate_limit=probe_rate_limit,
            skip_large=skip_large,
            timeout=timeout,
        )
        resolved_level = level
        for spec, fn in CHECKS:
            if resolved_level is None and spec.level >= 1:
                declared = ((ctx.agent_json or {}).get("capabilities") or {}).get("level")
                resolved_level = max(1, declared) if isinstance(declared, int) else 1
                ctx.level = resolved_level
            if resolved_level is not None and spec.level > resolved_level:
                continue
            if only and not any(spec.id.startswith(p) for p in only) and spec.id != "discovery.agent-json":
                continue
            started = time.monotonic()
            try:
                if spec.level >= 1 and ctx.agent_json is None:
                    raise CheckSkipped("agent.json unavailable; cannot address messages")
                detail = await fn(ctx) or ""
                status = "pass"
            except CheckSkipped as exc:
                status, detail = "skip", str(exc)
            except CheckFailed as exc:
                status, detail = "fail", str(exc)
            except httpx.HTTPError as exc:
                status, detail = "fail", f"{type(exc).__name__}: {exc}"
            report.results.append(CheckResult(
                id=spec.id, title=spec.title, section=spec.section,
                requirement=spec.requirement, level=spec.level, status=status,  # type: ignore[arg-type]
                detail=detail, duration_ms=int((time.monotonic() - started) * 1000),
            ))
        report.level = resolved_level if resolved_level is not None else ctx.level
    return report


def check_specs() -> list[CheckSpec]:
    """Static list of every check, in run order."""
    return [spec for spec, _ in CHECKS]
