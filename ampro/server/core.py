"""
AMP Reference Server — Core.

A minimal server like Python's ``http.server``.  One class: ``AgentServer``.

Framework-agnostic routing via ``route(method, path, body)``; optional
adapters for FastAPI and Flask.

Usage::

    from ampro.server import AgentServer

    server = AgentServer(agent_id="@weather", endpoint="https://weather.example.com")

    @server.on("task.create")
    async def handle_create(msg):
        return {"result": "sunny"}

    server.run(port=8000)

PURE — zero platform-specific imports at module level.
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
#
# Intended for `pip install ampro && python -m ampro.server`.
# Full-stack implementers mount AMPI handlers into their own HTTP
# framework and do not use this server.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ampro.ampi.app import AgentApp

from pydantic import BaseModel, ValidationError

from ampro.agent.health import HealthResponse
from ampro.agent.schema import AgentJson
from ampro.ampi.dispatch import build_context, dispatch
from ampro.ampi.errors import AMPError
from ampro.core.body_schemas import validate_body
from ampro.core.envelope import AgentMessage
from ampro.core.versioning import CURRENT_VERSION, SUPPORTED_VERSIONS, negotiate_version
from ampro.server.auth import ANONYMOUS, Principal, Unauthorized, authenticate
from ampro.server.http import HTTPRequest, HTTPResponse, ProtocolAdapter
from ampro.server.security import (
    CachedResponse,
    SecurityPolicy,
    origin_allowed,
    origin_of,
)
from ampro.trust.tiers import TrustTier
from ampro.wire.config import DEFAULTS, WireConfig
from ampro.wire.errors import (
    ProblemDetail,
    forbidden,
    internal_error,
    invalid_message,
    loop_detected,
    not_found,
    not_implemented,
    payload_too_large,
    rate_limited,
    timeout,
    unauthorized,
    unavailable,
    version_mismatch,
)

logger = logging.getLogger(__name__)


class AgentServer:
    """Minimal AMP reference server.

    Registers body-type handlers with ``@server.on("task.create")`` and
    routes incoming messages to them.  All routing goes through the
    framework-agnostic ``route(method, path, body)`` method; ``run()``
    starts a real HTTP server via FastAPI or Flask.
    """

    def __init__(
        self,
        agent_id: str,
        endpoint: str,
        config: WireConfig | None = None,
        agent_json: AgentJson | None = None,
        *,
        trust_tier: TrustTier = TrustTier.EXTERNAL,
        security: SecurityPolicy | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.endpoint = endpoint
        self.config = config or DEFAULTS
        self._start_time = time.monotonic()

        # Build agent.json — use provided or auto-generate a minimal one.
        if agent_json is not None:
            self.agent_json = agent_json
        else:
            self.agent_json = AgentJson(
                protocol_version=CURRENT_VERSION,
                identifiers=[agent_id],
                endpoint=endpoint,
            )

        # Handler registries.
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._default_handler: Callable[..., Any] | None = None

        # AMPI app (set by ``from_app``).  When present, handlers are
        # invoked as ``(msg, ctx)`` through the shared dispatcher, with
        # the app's middleware and error hook.
        self._app: AgentApp | None = None
        # Trust tier given to callers.  This server does not authenticate
        # senders itself, so the default is the least-privileged tier.
        self.trust_tier = trust_tier

        # Additional wire protocols (A2A, MCP, ...) served alongside AMP.
        self._adapters: list[ProtocolAdapter] = []

        # Security pipeline for POST /agent/message (WIRE-BINDING App. D).
        self.security = security or SecurityPolicy.from_config(self.config)

    # ------------------------------------------------------------------
    # Alternate constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_app(
        cls,
        app: AgentApp,
        *,
        security: SecurityPolicy | None = None,
        config: WireConfig | None = None,
    ) -> AgentServer:
        """Create an AgentServer from an AgentApp.

        AMPI handlers are called as ``(msg, ctx)`` through the same
        dispatcher as :class:`~ampro.server.test.TestServer`, so the
        app's middleware and ``@on_error`` hook run too.
        """

        server = cls(
            agent_id=app.agent_id,
            endpoint=app.endpoint,
            agent_json=app.agent_json,
            config=config,
            security=security,
        )
        server._app = app
        # Share the registry: ``@server.on`` on an app-backed server
        # registers an AMPI ``(msg, ctx)`` handler.
        server._handlers = app.handlers
        return server

    @property
    def app(self) -> AgentApp | None:
        """The AMPI app backing this server, if any."""
        return self._app

    # ------------------------------------------------------------------
    # Protocol adapters
    # ------------------------------------------------------------------

    def mount(self, adapter: ProtocolAdapter) -> ProtocolAdapter:
        """Serve an additional wire protocol (e.g. A2A, MCP) from this server.

        Adapters are consulted in mount order before the native AMP routes.
        """
        self._adapters.append(adapter)
        return adapter

    @property
    def adapters(self) -> list[ProtocolAdapter]:
        return list(self._adapters)

    async def handle(self, request: HTTPRequest) -> HTTPResponse:
        """Handle a transport-neutral request — the single server entry point."""
        if len(request.body) > self.config.max_message_bytes:
            return self.too_large_response()

        # Adapters that enforce their own Origin policy (and answer in
        # their protocol's error format) see requests first.
        for adapter in self._adapters:
            if getattr(adapter, "enforces_origin", False):
                response = await adapter.handle(request)
                if response is not None:
                    return response

        # Browser-originated state-changing requests must come from an
        # allowed origin (CSRF / DNS rebinding).  Applies to every other
        # protocol; agent-to-agent traffic carries no Origin header.
        origin = request.header("origin")
        if origin is not None and request.method.upper() not in ("GET", "HEAD", "OPTIONS"):
            if not origin_allowed(origin, self._allowed_origins()):
                logger.info("Refused cross-origin %s %s from %r", request.method, request.path, origin)
                status, headers, body = self._error_response(forbidden("Origin not allowed"))
                return HTTPResponse(status, _lower(headers), body.encode("utf-8"))

        for adapter in self._adapters:
            if getattr(adapter, "enforces_origin", False):
                continue
            response = await adapter.handle(request)
            if response is not None:
                return response

        if request.method.upper() == "POST" and request.path.rstrip("/") == "/agent/message":
            return await self._handle_message_request(request)

        payload: Any = None
        if request.method.upper() == "POST":
            try:
                payload = request.json()
            except ValueError:
                status, headers, body = self._error_response(
                    invalid_message("Request body is not valid JSON")
                )
                return HTTPResponse(status, _lower(headers), body.encode("utf-8"))
        status, headers, body = await self.route(request.method, request.path, payload)
        return HTTPResponse(status, _lower(headers), body.encode("utf-8"))

    def _allowed_origins(self) -> list[str]:
        own = origin_of(self.endpoint)
        return [*self.security.allowed_origins, *([own] if own else [])]

    def too_large_response(self) -> HTTPResponse:
        """413 problem response for a body over ``max_message_bytes``."""
        err = payload_too_large(
            "Request body exceeds the maximum message size",
            max_bytes=self.config.max_message_bytes,
        )
        status, headers, body = self._error_response(err)
        return HTTPResponse(status, _lower(headers), body.encode("utf-8"))

    def asgi(self) -> Callable[..., Any]:
        """Return an ASGI application serving every mounted protocol.

        Run it with any ASGI server, e.g. ``uvicorn.run(server.asgi())``.
        """
        from ampro.server.asgi import make_asgi_app

        return make_asgi_app(self)

    # ------------------------------------------------------------------
    # Decorators
    # ------------------------------------------------------------------

    def on(self, body_type: str) -> Callable[..., Any]:
        """Register a handler for a specific body_type.

        Example::

            @server.on("task.create")
            async def handle(msg: AgentMessage):
                return {"status": "ok"}
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self._handlers[body_type] = fn
            return fn

        return decorator

    def default(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Register a fallback handler for unrecognised body types.

        Example::

            @server.default
            async def fallback(msg: AgentMessage):
                return {"echo": msg.body}
        """
        self._default_handler = fn
        return fn

    # ------------------------------------------------------------------
    # Framework-agnostic routing
    # ------------------------------------------------------------------

    async def route(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """Route an HTTP-like request to the appropriate handler.

        Returns:
            ``(status_code, headers, json_body_string)``
        """
        method = method.upper()
        path = path.rstrip("/")

        # 1. GET /.well-known/agent.json
        if method == "GET" and path == "/.well-known/agent.json":
            return self._agent_json_response()

        # 2. GET /agent/health
        if method == "GET" and path == "/agent/health":
            return self._health_response()

        # 3. POST /agent/message
        if method == "POST" and path == "/agent/message":
            return await self._handle_message(body)

        # 4. GET /agent/stream (placeholder SSE)
        if method == "GET" and path == "/agent/stream":
            return self._stream_placeholder()

        # ---------------------------------------------------------------
        # Level 2-5 stubs — return 501 Not Implemented (not 404)
        # so clients know the endpoint exists in the spec but isn't
        # available on this server yet.
        # ---------------------------------------------------------------

        # Level 2 — Tools listing
        if path == "/agent/tools":
            return self._level_stub_response(2)

        # Level 3 — Task management
        if path == "/agent/tasks" or path.startswith("/agent/tasks/"):
            return self._level_stub_response(3)

        # Level 4 — Delegation
        if path == "/agent/delegate" or path.startswith("/agent/delegate/"):
            return self._level_stub_response(4)

        # Level 5 — Admin
        if path == "/agent/admin" or path.startswith("/agent/admin/"):
            return self._level_stub_response(5)

        # Everything else → 404
        err = not_found(f"No route for {method} {path}")
        return self._error_response(err)

    # ------------------------------------------------------------------
    # Built-in endpoint handlers
    # ------------------------------------------------------------------

    def _agent_json_response(self) -> tuple[int, dict[str, Any], str]:
        """Return the agent.json document."""
        payload = self.agent_json.model_dump(mode="json")
        return (
            200,
            {"Content-Type": "application/json"},
            json.dumps(payload),
        )

    def _health_response(self) -> tuple[int, dict[str, Any], str]:
        """Return a HealthResponse."""
        uptime = int(time.monotonic() - self._start_time)
        health = HealthResponse(
            status="healthy",
            protocol_version=CURRENT_VERSION,
            uptime_seconds=uptime,
        )
        return (
            200,
            {"Content-Type": "application/json"},
            json.dumps(health.model_dump(mode="json")),
        )

    def _stream_placeholder(self) -> tuple[int, dict[str, Any], str]:
        """Placeholder for SSE streaming endpoint."""
        return (
            200,
            {"Content-Type": "text/event-stream"},
            'event: heartbeat\ndata: {"seq": 1}\n\n',
        )

    def _level_stub_response(self, level: int) -> tuple[int, dict[str, Any], str]:
        """Return 501 Not Implemented for a protocol level 2-5 endpoint.

        This is semantically correct: the endpoint exists in the AMP spec
        but this server has not implemented it yet.  A 404 would wrongly
        imply the endpoint is unknown to the protocol.
        """
        err = not_implemented(
            f"Level {level} endpoint not yet available"
        )
        payload = err.model_dump(mode="json", exclude_none=True)
        payload["protocol_level"] = level
        return (
            501,
            {"Content-Type": "application/problem+json"},
            json.dumps(payload),
        )

    # ------------------------------------------------------------------
    # Message handling pipeline
    # ------------------------------------------------------------------

    async def _handle_message_request(self, request: HTTPRequest) -> HTTPResponse:
        """Full security pipeline for ``POST /agent/message``.

        Order follows WIRE-BINDING Appendix D, except that deduplication
        runs *after* authentication and is keyed by the authenticated
        caller: replaying a cached response to an unauthenticated party
        would let anyone who learns a message id read its reply.
        """
        policy = self.security

        def problem(err: ProblemDetail, extra: dict[str, str] | None = None) -> HTTPResponse:
            status, headers, body = self._error_response(err)
            hdrs = _lower(headers)
            hdrs["protocol-version"] = CURRENT_VERSION
            if extra:
                hdrs.update({k.lower(): v for k, v in extra.items()})
            return HTTPResponse(status, hdrs, body.encode("utf-8"))

        # Authentication.
        try:
            principal = await authenticate(request, policy.authenticators)
        except Unauthorized as exc:
            logger.info("Rejected credential on /agent/message: %s", exc)
            return problem(unauthorized(), {"WWW-Authenticate": 'Bearer realm="amp"'})
        if principal is None:
            if policy.require_auth:
                return problem(unauthorized(), {"WWW-Authenticate": 'Bearer realm="amp"'})
            principal = ANONYMOUS

        # Rate limiting — by principal, or by peer address when anonymous.
        # The limit state is reported on every response (Section 12.4).
        rate_key = principal.id if principal is not ANONYMOUS else f"ip:{request.client}"
        rl_headers: dict[str, str] = {}
        if policy.rate_limiter is not None:
            allowed, info = policy.rate_limiter.check(rate_key)
            rl_headers = {
                "X-RateLimit-Limit": str(info.limit),
                "X-RateLimit-Remaining": str(info.remaining),
                "X-RateLimit-Reset": str(info.reset),
            }
            if not allowed:
                retry = max(1, info.reset - int(time.time()))
                return problem(
                    rate_limited("Rate limit exceeded", retry_after=retry),
                    {**rl_headers, "Retry-After": str(retry)},
                )

        # A request without Content-Type is JSON (Section 3.2).
        content_type = request.header("content-type") or "application/json"
        content_type = content_type.split(";")[0].strip().lower()
        if content_type != "application/json" and not content_type.endswith("+json"):
            from ampro.wire.errors import content_type_mismatch

            return problem(
                content_type_mismatch("Content-Type must be application/json"), rl_headers
            )

        try:
            payload = request.json()
        except ValueError:
            return problem(invalid_message("Request body is not valid JSON"), rl_headers)

        status, headers, body = await self._handle_message(
            payload,
            principal=principal,
            accept_version=request.header("accept-version"),
        )
        hdrs = _lower(headers)
        hdrs.update({k.lower(): v for k, v in rl_headers.items()})
        return HTTPResponse(status, hdrs, body.encode("utf-8"))

    def _addresses(self) -> set[str]:
        from ampro.delegation.chain import normalize_agent_uri

        names = {self.agent_id, *self.agent_json.identifiers, *self.security.aliases}
        return {normalize_agent_uri(n) for n in names}

    async def _handle_message(
        self,
        body: dict[str, Any] | None,
        *,
        principal: Principal | None = None,
        accept_version: str | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """Validate and dispatch one AMP envelope.

        *principal* is the authenticated caller; ``None`` (the legacy
        :meth:`route` entry point, which has no headers) means anonymous.
        *accept_version* is the HTTP ``Accept-Version`` header, if any; an
        ``Accept-Version`` envelope header takes precedence.  Every
        response carries the negotiated ``Protocol-Version`` (Section 18.4).
        """
        status, headers, body_str = await self._handle_envelope(
            body, principal or ANONYMOUS, accept_version
        )
        return status, {"Protocol-Version": CURRENT_VERSION, **headers}, body_str

    async def _handle_envelope(
        self,
        body: dict[str, Any] | None,
        principal: Principal,
        accept_version: str | None,
    ) -> tuple[int, dict[str, Any], str]:
        policy = self.security

        # Step 1: Parse body as AgentMessage (Pydantic validation).
        if body is None:
            err = invalid_message("Request body is required")
            return self._error_response(err)

        try:
            msg = AgentMessage.model_validate(body)
        except ValidationError as exc:
            err = invalid_message(f"Invalid envelope: {exc.error_count()} validation error(s)")
            return self._error_response(err)

        # Step 2: Validate body against body_type schema.  An encrypted
        # envelope (``Content-Encryption``) carries ciphertext under the
        # plaintext body_type; its schema applies only after decryption,
        # which is the handler's (or a middleware's) job.
        encrypted = any(k.lower() == "content-encryption" for k in (msg.headers or {}))
        if encrypted:
            from ampro.security.encryption import EncryptedBody

            try:
                EncryptedBody.model_validate(msg.body)
            except ValidationError as exc:
                return self._error_response(invalid_message(
                    f"Encrypted body is malformed: {exc.error_count()} error(s)"
                ))
        elif msg.body is not None and isinstance(msg.body, dict):
            try:
                validate_body(msg.body_type, msg.body)
            except ValidationError as exc:
                err = invalid_message(
                    f"Body validation failed for '{msg.body_type}': "
                    f"{exc.error_count()} error(s)"
                )
                return self._error_response(err)

        # Sender binding: a principal proven to own an agent address may
        # only send as that address.
        if (
            policy.enforce_sender_binding
            and principal.claims.get("bound_sender")
            and msg.sender != principal.id
        ):
            return self._error_response(forbidden("Envelope sender does not match credential"))

        # Recipient check: refuse envelopes addressed to another agent so a
        # message signed for agent A cannot be replayed against agent B.
        if policy.enforce_recipient and msg.recipient:
            from ampro.delegation.chain import normalize_agent_uri

            if normalize_agent_uri(msg.recipient) not in self._addresses():
                return self._error_response(
                    invalid_message("Envelope recipient is not this agent")
                )

        # Version negotiation (Section 18.4; Appendix D places it after the
        # recipient check).
        requested = _header(msg.headers, "Accept-Version") or accept_version
        try:
            version = negotiate_version(requested) if requested else CURRENT_VERSION
        except ValueError:
            return self._error_response(version_mismatch(
                f"Requested protocol version {requested[:64]!r} is not supported",
                supported_versions=list(SUPPORTED_VERSIONS),
            ))

        status, headers, body_str = await self._dispatch_envelope(msg, principal)
        return status, {**headers, "Protocol-Version": version}, body_str

    async def _dispatch_envelope(
        self,
        msg: AgentMessage,
        principal: Principal,
    ) -> tuple[int, dict[str, Any], str]:
        policy = self.security

        # Loop detection on the Visited-Agents header.
        visited = (msg.headers or {}).get("Visited-Agents")
        if visited:
            from ampro.delegation.chain import (
                check_visited_agents_limit,
                check_visited_agents_loop,
            )

            if not check_visited_agents_limit(visited, policy.max_visited_agents):
                return self._error_response(loop_detected("Visited-Agents limit exceeded"))
            if any(check_visited_agents_loop(visited, a) for a in self._addresses()):
                return self._error_response(loop_detected("Message has already visited this agent"))

        # Step 3: Look up handler.
        handler = self._handlers.get(msg.body_type)
        if handler is None and self._app is None:
            handler = self._default_handler
        if handler is None:
            err = not_implemented(
                f"No handler registered for body_type '{msg.body_type}'"
            )
            return self._error_response(err)

        # Deduplication, keyed by caller so one party cannot read
        # another's cached reply.
        dedup_key = f"{principal.id}\x00{msg.sender}\x00{msg.id}"
        if policy.dedup is not None:
            claim = await policy.dedup.reserve(dedup_key)
            if isinstance(claim, CachedResponse):
                return claim.status, dict(claim.headers), claim.body.decode("utf-8")
            if claim is False:
                return self._error_response(
                    _conflict("A message with this id is already being processed")
                )

        # Concurrency.
        slot_key = principal.id if principal is not ANONYMOUS else msg.sender
        if policy.concurrency is not None and not policy.concurrency.acquire(slot_key):
            if policy.dedup is not None:
                await policy.dedup.release(dedup_key)
            return self._error_response(unavailable("Agent is at capacity", retry_after=5))

        try:
            response = await self._invoke(msg, handler, principal)
        finally:
            if policy.concurrency is not None:
                policy.concurrency.release(slot_key)

        if policy.dedup is not None:
            status, headers, body_str = response
            if status < 500:
                await policy.dedup.complete(
                    dedup_key, CachedResponse(status, dict(headers), body_str.encode("utf-8"))
                )
            else:
                await policy.dedup.release(dedup_key)
        return response

    async def _invoke(
        self,
        msg: AgentMessage,
        handler: Callable[..., Any],
        principal: Principal,
    ) -> tuple[int, dict[str, Any], str]:
        """Call the handler with a timeout and map failures to problems.

        Serialisation happens inside the same guard so a non-JSON result
        cannot escape as an unhandled exception.
        """
        tier = principal.trust_tier if principal is not ANONYMOUS else self.trust_tier

        async def call() -> Any:
            if self._app is not None:
                ctx = build_context(
                    self.agent_id,
                    msg,
                    trust_tier=tier,
                    principal=principal,
                    scopes=principal.scopes,
                    protocol="amp",
                )
                return await dispatch(self._app, msg, ctx)
            result = handler(msg)
            if inspect.isawaitable(result):
                result = await result
            return result

        try:
            limit = self.security.handler_timeout_seconds
            result = await (asyncio.wait_for(call(), limit) if limit else call())
            return self._success_response(result)
        except TimeoutError:
            logger.warning("Handler timed out for body_type '%s'", msg.body_type)
            return self._error_response(timeout("Handler did not finish in time"))
        except AMPError as exc:
            logger.info("Handler rejected body_type '%s': %s", msg.body_type, exc)
            return self._error_response(exc.to_problem_detail(status=400))
        except Exception:
            logger.exception("Handler raised for body_type '%s'", msg.body_type)
            err = internal_error(
                "An unexpected error occurred while processing the request."
            )
            return self._error_response(err)

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_response(
        problem: ProblemDetail,
    ) -> tuple[int, dict[str, Any], str]:
        """Format an RFC 7807 error response."""
        return (
            problem.status,
            {"Content-Type": "application/problem+json"},
            json.dumps(problem.model_dump(mode="json", exclude_none=True)),
        )

    @staticmethod
    def _success_response(
        result: Any,
    ) -> tuple[int, dict[str, Any], str]:
        """Format a 202 Accepted success response."""
        if isinstance(result, AgentMessage):
            payload = result.model_dump(mode="json")
        elif isinstance(result, BaseModel):
            payload = result.model_dump(mode="json")
        elif isinstance(result, dict):
            payload = result
        else:
            payload = {"result": result}

        return (
            202,
            {"Content-Type": "application/json"},
            json.dumps(payload),
        )

    # ------------------------------------------------------------------
    # Server runners (optional — require framework deps)
    # ------------------------------------------------------------------

    def run(
        self,
        port: int = 8000,
        adapter: str = "asgi",
        host: str = "127.0.0.1",
    ) -> None:
        """Start the server.

        Args:
            port:    TCP port to listen on.
            adapter: ``"asgi"`` (default, served by uvicorn), ``"fastapi"``
                     (alias of ``"asgi"``, kept for compatibility) or
                     ``"flask"``.
            host:    Interface to bind.  Defaults to loopback; pass
                     ``"0.0.0.0"`` explicitly to listen on all interfaces.
        """
        if adapter in ("asgi", "fastapi"):
            self._run_asgi(host, port)
        elif adapter == "flask":
            self._run_flask(host, port)
        else:
            raise ValueError(f"Unknown adapter '{adapter}'. Use 'asgi' or 'flask'.")

    def _run_asgi(self, host: str, port: int) -> None:
        """Start with uvicorn."""
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError(
                "Running the server requires 'uvicorn'. "
                "Install it: pip install 'ampro[server]'"
            ) from exc
        uvicorn.run(self.asgi(), host=host, port=port)

    def _run_flask(self, host: str, port: int) -> None:
        """Start with Flask (no streaming support)."""
        try:
            from flask import Flask, Response
            from flask import request as flask_request
        except ImportError as exc:
            raise RuntimeError(
                "Flask adapter requires 'flask'. "
                "Install it: pip install 'ampro[flask]'"
            ) from exc

        app = Flask(__name__)

        @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "DELETE", "PUT"])
        @app.route("/<path:path>", methods=["GET", "POST", "DELETE", "PUT"])
        def catch_all(path: str):  # type: ignore[no-untyped-def]
            req = HTTPRequest(
                method=flask_request.method,
                path="/" + path,
                headers={k.lower(): v for k, v in flask_request.headers.items()},
                query=dict(flask_request.args),
                body=flask_request.get_data(),
            )
            resp = asyncio.run(self.handle(req))
            if resp.is_streaming:
                return Response("Streaming requires the ASGI adapter", status=501)
            return Response(resp.body, status=resp.status, headers=resp.headers)

        app.run(host=host, port=port)


def _conflict(detail: str) -> ProblemDetail:
    from ampro.wire.errors import nonce_replay

    err = nonce_replay(detail)
    return err


def _header(headers: dict[str, str] | None, name: str) -> str | None:
    """Case-insensitive envelope header lookup."""
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return None


def _lower(headers: dict[str, Any]) -> dict[str, str]:
    return {k.lower(): str(v) for k, v in headers.items()}
