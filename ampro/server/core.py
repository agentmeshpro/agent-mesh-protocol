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
from ampro.core.versioning import CURRENT_VERSION
from ampro.server.http import HTTPRequest, HTTPResponse, ProtocolAdapter
from ampro.trust.tiers import TrustTier
from ampro.wire.config import DEFAULTS, WireConfig
from ampro.wire.errors import (
    ProblemDetail,
    internal_error,
    invalid_message,
    not_found,
    not_implemented,
    payload_too_large,
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

    # ------------------------------------------------------------------
    # Alternate constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_app(cls, app: AgentApp) -> AgentServer:
        """Create an AgentServer from an AgentApp.

        AMPI handlers are called as ``(msg, ctx)`` through the same
        dispatcher as :class:`~ampro.server.test.TestServer`, so the
        app's middleware and ``@on_error`` hook run too.
        """

        server = cls(
            agent_id=app.agent_id,
            endpoint=app.endpoint,
            agent_json=app.agent_json,
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

        for adapter in self._adapters:
            response = await adapter.handle(request)
            if response is not None:
                return response

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
            "event: ping\ndata: {}\n\n",
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

    async def _handle_message(
        self,
        body: dict[str, Any] | None,
    ) -> tuple[int, dict[str, Any], str]:
        """Process POST /agent/message."""

        # Step 1: Parse body as AgentMessage (Pydantic validation).
        if body is None:
            err = invalid_message("Request body is required")
            return self._error_response(err)

        try:
            msg = AgentMessage.model_validate(body)
        except ValidationError as exc:
            err = invalid_message(f"Invalid envelope: {exc.error_count()} validation error(s)")
            return self._error_response(err)

        # Step 2: Validate body against body_type schema.
        if msg.body is not None and isinstance(msg.body, dict):
            try:
                validate_body(msg.body_type, msg.body)
            except ValidationError as exc:
                err = invalid_message(
                    f"Body validation failed for '{msg.body_type}': "
                    f"{exc.error_count()} error(s)"
                )
                return self._error_response(err)

        # Step 3: Look up handler.
        handler = self._handlers.get(msg.body_type)
        if handler is None and self._app is None:
            handler = self._default_handler
        if handler is None:
            err = not_implemented(
                f"No handler registered for body_type '{msg.body_type}'"
            )
            return self._error_response(err)

        # Step 4: Call handler (supports sync and async), then serialise
        # inside the same guard so a non-JSON result cannot escape as an
        # unhandled exception.
        try:
            if self._app is not None:
                ctx = build_context(self.agent_id, msg, trust_tier=self.trust_tier)
                result = await dispatch(self._app, msg, ctx)
            else:
                result = handler(msg)
                if inspect.isawaitable(result):
                    result = await result
            return self._success_response(result)
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


def _lower(headers: dict[str, Any]) -> dict[str, str]:
    return {k.lower(): str(v) for k, v in headers.items()}
