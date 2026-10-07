"""MCP server adapter — serve an AMPI agent's tools over Streamable HTTP.

Mount on an :class:`~ampro.server.core.AgentServer`::

    server = AgentServer.from_app(agent)
    server.mount(MCPAdapter.for_server(server))       # POST/DELETE /mcp

or run ``ampro-server agent:agent --protocols amp,mcp``.

Two protocol eras are served from the one endpoint:

* **Handshake era** (2024-11-05 … 2025-11-25): ``initialize`` →
  ``Mcp-Session-Id`` → ``notifications/initialized`` → ``tools/*``.
  JSON-RPC batches are accepted only on 2025-03-26 sessions.
* **Modern era** (2026-07-28): stateless; selected by the
  ``MCP-Protocol-Version`` header; ``server/discover`` and per-request
  ``params._meta`` envelopes with header/body consistency checks.

Responses are always ``application/json`` (the SSE response form is
optional for servers).  There is no server-initiated stream, so ``GET``
answers ``405``.

Security: Origin validation (DNS-rebinding defence required by the MCP
transport spec), an optional ``authenticator`` hook, per-tool scope
enforcement, sessions bound to the principal that created them, and a
bounded session store with idle expiry.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import functools
import inspect
import json
import logging
import secrets
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

from ampro.ampi.dispatch import build_context, dispatch
from ampro.ampi.errors import AMPError
from ampro.core.envelope import AgentMessage
from ampro.interop.mcp import protocol as p
from ampro.interop.mcp.protocol import RPCError
from ampro.interop.mcp.tools import (
    ArgumentValidationError,
    ToolSpec,
    build_tool_spec,
    error_result,
    scopes_satisfied,
    to_call_result,
)
from ampro.server.http import HTTPRequest, HTTPResponse
from ampro.trust.tiers import TrustTier

if TYPE_CHECKING:
    from ampro.ampi.app import AgentApp
    from ampro.ampi.context import AMPContext
    from ampro.server.core import AgentServer

logger = logging.getLogger(__name__)

Authenticator = Callable[[HTTPRequest], Awaitable[Any]]

TASK_TOOL_NAME = "amp_task"
GENERIC_TOOL_ERROR = "Tool execution failed"
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_TASK_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "description": {
            "type": "string",
            "maxLength": 8192,
            "description": "What the agent should do, in natural language.",
        },
        "context": {
            "type": "object",
            "description": "Optional structured context passed to the agent.",
        },
        "priority": {
            "type": "string",
            "enum": ["low", "normal", "high", "urgent"],
            "default": "normal",
        },
        "task_id": {"type": "string", "maxLength": 256},
        "timeout_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
    },
    "required": ["description"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@dataclass
class MCPSession:
    """One handshake-era MCP session."""

    id: str
    protocol_version: str
    owner: str | None
    client_info: dict[str, Any] = field(default_factory=dict)
    initialized: bool = False
    created_at: float = 0.0
    last_seen: float = 0.0


@runtime_checkable
class SessionStore(Protocol):
    """Where handshake-era MCP sessions live.

    The default is :class:`InMemorySessionStore` (bounded, TTL-expiring,
    per-process).  Run several workers behind a load balancer?  Implement
    this protocol over a shared store (e.g. Redis) or use sticky sessions.

    ``get`` / ``delete`` must treat a session owned by a different
    principal exactly like an unknown one.
    """

    async def create(
        self, protocol_version: str, owner: str | None, client_info: dict[str, Any] | None = None
    ) -> MCPSession | None:
        """Create a session; ``None`` when at capacity."""
        ...

    async def get(self, session_id: str, owner: str | None) -> MCPSession | None: ...

    async def save(self, session: MCPSession) -> None:
        """Persist changes made to a session returned by :meth:`get`."""
        ...

    async def delete(self, session_id: str, owner: str | None) -> bool: ...


class InMemorySessionStore:
    """Bounded, expiring in-process session table (the default store).

    Sessions expire after *idle_timeout* seconds without traffic and after
    *max_lifetime* seconds regardless.  When full, expired sessions are
    purged first; if it is still full a new ``initialize`` is refused
    (``503``) rather than evicting live sessions, so one client cannot
    knock others off.
    """

    def __init__(
        self,
        max_sessions: int = 1024,
        idle_timeout: float = 3600.0,
        max_lifetime: float = 86400.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be >= 1")
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self.max_lifetime = max_lifetime
        self._clock = clock
        self._sessions: OrderedDict[str, MCPSession] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def _expired(self, session: MCPSession, now: float) -> bool:
        return (
            now - session.last_seen > self.idle_timeout
            or now - session.created_at > self.max_lifetime
        )

    def _purge(self) -> None:
        now = self._clock()
        for sid in [sid for sid, s in self._sessions.items() if self._expired(s, now)]:
            del self._sessions[sid]

    async def create(
        self, protocol_version: str, owner: str | None, client_info: dict[str, Any] | None = None
    ) -> MCPSession | None:
        if len(self._sessions) >= self.max_sessions:
            self._purge()
            if len(self._sessions) >= self.max_sessions:
                return None
        now = self._clock()
        session = MCPSession(
            id=secrets.token_hex(32),
            protocol_version=protocol_version,
            owner=owner,
            client_info=dict(client_info or {}),
            created_at=now,
            last_seen=now,
        )
        self._sessions[session.id] = session
        return session

    async def get(self, session_id: str, owner: str | None) -> MCPSession | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        now = self._clock()
        if self._expired(session, now):
            del self._sessions[session_id]
            return None
        if session.owner != owner:
            # Same answer as an unknown session: do not reveal it exists.
            return None
        session.last_seen = now
        self._sessions.move_to_end(session_id)
        return session

    async def save(self, session: MCPSession) -> None:
        if session.id in self._sessions:
            self._sessions[session.id] = session

    async def delete(self, session_id: str, owner: str | None) -> bool:
        if await self.get(session_id, owner) is None:
            return False
        del self._sessions[session_id]
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _principal_scopes(principal: Any) -> set[str]:
    if principal is None:
        return set()
    scopes = principal.get("scopes") if isinstance(principal, dict) else getattr(principal, "scopes", None)
    if scopes is None:
        return set()
    if isinstance(scopes, str):
        return set(scopes.split())
    return {str(s) for s in scopes}


def _principal_attr(principal: Any, name: str) -> Any:
    if principal is None:
        return None
    if isinstance(principal, dict):
        return principal.get(name)
    return getattr(principal, name, None)


def _principal_owner(principal: Any) -> str | None:
    if principal is None:
        return None
    pid = _principal_attr(principal, "id")
    return str(pid) if pid is not None else "authenticated"


def _resolve_tier(value: Any, default: TrustTier) -> TrustTier:
    if isinstance(value, TrustTier):
        return value
    if isinstance(value, str):
        try:
            return TrustTier(value)
        except ValueError:
            try:
                return TrustTier[value.upper()]
            except KeyError:
                return default
    return default


def _origin_is_local(origin: str) -> bool:
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    return (parts.hostname or "").lower() in _LOCAL_HOSTS


def _json_response(
    payload: Any, status: int = 200, headers: dict[str, str] | None = None
) -> HTTPResponse:
    return HTTPResponse.json(payload, status=status, headers=headers)


def _is_async_callable(fn: Any) -> bool:
    while isinstance(fn, functools.partial):
        fn = fn.func
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None))


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Any) -> int:
    if not isinstance(cursor, str) or len(cursor) > 256:
        raise RPCError(p.INVALID_PARAMS, "Invalid cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        offset = data["o"]
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise RPCError(p.INVALID_PARAMS, "Invalid cursor") from None
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise RPCError(p.INVALID_PARAMS, "Invalid cursor")
    return offset


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class MCPAdapter:
    """Serve an AMPI agent's tools as an MCP server (Streamable HTTP).

    Prefer :meth:`for_server`; the constructor is for embedding without an
    :class:`AgentServer`.
    """

    name = "mcp"

    def __init__(
        self,
        app: AgentApp | None,
        *,
        agent_id: str | None = None,
        path: str = "/mcp",
        authenticator: Authenticator | None = None,
        require_auth: bool = False,
        allowed_origins: Iterable[str] | None = None,
        expose_tasks: bool = True,
        trust_tier: TrustTier = TrustTier.EXTERNAL,
        task_handler: Callable[..., Any] | None = None,
        server_name: str | None = None,
        server_version: str | None = None,
        instructions: str | None = None,
        page_size: int = 100,
        max_sessions: int = 1024,
        session_idle_timeout: float = 3600.0,
        session_store: SessionStore | None = None,
        tool_timeout: float | None = 30.0,
        max_argument_bytes: int = 256 * 1024,
        run_sync_tools_in_thread: bool = True,
    ) -> None:
        self.app = app
        self.agent_id = agent_id or (app.agent_id if app is not None else "agent://unknown")
        self.path = "/" + path.strip("/")
        self.authenticator = authenticator
        self.require_auth = require_auth
        self.allowed_origins = None if allowed_origins is None else list(allowed_origins)
        self.expose_tasks = expose_tasks
        self.trust_tier = trust_tier
        self._task_handler = task_handler
        self.server_name = server_name or self.agent_id
        self.server_version = server_version or _package_version()
        self.instructions = instructions
        self.page_size = max(1, page_size)
        # ``is None`` (not ``or``): an empty store has len() == 0 and is falsy.
        self.sessions: SessionStore = (
            session_store
            if session_store is not None
            else InMemorySessionStore(max_sessions=max_sessions, idle_timeout=session_idle_timeout)
        )
        self.tool_timeout = tool_timeout
        self.max_argument_bytes = max_argument_bytes
        self.run_sync_tools_in_thread = run_sync_tools_in_thread
        if authenticator is None:
            logger.info(
                "MCP adapter at %s has no authenticator: any local client can call its tools. "
                "Configure authenticator=... and require_auth=True before binding beyond loopback.",
                self.path,
            )

    @classmethod
    def for_server(
        cls,
        server: AgentServer,
        *,
        path: str = "/mcp",
        authenticator: Authenticator | None = None,
        require_auth: bool = False,
        allowed_origins: Iterable[str] | None = None,
        expose_tasks: bool = True,
        **kwargs: Any,
    ) -> MCPAdapter:
        """Build an adapter serving *server*'s AMPI app (tools + ``task.create``)."""
        app = server.app
        task_handler = None
        if app is None:
            # Plain AgentServer: ``@server.on`` handlers take ``(msg)``.
            task_handler = getattr(server, "_handlers", {}).get("task.create")
        kwargs.setdefault("trust_tier", getattr(server, "trust_tier", TrustTier.EXTERNAL))
        return cls(
            app,
            agent_id=server.agent_id,
            path=path,
            authenticator=authenticator,
            require_auth=require_auth,
            allowed_origins=allowed_origins,
            expose_tasks=expose_tasks,
            task_handler=task_handler,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Tool registry
    # ------------------------------------------------------------------

    def _task_entry(self) -> tuple[Callable[..., Any] | None, bool]:
        """``(handler, is_ampi)`` for ``task.create``, if one is registered."""
        if self.app is not None:
            handler = self.app.handlers.get("task.create")
            return handler, True
        return self._task_handler, False

    def tool_specs(self) -> list[ToolSpec]:
        """All tools this adapter advertises, in registration order."""
        specs: list[ToolSpec] = []
        if self.app is not None:
            meta_table = getattr(self.app, "tool_meta", {}) or {}
            for name, fn in list(self.app.tools.items()):
                try:
                    specs.append(build_tool_spec(name, fn, meta_table.get(name)))
                except Exception:
                    logger.exception("Skipping MCP tool %r: cannot derive its schema", name)
        if self.expose_tasks and all(s.name != TASK_TOOL_NAME for s in specs):
            handler, _ = self._task_entry()
            if handler is not None:
                specs.append(self._task_spec(handler))
        return specs

    def _task_spec(self, handler: Callable[..., Any]) -> ToolSpec:
        meta = (getattr(self.app, "tool_meta", {}) or {}).get(TASK_TOOL_NAME, {}) if self.app else {}
        description = meta.get("description") or inspect.getdoc(handler) or ""
        lead = f"Send a task to the AMP agent {self.agent_id} and return its result."
        description = f"{lead}\n\n{description}".strip() if description else lead
        return ToolSpec(
            name=TASK_TOOL_NAME,
            fn=handler,
            description=description,
            input_schema=dict(_TASK_INPUT_SCHEMA),
            scopes=tuple(meta.get("scopes") or ()),
        )

    def _visible(self, spec: ToolSpec, principal: Any) -> bool:
        return not spec.scopes or scopes_satisfied(spec.scopes, _principal_scopes(principal))

    # ------------------------------------------------------------------
    # HTTP entry point
    # ------------------------------------------------------------------

    async def handle(self, request: HTTPRequest) -> HTTPResponse | None:
        if request.path.rstrip("/") != self.path.rstrip("/") and request.path != self.path:
            return None

        origin_error = self._check_origin(request)
        if origin_error is not None:
            return origin_error

        principal, auth_error = await self._authenticate(request)
        if auth_error is not None:
            return auth_error

        version_header = request.header(p.PROTOCOL_VERSION_HEADER)
        if version_header is not None and version_header not in p.HANDSHAKE_PROTOCOL_VERSIONS:
            # Modern era, or a version we do not speak (the modern ladder
            # answers that with -32022 naming what we support).
            return await self._handle_modern(request, principal, version_header)
        return await self._handle_handshake_era(request, principal, version_header)

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    def origin_allowed(self, origin: str | None) -> bool:
        """MCP transport spec: validate Origin to stop DNS-rebinding attacks.

        A missing Origin (non-browser client) is allowed.  With no
        ``allowed_origins`` configured, only localhost origins pass.
        Entries may be exact origins, ``"*"``, or ``"http://host:*"``.
        """
        if not origin:
            return True
        if self.allowed_origins is None:
            return _origin_is_local(origin)
        for allowed in self.allowed_origins:
            if allowed == "*" or allowed == origin:
                return True
            if allowed.endswith(":*") and origin.startswith(allowed[:-2] + ":"):
                return True
        return False

    def _check_origin(self, request: HTTPRequest) -> HTTPResponse | None:
        origin = request.header("origin")
        if self.origin_allowed(origin):
            return None
        logger.warning("MCP request rejected: Origin not allowed")
        return _json_response(
            p.error_message(None, p.INVALID_REQUEST, "Forbidden: Origin not allowed"), status=403
        )

    def _www_authenticate(self, error: str | None = None, scope: str | None = None) -> str:
        value = 'Bearer realm="mcp"'
        if error:
            value += f', error="{error}"'
        if scope:
            value += f', scope="{scope}"'
        return value

    def _unauthorized(self, error: str | None = None) -> HTTPResponse:
        return _json_response(
            p.error_message(None, p.INVALID_REQUEST, "Unauthorized"),
            status=401,
            headers={"WWW-Authenticate": self._www_authenticate(error)},
        )

    async def _authenticate(self, request: HTTPRequest) -> tuple[Any, HTTPResponse | None]:
        if self.authenticator is None:
            return None, None
        try:
            principal = await _maybe_await(self.authenticator(request))
        except Exception:
            logger.info("MCP authentication rejected", exc_info=True)
            return None, self._unauthorized("invalid_token")
        if principal is None and self.require_auth:
            return None, self._unauthorized()
        return principal, None

    # ------------------------------------------------------------------
    # Handshake era (2024-11-05 .. 2025-11-25)
    # ------------------------------------------------------------------

    async def _handle_handshake_era(
        self, request: HTTPRequest, principal: Any, version_header: str | None
    ) -> HTTPResponse:
        method = request.method.upper()
        if method == "GET":
            # No server-initiated SSE stream is offered.
            return HTTPResponse.empty(405, {"Allow": "POST, DELETE"})
        if method == "DELETE":
            return await self._handle_delete(request, principal)
        if method != "POST":
            return HTTPResponse.empty(405, {"Allow": "POST, DELETE"})

        pre = self._check_post_headers(request)
        if pre is not None:
            return pre
        try:
            payload = request.json()
        except (ValueError, RecursionError):
            return _json_response(p.error_message(None, p.PARSE_ERROR, "Parse error"), status=400)

        owner = _principal_owner(principal)

        if isinstance(payload, list):
            return await self._handle_batch(request, payload, principal, owner, version_header)

        kind = _classify(payload)
        if kind == "invalid":
            return _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Invalid JSON-RPC message"), status=400
            )
        if kind == "request" and payload["method"] == "initialize":
            return await self._initialize(payload, owner)

        session, err = await self._require_session(request, owner, version_header)
        if err is not None:
            return err
        assert session is not None
        headers = {p.SESSION_HEADER: session.id}

        if kind == "notification":
            await self._on_notification(session, payload)
            return HTTPResponse.empty(202, headers)
        if kind == "response":
            # We never send server→client requests, so there is nothing to match.
            return HTTPResponse.empty(202, headers)

        reply, status, extra = await self._answer(payload, principal, session.protocol_version, False)
        headers.update(extra)
        return _json_response(reply, status=status, headers=headers)

    def _check_post_headers(self, request: HTTPRequest) -> HTTPResponse | None:
        if not p.accepts_json(request.header("accept")):
            return _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Not Acceptable: client must accept application/json"),
                status=406,
            )
        if not p.is_json_content_type(request.header("content-type")):
            return _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Unsupported Media Type: use application/json"),
                status=415,
            )
        return None

    async def _require_session(
        self, request: HTTPRequest, owner: str | None, version_header: str | None
    ) -> tuple[MCPSession | None, HTTPResponse | None]:
        sid = request.header(p.SESSION_HEADER)
        if not sid:
            return None, _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Bad Request: missing Mcp-Session-Id header"),
                status=400,
            )
        session = await self.sessions.get(sid, owner)
        if session is None:
            return None, _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Not Found: unknown or expired session"),
                status=404,
            )
        if version_header is not None and version_header != session.protocol_version:
            return None, _json_response(
                p.error_message(
                    None,
                    p.INVALID_REQUEST,
                    "Bad Request: MCP-Protocol-Version does not match the negotiated version",
                ),
                status=400,
                headers={p.SESSION_HEADER: session.id},
            )
        return session, None

    async def _handle_delete(self, request: HTTPRequest, principal: Any) -> HTTPResponse:
        sid = request.header(p.SESSION_HEADER)
        if not sid:
            return _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Bad Request: missing Mcp-Session-Id header"),
                status=400,
            )
        if not await self.sessions.delete(sid, _principal_owner(principal)):
            return _json_response(
                p.error_message(None, p.INVALID_REQUEST, "Not Found: unknown or expired session"),
                status=404,
            )
        return HTTPResponse.empty(200)

    async def _initialize(self, message: dict[str, Any], owner: str | None) -> HTTPResponse:
        rid = message["id"]
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("protocolVersion"), str):
            return _json_response(
                p.error_message(rid, p.INVALID_PARAMS, "initialize requires params.protocolVersion")
            )
        requested = params["protocolVersion"]
        version = requested if requested in p.HANDSHAKE_PROTOCOL_VERSIONS else p.LATEST_HANDSHAKE_VERSION
        client_info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
        session = await self.sessions.create(version, owner, client_info)
        if session is None:
            logger.warning("Refusing MCP initialize: session store is full")
            return _json_response(
                p.error_message(rid, p.INTERNAL_ERROR, "Too many open sessions"), status=503
            )
        result: dict[str, Any] = {
            "protocolVersion": version,
            "capabilities": self._capabilities(),
            "serverInfo": self._server_info(),
        }
        if self.instructions:
            result["instructions"] = self.instructions
        return _json_response(
            p.result_message(rid, result), headers={p.SESSION_HEADER: session.id}
        )

    async def _on_notification(self, session: MCPSession, message: dict[str, Any]) -> None:
        if message.get("method") == "notifications/initialized" and not session.initialized:
            session.initialized = True
            await self.sessions.save(session)

    async def _handle_batch(
        self,
        request: HTTPRequest,
        batch: list[Any],
        principal: Any,
        owner: str | None,
        version_header: str | None,
    ) -> HTTPResponse:
        if not batch:
            return _json_response(p.error_message(None, p.INVALID_REQUEST, "Empty batch"), status=400)
        session, err = await self._require_session(request, owner, version_header)
        if err is not None:
            return err
        assert session is not None
        headers = {p.SESSION_HEADER: session.id}
        if session.protocol_version not in p.BATCH_PROTOCOL_VERSIONS:
            return _json_response(
                p.error_message(
                    None, p.INVALID_REQUEST, "JSON-RPC batches are not supported in this protocol version"
                ),
                status=400,
                headers=headers,
            )
        replies: list[dict[str, Any]] = []
        for item in batch:
            kind = _classify(item)
            if kind == "invalid":
                replies.append(p.error_message(None, p.INVALID_REQUEST, "Invalid JSON-RPC message"))
            elif kind == "notification":
                await self._on_notification(session, item)
            elif kind == "request":
                if item["method"] == "initialize":
                    replies.append(
                        p.error_message(item["id"], p.INVALID_REQUEST, "initialize must not be batched")
                    )
                    continue
                reply, _status, _extra = await self._answer(item, principal, session.protocol_version, False)
                replies.append(reply)
        if not replies:
            return HTTPResponse.empty(202, headers)
        return _json_response(replies, headers=headers)

    # ------------------------------------------------------------------
    # Modern era (2026-07-28)
    # ------------------------------------------------------------------

    async def _handle_modern(
        self, request: HTTPRequest, principal: Any, version_header: str
    ) -> HTTPResponse:
        if request.method.upper() != "POST":
            return HTTPResponse.empty(405, {"Allow": "POST"})
        pre = self._check_post_headers(request)
        if pre is not None:
            return pre
        try:
            payload = request.json()
        except (ValueError, RecursionError):
            return _json_response(p.error_message(None, p.PARSE_ERROR, "Parse error"), status=400)

        if isinstance(payload, dict) and "id" not in payload:
            # Notification: acknowledged and dropped (no client→server
            # notifications are defined on this wire).
            if _classify(payload) != "notification":
                return _json_response(_invalid_body(), status=400)
            if version_header not in p.MODERN_PROTOCOL_VERSIONS:
                return self._unsupported_version(None, version_header)
            return HTTPResponse.empty(202)
        if _classify(payload) != "request":
            return _json_response(_invalid_body(), status=400)

        rid = payload["id"]
        rejection = _modern_ladder(payload, request)
        if rejection is not None:
            code, message, data = rejection
            return _json_response(
                p.error_message(rid, code, message, data),
                status=p.MODERN_ERROR_HTTP_STATUS.get(code, 200),
            )
        version = payload["params"]["_meta"][p.META_PROTOCOL_VERSION]
        reply, status, extra = await self._answer(payload, principal, version, True)
        return _json_response(reply, status=status, headers=extra)

    def _unsupported_version(self, rid: Any, requested: Any) -> HTTPResponse:
        return _json_response(
            p.error_message(
                rid,
                p.UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
                p.unsupported_version_data(requested, p.MODERN_PROTOCOL_VERSIONS),
            ),
            status=400,
        )

    # ------------------------------------------------------------------
    # Method dispatch (both eras)
    # ------------------------------------------------------------------

    async def _answer(
        self, message: dict[str, Any], principal: Any, version: str, modern: bool
    ) -> tuple[dict[str, Any], int, dict[str, str]]:
        """Run one request; return ``(reply, http_status, extra_headers)``."""
        rid = message["id"]
        try:
            result = await self._call_method(message["method"], message.get("params"), principal, version, modern)
        except RPCError as exc:
            status = exc.http_status or (p.MODERN_ERROR_HTTP_STATUS.get(exc.code, 200) if modern else 200)
            return p.error_message(rid, exc.code, exc.message, exc.data), status, exc.headers
        except Exception:
            ref = uuid.uuid4().hex[:16]
            logger.exception("MCP method %r failed [ref=%s]", message.get("method"), ref)
            return p.error_message(rid, p.INTERNAL_ERROR, f"Internal error (reference {ref})"), 200, {}
        if modern:
            result.setdefault("resultType", "complete")
            meta = result.setdefault("_meta", {})
            meta.setdefault(p.META_SERVER_INFO, self._server_info())
        return p.result_message(rid, result), 200, {}

    async def _call_method(
        self, method: str, params: Any, principal: Any, version: str, modern: bool
    ) -> dict[str, Any]:
        if params is not None and not isinstance(params, dict):
            raise RPCError(p.INVALID_PARAMS, "params must be an object")
        params = params or {}
        if method == "ping" and not modern:
            return {}
        if method == "server/discover" and modern:
            result: dict[str, Any] = {
                "supportedVersions": list(p.MODERN_PROTOCOL_VERSIONS),
                "capabilities": self._capabilities(),
                "ttlMs": 0,
                "cacheScope": "private",
            }
            if self.instructions:
                result["instructions"] = self.instructions
            return result
        if method == "tools/list":
            result = self._list_tools(params, principal)
            if modern:
                result["ttlMs"] = 0
                result["cacheScope"] = "private"
            return result
        if method == "tools/call":
            return await self._call_tool(params, principal, version)
        raise RPCError(p.METHOD_NOT_FOUND, "Method not found")

    def _capabilities(self) -> dict[str, Any]:
        return {"tools": {"listChanged": False}}

    def _server_info(self) -> dict[str, Any]:
        return {"name": self.server_name, "version": self.server_version}

    def _list_tools(self, params: dict[str, Any], principal: Any) -> dict[str, Any]:
        cursor = params.get("cursor")
        offset = 0 if cursor is None else _decode_cursor(cursor)
        visible = [s for s in self.tool_specs() if self._visible(s, principal)]
        if offset > len(visible):
            raise RPCError(p.INVALID_PARAMS, "Invalid cursor")
        page = visible[offset : offset + self.page_size]
        result: dict[str, Any] = {"tools": [s.to_mcp() for s in page]}
        if offset + self.page_size < len(visible):
            result["nextCursor"] = _encode_cursor(offset + self.page_size)
        return result

    async def _call_tool(self, params: dict[str, Any], principal: Any, version: str) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(name, str):
            raise RPCError(p.INVALID_PARAMS, "tools/call requires params.name")
        if arguments is not None and not isinstance(arguments, dict):
            raise RPCError(p.INVALID_PARAMS, "tools/call params.arguments must be an object")
        spec = next((s for s in self.tool_specs() if s.name == name), None)
        if spec is None:
            raise RPCError(p.INVALID_PARAMS, f"Unknown tool: {name[:128]}")
        if not self._visible(spec, principal):
            if principal is None and self.authenticator is not None:
                raise RPCError(
                    p.INVALID_REQUEST,
                    "Unauthorized",
                    http_status=401,
                    headers={"WWW-Authenticate": self._www_authenticate()},
                )
            raise RPCError(
                p.INVALID_REQUEST,
                "Forbidden: insufficient scope",
                http_status=403,
                headers={
                    "WWW-Authenticate": self._www_authenticate(
                        "insufficient_scope", " ".join(spec.scopes)
                    )
                },
            )
        arguments = arguments or {}
        try:
            size = len(json.dumps(arguments, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise RPCError(p.INVALID_PARAMS, "tools/call arguments are not valid JSON") from None
        if size > self.max_argument_bytes:
            raise RPCError(
                p.INVALID_PARAMS,
                "tools/call arguments too large",
                {"maxBytes": self.max_argument_bytes},
            )
        if spec.name == TASK_TOOL_NAME and spec.fn is self._task_entry()[0]:
            return await self._run_task(arguments, principal)
        return await self._run_tool(spec, arguments, principal)

    def _context(self, principal: Any, message: AgentMessage) -> AMPContext:
        tier = _resolve_tier(_principal_attr(principal, "trust_tier"), self.trust_tier)
        ctx = build_context(self.agent_id, message, trust_tier=tier)
        try:
            ctx.protocol = "mcp"  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - frozen/slotted contexts
            pass
        return ctx

    def _sender(self, principal: Any) -> str:
        pid = _principal_attr(principal, "id")
        return str(pid)[:512] if pid is not None else "mcp://anonymous"

    async def _execute(self, label: str, call: Callable[[], Awaitable[Any]]) -> tuple[Any, dict | None]:
        """Run *call* under the tool timeout; ``(value, None)`` or ``(None, error_result)``.

        Failures are logged server-side with a reference id; the caller only
        sees a generic message carrying that reference — never exception text.
        """
        try:
            if self.tool_timeout is None:
                return await call(), None
            return await asyncio.wait_for(call(), self.tool_timeout), None
        except asyncio.TimeoutError:
            ref = uuid.uuid4().hex[:16]
            logger.warning("MCP %s timed out after %ss [ref=%s]", label, self.tool_timeout, ref)
            return None, error_result(f"Tool execution timed out (reference {ref})")
        except AMPError as exc:
            # Deliberate, caller-facing AMP error: expose its code only.
            ref = uuid.uuid4().hex[:16]
            logger.info("MCP %s raised AMPError %s [ref=%s]", label, exc.code, ref)
            return None, error_result(f"Tool error: {exc.code} (reference {ref})")
        except Exception:
            ref = uuid.uuid4().hex[:16]
            logger.exception("MCP %s raised [ref=%s]", label, ref)
            return None, error_result(f"{GENERIC_TOOL_ERROR} (reference {ref})")

    def _result(self, label: str, value: Any) -> dict[str, Any]:
        try:
            return to_call_result(value)
        except Exception:
            ref = uuid.uuid4().hex[:16]
            logger.exception("MCP %s returned an unserialisable value [ref=%s]", label, ref)
            return error_result(f"{GENERIC_TOOL_ERROR} (reference {ref})")

    async def _run_tool(self, spec: ToolSpec, arguments: dict[str, Any], principal: Any) -> dict[str, Any]:
        label = f"tool {spec.name!r}"
        try:
            args, kwargs = spec.bind(arguments)
        except ArgumentValidationError as exc:
            logger.info("MCP %s rejected arguments: %s", label, exc.fields)
            return error_result(str(exc))
        if spec.ctx_param is not None:
            message = AgentMessage(
                sender=self._sender(principal),
                recipient=self.agent_id,
                body_type="tool.invoke",
                body={"tool": spec.name},
            )
            kwargs[spec.ctx_param] = self._context(principal, message)

        async def call() -> Any:
            fn = spec.fn
            if self.run_sync_tools_in_thread and not _is_async_callable(fn):
                # Keep blocking tools off the event loop (and under the timeout).
                return await _maybe_await(await asyncio.to_thread(fn, *args, **kwargs))
            return await _maybe_await(fn(*args, **kwargs))

        value, error = await self._execute(label, call)
        return error if error is not None else self._result(label, value)

    async def _run_task(self, arguments: dict[str, Any], principal: Any) -> dict[str, Any]:
        from ampro.core.body_schemas import TaskCreateBody

        unknown = sorted(set(arguments) - set(_TASK_INPUT_SCHEMA["properties"]))
        if unknown:
            return error_result(str(ArgumentValidationError(unknown)))
        try:
            body = TaskCreateBody.model_validate_json(json.dumps(arguments), strict=True)
        except ValidationError as exc:
            fields = sorted({".".join(str(x) for x in e.get("loc", ())) for e in exc.errors()})
            return error_result(str(ArgumentValidationError(fields)))
        message = AgentMessage(
            sender=self._sender(principal),
            recipient=self.agent_id,
            body_type="task.create",
            body=body.model_dump(mode="json", exclude_none=True),
            headers={"Protocol": "mcp"},
        )
        handler, is_ampi = self._task_entry()

        async def call() -> Any:
            if is_ampi and self.app is not None:
                return await dispatch(self.app, message, self._context(principal, message))
            assert handler is not None
            return await _maybe_await(handler(message))

        result, error = await self._execute(f"tool {TASK_TOOL_NAME!r}", call)
        if error is not None:
            return error
        if isinstance(result, AgentMessage):
            result = result.model_dump(mode="json")
        elif isinstance(result, BaseModel):
            result = result.model_dump(mode="json")
        if not isinstance(result, dict):
            result = {"result": result}
        return self._result(f"tool {TASK_TOOL_NAME!r}", result)


# ---------------------------------------------------------------------------
# JSON-RPC classification
# ---------------------------------------------------------------------------


def _classify(message: Any) -> str:
    """``request`` | ``notification`` | ``response`` | ``invalid``."""
    if not isinstance(message, dict) or message.get("jsonrpc") != p.JSONRPC_VERSION:
        return "invalid"
    if "method" in message:
        if not isinstance(message["method"], str):
            return "invalid"
        if "params" in message and not isinstance(message["params"], (dict, type(None))):
            return "invalid"
        if "id" in message:
            return "request" if p.is_valid_id(message["id"]) else "invalid"
        return "notification"
    if "id" in message and ("result" in message or "error" in message):
        return "response"
    return "invalid"


def _invalid_body() -> dict[str, Any]:
    return p.error_message(
        None, p.INVALID_REQUEST, "Body must be a single JSON-RPC request or notification object"
    )


def _modern_ladder(body: dict[str, Any], request: HTTPRequest) -> tuple[int, str, Any] | None:
    """The 2026-07-28 per-request envelope checks; first failure wins."""
    params = body.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if not isinstance(meta, dict):
        return (
            p.INVALID_PARAMS,
            f"params._meta must be an object carrying the required {p.META_PROTOCOL_VERSION!r} "
            f"and {p.META_CLIENT_CAPABILITIES!r} envelope keys",
            None,
        )
    missing = [k for k in (p.META_PROTOCOL_VERSION, p.META_CLIENT_CAPABILITIES) if k not in meta]
    if missing:
        return (
            p.INVALID_PARAMS,
            f"params._meta is missing the required envelope key(s): {', '.join(missing)}",
            None,
        )
    version = meta[p.META_PROTOCOL_VERSION]
    if request.header(p.PROTOCOL_VERSION_HEADER) != version:
        return p.HEADER_MISMATCH, "mcp-protocol-version header does not match the request envelope", None
    method = body["method"]
    if request.header(p.METHOD_HEADER) != method:
        return p.HEADER_MISMATCH, "mcp-method header does not match the request body's method", None
    name_key = p.NAME_BEARING_METHODS.get(method)
    if name_key is not None and isinstance(params, dict):
        value = params.get(name_key)
        if value is not None and _decode_header_value(request.header(p.NAME_HEADER)) != value:
            return p.HEADER_MISMATCH, f"mcp-name header does not match the request body's {name_key!r}", None
    if not isinstance(version, str):
        return p.INVALID_PARAMS, "the protocol-version envelope value must be a string", None
    if version not in p.MODERN_PROTOCOL_VERSIONS:
        return (
            p.UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            p.unsupported_version_data(version, p.MODERN_PROTOCOL_VERSIONS),
        )
    return None


def _decode_header_value(value: str | None) -> str | None:
    """Undo the ``=?base64?...?=`` sentinel used for non-token header values."""
    if value is None:
        return None
    if value.startswith("=?base64?") and value.endswith("?=") and len(value) >= 11:
        payload = value[len("=?base64?") : -2]
        try:
            decoded = base64.b64decode(payload, validate=True)
            if base64.b64encode(decoded).decode("ascii") != payload:
                return None
            return decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
    return value


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("ampro")
    except Exception:
        return "0"


__all__ = ["InMemorySessionStore", "MCPAdapter", "MCPSession", "SessionStore", "TASK_TOOL_NAME"]
