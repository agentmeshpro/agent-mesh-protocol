"""A2A 1.0 protocol adapter for :class:`~ampro.server.core.AgentServer`.

Serves an AMP agent over Google A2A 1.0 — the HTTP+JSON binding and the
JSON-RPC 2.0 binding — next to its native AMP routes::

    server = AgentServer.from_app(app)
    server.mount(A2AAdapter.for_server(server, public_url="https://agent.example"))

Routes (``{base}`` = ``base_path``, default ``/a2a``)::

    GET  /.well-known/agent-card.json            agent card (unauthenticated)
    GET  {base}/.well-known/agent-card.json      agent card (unauthenticated)
    POST {base}                                  JSON-RPC 2.0 (SendMessage, ...)
    POST {base}/message:send                     SendMessage
    POST {base}/message:stream                   SendStreamingMessage (SSE)
    GET  {base}/tasks                            ListTasks
    GET  {base}/tasks/{id}                       GetTask
    POST {base}/tasks/{id}:cancel                CancelTask
    GET|POST {base}/tasks/{id}:subscribe         SubscribeToTask (SSE)
    *    {base}/tasks/{id}/pushNotificationConfigs[/{cfg}]  PUSH_NOTIFICATION_NOT_SUPPORTED
    GET  {base}/extendedAgentCard                EXTENDED_AGENT_CARD_NOT_CONFIGURED

Anything else under ``{base}`` is ``404`` (``405`` for a known path with
the wrong method) with no body; paths outside ``{base}`` return ``None`` so
the AMP routes keep working.  Routing happens before authentication, and
authentication before the body is parsed.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import time
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ampro.ampi.dispatch import build_context, dispatch
from ampro.ampi.errors import AMPError, StreamLimitExceeded
from ampro.core.body_schemas import validate_body
from ampro.core.envelope import AgentMessage
from ampro.identity.auth_methods import AuthMethod
from ampro.interop.a2a.auth import (
    ANONYMOUS,
    ANONYMOUS_SENDER,
    Authenticator,
    AuthRequired,
    AuthRequiredKeys,
    Principal,
    Unauthorized,
    authenticate,
    is_anonymous,
    www_authenticate,
)
from ampro.interop.a2a.card import AMP_EXTENSION_URI, build_agent_card
from ampro.interop.a2a.errors import A2AError
from ampro.interop.a2a.mapping import (
    Reply,
    a2a_to_amp,
    agent_message,
    amp_reply_metadata,
    apply_amp_metadata,
    auth_required_reply,
    new_id,
    read_amp_metadata,
    result_to_reply,
    value_to_parts,
)
from ampro.interop.a2a.store import (
    PENDING,
    ContextStore,
    IdempotencyStore,
    InMemoryContextStore,
    InMemoryIdempotencyStore,
    InMemoryTaskStore,
    TaskStore,
)
from ampro.interop.a2a.types import (
    A2A_JSON_MEDIA_TYPE,
    A2A_PROTOCOL_VERSION,
    AGENT_CARD_PATH,
    AgentCard,
    Artifact,
    Message,
    Part,
    Role,
    SendMessageRequest,
    Task,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    dump,
    now_timestamp,
)
from ampro.server.http import HTTPRequest, HTTPResponse
from ampro.streaming.events import MAX_SSE_EVENT_BYTES, StreamingEvent, StreamingEventType

if TYPE_CHECKING:
    from ampro.ampi.context import AMPContext
    from ampro.server.core import AgentServer

logger = logging.getLogger(__name__)

_TASK_ROUTE = re.compile(r"^/tasks/([^/:]+)(:cancel|:subscribe)?$")
_PUSH_ROUTE = re.compile(r"^/tasks/([^/:]+)/pushNotificationConfigs(/[^/]+)?$")
_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 100
_STREAM_QUEUE = 256

_SILENT_EVENTS = frozenset({
    StreamingEventType.HEARTBEAT,
    StreamingEventType.DONE,
    StreamingEventType.STREAM_ACK,
    StreamingEventType.STREAM_PAUSE,
    StreamingEventType.STREAM_RESUME,
    StreamingEventType.STREAM_CHANNEL_OPEN,
    StreamingEventType.STREAM_CHANNEL_CLOSE,
    StreamingEventType.STREAM_CHECKPOINT,
    StreamingEventType.STREAM_AUTH_REFRESH,
})

TEXT_MODES = ("text/plain",)


class _Unset:
    pass


_UNSET = _Unset()
DEFAULT_INPUT_MODES = ("text/plain", "application/json", "*/*")


@dataclass
class _Call:
    """Per-request state shared by both bindings."""

    principal: Principal
    extensions: frozenset[str]
    request: HTTPRequest
    request_id: str = ""

    @property
    def amp_active(self) -> bool:
        return AMP_EXTENSION_URI in self.extensions


@dataclass
class _Prepared:
    call: _Call
    request: SendMessageRequest
    message: Message
    context_id: str
    task_id: str
    continuing: Task | None
    amp_message: AgentMessage
    ctx: AMPContext
    history_length: int | None
    return_immediately: bool
    released: bool = False


@dataclass
class _Live:
    """A task whose handler is still running (stream or background)."""

    runner: asyncio.Task[Any] | None = None
    subscribers: list[asyncio.Queue[dict[str, Any] | None]] = field(default_factory=list)

    def publish(self, item: dict[str, Any] | None) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:  # slow subscriber: drop it
                self.subscribers.remove(q)


class _AppView:
    """The app as :func:`dispatch` sees it, with an error hook that lets
    :class:`AuthRequired` / :class:`A2AError` through before the app's own
    ``@on_error`` hook runs."""

    def __init__(self, app: Any) -> None:
        self.handlers = app.handlers
        self.middleware_chain = app.middleware_chain
        user_hook = app.error_handler

        async def hook(exc: Exception, msg: AgentMessage, ctx: Any) -> Any:
            if isinstance(exc, (AuthRequired, A2AError)) or user_hook is None:
                raise exc
            result = user_hook(exc, msg, ctx)
            if inspect.isawaitable(result):
                result = await result
            return result

        self.error_handler = hook


class A2AAdapter:
    """Serve an AMP agent over A2A 1.0.  See the module docstring for routes.

    Args:
        server: the :class:`AgentServer` whose handlers answer A2A traffic.
        base_path: path prefix of the A2A interface (e.g. ``"/a2a"`` or
            ``"/a2a/brand-42"``).
        public_url: externally visible origin used in the card
            (default: the agent's AMP ``endpoint``).
        authenticators: tried in order — see :mod:`ampro.interop.a2a.auth`
            (default: ``server.security.authenticators``).
        require_auth: reject unauthenticated callers with ``401``
            (default: ``server.security.require_auth``).
        task_store / context_store / idempotency_store: state backends
            (defaults: bounded in-memory stores, see :mod:`.store`).
        card: a fixed :class:`AgentCard`; otherwise one is built per request
            from the options below and the server's handlers.
        name / description / version / skills / provider: card fields.
        security_schemes / security_requirements: extra card security
            declarations (proto JSON shape, see :func:`card.bearer_scheme`).
        input_modes: accepted input media types.  ``("text/plain",)`` makes
            data/file parts ``CONTENT_TYPE_NOT_SUPPORTED``.
        auth_required_keys: metadata keys on ``AUTH_REQUIRED`` tasks.
        amp_metadata_key: metadata key of the AMP extension object
            (default: the extension URI; ``"amp"`` is also read).
        accept_unknown_contexts: let callers start a conversation with a
            ``contextId`` the server never issued (bound to the caller).
        serve_root_card: also serve ``/.well-known/agent-card.json``.
        streaming: advertise and serve ``message:stream`` / subscribe.
        max_parts: maximum parts per message.
        max_text_chars: maximum total characters across text parts.
        max_metadata_bytes: maximum JSON size of request / message metadata.
        handler_timeout: seconds a handler may run per request (``None`` =
            unbounded; default: ``server.security.handler_timeout_seconds``);
            on expiry the task fails with a generic message.

    The server's ``security.rate_limiter`` and ``security.concurrency`` apply
    to every A2A request (keyed by principal id, or ``ip:<peer>`` when
    anonymous): ``429`` with ``Retry-After`` / ``503`` with no body.
    """

    name = "a2a"

    def __init__(
        self,
        server: AgentServer,
        *,
        base_path: str = "/a2a",
        public_url: str | None = None,
        authenticators: Iterable[Authenticator] | None = None,
        require_auth: bool | None = None,
        task_store: TaskStore | None = None,
        context_store: ContextStore | None = None,
        idempotency_store: IdempotencyStore | None = None,
        card: AgentCard | None = None,
        name: str | None = None,
        description: str | None = None,
        version: str = "1.0.0",
        skills: Iterable[Any] | None = None,
        provider: Any = None,
        security_schemes: dict[str, dict[str, Any]] | None = None,
        security_requirements: Iterable[Any] | None = None,
        input_modes: Sequence[str] = DEFAULT_INPUT_MODES,
        output_modes: Sequence[str] = ("text/plain", "application/json"),
        auth_required_keys: AuthRequiredKeys = AuthRequiredKeys(),
        amp_metadata_key: str = AMP_EXTENSION_URI,
        accept_unknown_contexts: bool = False,
        serve_root_card: bool = True,
        streaming: bool = True,
        max_parts: int = 64,
        max_text_chars: int = 65_536,
        max_metadata_bytes: int = 16_384,
        handler_timeout: float | None | _Unset = _UNSET,
        realm: str = "a2a",
    ) -> None:
        self.server = server
        self.base_path = "/" + base_path.strip("/") if base_path.strip("/") else ""
        self.public_url = public_url
        policy = getattr(server, "security", None)
        if authenticators is None:
            authenticators = policy.authenticators if policy is not None else ()
        if require_auth is None:
            require_auth = bool(policy.require_auth) if policy is not None else False
        if isinstance(handler_timeout, _Unset):
            handler_timeout = policy.handler_timeout_seconds if policy is not None else 120.0
        self.authenticators = list(authenticators)
        self.require_auth = require_auth
        self.store: TaskStore = task_store if task_store is not None else InMemoryTaskStore()
        self.contexts: ContextStore = (context_store if context_store is not None
                                       else InMemoryContextStore())
        self.replies: IdempotencyStore = (idempotency_store if idempotency_store is not None
                                          else InMemoryIdempotencyStore())
        self._card = card
        self._card_options: dict[str, Any] = {
            "name": name, "description": description, "version": version,
            "skills": list(skills) if skills is not None else None,
            "provider": provider, "security_schemes": security_schemes,
            "security_requirements": (list(security_requirements)
                                      if security_requirements is not None else None),
            "streaming": streaming,
        }
        self.input_modes = tuple(input_modes)
        self.output_modes = tuple(output_modes)
        self.auth_required_keys = auth_required_keys
        self.amp_metadata_key = amp_metadata_key
        self.accept_unknown_contexts = accept_unknown_contexts
        self.serve_root_card = serve_root_card
        self.streaming = streaming
        self.max_parts = max_parts
        self.max_text_chars = max_text_chars
        self.max_metadata_bytes = max_metadata_bytes
        self.handler_timeout = handler_timeout
        self.realm = realm
        self._live: dict[str, _Live] = {}
        self._busy_tasks: set[str] = set()
        self._background: set[asyncio.Task[Any]] = set()

    @classmethod
    def for_server(
        cls,
        server: AgentServer,
        *,
        base_path: str = "/a2a",
        public_url: str | None = None,
        authenticators: Iterable[Authenticator] | None = None,
        require_auth: bool | None = None,
        task_store: TaskStore | None = None,
        **options: Any,
    ) -> A2AAdapter:
        """Create an adapter for *server* (mount it with ``server.mount``)."""
        return cls(server, base_path=base_path, public_url=public_url,
                   authenticators=authenticators, require_auth=require_auth,
                   task_store=task_store, **options)

    # ------------------------------------------------------------------
    # Card
    # ------------------------------------------------------------------

    @property
    def agent_card(self) -> AgentCard:
        if self._card is not None:
            return self._card
        card = build_agent_card(self.server, public_url=self.public_url,
                                base_path=self.base_path, **self._card_options)
        card.default_input_modes = [m for m in self.input_modes if m != "*/*"] or ["text/plain"]
        card.default_output_modes = list(self.output_modes)
        return card

    @property
    def interface_url(self) -> str:
        return (self.public_url or self.server.endpoint).rstrip("/") + self.base_path

    async def close_context(self, context_id: str) -> None:
        """Close a conversation; later messages to it get ``UNSUPPORTED_OPERATION``."""
        await self.contexts.close_context(context_id)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def handle(self, request: HTTPRequest) -> HTTPResponse | None:
        method = request.method.upper()
        path = request.path.rstrip("/") or "/"

        card_paths = {self.base_path + AGENT_CARD_PATH}
        if self.serve_root_card:
            card_paths.add(AGENT_CARD_PATH)
        if path in card_paths:
            if method not in ("GET", "HEAD"):
                return HTTPResponse.empty(405, {"allow": "GET"})
            return HTTPResponse.json(dump(self.agent_card))

        base = self.base_path
        if base and path != base and not path.startswith(base + "/"):
            return None
        rel = path[len(base):] if base else path
        if rel == "/":
            rel = ""

        route = self._route(method, rel)
        if route is None:
            return None if not base else HTTPResponse.empty(404)
        if isinstance(route, HTTPResponse):
            return route
        kind, arg = route

        # Authentication (before the body is parsed).
        principal_or_resp = await self._authenticate(request)
        if isinstance(principal_or_resp, HTTPResponse):
            return principal_or_resp
        request_id = (request.header("x-request-id") or "")[:64] or new_id()
        call = _Call(principal_or_resp, self._activated_extensions(request), request, request_id)

        # Same rate / concurrency limits as the native AMP route.
        policy = getattr(self.server, "security", None)
        limit_key = (call.principal.id if not is_anonymous(call.principal)
                     else f"ip:{request.client}")
        if policy is not None and policy.rate_limiter is not None:
            allowed, info = policy.rate_limiter.check(limit_key)
            if not allowed:
                retry = max(1, int(info.reset - time.time()))
                return HTTPResponse.empty(429, {
                    "retry-after": str(retry),
                    "x-ratelimit-limit": str(info.limit),
                    "x-ratelimit-remaining": str(info.remaining),
                    "x-ratelimit-reset": str(info.reset),
                })
        limiter = policy.concurrency if policy is not None else None
        if limiter is not None and not limiter.acquire(limit_key):
            return HTTPResponse.empty(503, {"retry-after": "5"})
        try:
            response = await self._dispatch(kind, arg, call)
        except BaseException:
            if limiter is not None:
                limiter.release(limit_key)
            raise
        if limiter is None:
            return response
        if not response.is_streaming:
            limiter.release(limit_key)
            return response
        inner = response.body

        async def released() -> AsyncIterator[bytes]:
            try:
                async for chunk in inner:  # type: ignore[union-attr]
                    yield chunk
            finally:
                limiter.release(limit_key)

        response.body = released()
        return response

    async def _dispatch(self, kind: str, arg: str | None, call: _Call) -> HTTPResponse:
        if kind == "jsonrpc":
            return await self._handle_jsonrpc(call)
        try:
            self._check_version(call.request)
            return await self._handle_rest(kind, arg, call)
        except A2AError as exc:
            return self._rest_error(exc, call)
        except Exception:
            logger.exception("A2A request failed (request_id=%s)", call.request_id)
            return self._rest_error(A2AError("INTERNAL_ERROR"), call)

    def _route(self, method: str, rel: str) -> tuple[str, str | None] | HTTPResponse | None:
        def allow(*methods: str) -> HTTPResponse:
            return HTTPResponse.empty(405, {"allow": ", ".join(methods)})

        if rel == "":
            return ("jsonrpc", None) if method == "POST" else allow("POST")
        if rel == "/message:send":
            return ("send", None) if method == "POST" else allow("POST")
        if rel == "/message:stream":
            return ("stream", None) if method == "POST" else allow("POST")
        if rel == "/tasks":
            return ("list", None) if method == "GET" else allow("GET")
        if rel == "/extendedAgentCard":
            return ("extended_card", None) if method == "GET" else allow("GET")
        m = _TASK_ROUTE.match(rel)
        if m:
            task_id, action = m.group(1), m.group(2)
            if action == ":cancel":
                return ("cancel", task_id) if method == "POST" else allow("POST")
            if action == ":subscribe":
                return ("subscribe", task_id) if method in ("GET", "POST") else allow("GET", "POST")
            return ("get", task_id) if method == "GET" else allow("GET")
        if _PUSH_ROUTE.match(rel):
            if method in ("GET", "POST", "DELETE"):
                return ("push", None)
            return allow("GET", "POST", "DELETE")
        return HTTPResponse.empty(404) if self.base_path else None

    # ------------------------------------------------------------------
    # Auth / headers
    # ------------------------------------------------------------------

    async def _authenticate(self, request: HTTPRequest) -> Principal | HTTPResponse:
        try:
            principal = await authenticate(request, self.authenticators)
        except Unauthorized as exc:
            logger.info("A2A authentication rejected: %s", exc)
            return self._unauthorized(getattr(exc, "error", None))
        except Exception:
            logger.exception("A2A authenticator failed")
            return self._unauthorized(None)
        if principal is not None:
            return principal
        if self.require_auth:
            return self._unauthorized(None)
        return ANONYMOUS

    def _unauthorized(self, error: str | None) -> HTTPResponse:
        return HTTPResponse.empty(401, {"www-authenticate": www_authenticate(error, self.realm)})

    def _activated_extensions(self, request: HTTPRequest) -> frozenset[str]:
        raw = request.header("a2a-extensions") or request.header("x-a2a-extensions") or ""
        requested = {e.strip() for e in raw.split(",") if e.strip()}
        return frozenset(requested & {AMP_EXTENSION_URI})

    @staticmethod
    def _check_version(request: HTTPRequest) -> None:
        version = (request.header("a2a-version") or request.query.get("A2A-Version") or "").strip()
        if version and version.split(".")[0] != A2A_PROTOCOL_VERSION.split(".")[0]:
            raise A2AError("VERSION_NOT_SUPPORTED",
                           f"A2A version '{version[:16]}' is not supported; expected 1.x")

    def _headers(self, call: _Call, content_type: str = A2A_JSON_MEDIA_TYPE) -> dict[str, str]:
        headers = {"content-type": content_type, "a2a-version": A2A_PROTOCOL_VERSION}
        if call.extensions:
            headers["a2a-extensions"] = ", ".join(sorted(call.extensions))
        return headers

    def _rest_error(self, exc: A2AError, call: _Call) -> HTTPResponse:
        return HTTPResponse(exc.http_status, self._headers(call),
                            json.dumps(exc.rest_payload()).encode("utf-8"))

    # ------------------------------------------------------------------
    # HTTP+JSON binding
    # ------------------------------------------------------------------

    async def _handle_rest(self, kind: str, arg: str | None, call: _Call) -> HTTPResponse:
        if kind == "push":
            raise A2AError("PUSH_NOTIFICATION_NOT_SUPPORTED")
        if kind == "extended_card":
            raise A2AError("EXTENDED_AGENT_CARD_NOT_CONFIGURED")
        if kind == "get":
            assert arg is not None
            task = await self.op_get_task(arg, call, _int_param(call.request.query, "historyLength"))
            return self._ok(task, call)
        if kind == "cancel":
            assert arg is not None
            return self._ok(await self.op_cancel_task(arg, call), call)
        if kind == "list":
            return self._ok(await self.op_list_tasks(dict(call.request.query), call), call)

        if kind in ("stream", "subscribe") and not self.streaming:
            raise A2AError("UNSUPPORTED_OPERATION", "Streaming is not supported")
        if kind == "subscribe":
            assert arg is not None
            stream = self.op_subscribe(arg, call)
        else:
            try:
                body = call.request.json()
            except ValueError:
                raise A2AError("INVALID_REQUEST", "Request body is not valid JSON") from None
            if kind == "send":
                return self._ok(await self.op_send_message(body, call), call)
            stream = self.op_stream_message(body, call)

        first = await _first(stream)  # errors before the first event -> HTTP error

        async def sse() -> AsyncIterator[bytes]:
            try:
                if first is not None:
                    yield _sse(first)
                    async for item in stream:
                        yield _sse(item)
            except A2AError as exc:
                yield _sse(exc.rest_payload(), event="error")
            except Exception:
                logger.exception("A2A stream failed")
                yield _sse(A2AError("INTERNAL_ERROR").rest_payload(), event="error")
            finally:
                await stream.aclose()

        headers = self._headers(call, "text/event-stream")
        headers["cache-control"] = "no-store"
        return HTTPResponse(200, headers, sse())

    def _ok(self, payload: dict[str, Any], call: _Call) -> HTTPResponse:
        return HTTPResponse(200, self._headers(call), json.dumps(payload).encode("utf-8"))

    # ------------------------------------------------------------------
    # JSON-RPC binding
    # ------------------------------------------------------------------

    async def _handle_jsonrpc(self, call: _Call) -> HTTPResponse:
        def reply(payload: dict[str, Any]) -> HTTPResponse:
            return HTTPResponse(200, self._headers(call, "application/json"),
                                json.dumps(payload).encode("utf-8"))

        def error(rid: Any, exc: A2AError) -> HTTPResponse:
            return reply({"jsonrpc": "2.0", "id": rid, "error": exc.jsonrpc_error()})

        try:
            body = call.request.json()
        except ValueError:
            return error(None, A2AError("PARSE_ERROR"))
        if isinstance(body, list):
            return error(None, A2AError("INVALID_REQUEST", "Batch requests are not supported"))
        if not isinstance(body, dict):
            return error(None, A2AError("INVALID_REQUEST"))
        rid = body.get("id")
        if rid is not None and (not isinstance(rid, (str, int)) or isinstance(rid, bool)):
            rid = None
        if body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
            return error(rid, A2AError("INVALID_REQUEST",
                                       "Invalid request: 'jsonrpc' must be '2.0' and 'method' a string"))
        method: str = body["method"]
        params = body.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return error(rid, A2AError("INVALID_PARAMS", "params must be an object"))

        try:
            self._check_version(call.request)
            if method in ("SendStreamingMessage", "SubscribeToTask"):
                if not self.streaming:
                    raise A2AError("UNSUPPORTED_OPERATION", "Streaming is not supported")
                if method == "SubscribeToTask":
                    stream = self.op_subscribe(_str_param(params, "id"), call)
                else:
                    stream = self.op_stream_message(params, call)
                first = await _first(stream)
            else:
                result = await self._jsonrpc_unary(method, params, call)
                return reply({"jsonrpc": "2.0", "id": rid, "result": result})
        except A2AError as exc:
            return error(rid, exc)
        except Exception:
            logger.exception("A2A JSON-RPC request failed")
            return error(rid, A2AError("INTERNAL_ERROR"))

        async def sse() -> AsyncIterator[bytes]:
            try:
                if first is not None:
                    yield _sse({"jsonrpc": "2.0", "id": rid, "result": first})
                    async for item in stream:
                        yield _sse({"jsonrpc": "2.0", "id": rid, "result": item})
            except A2AError as exc:
                yield _sse({"jsonrpc": "2.0", "id": rid, "error": exc.jsonrpc_error()}, event="error")
            except Exception:
                logger.exception("A2A JSON-RPC stream failed")
                yield _sse({"jsonrpc": "2.0", "id": rid,
                            "error": A2AError("INTERNAL_ERROR").jsonrpc_error()}, event="error")
            finally:
                await stream.aclose()

        headers = self._headers(call, "text/event-stream")
        headers["cache-control"] = "no-store"
        return HTTPResponse(200, headers, sse())

    async def _jsonrpc_unary(self, method: str, params: dict[str, Any], call: _Call) -> Any:
        if method == "SendMessage":
            return await self.op_send_message(params, call)
        if method == "GetTask":
            return await self.op_get_task(_str_param(params, "id"), call,
                                          _int_param(params, "historyLength"))
        if method == "CancelTask":
            return await self.op_cancel_task(_str_param(params, "id"), call)
        if method == "ListTasks":
            return await self.op_list_tasks(params, call)
        if method in ("CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig",
                      "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig"):
            raise A2AError("PUSH_NOTIFICATION_NOT_SUPPORTED")
        if method == "GetExtendedAgentCard":
            raise A2AError("EXTENDED_AGENT_CARD_NOT_CONFIGURED")
        raise A2AError("METHOD_NOT_FOUND")

    # ------------------------------------------------------------------
    # Operations (binding-independent; raise A2AError)
    # ------------------------------------------------------------------

    async def op_get_task(self, task_id: str, call: _Call,
                          history_length: int | None = None) -> dict[str, Any]:
        task = await self.store.get_task(task_id, call.principal.id)
        if task is None:
            raise A2AError("TASK_NOT_FOUND")
        return dump(_trim_history(task, history_length))

    async def op_cancel_task(self, task_id: str, call: _Call) -> dict[str, Any]:
        owner = call.principal.id
        task = await self.store.get_task(task_id, owner)
        if task is None:
            raise A2AError("TASK_NOT_FOUND")
        if task.status.state.is_terminal:
            raise A2AError("TASK_NOT_CANCELABLE")
        live = self._live.get(task_id)
        if live is not None and live.runner is not None and not live.runner.done():
            live.runner.cancel()
        task.status = TaskStatus(state=TaskState.CANCELED, timestamp=now_timestamp())
        await self.store.save_task(task, owner)
        if live is not None:
            live.publish({"statusUpdate": dump(TaskStatusUpdateEvent(
                task_id=task.id, context_id=task.context_id, status=task.status))})
            live.publish(None)
        return dump(task)

    async def op_list_tasks(self, params: dict[str, Any], call: _Call) -> dict[str, Any]:
        page_size = _int_param(params, "pageSize")
        if page_size is None:
            page_size = _DEFAULT_PAGE_SIZE
        if not 1 <= page_size <= _MAX_PAGE_SIZE:
            raise A2AError("INVALID_PARAMS", f"pageSize must be between 1 and {_MAX_PAGE_SIZE}")
        token = params.get("pageToken") or ""
        try:
            offset = int(token) if token else 0
            if offset < 0:
                raise ValueError
        except (TypeError, ValueError):
            raise A2AError("INVALID_PARAMS", "Invalid pageToken") from None
        state = None
        if params.get("status") not in (None, "", "TASK_STATE_UNSPECIFIED", 0):
            try:
                state = TaskState.parse(params["status"])
            except ValueError:
                raise A2AError("INVALID_PARAMS", "Invalid status filter") from None
        history_length = _int_param(params, "historyLength")
        include_artifacts = str(params.get("includeArtifacts", "")).lower() in ("true", "1")
        after = _parse_ts(params.get("statusTimestampAfter"))

        if is_anonymous(call.principal):
            tasks: list[Task] = []  # anonymous callers share an id; never list
        else:
            context_id = params.get("contextId") or None
            tasks = await self.store.list_tasks(
                call.principal.id,
                context_id=str(context_id) if context_id else None,
                state=state,
            )
        if after is not None:
            tasks = [t for t in tasks
                     if (ts := _parse_ts(t.status.timestamp)) is not None and ts >= after]
        total = len(tasks)
        page = tasks[offset:offset + page_size]
        out = []
        for t in page:
            t = _trim_history(t, history_length)
            if not include_artifacts:
                t = t.model_copy(update={"artifacts": None})
            out.append(dump(t))
        next_token = str(offset + page_size) if offset + page_size < total else ""
        return {"tasks": out, "nextPageToken": next_token, "pageSize": page_size,
                "totalSize": total}

    async def op_send_message(self, body: Any, call: _Call) -> dict[str, Any]:
        prep_or_reply = await self._prepare(body, call)
        if isinstance(prep_or_reply, dict):
            return prep_or_reply
        prep = prep_or_reply
        try:
            if prep.return_immediately:
                return await self._start_background(prep)
            reply = await self._run(prep)
            payload = await self._finish(prep, reply)
        except BaseException:
            await self._release(prep, None)
            raise
        await self._release(prep, payload)
        return payload

    async def op_stream_message(self, body: Any, call: _Call) -> AsyncIterator[dict[str, Any]]:
        prep_or_reply = await self._prepare(body, call)
        if isinstance(prep_or_reply, dict):
            yield prep_or_reply  # idempotent retry: the stored reply
            return
        prep = prep_or_reply
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_STREAM_QUEUE)
        live = _Live()
        streamed: list[Part] = []
        artifact_id = new_id()
        state = {"started": False}

        async def push(event: TaskStatusUpdateEvent | TaskArtifactUpdateEvent) -> None:
            key = "statusUpdate" if isinstance(event, TaskStatusUpdateEvent) else "artifactUpdate"
            await queue.put({key: dump(event)})

        self._bind_emit(prep, push, streamed, artifact_id)
        runner = asyncio.ensure_future(self._run(prep))
        live.runner = runner
        payload: dict[str, Any] | None = None
        try:
            while True:
                getter = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait({getter, runner}, return_when=asyncio.FIRST_COMPLETED)
                if getter in done:
                    item = getter.result()
                    if not state["started"]:
                        state["started"] = True
                        working = self._working_task(prep)
                        await self.store.save_task(working, prep.call.principal.id)
                        self._live[prep.task_id] = live
                        first = {"task": dump(working)}
                        live.publish(first)
                        yield first
                    live.publish(item)
                    yield item
                    continue
                getter.cancel()
                break
            # Drain anything emitted right before the handler returned.
            pending: list[dict[str, Any]] = []
            while not queue.empty():
                pending.append(queue.get_nowait())
            if runner.cancelled():
                reply = None
            else:
                reply = runner.result()  # raises the handler's A2AError / exception
            if not state["started"] and reply is not None:
                payload = await self._finish(prep, reply)
                yield payload
                return
            if not state["started"]:
                # Canceled before anything was emitted.
                return
            for item in pending:
                live.publish(item)
                yield item
            async for item in self._final_events(prep, reply, streamed, artifact_id):
                live.publish(item)
                yield item
            task = await self.store.get_task(prep.task_id, prep.call.principal.id)
            payload = {"task": dump(task)} if task is not None else None
        finally:
            if not runner.done():
                runner.cancel()
            live.publish(None)
            self._live.pop(prep.task_id, None)
            await self._release(prep, payload)

    async def op_subscribe(self, task_id: str, call: _Call) -> AsyncIterator[dict[str, Any]]:
        task = await self.store.get_task(task_id, call.principal.id)
        if task is None:
            raise A2AError("TASK_NOT_FOUND")
        if task.status.state.is_terminal:
            raise A2AError("UNSUPPORTED_OPERATION",
                           "Task is in a terminal state and cannot be subscribed to")
        live = self._live.get(task_id)
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=_STREAM_QUEUE)
        if live is not None:
            live.subscribers.append(queue)
        try:
            yield {"task": dump(task)}
            if live is None:
                return
            while True:
                item = await queue.get()
                if item is None:
                    return
                if "task" in item:
                    continue
                yield item
        finally:
            if live is not None and queue in live.subscribers:
                live.subscribers.remove(queue)

    # ------------------------------------------------------------------
    # Message pipeline
    # ------------------------------------------------------------------

    async def _prepare(self, body: Any, call: _Call) -> _Prepared | dict[str, Any]:
        if not isinstance(body, dict):
            raise A2AError("INVALID_PARAMS", "Request body must be a SendMessageRequest object")
        try:
            req = SendMessageRequest.model_validate(body)
        except ValidationError as exc:
            raise A2AError("INVALID_PARAMS",
                           f"Invalid SendMessageRequest ({exc.error_count()} error(s))") from None
        msg = req.message
        self._validate_message(msg)
        for meta in (req.metadata, msg.metadata):
            if meta and len(json.dumps(meta)) > self.max_metadata_bytes:
                raise A2AError("INVALID_PARAMS", "metadata is too large")
        owner = call.principal.id
        cfg = req.configuration
        history_length = cfg.history_length if cfg else None
        if history_length is not None and history_length < 0:
            raise A2AError("INVALID_PARAMS", "historyLength must be non-negative")

        continuing: Task | None = None
        if msg.task_id:
            continuing = await self.store.get_task(msg.task_id, owner)
            if continuing is None:
                raise A2AError("TASK_NOT_FOUND")
            if msg.context_id and continuing.context_id != msg.context_id:
                raise A2AError("INVALID_PARAMS", "contextId does not match the task")
            if not continuing.status.state.is_interrupted:
                raise A2AError("UNSUPPORTED_OPERATION",
                               "Task does not accept messages in its current state")
            context_id = continuing.context_id or new_id()
            task_id = continuing.id
        elif msg.context_id:
            context_id = msg.context_id
            task_id = new_id()
        else:
            context_id = new_id()
            task_id = new_id()

        if not await self.contexts.claim_context(
            context_id, owner,
            create=msg.context_id is None or self.accept_unknown_contexts,
        ):
            raise A2AError("INVALID_PARAMS", "Invalid contextId")
        if await self.contexts.is_context_closed(context_id):
            raise A2AError("UNSUPPORTED_OPERATION", "This conversation is closed")

        stored = await self.replies.begin_message(context_id, msg.message_id)
        if stored is PENDING:
            raise A2AError("INVALID_PARAMS", "A message with this messageId is still in progress")
        if isinstance(stored, dict):
            return stored

        if continuing is not None:
            if task_id in self._busy_tasks:
                await self.replies.finish_message(context_id, msg.message_id, None)
                raise A2AError("UNSUPPORTED_OPERATION", "Task is busy")
            self._busy_tasks.add(task_id)
        try:
            amp_message, ctx = self._build_amp(msg, req, call, context_id, task_id, continuing)
        except BaseException:
            if continuing is not None:
                self._busy_tasks.discard(task_id)
            await self.replies.finish_message(context_id, msg.message_id, None)
            raise
        return _Prepared(
            call=call, request=req, message=msg, context_id=context_id, task_id=task_id,
            continuing=continuing, amp_message=amp_message, ctx=ctx,
            history_length=history_length,
            return_immediately=bool(cfg and cfg.return_immediately),
        )

    def _validate_message(self, msg: Message) -> None:
        if msg.role != Role.USER:
            raise A2AError("INVALID_PARAMS", "message.role must be ROLE_USER")
        if not msg.parts:
            raise A2AError("INVALID_PARAMS", "message.parts must not be empty")
        if len(msg.parts) > self.max_parts:
            raise A2AError("INVALID_PARAMS", f"At most {self.max_parts} parts are allowed")
        modes = set(self.input_modes)
        wildcard = "*/*" in modes
        for p in msg.parts:
            if p.text is not None:
                continue
            if p.data is not None:
                if not (wildcard or "application/json" in modes):
                    raise A2AError("CONTENT_TYPE_NOT_SUPPORTED", "Data parts are not supported")
            elif not (wildcard or (p.media_type and p.media_type in modes)):
                raise A2AError("CONTENT_TYPE_NOT_SUPPORTED", "File parts are not supported")
        if sum(len(p.text) for p in msg.parts if p.text is not None) > self.max_text_chars:
            raise A2AError("INVALID_PARAMS", f"Text exceeds {self.max_text_chars} characters")
        has_content = any(
            (p.text is not None and p.text.strip()) or p.text is None for p in msg.parts
        )
        if not has_content:
            raise A2AError("INVALID_PARAMS", "message must contain non-blank text")

    def _handlers(self) -> dict[str, Callable[..., Any]]:
        return self.server._handlers

    def _body_type(self, continuing: Task | None) -> str:
        if continuing is not None:
            return "task.response"
        handlers = self._handlers()
        if "task.create" in handlers:
            return "task.create"
        if "message" in handlers:
            return "message"
        return "task.create"

    def _build_amp(self, msg: Message, req: SendMessageRequest, call: _Call,
                   context_id: str, task_id: str,
                   continuing: Task | None) -> tuple[AgentMessage, AMPContext]:
        principal = call.principal
        amp_message = a2a_to_amp(
            msg, agent_id=self.server.agent_id,
            sender=ANONYMOUS_SENDER if is_anonymous(principal) else principal.id,
            context_id=context_id, task_id=task_id, continuing=continuing,
            body_type=self._body_type(continuing),
        )
        try:
            validate_body(amp_message.body_type, amp_message.body)
        except ValidationError as exc:
            raise A2AError("INVALID_PARAMS",
                           f"Message does not fit '{amp_message.body_type}' "
                           f"({exc.error_count()} error(s))") from None
        auth_method = None
        if principal.auth_method:
            try:
                auth_method = AuthMethod(principal.auth_method)
            except ValueError:
                auth_method = None
        ctx = build_context(
            self.server.agent_id, amp_message,
            trust_tier=principal.trust_tier,
            principal=None if is_anonymous(principal) else principal,
            scopes=frozenset(principal.scopes),
            protocol="a2a",
            auth_method=auth_method,
            metadata={
                "a2a.message": msg,
                "a2a.request": req,
                "a2a.contextId": context_id,
                "a2a.taskId": task_id,
                "a2a.extensions": call.extensions,
            },
        )
        if call.amp_active:
            amp = read_amp_metadata(req.metadata, msg.metadata,
                                    keys=(self.amp_metadata_key, "amp"))
            if amp:
                apply_amp_metadata(ctx, amp)

        contexts = self.contexts

        async def close_session() -> None:
            await contexts.close_context(context_id)

        ctx.close_session = close_session  # type: ignore[method-assign]
        # Non-streaming default: events are accepted and dropped.
        self._bind_emit_noop(ctx)
        return amp_message, ctx

    @staticmethod
    def _bind_emit_noop(ctx: AMPContext) -> None:
        async def emit(event: Any) -> None:
            return None

        async def emit_event(topic: str, data: dict) -> None:
            return None

        ctx.emit = emit  # type: ignore[method-assign]
        ctx.emit_event = emit_event  # type: ignore[method-assign]

    def _bind_emit(self, prep: _Prepared, push: Callable[..., Any],
                   streamed: list[Part], artifact_id: str) -> None:
        """Route ``ctx.emit`` / ``ctx.emit_event`` to A2A stream events.

        Events larger than :data:`MAX_SSE_EVENT_BYTES` raise
        :class:`StreamLimitExceeded` in the handler.
        """
        ctx = prep.ctx
        raw_push = push

        async def push(event: TaskStatusUpdateEvent | TaskArtifactUpdateEvent) -> None:
            size = len(event.model_dump_json(by_alias=True, exclude_none=True))
            if size > MAX_SSE_EVENT_BYTES:
                raise StreamLimitExceeded("stream event too large",
                                          limit=MAX_SSE_EVENT_BYTES, current=size)
            await raw_push(event)

        task_id, context_id = prep.task_id, prep.context_id
        counter = {"chunks": 0}

        def status(parts: list[Part], meta: dict[str, Any]) -> TaskStatusUpdateEvent:
            return TaskStatusUpdateEvent(
                task_id=task_id, context_id=context_id,
                status=TaskStatus(
                    state=TaskState.WORKING, timestamp=now_timestamp(),
                    message=agent_message(parts, context_id=context_id, task_id=task_id),
                ),
                metadata=meta,
            )

        async def emit(event: Any) -> None:
            if isinstance(event, (TaskStatusUpdateEvent, TaskArtifactUpdateEvent)):
                await push(event.model_copy(update={"task_id": task_id, "context_id": context_id}))
                return
            if not isinstance(event, StreamingEvent):
                event = StreamingEvent.model_validate(event)
            if event.type in _SILENT_EVENTS:
                return
            if event.type == StreamingEventType.TEXT_DELTA:
                text = event.data.get("text", event.data.get("delta", ""))
                part = Part(text=str(text))
                streamed.append(part)
                await push(TaskArtifactUpdateEvent(
                    task_id=task_id, context_id=context_id,
                    artifact=Artifact(artifact_id=artifact_id, name="response", parts=[part]),
                    append=counter["chunks"] > 0, last_chunk=False,
                ))
                counter["chunks"] += 1
                return
            await push(status([Part(data={"type": event.type.value, **event.data})],
                              {"amp.event": event.type.value}))

        async def emit_event(topic: str, data: dict) -> None:
            await push(status([Part(data={"topic": topic, "data": data})],
                              {"amp.event": "event", "amp.topic": topic}))

        ctx.emit = emit  # type: ignore[method-assign]
        ctx.emit_event = emit_event  # type: ignore[method-assign]

    async def _invoke(self, prep: _Prepared) -> Any:
        msg, ctx = prep.amp_message, prep.ctx
        app = self.server.app
        if app is not None:
            result = await dispatch(_AppView(app), msg, ctx)  # type: ignore[arg-type]
        else:
            handler = self._handlers().get(msg.body_type) or self.server._default_handler
            if handler is None:
                raise AMPError("no_handler", f"No handler for body_type '{msg.body_type}'")
            result = handler(msg)
            if inspect.isawaitable(result):
                result = await result
        # Streaming handlers return an async iterator of StreamingEvents.
        if hasattr(result, "__aiter__"):
            final = None
            async for event in result:
                if isinstance(event, StreamingEvent) and event.type == StreamingEventType.DONE:
                    final = event.data.get("result", final)
                await ctx.emit(event)
            result = final
        return result

    async def _run(self, prep: _Prepared) -> Reply:
        """Invoke the handler and map its result (never leaks exception text)."""
        try:
            if self.handler_timeout is None:
                result = await self._invoke(prep)
            else:
                result = await asyncio.wait_for(self._invoke(prep), self.handler_timeout)
        except TimeoutError:
            logger.warning("A2A handler timed out after %ss (request_id=%s)",
                           self.handler_timeout, prep.call.request_id)
            result = {"body_type": "task.error",
                      "body": {"task_id": prep.task_id, "reason": "timeout",
                               "detail": "The agent did not respond in time."}}
        except AuthRequired as exc:
            return auth_required_reply(exc, context_id=prep.context_id, task_id=prep.task_id,
                                       user_message=prep.message, keys=self.auth_required_keys,
                                       continuing=prep.continuing)
        except A2AError:
            raise
        except AMPError as exc:
            if exc.code == "no_handler":
                raise A2AError("UNSUPPORTED_OPERATION",
                               "This agent cannot handle that message") from None
            logger.info("A2A handler rejected message (request_id=%s): %s",
                        prep.call.request_id, exc)
            result = {"body_type": "task.error",
                      "body": {"task_id": prep.task_id, "reason": exc.code,
                               "detail": exc.message or exc.code}}
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("A2A handler failed for body_type '%s' (request_id=%s)",
                             prep.amp_message.body_type, prep.call.request_id)
            raise A2AError("INTERNAL_ERROR") from None
        try:
            reply = result_to_reply(result, context_id=prep.context_id, task_id=prep.task_id,
                                    user_message=prep.message, continuing=prep.continuing)
        except (ValidationError, ValueError, TypeError):
            logger.exception("A2A handler returned an unmappable result (request_id=%s)",
                             prep.call.request_id)
            raise A2AError("INVALID_AGENT_RESPONSE") from None
        if prep.call.amp_active:
            amp_meta = amp_reply_metadata(prep.ctx, self.server.agent_id, reply.amp)
            target = reply.task if reply.task is not None else reply.message
            assert target is not None
            target.metadata = {**(target.metadata or {}), self.amp_metadata_key: amp_meta}
        return reply

    async def _finish(self, prep: _Prepared, reply: Reply) -> dict[str, Any]:
        if reply.task is not None:
            await self.store.save_task(reply.task, prep.call.principal.id)
            return {"task": dump(_trim_history(reply.task, prep.history_length))}
        assert reply.message is not None
        return {"message": dump(reply.message)}

    async def _release(self, prep: _Prepared, payload: dict[str, Any] | None) -> None:
        if prep.released:
            return
        prep.released = True
        if prep.continuing is not None:
            self._busy_tasks.discard(prep.task_id)
        await self.replies.finish_message(prep.context_id, prep.message.message_id, payload)

    def _working_task(self, prep: _Prepared) -> Task:
        base = prep.continuing
        history = list(base.history or []) if base else []
        history.append(prep.message.model_copy(
            update={"task_id": prep.task_id, "context_id": prep.context_id}))
        return Task(
            id=prep.task_id, context_id=prep.context_id,
            status=TaskStatus(state=TaskState.WORKING, timestamp=now_timestamp()),
            artifacts=(base.artifacts if base else None),
            history=history,
            metadata=(base.metadata if base else None),
        )

    async def _final_events(self, prep: _Prepared, reply: Reply | None,
                            streamed: list[Part], artifact_id: str) -> AsyncIterator[dict[str, Any]]:
        """Closing events of a stream that already announced a task."""
        owner = prep.call.principal.id
        tid, cid = prep.task_id, prep.context_id
        working = self._working_task(prep)
        if streamed:
            text = "".join(p.text or "" for p in streamed)
            working.artifacts = list(working.artifacts or []) + [
                Artifact(artifact_id=artifact_id, name="response", parts=[Part(text=text)])]
        if reply is None:  # canceled
            current = await self.store.get_task(tid, owner)
            if current is not None and current.status.state == TaskState.CANCELED:
                working.status = current.status
            else:
                working.status = TaskStatus(state=TaskState.CANCELED, timestamp=now_timestamp())
                await self.store.save_task(working, owner)
            yield {"statusUpdate": dump(TaskStatusUpdateEvent(task_id=tid, context_id=cid,
                                                              status=working.status))}
            return
        if reply.message is not None:
            final = working
            final.status = TaskStatus(state=TaskState.COMPLETED, timestamp=now_timestamp())
            parts = list(reply.message.parts)
            if parts and not (len(parts) == 1 and parts[0].text == ""):
                art = Artifact(artifact_id=new_id(), name="result", parts=parts)
                final.artifacts = list(final.artifacts or []) + [art]
                yield {"artifactUpdate": dump(TaskArtifactUpdateEvent(
                    task_id=tid, context_id=cid, artifact=art, last_chunk=True))}
            final.metadata = {**(final.metadata or {}), **(reply.message.metadata or {})} or None
        else:
            assert reply.task is not None
            final = reply.task
            known = {a.artifact_id for a in (prep.continuing.artifacts or [])} if prep.continuing else set()
            if streamed:
                final.artifacts = [a for a in (working.artifacts or [])
                                   if a.artifact_id == artifact_id] + list(final.artifacts or [])
                known.add(artifact_id)
            for art in final.artifacts or []:
                if art.artifact_id in known:
                    continue
                yield {"artifactUpdate": dump(TaskArtifactUpdateEvent(
                    task_id=tid, context_id=cid, artifact=art, last_chunk=True))}
        await self.store.save_task(final, owner)
        yield {"statusUpdate": dump(TaskStatusUpdateEvent(
            task_id=tid, context_id=cid, status=final.status, metadata=final.metadata))}

    async def _start_background(self, prep: _Prepared) -> dict[str, Any]:
        """``returnImmediately``: answer with a WORKING task, finish in the background."""
        owner = prep.call.principal.id
        working = self._working_task(prep)
        await self.store.save_task(working, owner)
        live = _Live()
        self._live[prep.task_id] = live
        streamed: list[Part] = []
        artifact_id = new_id()

        async def push(event: TaskStatusUpdateEvent | TaskArtifactUpdateEvent) -> None:
            key = "statusUpdate" if isinstance(event, TaskStatusUpdateEvent) else "artifactUpdate"
            live.publish({key: dump(event)})

        self._bind_emit(prep, push, streamed, artifact_id)

        async def runner() -> None:
            payload = None
            try:
                try:
                    reply: Reply | None = await work
                except asyncio.CancelledError:
                    reply = None
                except A2AError as exc:
                    reply = Reply(task=working.model_copy(update={"status": TaskStatus(
                        state=TaskState.FAILED, timestamp=now_timestamp(),
                        message=agent_message([Part(text=exc.message)], context_id=prep.context_id,
                                              task_id=prep.task_id))}))
                if reply is not None and reply.message is not None:
                    done = self._working_task(prep)
                    done.status = TaskStatus(state=TaskState.COMPLETED, timestamp=now_timestamp(),
                                             message=reply.message.model_copy(
                                                 update={"task_id": prep.task_id}))
                    reply = Reply(task=done)
                async for item in self._final_events(prep, reply, streamed, artifact_id):
                    live.publish(item)
                task = await self.store.get_task(prep.task_id, owner)
                payload = {"task": dump(task)} if task is not None else None
            except Exception:
                logger.exception("A2A background task failed")
            finally:
                live.publish(None)
                self._live.pop(prep.task_id, None)
                await self._release(prep, payload)
                self._background.discard(asyncio.current_task())  # type: ignore[arg-type]

        # ``live.runner`` is the handler work itself so cancel() always lands
        # there (even before it started); the wrapper always cleans up.
        work = asyncio.ensure_future(self._run(prep))
        live.runner = work
        self._background.add(asyncio.ensure_future(runner()))
        return {"task": dump(_trim_history(working, prep.history_length))}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _first(stream: AsyncIterator[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        return await stream.__anext__()
    except StopAsyncIteration:
        return None


def _sse(payload: dict[str, Any], event: str | None = None) -> bytes:
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {json.dumps(payload)}\n\n".encode()


def _int_param(params: dict[str, Any], name: str) -> int | None:
    value = params.get(name)
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise A2AError("INVALID_PARAMS", f"Invalid {name}")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise A2AError("INVALID_PARAMS", f"Invalid {name}") from None


def _str_param(params: dict[str, Any], name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str) or not value or len(value) > 256:
        raise A2AError("INVALID_PARAMS", f"'{name}' is required")
    return value


def _parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise A2AError("INVALID_PARAMS", "Invalid timestamp") from None


def _trim_history(task: Task, history_length: int | None) -> Task:
    if history_length is None or task.history is None:
        return task
    history = task.history[-history_length:] if history_length > 0 else []
    return task.model_copy(update={"history": history or None})


__all__ = ["A2AAdapter", "DEFAULT_INPUT_MODES", "TEXT_MODES"]
