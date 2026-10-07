"""Outbound A2A 1.0 client (httpx).

::

    async with A2AClient("https://agent.example/.well-known/agent-card.json",
                         auth="<bearer token>") as client:
        reply = await client.send_message("What's the weather?")
        if isinstance(reply, Task) and reply.status.state == TaskState.INPUT_REQUIRED:
            reply = await client.send_message("Paris", task_id=reply.id,
                                              context_id=reply.context_id)

The interface is chosen from ``supportedInterfaces`` by ``protocolBinding``
and ``protocolVersion`` — HTTP+JSON 1.x preferred, JSON-RPC 1.x as a
fallback — never by position.

Hardening: every request has a timeout; redirects are followed only to the
same origin (max 3); response bodies and SSE events are capped at
``max_response_bytes``; an optional ``url_validator`` (e.g. an SSRF guard)
is called with every URL before it is requested and may raise.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Callable, Iterable
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import httpx

from ampro.interop.a2a.card import AMP_EXTENSION_URI
from ampro.interop.a2a.errors import A2AError
from ampro.interop.a2a.types import (
    A2A_PROTOCOL_VERSION,
    AGENT_CARD_PATH,
    BINDING_HTTP_JSON,
    BINDING_JSONRPC,
    AgentCard,
    AgentInterface,
    ListTasksResponse,
    Message,
    Part,
    Role,
    SendMessageResponse,
    StreamResponse,
    Task,
    dump,
)

_MAX_REDIRECTS = 3
AMP_CARD_PATH = "/.well-known/agent.json"


class A2AClientError(Exception):
    """Transport-level failure (not an A2A protocol error)."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        self.status = status
        super().__init__(message)


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port


def _card_url(url: str) -> str:
    if url.endswith(".json"):
        return url
    return url.rstrip("/") + AGENT_CARD_PATH


class _HTTP:
    """Shared request helper: url validation, same-origin redirects, size cap."""

    def __init__(self, client: httpx.AsyncClient, *, timeout: float, max_bytes: int,
                 url_validator: Callable[[str], None] | None) -> None:
        self.client = client
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.url_validator = url_validator

    def _check(self, url: str) -> None:
        if urlsplit(url).scheme not in ("http", "https"):
            raise A2AClientError(f"Unsupported URL scheme in {url!r}")
        if self.url_validator is not None:
            self.url_validator(url)

    async def _send(self, method: str, url: str, *, stream: bool, **kw: Any) -> httpx.Response:
        start = url
        for _ in range(_MAX_REDIRECTS + 1):
            self._check(url)
            request = self.client.build_request(method, url, timeout=self.timeout, **kw)
            response = await self.client.send(request, stream=True, follow_redirects=False)
            if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                await response.aclose()
                target = urljoin(url, response.headers["location"])
                if _origin(target) != _origin(start):
                    raise A2AClientError("Refusing cross-origin redirect", status=response.status_code)
                if response.status_code == 303:
                    method, kw = "GET", {k: v for k, v in kw.items() if k not in ("json", "content")}
                url = target
                continue
            if not stream:
                try:
                    await self._read_capped(response)
                finally:
                    await response.aclose()
            return response
        raise A2AClientError("Too many redirects")

    async def _read_capped(self, response: httpx.Response) -> None:
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            raise A2AClientError("Response too large", status=response.status_code)
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self.max_bytes:
                raise A2AClientError("Response too large", status=response.status_code)
            chunks.append(chunk)
        response._content = b"".join(chunks)

    async def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        try:
            return await self._send(method, url, stream=False, **kw)
        except httpx.TimeoutException as exc:
            raise A2AClientError("Request timed out") from exc
        except httpx.HTTPError as exc:
            raise A2AClientError(f"HTTP error: {type(exc).__name__}") from exc

    async def stream_lines(self, method: str, url: str, **kw: Any) -> AsyncIterator[tuple[str, str]]:
        """Yield ``(event, data)`` SSE events (non-SSE bodies yield one ``("json", body)``)."""
        try:
            response = await self._send(method, url, stream=True, **kw)
        except httpx.TimeoutException as exc:
            raise A2AClientError("Request timed out") from exc
        except httpx.HTTPError as exc:
            raise A2AClientError(f"HTTP error: {type(exc).__name__}") from exc
        try:
            if "text/event-stream" not in response.headers.get("content-type", ""):
                await self._read_capped(response)
                yield "json", f"{response.status_code}\n{response.text}"
                return
            event, data, size = "message", [], 0
            async for line in response.aiter_lines():
                line = line.rstrip("\r\n")
                if not line:
                    if data:
                        yield event, "\n".join(data)
                    event, data, size = "message", [], 0
                    continue
                if line.startswith(":"):
                    continue
                key, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
                if key == "event":
                    event = value
                elif key == "data":
                    size += len(value)
                    if size > self.max_bytes:
                        raise A2AClientError("SSE event too large")
                    data.append(value)
            if data:
                yield event, "\n".join(data)
        except httpx.TimeoutException as exc:
            raise A2AClientError("Stream timed out") from exc
        except httpx.HTTPError as exc:
            raise A2AClientError(f"HTTP error: {type(exc).__name__}") from exc
        finally:
            await response.aclose()


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


class A2AClient:
    """Talk to an A2A 1.0 agent.

    Args:
        card: the agent-card URL (or agent base URL), an :class:`AgentCard`,
            or a card dict.
        http_client: an ``httpx.AsyncClient`` to use (not closed by us).
        auth: a bearer token string, an ``httpx.Auth``, or a dict of headers.
        extensions: extension URIs to activate.  ``None`` activates the AMP
            extension when the card advertises it.
        timeout: per-request timeout in seconds.
        max_response_bytes: cap on any response body / SSE event.
        url_validator: called with every URL before it is fetched; raise to
            refuse (plug ``ampro.security.ssrf`` here).
        bindings: preferred protocol bindings, in order.
    """

    def __init__(
        self,
        card: str | AgentCard | dict[str, Any],
        *,
        http_client: httpx.AsyncClient | None = None,
        auth: str | httpx.Auth | dict[str, str] | None = None,
        extensions: Iterable[str] | None = None,
        timeout: float = 30.0,
        max_response_bytes: int = 10 * 1024 * 1024,
        url_validator: Callable[[str], None] | None = None,
        bindings: Iterable[str] = (BINDING_HTTP_JSON, BINDING_JSONRPC),
    ) -> None:
        self._card: AgentCard | None = None
        self.card_url: str | None = None
        if isinstance(card, AgentCard):
            self._card = card
        elif isinstance(card, dict):
            self._card = AgentCard.model_validate(card)
        else:
            self.card_url = _card_url(card)
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient()
        self._http = _HTTP(self._client, timeout=timeout, max_bytes=max_response_bytes,
                           url_validator=url_validator)
        self._auth: httpx.Auth | None = auth if isinstance(auth, httpx.Auth) else None
        self._auth_headers: dict[str, str] = {}
        if isinstance(auth, str):
            self._auth_headers = {"Authorization": f"Bearer {auth}"}
        elif isinstance(auth, dict):
            self._auth_headers = dict(auth)
        self._extensions = list(extensions) if extensions is not None else None
        self.bindings = tuple(bindings)
        self.activated_extensions: frozenset[str] = frozenset()

    async def __aenter__(self) -> A2AClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Card / interface
    # ------------------------------------------------------------------

    async def fetch_card(self, *, refresh: bool = False) -> AgentCard:
        if self._card is not None and not refresh:
            return self._card
        if self.card_url is None:
            assert self._card is not None
            return self._card
        resp = await self._http.request("GET", self.card_url,
                                        headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise A2AClientError(f"Agent card fetch failed: HTTP {resp.status_code}",
                                 status=resp.status_code)
        data = _json(resp)
        if not isinstance(data, dict):
            raise A2AClientError("Agent card is not a JSON object")
        try:
            self._card = AgentCard.model_validate(data)
        except ValueError as exc:
            raise A2AClientError("Agent card is invalid") from exc
        return self._card

    async def interface(self) -> AgentInterface:
        card = await self.fetch_card()
        for binding in self.bindings:
            iface = card.interface(binding)
            if iface is not None:
                return iface
        raise A2AClientError("The agent offers no supported A2A 1.x interface")

    async def _headers(self) -> dict[str, str]:
        headers = {"A2A-Version": A2A_PROTOCOL_VERSION, "Content-Type": "application/json",
                   **self._auth_headers}
        exts = self._extensions
        if exts is None:
            card = await self.fetch_card()
            exts = [AMP_EXTENSION_URI] if card.extension(AMP_EXTENSION_URI) else []
        if exts:
            headers["A2A-Extensions"] = ", ".join(exts)
        return headers

    def _record_extensions(self, response: httpx.Response) -> None:
        raw = response.headers.get("a2a-extensions", "")
        self.activated_extensions = frozenset(e.strip() for e in raw.split(",") if e.strip())

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    @staticmethod
    def build_message(
        content: str | Part | Iterable[Part | dict[str, Any]] | Message,
        *,
        context_id: str | None = None,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        amp: dict[str, Any] | None = None,
        message_id: str | None = None,
    ) -> Message:
        if isinstance(content, Message):
            msg = content
        else:
            if isinstance(content, str):
                parts = [Part(text=content)]
            elif isinstance(content, Part):
                parts = [content]
            else:
                parts = [p if isinstance(p, Part) else Part.model_validate(p) for p in content]
            msg = Message(message_id=message_id or str(uuid.uuid4()), role=Role.USER, parts=parts)
        update: dict[str, Any] = {}
        if context_id:
            update["context_id"] = context_id
        if task_id:
            update["task_id"] = task_id
        meta = dict(msg.metadata or {})
        meta.update(metadata or {})
        if amp:
            meta[AMP_EXTENSION_URI] = amp
        update["metadata"] = meta or None
        return msg.model_copy(update=update)

    async def send_message(
        self,
        content: str | Part | Iterable[Part | dict[str, Any]] | Message,
        *,
        context_id: str | None = None,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        amp: dict[str, Any] | None = None,
        configuration: dict[str, Any] | None = None,
        message_id: str | None = None,
    ) -> Message | Task:
        """Send a message; returns the agent's ``Message`` or a ``Task``.

        *amp* is placed under the AMP extension key in the message metadata.
        """
        msg = self.build_message(content, context_id=context_id, task_id=task_id,
                                 metadata=metadata, amp=amp, message_id=message_id)
        params: dict[str, Any] = {"message": dump(msg)}
        if configuration:
            params["configuration"] = configuration
        result = await self._call("SendMessage", "POST", "/message:send", json_body=params)
        resp = SendMessageResponse.model_validate(result)
        return resp.task if resp.task is not None else resp.message  # type: ignore[return-value]

    async def stream_message(
        self,
        content: str | Part | Iterable[Part | dict[str, Any]] | Message,
        *,
        context_id: str | None = None,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        amp: dict[str, Any] | None = None,
        message_id: str | None = None,
    ) -> AsyncIterator[StreamResponse]:
        """Send a message and yield ``StreamResponse`` events as they arrive."""
        msg = self.build_message(content, context_id=context_id, task_id=task_id,
                                 metadata=metadata, amp=amp, message_id=message_id)
        async for event in self._stream("SendStreamingMessage", "/message:stream",
                                        {"message": dump(msg)}):
            yield event

    async def subscribe(self, task_id: str) -> AsyncIterator[StreamResponse]:
        async for event in self._stream("SubscribeToTask", f"/tasks/{task_id}:subscribe",
                                        {"id": task_id}):
            yield event

    async def get_task(self, task_id: str, *, history_length: int | None = None) -> Task:
        params: dict[str, Any] = {"id": task_id}
        query = {}
        if history_length is not None:
            params["historyLength"] = history_length
            query["historyLength"] = str(history_length)
        result = await self._call("GetTask", "GET", f"/tasks/{task_id}", json_body=params,
                                  query=query)
        return Task.model_validate(result)

    async def cancel_task(self, task_id: str) -> Task:
        result = await self._call("CancelTask", "POST", f"/tasks/{task_id}:cancel",
                                  json_body={"id": task_id})
        return Task.model_validate(result)

    async def list_tasks(self, **filters: Any) -> ListTasksResponse:
        """``filters`` use A2A names: ``contextId``, ``status``, ``pageSize``, ``pageToken`` ..."""
        query = {k: (str(v).lower() if isinstance(v, bool) else str(v))
                 for k, v in filters.items() if v is not None}
        result = await self._call("ListTasks", "GET", "/tasks", json_body=dict(filters),
                                  query=query)
        return ListTasksResponse.model_validate(result)

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    async def _call(self, rpc_method: str, http_method: str, path: str, *,
                    json_body: dict[str, Any], query: dict[str, str] | None = None) -> Any:
        iface = await self.interface()
        headers = await self._headers()
        if iface.protocol_binding == BINDING_HTTP_JSON:
            url = iface.url.rstrip("/") + path
            kw: dict[str, Any] = {"headers": headers, "params": query or None}
            if http_method == "POST":
                kw["json"] = json_body
            if self._auth is not None:
                kw["auth"] = self._auth
            resp = await self._http.request(http_method, url, **kw)
            self._record_extensions(resp)
            payload = _json(resp)
            if resp.status_code >= 400:
                if isinstance(payload, dict) and "error" in payload:
                    raise A2AError.from_rest_payload(payload, resp.status_code)
                raise A2AClientError(f"HTTP {resp.status_code}", status=resp.status_code)
            if not isinstance(payload, dict):
                raise A2AClientError("Response is not a JSON object", status=resp.status_code)
            return payload
        rpc = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": rpc_method,
               "params": json_body}
        kw = {"headers": headers, "json": rpc}
        if self._auth is not None:
            kw["auth"] = self._auth
        resp = await self._http.request("POST", iface.url, **kw)
        self._record_extensions(resp)
        payload = _json(resp)
        if resp.status_code >= 400 or not isinstance(payload, dict):
            raise A2AClientError(f"HTTP {resp.status_code}", status=resp.status_code)
        if "error" in payload:
            raise A2AError.from_jsonrpc_error(payload["error"])
        return payload.get("result")

    async def _stream(self, rpc_method: str, path: str,
                      params: dict[str, Any]) -> AsyncIterator[StreamResponse]:
        iface = await self.interface()
        headers = await self._headers()
        headers["Accept"] = "text/event-stream"
        rest = iface.protocol_binding == BINDING_HTTP_JSON
        if rest:
            url = iface.url.rstrip("/") + path
            body: dict[str, Any] = params if rpc_method != "SubscribeToTask" else {}
        else:
            url = iface.url
            body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": rpc_method,
                    "params": params}
        kw: dict[str, Any] = {"headers": headers, "json": body}
        if self._auth is not None:
            kw["auth"] = self._auth
        async for event, data in self._http.stream_lines("POST", url, **kw):
            if event == "json":
                status_line, _, text = data.partition("\n")
                status = int(status_line)
                try:
                    payload = json.loads(text) if text else None
                except ValueError:
                    payload = None
                if rest:
                    if isinstance(payload, dict) and "error" in payload:
                        raise A2AError.from_rest_payload(payload, status)
                    raise A2AClientError(f"HTTP {status}", status=status)
                if isinstance(payload, dict) and "error" in payload:
                    raise A2AError.from_jsonrpc_error(payload["error"])
                raise A2AClientError(f"HTTP {status}", status=status)
            try:
                payload = json.loads(data)
            except ValueError:
                raise A2AClientError("Malformed SSE event") from None
            if not rest:
                if isinstance(payload, dict) and "error" in payload:
                    raise A2AError.from_jsonrpc_error(payload["error"])
                payload = payload.get("result") if isinstance(payload, dict) else None
            elif event == "error" or (isinstance(payload, dict) and "error" in payload):
                raise A2AError.from_rest_payload(payload, 500)
            yield StreamResponse.model_validate(payload)


async def discover_protocol(
    url: str,
    *,
    http_client: httpx.AsyncClient | None = None,
    url_validator: Callable[[str], None] | None = None,
    timeout: float = 10.0,
) -> Literal["amp", "a2a"]:
    """Probe *url* (an agent base URL) and report which protocol it speaks.

    AMP (``/.well-known/agent.json``) is preferred when both are served,
    since it is the richer native protocol.  Raises :class:`LookupError`
    when neither discovery document is found.
    """
    base = url.rstrip("/")
    for suffix in (AMP_CARD_PATH, AGENT_CARD_PATH):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    client = http_client or httpx.AsyncClient()
    http = _HTTP(client, timeout=timeout, max_bytes=1024 * 1024, url_validator=url_validator)
    try:
        for path, proto, key in ((AMP_CARD_PATH, "amp", "endpoint"),
                                 (AGENT_CARD_PATH, "a2a", "supportedInterfaces")):
            try:
                resp = await http.request("GET", base + path, headers={"Accept": "application/json"})
            except A2AClientError:
                continue
            data = _json(resp) if resp.status_code == 200 else None
            if isinstance(data, dict) and (key in data or (proto == "a2a" and "url" in data)):
                return proto  # type: ignore[return-value]
    finally:
        if http_client is None:
            await client.aclose()
    raise LookupError(f"No AMP or A2A discovery document at {base}")


__all__ = ["A2AClient", "A2AClientError", "AMP_CARD_PATH", "discover_protocol"]
