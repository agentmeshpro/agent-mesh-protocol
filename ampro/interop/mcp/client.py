"""Consume a remote MCP server's tools from an AMP agent.

A lean Streamable HTTP client (handshake era, ``initialize`` →
``tools/list`` → ``tools/call``) built on ``httpx``::

    async with MCPToolSource("http://127.0.0.1:9000/mcp") as source:
        names = await source.register_into(agent, prefix="files.")

Each remote tool becomes an async proxy in ``agent.tools`` (with its JSON
Schema in ``agent.tool_meta``), so AMPI handlers call it like any local
tool — and an :class:`~ampro.interop.mcp.server.MCPAdapter` on the same
agent re-exports it.

Accepts both ``application/json`` and ``text/event-stream`` responses.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlsplit

import httpx

from ampro.interop.mcp import protocol as p

if TYPE_CHECKING:
    from ampro.ampi.app import AgentApp

logger = logging.getLogger(__name__)

_MAX_PAGES = 100
_MAX_REDIRECTS = 3
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class _Reply:
    status: int
    headers: httpx.Headers
    body: bytes


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS.get(scheme)


class MCPClientError(Exception):
    """A transport or JSON-RPC failure talking to a remote MCP server."""

    def __init__(self, message: str, *, code: int | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class MCPToolError(Exception):
    """A remote tool reported ``isError: true``."""

    def __init__(self, message: str, result: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.result = result or {}


def _text_of(result: Mapping[str, Any]) -> str:
    parts = [
        str(block.get("text", ""))
        for block in result.get("content") or []
        if isinstance(block, Mapping) and block.get("type") == "text"
    ]
    return "\n".join(parts)


def _parse_sse(text: str) -> list[Any]:
    """Return the JSON payloads of every SSE ``message`` event in *text*."""
    messages: list[Any] = []
    event, data_lines = "message", []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw == "":
            if data_lines:
                if event == "message":
                    try:
                        messages.append(json.loads("\n".join(data_lines)))
                    except ValueError:
                        logger.debug("Ignoring non-JSON SSE data")
                event, data_lines = "message", []
            continue
        if raw.startswith(":"):
            continue
        name, _, value = raw.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "event":
            event = value
        elif name == "data":
            data_lines.append(value)
    if data_lines and event == "message":
        try:
            messages.append(json.loads("\n".join(data_lines)))
        except ValueError:
            pass
    return messages


class MCPToolSource:
    """A remote MCP server whose tools can be registered into an AgentApp."""

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        http_client: httpx.AsyncClient | None = None,
        protocol_version: str = p.LATEST_HANDSHAKE_VERSION,
        timeout: float = 30.0,
        max_response_bytes: int = 4 * 1024 * 1024,
        client_name: str = "ampro",
    ) -> None:
        if protocol_version not in p.HANDSHAKE_PROTOCOL_VERSIONS:
            raise ValueError(f"protocol_version must be one of {p.HANDSHAKE_PROTOCOL_VERSIONS}")
        self.url = url
        self.headers = dict(headers or {})
        self._client = http_client
        self._owns_client = http_client is None
        self._requested_version = protocol_version
        self._timeout = timeout
        self._http_timeout = httpx.Timeout(timeout, connect=min(timeout, 10.0))
        self.max_response_bytes = max_response_bytes
        self._client_name = client_name
        self._ids = itertools.count(1)
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        self.instructions: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> MCPToolSource:
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @property
    def connected(self) -> bool:
        return self.protocol_version is not None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._http_timeout, follow_redirects=False)
        return self._client

    async def connect(self) -> dict[str, Any]:
        """Run the ``initialize`` handshake; returns the server's result."""
        self.session_id = None
        self.protocol_version = None
        from ampro.interop.mcp.server import _package_version

        result = await self._request(
            "initialize",
            {
                "protocolVersion": self._requested_version,
                "capabilities": {},
                "clientInfo": {"name": self._client_name, "version": _package_version()},
            },
            _handshake=True,
        )
        version = result.get("protocolVersion")
        if version not in p.HANDSHAKE_PROTOCOL_VERSIONS:
            await self.close()
            raise MCPClientError(f"Server chose unsupported protocol version {version!r}")
        self.protocol_version = version
        self.server_info = dict(result.get("serverInfo") or {})
        self.server_capabilities = dict(result.get("capabilities") or {})
        self.instructions = result.get("instructions")
        await self._notify("notifications/initialized")
        return result

    async def close(self) -> None:
        """End the session (``DELETE``) and close an owned HTTP client."""
        if self.session_id and self._client is not None:
            try:
                await self._send("DELETE")
            except MCPClientError:
                logger.debug("MCP session DELETE failed", exc_info=True)
        self.session_id = None
        self.protocol_version = None
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Wire
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            **self.headers,
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        if self.session_id:
            headers[p.SESSION_HEADER] = self.session_id
        if self.protocol_version:
            headers[p.PROTOCOL_VERSION_HEADER] = self.protocol_version
        return headers

    async def _post(self, message: dict[str, Any]) -> _Reply:
        return await self._send("POST", json.dumps(message).encode())

    async def _send(self, method: str, content: bytes | None = None) -> _Reply:
        """One HTTP exchange under an overall deadline and a response-size cap.

        Redirects are followed only within the endpoint's origin (same
        scheme, host and port) and only as 307/308, so a server cannot
        bounce our session id or credentials to another host.
        """
        try:
            return await asyncio.wait_for(self._send_once(method, content), self._timeout)
        except asyncio.TimeoutError:
            raise MCPClientError(f"MCP {method} timed out after {self._timeout}s") from None
        except httpx.HTTPError as exc:
            raise MCPClientError(f"MCP transport error: {type(exc).__name__}") from exc

    async def _send_once(self, method: str, content: bytes | None) -> _Reply:
        client = self._http()
        url = self.url
        for _ in range(_MAX_REDIRECTS + 1):
            request = client.build_request(
                method, url, content=content, headers=self._headers(), timeout=self._http_timeout
            )
            response = await client.send(request, stream=True, follow_redirects=False)
            try:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("location")
                    if response.status_code not in (307, 308) or not location:
                        raise MCPClientError(
                            f"MCP server answered an unfollowable redirect ({response.status_code})",
                            status=response.status_code,
                        )
                    target = urljoin(url, location)
                    if _origin(target) != _origin(self.url):
                        raise MCPClientError(
                            "Refusing cross-origin redirect from MCP server", status=response.status_code
                        )
                    url = target
                    continue
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > self.max_response_bytes:
                    raise MCPClientError("MCP response too large", status=response.status_code)
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise MCPClientError("MCP response too large", status=response.status_code)
                    chunks.append(chunk)
                return _Reply(response.status_code, response.headers, b"".join(chunks))
            finally:
                await response.aclose()
        raise MCPClientError("Too many redirects from MCP server")

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": p.JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = params
        response = await self._post(message)
        if response.status >= 400:
            raise MCPClientError(f"Notification {method} rejected", status=response.status)

    async def _request(
        self, method: str, params: dict[str, Any] | None = None, *, _handshake: bool = False
    ) -> dict[str, Any]:
        if not _handshake and not self.connected:
            await self.connect()
        for attempt in range(2):
            rid = next(self._ids)
            message: dict[str, Any] = {"jsonrpc": p.JSONRPC_VERSION, "id": rid, "method": method}
            if params is not None:
                message["params"] = params
            response = await self._post(message)
            if response.status == 404 and self.session_id and not _handshake and attempt == 0:
                # Session expired server-side: the spec says start a new one.
                await self.connect()
                continue
            return self._read_reply(response, rid, method)
        raise MCPClientError("MCP session could not be re-established")  # pragma: no cover

    def _read_reply(self, response: _Reply, rid: int, method: str) -> dict[str, Any]:
        sid = response.headers.get(p.SESSION_HEADER)
        if sid:
            self.session_id = sid
        ctype = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype == "text/event-stream":
            candidates = _parse_sse(response.body.decode("utf-8", errors="replace"))
        elif ctype == "application/json":
            try:
                body = json.loads(response.body)
            except ValueError:
                raise MCPClientError(f"{method}: invalid JSON response", status=response.status) from None
            candidates = body if isinstance(body, list) else [body]
        else:
            raise MCPClientError(
                f"{method}: HTTP {response.status}", status=response.status
            )
        for reply in candidates:
            if not isinstance(reply, dict) or reply.get("id") != rid:
                continue
            if "error" in reply:
                err = reply["error"] if isinstance(reply["error"], dict) else {}
                raise MCPClientError(
                    f"{method}: {err.get('message', 'error')}",
                    code=err.get("code"),
                    status=response.status,
                )
            result = reply.get("result")
            if not isinstance(result, dict):
                raise MCPClientError(f"{method}: malformed result", status=response.status)
            return result
        raise MCPClientError(f"{method}: HTTP {response.status}, no reply", status=response.status)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def list_tools(self) -> list[dict[str, Any]]:
        """All tools, following ``nextCursor`` pagination."""
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(_MAX_PAGES):
            result = await self._request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in result.get("tools") or [] if isinstance(t, dict) and "name" in t)
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or cursor in seen:
                break
            seen.add(cursor)
        return tools

    async def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Call *name*; returns the raw ``CallToolResult`` dict."""
        return await self._request("tools/call", {"name": name, "arguments": dict(arguments or {})})

    def proxy(self, name: str) -> Callable[..., Any]:
        """An async function ``(**arguments)`` calling remote tool *name*.

        Returns ``structuredContent`` when present, else the joined text
        content; raises :class:`MCPToolError` when the tool reports an error.
        """
        source = self

        async def call_remote_tool(**arguments: Any) -> Any:
            result = await source.call_tool(name, arguments)
            if result.get("isError"):
                raise MCPToolError(_text_of(result) or "Remote tool failed", result)
            if result.get("structuredContent") is not None:
                return result["structuredContent"]
            return _text_of(result)

        call_remote_tool.__name__ = f"mcp_{''.join(c if c.isalnum() else '_' for c in name)}"
        call_remote_tool.__qualname__ = call_remote_tool.__name__
        return call_remote_tool

    async def register_into(
        self, app: AgentApp, prefix: str = "", *, overwrite: bool = False
    ) -> list[str]:
        """Add every remote tool to ``app.tools`` as ``prefix + name``.

        Existing local tools are kept unless *overwrite* is true.  Returns
        the registered names.
        """
        tool_meta = getattr(app, "tool_meta", None)
        if tool_meta is None:
            tool_meta = {}
            app.tool_meta = tool_meta  # type: ignore[attr-defined]
        registered: list[str] = []
        for tool in await self.list_tools():
            local = f"{prefix}{tool['name']}"
            if local in app.tools and not overwrite:
                logger.warning("Not overwriting existing tool %r with remote MCP tool", local)
                continue
            app.tools[local] = self.proxy(tool["name"])
            meta: dict[str, Any] = {
                "description": tool.get("description") or "",
                "input_schema": dict(tool.get("inputSchema") or {"type": "object"}),
                "source": self.url,
            }
            if tool.get("title"):
                meta["title"] = tool["title"]
            tool_meta[local] = meta
            registered.append(local)
        return registered


__all__ = ["MCPClientError", "MCPToolError", "MCPToolSource"]
