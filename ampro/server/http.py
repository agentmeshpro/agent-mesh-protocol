"""Framework-agnostic HTTP primitives for the reference server.

``HTTPRequest`` / ``HTTPResponse`` are the neutral types every protocol
adapter speaks.  :class:`AgentServer` turns ASGI (or Flask) traffic into
an ``HTTPRequest``, offers it to each mounted :class:`ProtocolAdapter`
in turn, and falls back to the native AMP routes.

This lets one agent be reachable over several wire protocols — AMP,
A2A, MCP — from a single process without any of them knowing about the
others.

PURE — zero platform-specific imports.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class HTTPRequest:
    """A transport-neutral HTTP request.

    Header names are lower-cased.  ``path`` excludes the query string.
    """

    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)

    def json(self) -> Any:
        """Decode the body as JSON (raises ``ValueError`` on bad input)."""
        if not self.body:
            return None
        return json.loads(self.body)


@dataclass
class HTTPResponse:
    """A transport-neutral HTTP response.

    ``body`` is either a complete payload or an async iterator of chunks
    (used for Server-Sent Events).
    """

    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | AsyncIterator[bytes] = b""

    @classmethod
    def json(
        cls,
        payload: Any,
        status: int = 200,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        hdrs = {"content-type": content_type}
        if headers:
            hdrs.update({k.lower(): v for k, v in headers.items()})
        return cls(status=status, headers=hdrs, body=json.dumps(payload).encode("utf-8"))

    @classmethod
    def empty(cls, status: int, headers: dict[str, str] | None = None) -> HTTPResponse:
        return cls(status=status, headers={k.lower(): v for k, v in (headers or {}).items()})

    @property
    def is_streaming(self) -> bool:
        return not isinstance(self.body, (bytes, bytearray))


@runtime_checkable
class ProtocolAdapter(Protocol):
    """A wire protocol mounted on an :class:`AgentServer`.

    ``handle`` returns ``None`` when the request is not for this adapter,
    so the server can offer it to the next one.
    """

    name: str

    async def handle(self, request: HTTPRequest) -> HTTPResponse | None: ...
