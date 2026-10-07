"""MCP wire constants and JSON-RPC helpers shared by server and client.

Mirrors the protocol registry of the official MCP Python SDK
(``mcp_types.version``) without depending on it:

* **Handshake era** (``2024-11-05`` … ``2025-11-25``): ``initialize`` /
  ``notifications/initialized`` handshake, ``Mcp-Session-Id`` sessions.
* **Modern era** (``2026-07-28``): stateless — every request carries the
  protocol version and client capabilities in ``params._meta`` and the
  ``MCP-Protocol-Version`` / ``Mcp-Method`` / ``Mcp-Name`` headers;
  ``server/discover`` replaces ``initialize``.

PURE — zero platform-specific imports.
"""
from __future__ import annotations

from typing import Any, Final

JSONRPC_VERSION: Final = "2.0"

HANDSHAKE_PROTOCOL_VERSIONS: Final[tuple[str, ...]] = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
"""Revisions negotiated through the ``initialize`` handshake, oldest first."""

MODERN_PROTOCOL_VERSIONS: Final[tuple[str, ...]] = ("2026-07-28",)
"""Revisions that use the stateless per-request envelope."""

SUPPORTED_PROTOCOL_VERSIONS: Final[tuple[str, ...]] = (
    *HANDSHAKE_PROTOCOL_VERSIONS,
    *MODERN_PROTOCOL_VERSIONS,
)
LATEST_HANDSHAKE_VERSION: Final = HANDSHAKE_PROTOCOL_VERSIONS[-1]
LATEST_PROTOCOL_VERSION: Final = SUPPORTED_PROTOCOL_VERSIONS[-1]
DEFAULT_NEGOTIATED_VERSION: Final = "2025-03-26"
"""Version a server assumes when a handshake-era request has no version header."""

BATCH_PROTOCOL_VERSIONS: Final[frozenset[str]] = frozenset({"2025-03-26"})
"""The only revision whose Streamable HTTP transport allows JSON-RPC batches."""

# HTTP header names (lower-case — HTTPRequest lower-cases header names).
SESSION_HEADER: Final = "mcp-session-id"
PROTOCOL_VERSION_HEADER: Final = "mcp-protocol-version"
METHOD_HEADER: Final = "mcp-method"
NAME_HEADER: Final = "mcp-name"

# ``params._meta`` keys used by the modern envelope.
META_PROTOCOL_VERSION: Final = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO: Final = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES: Final = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO: Final = "io.modelcontextprotocol/serverInfo"

# JSON-RPC error codes.
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
HEADER_MISMATCH: Final = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY: Final = -32021
UNSUPPORTED_PROTOCOL_VERSION: Final = -32022

MODERN_ERROR_HTTP_STATUS: Final[dict[int, int]] = {
    PARSE_ERROR: 400,
    INVALID_REQUEST: 400,
    INVALID_PARAMS: 400,
    HEADER_MISMATCH: 400,
    MISSING_REQUIRED_CLIENT_CAPABILITY: 400,
    UNSUPPORTED_PROTOCOL_VERSION: 400,
    METHOD_NOT_FOUND: 404,
}
"""HTTP status for a JSON-RPC error code on the 2026-07-28 wire (default 200)."""

NAME_BEARING_METHODS: Final[dict[str, str]] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}
"""Methods whose named param is mirrored into the ``Mcp-Name`` header."""


class RPCError(Exception):
    """A JSON-RPC error to send back to the caller.

    *http_status* / *headers* override the HTTP response line for errors
    that the transport maps to an HTTP status (e.g. 403 insufficient scope).
    """

    def __init__(
        self,
        code: int,
        message: str,
        data: Any = None,
        *,
        http_status: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.http_status = http_status
        self.headers = headers or {}

    def to_error(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


def error_message(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build a JSON-RPC error response object (``id`` may be ``None``)."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": err}


def result_message(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def is_valid_id(value: Any) -> bool:
    """JSON-RPC request ids are strings or integers (MCP forbids ``null``)."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def unsupported_version_data(requested: Any, supported: tuple[str, ...]) -> dict[str, Any]:
    return {"supported": list(supported), "requested": requested}


def accepts_json(accept: str | None) -> bool:
    """Whether an ``Accept`` header admits ``application/json`` (RFC 9110 wildcards)."""
    if not accept:
        # A missing Accept header means "anything" (RFC 9110 §12.5.1).
        return True
    for part in accept.split(","):
        media = part.split(";")[0].strip().lower()
        if media in ("application/json", "application/*", "*/*"):
            return True
    return False


def is_json_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";")[0].strip().lower() == "application/json"


__all__ = [
    "BATCH_PROTOCOL_VERSIONS",
    "DEFAULT_NEGOTIATED_VERSION",
    "HANDSHAKE_PROTOCOL_VERSIONS",
    "HEADER_MISMATCH",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "JSONRPC_VERSION",
    "LATEST_HANDSHAKE_VERSION",
    "LATEST_PROTOCOL_VERSION",
    "METHOD_HEADER",
    "METHOD_NOT_FOUND",
    "MODERN_ERROR_HTTP_STATUS",
    "MODERN_PROTOCOL_VERSIONS",
    "NAME_HEADER",
    "PARSE_ERROR",
    "PROTOCOL_VERSION_HEADER",
    "RPCError",
    "SESSION_HEADER",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "UNSUPPORTED_PROTOCOL_VERSION",
]
