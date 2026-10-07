"""A2A 1.0 errors — reasons, HTTP/gRPC status, JSON-RPC codes, envelopes.

The table mirrors the official SDK (``a2a.utils.errors``):

* HTTP+JSON: AIP-193 envelope ``{"error": {"code", "status", "message",
  "details": [{"@type": ".../google.rpc.ErrorInfo", "reason", "domain",
  "metadata"}]}}``; clients read the reason from ``details[0].reason``.
* JSON-RPC: ``{"jsonrpc": "2.0", "id", "error": {"code", "message",
  "data": [<ErrorInfo>]}}``, always HTTP 200.
"""
from __future__ import annotations

from typing import Any, NamedTuple

ERROR_INFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
A2A_ERROR_DOMAIN = "a2a-protocol.org"


class _Mapping(NamedTuple):
    http: int
    grpc_status: str
    jsonrpc: int
    default_message: str


# reason -> mapping  (reasons and numbers taken from a2a-sdk 1.x)
ERROR_TABLE: dict[str, _Mapping] = {
    "TASK_NOT_FOUND": _Mapping(404, "NOT_FOUND", -32001, "Task not found"),
    "TASK_NOT_CANCELABLE": _Mapping(400, "FAILED_PRECONDITION", -32002, "Task cannot be canceled"),
    "PUSH_NOTIFICATION_NOT_SUPPORTED": _Mapping(
        400, "FAILED_PRECONDITION", -32003, "Push Notification is not supported"
    ),
    "UNSUPPORTED_OPERATION": _Mapping(
        400, "FAILED_PRECONDITION", -32004, "This operation is not supported"
    ),
    "CONTENT_TYPE_NOT_SUPPORTED": _Mapping(
        400, "INVALID_ARGUMENT", -32005, "Incompatible content types"
    ),
    "INVALID_AGENT_RESPONSE": _Mapping(500, "INTERNAL", -32006, "Invalid agent response"),
    "EXTENDED_AGENT_CARD_NOT_CONFIGURED": _Mapping(
        400, "FAILED_PRECONDITION", -32007, "Authenticated Extended Card is not configured"
    ),
    "EXTENSION_SUPPORT_REQUIRED": _Mapping(
        400, "FAILED_PRECONDITION", -32008, "Extension support required"
    ),
    "VERSION_NOT_SUPPORTED": _Mapping(400, "FAILED_PRECONDITION", -32009, "Version not supported"),
    "INVALID_PARAMS": _Mapping(400, "INVALID_ARGUMENT", -32602, "Invalid params"),
    "INVALID_REQUEST": _Mapping(400, "INVALID_ARGUMENT", -32600, "Invalid Request"),
    "METHOD_NOT_FOUND": _Mapping(404, "NOT_FOUND", -32601, "Method not found"),
    "INTERNAL_ERROR": _Mapping(500, "INTERNAL", -32603, "Internal error"),
    "PARSE_ERROR": _Mapping(400, "INVALID_ARGUMENT", -32700, "Invalid JSON payload"),
}

_JSONRPC_TO_REASON = {m.jsonrpc: reason for reason, m in ERROR_TABLE.items()}


class A2AError(Exception):
    """An A2A protocol error, renderable on either binding.

    ``data`` becomes ``ErrorInfo.metadata`` and is sent to the client —
    never put internal details in it.
    """

    def __init__(
        self,
        reason: str,
        message: str | None = None,
        *,
        data: dict[str, Any] | None = None,
        http_status: int | None = None,
    ) -> None:
        mapping = ERROR_TABLE.get(reason, ERROR_TABLE["INTERNAL_ERROR"])
        self.reason = reason
        self.message = message or mapping.default_message
        self.data = data
        self.http_status = http_status or mapping.http
        super().__init__(f"{reason}: {self.message}")

    @property
    def grpc_status(self) -> str:
        return ERROR_TABLE.get(self.reason, ERROR_TABLE["INTERNAL_ERROR"]).grpc_status

    @property
    def jsonrpc_code(self) -> int:
        return ERROR_TABLE.get(self.reason, ERROR_TABLE["INTERNAL_ERROR"]).jsonrpc

    def error_info(self) -> dict[str, Any]:
        return {
            "@type": ERROR_INFO_TYPE,
            "reason": self.reason,
            "domain": A2A_ERROR_DOMAIN,
            "metadata": {k: str(v) for k, v in (self.data or {}).items()},
        }

    def rest_payload(self) -> dict[str, Any]:
        """AIP-193 envelope for the HTTP+JSON binding."""
        return {
            "error": {
                "code": self.http_status,
                "status": self.grpc_status,
                "message": self.message,
                "details": [self.error_info()],
            }
        }

    def jsonrpc_error(self) -> dict[str, Any]:
        return {"code": self.jsonrpc_code, "message": self.message, "data": [self.error_info()]}

    @classmethod
    def from_rest_payload(cls, payload: Any, status: int) -> A2AError:
        """Rebuild an error from an HTTP+JSON error body (client side)."""
        reason = "INTERNAL_ERROR"
        message = f"HTTP {status}"
        data: dict[str, Any] | None = None
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            err = payload["error"]
            message = str(err.get("message") or message)
            for d in err.get("details") or []:
                if isinstance(d, dict) and d.get("@type") == ERROR_INFO_TYPE:
                    reason = str(d.get("reason") or reason)
                    data = d.get("metadata") or None
                    break
        return cls(reason, message, data=data, http_status=status)

    @classmethod
    def from_jsonrpc_error(cls, err: Any) -> A2AError:
        if not isinstance(err, dict):
            return cls("INTERNAL_ERROR", "malformed JSON-RPC error")
        code = err.get("code")
        reason = _JSONRPC_TO_REASON.get(code, "INTERNAL_ERROR")
        data = None
        details = err.get("data")
        for d in details if isinstance(details, list) else []:
            if isinstance(d, dict) and d.get("@type") == ERROR_INFO_TYPE:
                reason = str(d.get("reason") or reason)
                data = d.get("metadata") or None
                break
        return cls(reason, str(err.get("message") or ""), data=data)


def task_not_found(task_id: str | None = None) -> A2AError:
    return A2AError("TASK_NOT_FOUND")


def invalid_params(message: str = "Invalid params") -> A2AError:
    return A2AError("INVALID_PARAMS", message)


def unsupported(message: str = "This operation is not supported") -> A2AError:
    return A2AError("UNSUPPORTED_OPERATION", message)


def internal() -> A2AError:
    return A2AError("INTERNAL_ERROR")


__all__ = [
    "A2AError",
    "A2A_ERROR_DOMAIN",
    "ERROR_INFO_TYPE",
    "ERROR_TABLE",
    "internal",
    "invalid_params",
    "task_not_found",
    "unsupported",
]
