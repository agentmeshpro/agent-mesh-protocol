"""PACT §6 errors and the non-A2A responses (§3.4, §5.5, OAuth).

A2A errors use the AIP-193 envelope with ``Content-Type:
application/a2a+json``; ``code`` repeats the HTTP status and the reason is
``error.details[0].reason``.  Messages are fixed strings — exception text
never reaches a client.
"""
from __future__ import annotations

import json
from typing import Any

from ampro.server.http import HTTPResponse

A2A_CONTENT_TYPE = "application/a2a+json"
ERROR_INFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
A2A_DOMAIN = "a2a-protocol.org"

#: reason -> (HTTP status, google.rpc status) — spec §6
REASONS: dict[str, tuple[int, str]] = {
    "INVALID_PARAMS": (400, "INVALID_ARGUMENT"),
    "CONTENT_TYPE_NOT_SUPPORTED": (400, "INVALID_ARGUMENT"),
    "UNSUPPORTED_OPERATION": (400, "FAILED_PRECONDITION"),
    "PUSH_NOTIFICATION_NOT_SUPPORTED": (400, "FAILED_PRECONDITION"),
    "TASK_NOT_FOUND": (404, "NOT_FOUND"),
    "INTERNAL": (500, "INTERNAL"),
}

#: reasons other A2A implementations use for the same thing
REASON_ALIASES = {"INTERNAL_ERROR": "INTERNAL"}

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
}


class PACTError(Exception):
    """An A2A error the PACT layer answers with (§6)."""

    def __init__(self, reason: str, message: str) -> None:
        if reason not in REASONS:
            reason = "INTERNAL"
        self.reason = reason
        self.message = message
        super().__init__(f"{reason}: {message}")

    def response(self) -> HTTPResponse:
        return a2a_error(self.reason, self.message)


def a2a_json(payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> HTTPResponse:
    hdrs = {**SECURITY_HEADERS, **(headers or {})}
    return HTTPResponse.json(payload, status=status, content_type=A2A_CONTENT_TYPE, headers=hdrs)


def a2a_error(reason: str, message: str) -> HTTPResponse:
    http, status = REASONS.get(reason, REASONS["INTERNAL"])
    return a2a_json(
        {"error": {"code": http, "status": status, "message": message, "details": [
            {"@type": ERROR_INFO_TYPE, "reason": reason, "domain": A2A_DOMAIN}]}},
        status=http,
    )


def not_found() -> HTTPResponse:
    """``404`` with no A2A body (§2.1, §2.2)."""
    return HTTPResponse.empty(404)


def method_not_allowed(allow: str) -> HTTPResponse:
    return HTTPResponse.empty(405, {"Allow": allow})


def unauthorized(error: str | None = None) -> HTTPResponse:
    """``401`` + ``WWW-Authenticate`` and no body (§3.4; §5.5 with ``invalid_token``)."""
    value = 'Bearer realm="a2a"'
    if error:
        value += f', error="{error}"'
    return HTTPResponse.empty(401, {"WWW-Authenticate": value})


def too_many_requests(retry_after: int) -> HTTPResponse:
    return HTTPResponse.empty(429, {"Retry-After": str(max(1, int(retry_after)))})


def oauth_json(payload: Any, status: int = 200) -> HTTPResponse:
    return HTTPResponse.json(payload, status=status, headers={
        "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


def oauth_error(error: str, description: str, status: int = 400) -> HTTPResponse:
    """RFC 6749 §5.2 / RFC 8628 §3.5 error body."""
    return oauth_json({"error": error, "error_description": description}, status)


def normalize_a2a_response(response: HTTPResponse, *, task_id: str | None = None) -> HTTPResponse:
    """Bring an A2A adapter response in line with PACT's wire rules.

    * JSON bodies are served as ``application/a2a+json``;
    * reason aliases (``INTERNAL_ERROR``) become the PACT name;
    * a ``TASK_NOT_FOUND`` on ``tasks/{id}`` routes says ``Task not found: {id}``;
    * non-JSON error bodies are dropped.
    """
    if response.is_streaming:
        return response
    body = response.body
    if not body:
        return response
    try:
        payload = json.loads(body)
    except ValueError:
        if response.status >= 400:
            return HTTPResponse.empty(response.status)
        return response
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        details = err.get("details") if isinstance(err.get("details"), list) else []
        reason = None
        for d in details:
            if isinstance(d, dict) and d.get("@type") == ERROR_INFO_TYPE:
                reason = d.get("reason")
                break
        reason = REASON_ALIASES.get(reason, reason) if isinstance(reason, str) else "INTERNAL"
        if reason not in REASONS:
            reason = "INTERNAL"
        message = err.get("message") if isinstance(err.get("message"), str) else reason
        if reason == "INTERNAL":
            message = "Internal error"
        if reason == "TASK_NOT_FOUND" and task_id is not None:
            message = f"Task not found: {task_id}"
        return a2a_error(reason, message)
    headers = {k: v for k, v in response.headers.items() if k != "content-type"}
    return a2a_json(payload, status=response.status, headers=headers)


__all__ = [
    "A2A_CONTENT_TYPE",
    "PACTError",
    "REASONS",
    "a2a_error",
    "a2a_json",
    "method_not_allowed",
    "normalize_a2a_response",
    "not_found",
    "oauth_error",
    "oauth_json",
    "too_many_requests",
    "unauthorized",
]
