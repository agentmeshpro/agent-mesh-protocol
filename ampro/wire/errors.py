"""
AMP Wire Binding -- Error Response Format (RFC 7807).

All AMP error responses use the RFC 7807 Problem Details structure.
Each error type has a stable URN (``urn:amp:error:*``) that clients can
match on programmatically.  The ``detail`` field carries a human-readable
explanation.

Usage::

    from ampro.wire.errors import rate_limited, ProblemDetail

    err = rate_limited("Too many requests from @alice-agi", retry_after=30)
    # err.model_dump() -> RFC 7807 JSON

PURE -- zero platform-specific imports.  Only pydantic and stdlib.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# RFC 7807 Problem Detail
# ---------------------------------------------------------------------------


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details for HTTP APIs.

    Extension fields are permitted (``extra = "allow"``).  Consumers MUST
    ignore extension fields they do not recognise.
    """

    type: str = Field(description="URN identifying the error type (e.g. urn:amp:error:rate-limited)")
    title: str = Field(description="Short human-readable summary of the problem")
    status: int = Field(description="HTTP status code applicable to this problem")
    detail: str | None = Field(default=None, max_length=1024, description="Human-readable explanation specific to this occurrence")
    instance: str | None = Field(default=None, description="URI identifying the specific occurrence of the problem")
    retry_after_seconds: int | None = Field(default=None, ge=0, description="Seconds the client should wait before retrying")
    max_bytes: int | None = Field(default=None, ge=0, description="413 only: the receiver's maximum message size in bytes")
    supported_versions: list[str] | None = Field(default=None, description="406 only: protocol versions the receiver supports")

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Standard error URNs
# ---------------------------------------------------------------------------


class ErrorType:
    """Stable URN constants for all AMP error types.

    Clients SHOULD match on these URNs rather than HTTP status codes,
    because a single status code (e.g. 403) can map to multiple
    distinct error conditions.
    """

    # 400 -- Bad Request family
    INVALID_MESSAGE = "urn:amp:error:invalid-message"
    INVALID_CALLBACK_URL = "urn:amp:error:invalid-callback-url"
    HEADER_INJECTION = "urn:amp:error:header-injection"
    PAYLOAD_TOO_LARGE = "urn:amp:error:payload-too-large"

    # 401 -- Unauthorized
    UNAUTHORIZED = "urn:amp:error:unauthorized"

    # 403 -- Forbidden family
    FORBIDDEN = "urn:amp:error:forbidden"
    CAPABILITY_NOT_NEGOTIATED = "urn:amp:error:capability-not-negotiated"
    CONTACT_POLICY_VIOLATION = "urn:amp:error:contact-policy-violation"
    DELEGATION_DENIED = "urn:amp:error:delegation-denied"
    DELEGATION_VALIDATION_FAILED = "urn:amp:error:delegation-validation-failed"
    JURISDICTION_CONFLICT = "urn:amp:error:jurisdiction-conflict"
    RESIDENCY_VIOLATION = "urn:amp:error:residency-violation"
    CONSENT_DENIED = "urn:amp:error:consent-denied"

    # 404 -- Not Found
    NOT_FOUND = "urn:amp:error:not-found"

    # 406 -- Not Acceptable
    VERSION_MISMATCH = "urn:amp:error:version-mismatch"

    # 408 -- Request Timeout
    TIMEOUT = "urn:amp:error:timeout"

    # 409 -- Conflict
    NONCE_REPLAY = "urn:amp:error:nonce-replay"
    LOOP_DETECTED = "urn:amp:error:loop-detected"

    # 410 -- Gone
    SESSION_EXPIRED = "urn:amp:error:session-expired"

    # 415 -- Unsupported Media Type
    CONTENT_TYPE_MISMATCH = "urn:amp:error:content-type-mismatch"

    # 429 -- Too Many Requests
    RATE_LIMITED = "urn:amp:error:rate-limited"
    STREAM_LIMIT_EXCEEDED = "urn:amp:error:stream-limit-exceeded"

    # 500 -- Internal Server Error
    INTERNAL_ERROR = "urn:amp:error:internal-error"

    # 501 -- Not Implemented
    NOT_IMPLEMENTED = "urn:amp:error:not-implemented"

    # 503 -- Service Unavailable
    UNAVAILABLE = "urn:amp:error:unavailable"


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def rate_limited(detail: str, retry_after: int = 60) -> ProblemDetail:
    """Create a 429 Too Many Requests error."""
    return ProblemDetail(
        type=ErrorType.RATE_LIMITED,
        title="Rate limit exceeded",
        status=429,
        detail=detail,
        retry_after_seconds=retry_after,
    )


def invalid_message(detail: str) -> ProblemDetail:
    """Create a 400 Bad Request error for malformed messages."""
    return ProblemDetail(
        type=ErrorType.INVALID_MESSAGE,
        title="Invalid message",
        status=400,
        detail=detail,
    )


def unauthorized(detail: str = "Authentication required") -> ProblemDetail:
    """Create a 401 Unauthorized error."""
    return ProblemDetail(
        type=ErrorType.UNAUTHORIZED,
        title="Unauthorized",
        status=401,
        detail=detail,
    )


def forbidden(detail: str = "Access denied") -> ProblemDetail:
    """Create a 403 Forbidden error."""
    return ProblemDetail(
        type=ErrorType.FORBIDDEN,
        title="Forbidden",
        status=403,
        detail=detail,
    )


def not_found(detail: str = "Resource not found") -> ProblemDetail:
    """Create a 404 Not Found error."""
    return ProblemDetail(
        type=ErrorType.NOT_FOUND,
        title="Not found",
        status=404,
        detail=detail,
    )


def version_mismatch(detail: str, supported_versions: list[str] | None = None) -> ProblemDetail:
    """Create a 406 Not Acceptable error for protocol version mismatches."""
    return ProblemDetail(
        type=ErrorType.VERSION_MISMATCH,
        title="Protocol version mismatch",
        status=406,
        detail=detail,
        supported_versions=supported_versions,
    )


def nonce_replay(detail: str = "Nonce has already been used") -> ProblemDetail:
    """Create a 409 Conflict error for replayed nonces."""
    return ProblemDetail(
        type=ErrorType.NONCE_REPLAY,
        title="Nonce replay detected",
        status=409,
        detail=detail,
    )


def session_expired(detail: str = "Session has expired or been closed") -> ProblemDetail:
    """Create a 410 Gone error for expired sessions."""
    return ProblemDetail(
        type=ErrorType.SESSION_EXPIRED,
        title="Session expired",
        status=410,
        detail=detail,
    )


def payload_too_large(detail: str, max_bytes: int | None = None) -> ProblemDetail:
    """Create a 413 Payload Too Large error."""
    extra: dict[str, int] = {}
    if max_bytes is not None:
        extra["max_bytes"] = max_bytes
    return ProblemDetail(
        type=ErrorType.PAYLOAD_TOO_LARGE,
        title="Payload too large",
        status=413,
        detail=detail,
        **extra,
    )


def internal_error(detail: str = "An unexpected error occurred") -> ProblemDetail:
    """Create a 500 Internal Server Error."""
    return ProblemDetail(
        type=ErrorType.INTERNAL_ERROR,
        title="Internal error",
        status=500,
        detail=detail,
    )


def not_implemented(detail: str = "This capability is not implemented") -> ProblemDetail:
    """Create a 501 Not Implemented error."""
    return ProblemDetail(
        type=ErrorType.NOT_IMPLEMENTED,
        title="Not implemented",
        status=501,
        detail=detail,
    )


def unavailable(detail: str = "Service temporarily unavailable", retry_after: int | None = None) -> ProblemDetail:
    """Create a 503 Service Unavailable error."""
    return ProblemDetail(
        type=ErrorType.UNAVAILABLE,
        title="Service unavailable",
        status=503,
        detail=detail,
        retry_after_seconds=retry_after,
    )


def capability_not_negotiated(detail: str) -> ProblemDetail:
    """Create a 403 error when a required capability was not negotiated."""
    return ProblemDetail(
        type=ErrorType.CAPABILITY_NOT_NEGOTIATED,
        title="Capability not negotiated",
        status=403,
        detail=detail,
    )


def contact_policy_violation(detail: str) -> ProblemDetail:
    """Create a 403 error when the sender violates the agent's contact policy."""
    return ProblemDetail(
        type=ErrorType.CONTACT_POLICY_VIOLATION,
        title="Contact policy violation",
        status=403,
        detail=detail,
    )


def delegation_denied(detail: str) -> ProblemDetail:
    """Create a 403 error when a delegation request is denied."""
    return ProblemDetail(
        type=ErrorType.DELEGATION_DENIED,
        title="Delegation denied",
        status=403,
        detail=detail,
    )


def jurisdiction_conflict(detail: str) -> ProblemDetail:
    """Create a 403 error for jurisdictional conflicts."""
    return ProblemDetail(
        type=ErrorType.JURISDICTION_CONFLICT,
        title="Jurisdiction conflict",
        status=403,
        detail=detail,
    )


def residency_violation(detail: str) -> ProblemDetail:
    """Create a 403 error for data residency violations."""
    return ProblemDetail(
        type=ErrorType.RESIDENCY_VIOLATION,
        title="Data residency violation",
        status=403,
        detail=detail,
    )


def consent_denied(detail: str = "Consent was not granted") -> ProblemDetail:
    """Create a 403 error when required consent is absent."""
    return ProblemDetail(
        type=ErrorType.CONSENT_DENIED,
        title="Consent denied",
        status=403,
        detail=detail,
    )


def timeout(detail: str, retry_after: int | None = None) -> ProblemDetail:
    """Create a 408 Request Timeout error."""
    return ProblemDetail(
        type=ErrorType.TIMEOUT,
        title="Request timeout",
        status=408,
        detail=detail,
        retry_after_seconds=retry_after,
    )


def loop_detected(detail: str) -> ProblemDetail:
    """Create a 409 Conflict error when a message loop is detected."""
    return ProblemDetail(
        type=ErrorType.LOOP_DETECTED,
        title="Loop detected",
        status=409,
        detail=detail,
    )


def invalid_callback_url(detail: str) -> ProblemDetail:
    """Create a 400 Bad Request error for invalid callback URLs."""
    return ProblemDetail(
        type=ErrorType.INVALID_CALLBACK_URL,
        title="Invalid callback URL",
        status=400,
        detail=detail,
    )


def delegation_validation_failed(detail: str) -> ProblemDetail:
    """Create a 403 Forbidden error when delegation chain validation fails."""
    return ProblemDetail(
        type=ErrorType.DELEGATION_VALIDATION_FAILED,
        title="Delegation validation failed",
        status=403,
        detail=detail,
    )


def stream_limit_exceeded(detail: str, retry_after: int | None = None) -> ProblemDetail:
    """Create a 429 Too Many Requests error when stream limits are exceeded."""
    return ProblemDetail(
        type=ErrorType.STREAM_LIMIT_EXCEEDED,
        title="Stream limit exceeded",
        status=429,
        detail=detail,
        retry_after_seconds=retry_after,
    )


def content_type_mismatch(detail: str) -> ProblemDetail:
    """Create a 415 Unsupported Media Type error for content type mismatches."""
    return ProblemDetail(
        type=ErrorType.CONTENT_TYPE_MISMATCH,
        title="Content type mismatch",
        status=415,
        detail=detail,
    )


def header_injection(detail: str) -> ProblemDetail:
    """Create a 400 Bad Request error for header injection attempts."""
    return ProblemDetail(
        type=ErrorType.HEADER_INJECTION,
        title="Header injection detected",
        status=400,
        detail=detail,
    )
