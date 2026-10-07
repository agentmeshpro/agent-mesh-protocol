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

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, StrictInt, field_validator, model_validator

from ampro.errors import AmpError

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
    AUTHORITY_REQUIRED = "urn:amp:error:authority-required"

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


# ---------------------------------------------------------------------------
# 403 authority-required (WIRE-BINDING 7.2.14)
# ---------------------------------------------------------------------------

#: Bounds on the typed members of an authority-required problem.
MAX_MISSING_SCOPES = 64
MAX_SCOPE_LENGTH = 256
MAX_REQUIRED_CONSTRAINTS = 16
MAX_CONSTRAINT_BYTES = 4096
MAX_PAYMENT_METHODS = 16
MAX_AUTHORITY_URI_LENGTH = 2048
MAX_APPROVAL_EXPIRES_IN = 86_400
MAX_AUTHORITY_PROBLEM_BYTES = 65_536
#: Largest amount that survives a round trip through an IEEE-754 double.
MAX_PAYMENT_AMOUNT = 2**53 - 1

#: RFC 6749 section 3.3 ``scope-token``.
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
_PAYMENT_METHOD = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_REALM = re.compile(r"^[A-Za-z0-9 ._:/-]{1,128}$")

ScopeToken = Annotated[str, Field(
    min_length=1, max_length=MAX_SCOPE_LENGTH, pattern=r"^[\x21\x23-\x5B\x5D-\x7E]+$",
)]
PaymentMethod = Annotated[str, Field(
    min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._:-]{0,63}$",
)]


def _no_controls(value: str, what: str) -> str:
    for ch in value:
        if unicodedata.category(ch)[0] == "C" or ch.isspace():
            raise ValueError(f"{what} must not contain control or whitespace characters")
    return value


def _https_uri(value: str, what: str) -> str:
    """An absolute https URI with a host, no userinfo, no fragment, bounded."""
    if not isinstance(value, str) or not value or len(value) > MAX_AUTHORITY_URI_LENGTH:
        raise ValueError(f"{what} must be 1..{MAX_AUTHORITY_URI_LENGTH} characters")
    if not value.isascii():
        raise ValueError(f"{what} must be ASCII")
    _no_controls(value, what)
    if '"' in value or "\\" in value:
        raise ValueError(f"{what} must not contain quotes or backslashes")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"{what} is not a valid URI: {exc}") from exc
    if parts.scheme != "https":
        raise ValueError(f"{what} must use the https scheme")
    if not parts.hostname or "@" in parts.netloc:
        raise ValueError(f"{what} must have a host and no userinfo")
    if port == 0:
        raise ValueError(f"{what} has an invalid port")
    if "#" in value:
        raise ValueError(f"{what} must not have a fragment")
    # A peer controls this value, and clients may show or open it: refuse
    # IP literals, localhost, single-label and numeric-looking hosts, which
    # would point a user or a fetcher at their own machine or network.
    from ampro.core.addressing import _canonical_dns_host

    host = parts.hostname
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError(f"{what} must not point at localhost")
    _canonical_dns_host(host, what)
    return value


#: Maximum nesting of the opaque members of a constraint.
MAX_CONSTRAINT_DEPTH = 8


def _check_plain_json(value: Any, depth: int) -> None:
    """Only JSON types, finite numbers, string keys, bounded nesting."""
    if depth > MAX_CONSTRAINT_DEPTH:
        raise ValueError(f"constraint is nested deeper than {MAX_CONSTRAINT_DEPTH} levels")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("constraint keys must be strings")
            _check_plain_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_plain_json(item, depth + 1)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("constraint numbers must be finite")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise ValueError("constraint members must be plain JSON")


def _json_size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8"))


class AuthorityConstraint(BaseModel):
    """An opaque, typed constraint the caller's authority must satisfy.

    Only ``type`` is interpreted by AMP; the other members are defined by
    whoever owns the ``type`` (for example ``"com.acme:region"``).  Each
    constraint is at most :data:`MAX_CONSTRAINT_BYTES` of JSON.
    """

    type: str = Field(
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9._:/+-]{0,127}$",
        description="Constraint type identifier; the type's owner defines the other members",
    )

    model_config = {"extra": "allow"}

    @model_validator(mode="after")
    def _bounded(self) -> AuthorityConstraint:
        _check_plain_json(self.model_extra or {}, depth=0)
        try:
            size = _json_size(self.model_dump(mode="json"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"constraint must be plain JSON: {exc}") from exc
        if size > MAX_CONSTRAINT_BYTES:
            raise ValueError(f"constraint is larger than {MAX_CONSTRAINT_BYTES} bytes")
        return self


class PaymentRequirement(BaseModel):
    """Payment the caller must make first (maps to x402 / HTTP 402)."""

    amount: StrictInt = Field(
        ge=1, le=MAX_PAYMENT_AMOUNT,
        description="Amount in integer minor units of currency (e.g. cents)",
    )
    currency: str = Field(
        pattern=r"^[A-Z]{3}$",
        description="ISO 4217 alphabetic currency code",
    )
    methods: list[PaymentMethod] = Field(
        default_factory=list,
        max_length=MAX_PAYMENT_METHODS,
        description="Accepted payment methods (e.g. x402, card); empty means unspecified",
    )

    model_config = {"extra": "ignore"}

    @field_validator("methods")
    @classmethod
    def _methods(cls, value: list[str]) -> list[str]:
        for method in value:
            if not _PAYMENT_METHOD.fullmatch(method):
                raise ValueError(f"invalid payment method {method!r}")
        if len(set(value)) != len(value):
            raise ValueError("payment methods must be unique")
        return value


class HumanApproval(BaseModel):
    """A human must approve at ``verification_uri`` (RFC 8628 style)."""

    verification_uri: str = Field(
        max_length=MAX_AUTHORITY_URI_LENGTH,
        description="https URI where the human approves the request",
    )
    expires_in: StrictInt | None = Field(
        default=None, ge=1, le=MAX_APPROVAL_EXPIRES_IN,
        description="Seconds until the approval request expires",
    )

    model_config = {"extra": "ignore"}

    @field_validator("verification_uri")
    @classmethod
    def _uri(cls, value: str) -> str:
        return _https_uri(value, "verification_uri")


class AuthorityRequiredProblem(ProblemDetail):
    """403 ``urn:amp:error:authority-required``: the caller needs more authority.

    At least one of ``missing_scopes``, ``required_constraints``,
    ``payment_required`` or ``human_approval`` is present.
    """

    type: Literal["urn:amp:error:authority-required"] = Field(  # type: ignore[assignment]
        default="urn:amp:error:authority-required",
        description="Always urn:amp:error:authority-required",
    )
    title: str = Field(
        default="Authority required", max_length=256,
        description="Short human-readable summary of the problem",
    )
    status: Literal[403] = Field(  # type: ignore[assignment]
        default=403, description="Always 403",
    )
    missing_scopes: list[ScopeToken] = Field(
        default_factory=list,
        max_length=MAX_MISSING_SCOPES,
        description="OAuth scope tokens (RFC 6749 section 3.3) the caller lacks",
    )
    required_constraints: list[AuthorityConstraint] = Field(
        default_factory=list,
        max_length=MAX_REQUIRED_CONSTRAINTS,
        description="Typed constraints the caller's authority must satisfy",
    )
    payment_required: PaymentRequirement | None = Field(
        default=None, description="Payment the caller must make first",
    )
    human_approval: HumanApproval | None = Field(
        default=None, description="Human approval the caller must obtain first",
    )
    audience: str | None = Field(
        default=None, max_length=MAX_AUTHORITY_URI_LENGTH,
        description="Audience (resource or agent) the new authority must be issued for",
    )

    model_config = {"extra": "ignore"}

    @field_validator("missing_scopes")
    @classmethod
    def _scopes(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for scope in value:
            if not 1 <= len(scope) <= MAX_SCOPE_LENGTH:
                raise ValueError(f"scope tokens must be 1..{MAX_SCOPE_LENGTH} characters")
            if not _SCOPE_TOKEN.fullmatch(scope):
                raise ValueError(f"invalid scope token {scope!r} (RFC 6749 section 3.3)")
            if scope not in out:
                out.append(scope)
        return out

    @field_validator("audience")
    @classmethod
    def _audience(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value:
            raise ValueError("audience must not be empty")
        return _no_controls(value, "audience")

    @model_validator(mode="after")
    def _something_required(self) -> AuthorityRequiredProblem:
        if not (self.missing_scopes or self.required_constraints
                or self.payment_required or self.human_approval):
            raise ValueError(
                "authority-required needs at least one of missing_scopes, "
                "required_constraints, payment_required or human_approval"
            )
        if _json_size(self.model_dump(mode="json", exclude_none=True)) > MAX_AUTHORITY_PROBLEM_BYTES:
            raise ValueError(f"problem is larger than {MAX_AUTHORITY_PROBLEM_BYTES} bytes")
        return self


def authority_required(
    detail: str = "The caller needs more authority for this request",
    *,
    missing_scopes: Iterable[str] = (),
    required_constraints: Iterable[AuthorityConstraint | Mapping[str, Any]] = (),
    payment_required: PaymentRequirement | Mapping[str, Any] | None = None,
    human_approval: HumanApproval | Mapping[str, Any] | None = None,
    audience: str | None = None,
    instance: str | None = None,
) -> AuthorityRequiredProblem:
    """Create a 403 ``urn:amp:error:authority-required`` problem.

    Raises ``ValueError`` (pydantic ``ValidationError``) when a member is
    malformed or out of bounds, or when nothing is said to be missing.
    """
    if isinstance(missing_scopes, str):
        raise ValueError("missing_scopes must be an iterable of scope tokens, not a string")
    return AuthorityRequiredProblem.model_validate({
        "detail": detail,
        "instance": instance,
        "missing_scopes": list(missing_scopes),
        "required_constraints": [
            c.model_dump(mode="json") if isinstance(c, AuthorityConstraint) else c
            for c in required_constraints
        ],
        "payment_required": (
            payment_required.model_dump(mode="json")
            if isinstance(payment_required, PaymentRequirement) else payment_required
        ),
        "human_approval": (
            human_approval.model_dump(mode="json")
            if isinstance(human_approval, HumanApproval) else human_approval
        ),
        "audience": audience,
    })


def parse_authority_required(data: Mapping[str, Any]) -> AuthorityRequiredProblem:
    """Validate a received ``application/problem+json`` body as authority-required.

    Raises ``ValueError`` unless ``type`` is exactly the authority-required
    URN, ``status`` is 403, and every member is well formed.
    """
    if not isinstance(data, Mapping):
        raise ValueError("problem must be a JSON object")
    if data.get("type") != ErrorType.AUTHORITY_REQUIRED:
        raise ValueError("not an authority-required problem")
    return AuthorityRequiredProblem.model_validate(dict(data))


def insufficient_scope_challenge(
    problem: AuthorityRequiredProblem,
    *,
    realm: str = "amp",
    resource_metadata: str | None = None,
) -> str:
    """``WWW-Authenticate`` value for *problem* (RFC 6750 ``insufficient_scope``).

    MCP clients step up on ``error="insufficient_scope"`` plus ``scope``;
    ``resource_metadata`` (RFC 9728) points them at the protected-resource
    metadata.  Scope tokens cannot contain ``"`` or ``\\`` (RFC 6749), so
    no escaping is needed.
    """
    if not _REALM.fullmatch(realm):
        raise ValueError("realm must be 1..128 characters of [A-Za-z0-9 ._:/-]")
    value = f'Bearer realm="{realm}", error="insufficient_scope"'
    if problem.missing_scopes:
        value += f', scope="{" ".join(problem.missing_scopes)}"'
    if resource_metadata is not None:
        value += f', resource_metadata="{_https_uri(resource_metadata, "resource_metadata")}"'
    return value


class AuthorityRequiredError(AmpError):
    """Raise from a handler when the caller needs more authority.

    The AMP server answers with the 403 ``urn:amp:error:authority-required``
    problem, plus ``WWW-Authenticate: Bearer error="insufficient_scope"``
    when scopes are missing.  Build it from the keyword arguments of
    :func:`authority_required`, or from an existing *problem*.
    """

    def __init__(
        self,
        detail: str = "The caller needs more authority for this request",
        *,
        problem: AuthorityRequiredProblem | None = None,
        **requirements: Any,
    ) -> None:
        if problem is not None:
            if requirements:
                raise ValueError("pass either problem or requirement keywords, not both")
            if not isinstance(problem, AuthorityRequiredProblem):
                raise ValueError("problem must be an AuthorityRequiredProblem")
            self.problem = problem
        else:
            self.problem = authority_required(detail, **requirements)
        super().__init__(self.problem.detail or self.problem.title)

    def to_problem(self) -> AuthorityRequiredProblem:
        """The problem to send."""
        return self.problem

    def www_authenticate(self, realm: str = "amp") -> str:
        """The matching ``WWW-Authenticate`` header value."""
        return insufficient_scope_challenge(self.problem, realm=realm)
