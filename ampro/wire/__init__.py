"""
AMP Wire Binding -- HTTP transport contract for the Agent Mesh Protocol.

This subpackage formally defines the HTTP contract that any AMP-compliant
server MUST (or MAY) implement.  It covers:

  - Endpoint definitions with conformance levels
  - RFC 7807 error responses
  - Configurable defaults (rate limits, dedup windows, etc.)
  - Body-type to HTTP-semantics mapping

All types are pure Pydantic + stdlib.  Zero platform-specific references.
"""

from __future__ import annotations

from ampro.wire.body_type_map import (
    BODY_TYPE_BINDINGS,
    BodyTypeBinding,
    ResponseMode,
    binding_for,
    idempotent_body_types,
    is_canonical,
    streaming_body_types,
)
from ampro.wire.config import DEFAULTS as WIRE_DEFAULTS
from ampro.wire.config import WireConfig
from ampro.wire.endpoints import (
    # Level 0
    AGENT_JSON,
    ALL_ENDPOINTS,
    AUDIT_LOG,
    CONSENT_REQUEST,
    CONSENT_REVOKE,
    HEALTH,
    IDENTITY_VERIFY,
    # Level 0 (JWKS)
    JWKS,
    # Level 1
    MESSAGE,
    # Level 5
    PRESENCE,
    REGISTRY_REGISTER,
    REGISTRY_RESOLVE,
    REGISTRY_SEARCH,
    SESSION_CLOSE,
    SESSION_GET,
    # Level 4
    SESSION_START,
    SESSION_UPDATE,
    STREAM,
    # Level 3
    TASK_STATUS,
    TASK_UPDATE,
    TOOL_INVOKE,
    # Level 2
    TOOLS_LIST,
    ConformanceLevel,
    EndpointSpec,
    HttpMethod,
    endpoints_at_level,
    endpoints_for_level,
)
from ampro.wire.errors import (
    AuthorityConstraint,
    AuthorityRequiredError,
    AuthorityRequiredProblem,
    ErrorType,
    HumanApproval,
    PaymentRequirement,
    ProblemDetail,
    authority_required,
    capability_not_negotiated,
    consent_denied,
    contact_policy_violation,
    content_type_mismatch,
    delegation_denied,
    delegation_validation_failed,
    forbidden,
    header_injection,
    insufficient_scope_challenge,
    internal_error,
    invalid_callback_url,
    invalid_message,
    jurisdiction_conflict,
    loop_detected,
    nonce_replay,
    not_found,
    not_implemented,
    parse_authority_required,
    payload_too_large,
    rate_limited,
    residency_violation,
    session_expired,
    stream_limit_exceeded,
    timeout,
    unauthorized,
    unavailable,
    version_mismatch,
)

__all__ = [
    # Endpoints
    "ConformanceLevel",
    "EndpointSpec",
    "HttpMethod",
    "ALL_ENDPOINTS",
    "endpoints_for_level",
    "endpoints_at_level",
    "AGENT_JSON",
    "HEALTH",
    "MESSAGE",
    "TOOLS_LIST",
    "TOOL_INVOKE",
    "TASK_STATUS",
    "STREAM",
    "TASK_UPDATE",
    "SESSION_START",
    "SESSION_GET",
    "SESSION_UPDATE",
    "SESSION_CLOSE",
    "IDENTITY_VERIFY",
    "CONSENT_REQUEST",
    "CONSENT_REVOKE",
    "PRESENCE",
    "AUDIT_LOG",
    "REGISTRY_RESOLVE",
    "REGISTRY_REGISTER",
    "REGISTRY_SEARCH",
    "JWKS",
    # Errors
    "ProblemDetail",
    "ErrorType",
    # Authority required (7.2.14)
    "AuthorityRequiredProblem",
    "AuthorityRequiredError",
    "AuthorityConstraint",
    "PaymentRequirement",
    "HumanApproval",
    "authority_required",
    "parse_authority_required",
    "insufficient_scope_challenge",
    "rate_limited",
    "invalid_message",
    "unauthorized",
    "forbidden",
    "not_found",
    "version_mismatch",
    "nonce_replay",
    "session_expired",
    "payload_too_large",
    "internal_error",
    "not_implemented",
    "unavailable",
    "capability_not_negotiated",
    "contact_policy_violation",
    "delegation_denied",
    "jurisdiction_conflict",
    "residency_violation",
    "consent_denied",
    "timeout",
    "loop_detected",
    "invalid_callback_url",
    "delegation_validation_failed",
    "stream_limit_exceeded",
    "content_type_mismatch",
    "header_injection",
    # Config
    "WireConfig",
    "WIRE_DEFAULTS",
    # Body type map
    "ResponseMode",
    "BodyTypeBinding",
    "BODY_TYPE_BINDINGS",
    "binding_for",
    "is_canonical",
    "streaming_body_types",
    "idempotent_body_types",
]
