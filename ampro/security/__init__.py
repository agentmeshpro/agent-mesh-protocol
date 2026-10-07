"""Rate limiting, dedup, challenges, and encryption."""

from ampro.security.challenge import (
    ChallengeReason,
    TaskChallengeBody,
    TaskChallengeResponseBody,
)
from ampro.security.circuit_breaker import CircuitBreakerInfo, CircuitState
from ampro.security.concurrency_limiter import ConcurrencyLimiter
from ampro.security.dedup import DedupStore, InMemoryDedupStore
from ampro.security.encryption import CONTENT_ENCRYPTION_HEADER, EncryptedBody
from ampro.security.key_revocation import (
    InMemoryKeyStatusResolver,
    KeyRevocationBody,
    KeyStatus,
    KeyStatusRecord,
    KeyStatusResolver,
    RevocationReason,
    canonical_revocation_bytes,
    delegation_key_check,
    is_revocation_authentic,
    key_status_for_reason,
    parse_rfc3339_timestamp,
    signature_allowed,
    validate_revocation_signature,
)
from ampro.security.nonce_tracker import NonceTracker
from ampro.security.rate_limit import RateLimitInfo, format_rate_limit_headers
from ampro.security.rate_limiter import RateLimiter
from ampro.security.sender_tracker import SenderState, SenderTracker
from ampro.security.ssrf import (
    SSRFError,
    ValidatedURL,
    check_url_static,
    is_blocked_ip,
    is_url_safe_static,
    pinned_async_transport,
    validate_url,
    validate_url_async,
)

__all__ = [
    # Rate limiting
    "RateLimitInfo", "format_rate_limit_headers", "RateLimiter",
    # Dedup
    "DedupStore", "InMemoryDedupStore",
    # Nonce
    "NonceTracker",
    # Challenge
    "ChallengeReason", "TaskChallengeBody", "TaskChallengeResponseBody",
    # Circuit breaker
    "CircuitState", "CircuitBreakerInfo",
    # Encryption
    "EncryptedBody", "CONTENT_ENCRYPTION_HEADER",
    # Key revocation
    "RevocationReason", "KeyRevocationBody", "validate_revocation_signature",
    "is_revocation_authentic", "canonical_revocation_bytes", "parse_rfc3339_timestamp",
    # Key status (compromise vs rotation)
    "KeyStatus", "KeyStatusResolver", "KeyStatusRecord",
    "InMemoryKeyStatusResolver", "signature_allowed", "delegation_key_check", "key_status_for_reason",
    # Concurrency
    "ConcurrencyLimiter",
    # Sender tracker
    "SenderTracker", "SenderState",
    # SSRF guard
    "SSRFError", "ValidatedURL", "validate_url", "validate_url_async",
    "check_url_static", "is_url_safe_static", "is_blocked_ip",
    "pinned_async_transport",
]
