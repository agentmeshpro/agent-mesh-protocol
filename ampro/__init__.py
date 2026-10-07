"""
agent-protocol — Universal agent-to-agent communication protocol.

The protocol answers four questions:
  - Can I reach you?   → agent:// addressing
  - Can I trust you?   → 4-tier trust (internal/owner/verified/external)
  - What can you do?   → 8 capability groups, 6 progressive levels
  - How do we talk?    → POST /agent/message with typed body schemas

Install: pip install agent-protocol
"""

# --- Unified error hierarchy ---
# --- Context schemas ---
from ampro.agent.context_schema import ContextSchemaInfo, check_schema_supported, parse_schema_urn

# --- Operational types ---
from ampro.agent.health import HealthResponse

# --- Agent lifecycle ---
from ampro.agent.lifecycle import AgentDeactivationNoticeBody, AgentLifecycleStatus

# --- Agent metadata cache invalidation ---
from ampro.agent.schema import (
    MAX_MIGRATION_HOPS,
    AgentJson,
    AgentMetadataInvalidateBody,
    follow_migration_chain,
)

# --- Tool consent ---
from ampro.agent.tool_consent import ToolConsentGrantBody, ToolConsentRequestBody, ToolDefinition

# --- Visibility & contact policies ---
from ampro.agent.visibility import (
    ContactPolicy,
    VisibilityConfig,
    VisibilityLevel,
    check_contact_allowed,
    filter_agent_json,
)

# --- AMPI (Agent Message Processing Interface) ---
from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.ampi.errors import AMPError, BackpressureError, StreamLimitExceeded
from ampro.ampi.types import AMPIApp, AMPIServer, HandlerFunc, MiddlewareFunc

# --- Audit attestation ---
from ampro.compliance.audit_attestation import AuditAttestationBody, verify_attestation
from ampro.compliance.audit_logger import (
    AuditEntry,
    AuditLogger,
    AuditStorage,
    InMemoryAuditStorage,
)

# --- Certifications ---
from ampro.compliance.certifications import CertificationLink

# --- Consent revocation ---
from ampro.compliance.consent_revoke import DataConsentRevokeBody

# --- Data residency ---
from ampro.compliance.data_residency import (
    DataResidency,
    check_residency_violation,
    validate_residency_region,
)
from ampro.compliance.erasure import ErasureProcessor

# --- Erasure propagation ---
from ampro.compliance.erasure_propagation import (
    ErasurePropagationStatus,
    ErasurePropagationStatusBody,
)

# --- Jurisdiction ---
from ampro.compliance.jurisdiction import (
    JurisdictionInfo,
    check_jurisdiction_conflict,
    validate_jurisdiction_code,
)
from ampro.compliance.middleware import (
    ComplianceCheckResult,
    check_content_classification,
    check_minor_protection,
    requires_audit,
)

# --- Compliance ---
from ampro.compliance.types import (
    ContentClassification,
    ErasureRequest,
    ErasureResponse,
    ExportRequest,
    ExportResponse,
    RetentionPolicy,
)

# --- Addressing ---
from ampro.core.addressing import AddressType, AgentAddress, normalize_shorthand, parse_agent_uri

# --- Body type schemas ---
from ampro.core.body_schemas import (
    DataConsentRequestBody,
    DataConsentResponseBody,
    MessageBody,
    NotificationBody,
    TaskAcknowledgeBody,
    TaskAssignBody,
    TaskCompleteBody,
    TaskCreateBody,
    TaskDelegateBody,
    TaskErrorBody,
    TaskEscalateBody,
    TaskInputRequiredBody,
    TaskProgressBody,
    TaskQuoteBody,
    TaskRejectBody,
    TaskRerouteBody,
    TaskResponseBody,
    TaskSpawnBody,
    TaskTransferBody,
    validate_body,
)
from ampro.core.capabilities import CapabilityGroup, CapabilityLevel, CapabilitySet

# --- Core envelope ---
from ampro.core.envelope import STANDARD_HEADERS, AgentMessage
from ampro.core.message_middleware import (
    MessageSizeError,
    build_negotiation_headers,
    check_message_size,
    enforce_encryption_requirement,
    validate_message_body,
)

# --- Priority ---
from ampro.core.priority import Priority
from ampro.core.status import AgentStatus
from ampro.core.versioning import (
    CURRENT_VERSION,
    SUPPORTED_VERSIONS,
    check_version,
    negotiate_version,
)

# --- Delegation ---
from ampro.delegation.chain import (
    DelegationChain,
    DelegationLink,
    check_visited_agents_limit,
    check_visited_agents_loop,
    normalize_agent_uri,
    parse_chain_budget,
    parse_visited_agents,
    sign_delegation,
    validate_chain,
    validate_scope_narrowing,
)

# --- Cost receipts ---
from ampro.delegation.cost_receipt import (
    CostReceipt,
    CostReceiptChain,
    CostReceiptVerificationError,
)

# --- Tracing ---
from ampro.delegation.tracing import (
    TraceContext,
    extract_trace_context,
    generate_span_id,
    generate_trace_id,
    inject_trace_headers,
)
from ampro.errors import (
    AmpError,
    CompliancePolicyError,
    CryptoError,
    MigrationChainTooLongError,
    NotImplementedInProtocol,
    RateLimitError,
    RedirectLoopError,
    SessionError,
    TransportError,
    TrustError,
)
from ampro.errors import (
    ValidationError as AmpValidationError,
)
from ampro.identity.auth_methods import AuthMethod, ParsedAuth, parse_authorization

# --- Cross-verification ---
from ampro.identity.cross_verification import (
    CrossVerificationRequiredError,
    VerificationResult,
    check_all_verified,
    cross_verify_identifiers,
    get_failed_identifiers,
    register_cross_verification_policy,
)

# --- Identity linking ---
# --- Identity link expiry ---
from ampro.identity.link import (
    DEFAULT_LINK_PROOF_LIFETIME,
    IdentityLinkProofBody,
    is_link_proof_valid,
)

# --- Identity migration ---
from ampro.identity.migration import IdentityMigrationBody

# --- Identity & auth ---
from ampro.identity.types import ConsentGrant, ConsentRequest, ConsentScope, IdentityProof

# --- Registry federation ---
from ampro.registry.federation import (
    RegistryFederationRequest,
    RegistryFederationResponse,
    RegistryFederationRevokeBody,
    RegistryFederationSyncBody,
    RegistryFederationSyncResponseBody,
    resolve_federation_conflict,
    verify_federation_trust_proof,
)
from ampro.registry.search import RegistrySearchMatch, RegistrySearchRequest, RegistrySearchResult

# --- Registry & discovery ---
from ampro.registry.types import RegistryRegistration, RegistryResolution

# --- Challenge (anti-abuse) ---
from ampro.security.challenge import (
    ChallengeReason,
    ChallengeType,
    TaskChallengeBody,
    TaskChallengeResponseBody,
    register_challenge_validator,
    validate_challenge_solution,
)
from ampro.security.circuit_breaker import CircuitBreakerInfo, CircuitState
from ampro.security.concurrency_limiter import ConcurrencyLimiter

# --- Security modules ---
from ampro.security.dedup import DedupStore, InMemoryDedupStore

# --- Encryption ---
from ampro.security.encryption import (
    CONTENT_ENCRYPTION_HEADER,
    EncryptedBody,
    EncryptionDowngradeError,
    EncryptionKeyAcceptBody,
    EncryptionKeyOfferBody,
)

# --- Key revocation ---
from ampro.security.key_revocation import (
    KeyRevocationBody,
    KeyRevocationBroadcastBody,
    RevocationReason,
    RevocationStore,
    is_revocation_authentic,
    register_revocation_store,
    revocation_verify_cached_key,
    should_reject_cached_key,
)
from ampro.security.nonce_tracker import NonceTracker
from ampro.security.rate_limit import RateLimitInfo, format_rate_limit_headers
from ampro.security.rate_limiter import RateLimiter
from ampro.security.sender_tracker import SenderState, SenderTracker
from ampro.server.core import AgentServer
from ampro.server.test import TestServer

# --- Session binding ---
from ampro.session.binding import (
    SessionBinding,
    create_message_binding,
    derive_binding_token,
    verify_message_binding,
)

# --- Handshake ---
from ampro.session.handshake import (
    HandshakeState,
    HandshakeStateMachine,
    HandshakeTimeoutError,
    SessionCloseBody,
    SessionConfirmBody,
    SessionEstablishedBody,
    SessionInitBody,
    SessionPauseBody,
    SessionPingBody,
    SessionPongBody,
    SessionReplayError,
    SessionResumeBody,
    create_resume_token,
    parse_resume_token,
)
from ampro.session.presence import PresenceState, PresenceUpdate
from ampro.session.types import SessionConfig, SessionContext, SessionState

# --- Stream auth ---
from ampro.streaming.auth import StreamAuthRefreshEvent

# --- Backpressure ---
from ampro.streaming.backpressure import StreamAckEvent, StreamPauseEvent, StreamResumeEvent

# --- Stream channels ---
from ampro.streaming.channel import (
    MAX_CHANNELS_PER_SESSION,
    ChannelQuotaExceededError,
    ChannelRegistry,
    StreamChannel,
    StreamChannelCloseEvent,
    StreamChannelOpenEvent,
)

# --- Stream checkpoints ---
from ampro.streaming.checkpoint import StreamCheckpointEvent
from ampro.streaming.events import StreamingEvent, StreamingEventType
from ampro.transport.api_key_store import ApiKeyStore

# --- Attachments ---
from ampro.transport.attachment import Attachment, validate_attachment_url
from ampro.transport.callback import deliver_callback, validate_callback_url

# --- Events & sessions ---
from ampro.transport.events import EventNotification, EventSubscription, EventType
from ampro.transport.heartbeat import HeartbeatEmitter
from ampro.transport.jwks_cache import JWKSCache

# --- Negotiation & versioning ---
from ampro.transport.negotiation import CapabilityNegotiator, NegotiationResult

# --- Task redirect ---
# --- Task redirect loop detection ---
from ampro.transport.task_redirect import TaskRedirectBody, check_redirect_chain

# --- Task revoke ---
from ampro.transport.task_revoke import TaskRevokeBody

# --- Trust proof ---
from ampro.trust.proof import TrustProofBody

# --- Trust resolution ---
from ampro.trust.resolver import resolve_trust_tier

# --- Trust scoring ---
from ampro.trust.score import (
    TrustFactor,
    TrustPolicy,
    TrustScore,
    calculate_trust_score,
    score_to_policy,
)
from ampro.trust.tiers import CLOCK_SKEW_SECONDS, TrustConfig, TrustTier

# --- Trust upgrade ---
from ampro.trust.upgrade import TrustUpgradeRequestBody, TrustUpgradeResponseBody
from ampro.wire.body_type_map import BODY_TYPE_BINDINGS, BodyTypeBinding, ResponseMode, binding_for
from ampro.wire.config import DEFAULTS as WIRE_DEFAULTS
from ampro.wire.config import WireConfig

# --- Wire binding (HTTP transport contract) ---
from ampro.wire.endpoints import ALL_ENDPOINTS, ConformanceLevel, EndpointSpec, endpoints_for_level
from ampro.wire.errors import ErrorType, ProblemDetail

__version__ = "0.4.0"

__all__ = [
    # Core
    "AgentMessage", "STANDARD_HEADERS", "AgentStatus",
    "CapabilityGroup", "CapabilityLevel", "CapabilitySet",
    "StreamingEvent", "StreamingEventType",
    "TrustTier", "TrustConfig", "CLOCK_SKEW_SECONDS",
    # Addressing
    "AgentAddress", "AddressType", "parse_agent_uri", "normalize_shorthand",
    # Identity & auth
    "IdentityProof", "ConsentScope", "ConsentRequest", "ConsentGrant",
    "AuthMethod", "ParsedAuth", "parse_authorization",
    # Body schemas
    "MessageBody", "TaskCreateBody", "TaskAssignBody", "TaskDelegateBody",
    "TaskSpawnBody", "TaskQuoteBody", "NotificationBody",
    "TaskProgressBody", "TaskInputRequiredBody", "TaskEscalateBody",
    "TaskRerouteBody", "TaskTransferBody", "TaskAcknowledgeBody",
    "TaskRejectBody", "TaskCompleteBody", "TaskErrorBody",
    "TaskResponseBody", "validate_body",
    "DataConsentRequestBody", "DataConsentResponseBody",
    # Delegation
    "DelegationLink", "DelegationChain",
    "validate_chain", "validate_scope_narrowing", "sign_delegation",
    "parse_chain_budget", "parse_visited_agents", "normalize_agent_uri",
    "check_visited_agents_loop", "check_visited_agents_limit",
    # Events & sessions
    "EventType", "EventSubscription", "EventNotification",
    "SessionState", "SessionConfig", "SessionContext",
    "PresenceState", "PresenceUpdate",
    # Attachments
    "Attachment", "validate_attachment_url",
    # Compliance
    "ContentClassification", "RetentionPolicy",
    "ErasureRequest", "ErasureResponse", "ExportRequest", "ExportResponse",
    "check_content_classification", "check_minor_protection",
    "requires_audit", "ComplianceCheckResult",
    "AuditLogger", "AuditEntry", "AuditStorage", "InMemoryAuditStorage",
    "ErasureProcessor",
    # Security
    "InMemoryDedupStore", "DedupStore", "NonceTracker",
    "RateLimiter", "RateLimitInfo", "format_rate_limit_headers",
    "ConcurrencyLimiter", "SenderTracker", "SenderState",
    "JWKSCache", "ApiKeyStore",
    # Operational
    "HealthResponse", "CircuitState", "CircuitBreakerInfo",
    "HeartbeatEmitter", "validate_callback_url", "deliver_callback",
    "validate_message_body", "build_negotiation_headers",
    "check_message_size", "MessageSizeError",
    # Registry & discovery
    "RegistryResolution", "RegistryRegistration",
    "RegistrySearchRequest", "RegistrySearchMatch", "RegistrySearchResult",
    "AgentJson",
    # Cross-verification
    "cross_verify_identifiers", "check_all_verified",
    "get_failed_identifiers", "VerificationResult",
    "CrossVerificationRequiredError", "register_cross_verification_policy",
    # Trust scoring
    "TrustFactor", "TrustScore", "TrustPolicy",
    "calculate_trust_score", "score_to_policy",
    # Trust resolution
    "resolve_trust_tier",
    # Trust upgrade
    "TrustUpgradeRequestBody", "TrustUpgradeResponseBody",
    # Handshake
    "HandshakeState", "HandshakeStateMachine",
    "HandshakeTimeoutError", "SessionReplayError",
    "SessionInitBody", "SessionEstablishedBody", "SessionConfirmBody",
    "SessionPingBody", "SessionPongBody",
    "SessionPauseBody", "SessionResumeBody", "SessionCloseBody",
    "create_resume_token", "parse_resume_token",
    # Visibility & contact policies
    "VisibilityLevel", "ContactPolicy", "VisibilityConfig",
    "check_contact_allowed", "filter_agent_json",
    # Session binding
    "SessionBinding", "derive_binding_token",
    "create_message_binding", "verify_message_binding",
    # Context schemas
    "ContextSchemaInfo", "parse_schema_urn", "check_schema_supported",
    # Challenge (anti-abuse)
    "ChallengeReason", "ChallengeType",
    "TaskChallengeBody", "TaskChallengeResponseBody",
    "validate_challenge_solution", "register_challenge_validator",
    # Key revocation
    "RevocationReason", "KeyRevocationBody", "is_revocation_authentic",
    "KeyRevocationBroadcastBody", "RevocationStore",
    "register_revocation_store", "should_reject_cached_key",
    "revocation_verify_cached_key",
    # Tool consent
    "ToolConsentRequestBody", "ToolConsentGrantBody", "ToolDefinition",
    # Backpressure
    "StreamAckEvent", "StreamPauseEvent", "StreamResumeEvent",
    # Agent lifecycle
    "AgentLifecycleStatus", "AgentDeactivationNoticeBody",
    # Cost receipts
    "CostReceipt", "CostReceiptChain", "CostReceiptVerificationError",
    # Task redirect
    "TaskRedirectBody",
    # Tracing
    "TraceContext", "generate_trace_id", "generate_span_id",
    "inject_trace_headers", "extract_trace_context",
    # Task revoke
    "TaskRevokeBody",
    # Priority
    "Priority",
    # Jurisdiction
    "JurisdictionInfo", "validate_jurisdiction_code", "check_jurisdiction_conflict",
    # Erasure propagation
    "ErasurePropagationStatus", "ErasurePropagationStatusBody",
    # Consent revocation
    "DataConsentRevokeBody",
    # Data residency
    "DataResidency", "validate_residency_region", "check_residency_violation",
    # Stream channels
    "StreamChannel", "StreamChannelOpenEvent", "StreamChannelCloseEvent",
    "ChannelRegistry", "ChannelQuotaExceededError", "MAX_CHANNELS_PER_SESSION",
    # Stream checkpoints
    "StreamCheckpointEvent",
    # Stream auth
    "StreamAuthRefreshEvent",
    # Identity linking
    "IdentityLinkProofBody",
    # Registry federation
    "RegistryFederationRequest", "RegistryFederationResponse",
    "RegistryFederationRevokeBody",
    "RegistryFederationSyncBody", "RegistryFederationSyncResponseBody",
    "verify_federation_trust_proof", "resolve_federation_conflict",
    # Agent metadata cache invalidation
    "AgentMetadataInvalidateBody",
    "MAX_MIGRATION_HOPS", "follow_migration_chain",
    # Task redirect loop detection
    "check_redirect_chain",
    # Identity link expiry
    "is_link_proof_valid", "DEFAULT_LINK_PROOF_LIFETIME",
    # Unified error hierarchy
    "AmpError", "AmpValidationError", "TrustError", "CryptoError",
    "SessionError", "CompliancePolicyError", "RateLimitError",
    "TransportError", "NotImplementedInProtocol",
    "RedirectLoopError", "MigrationChainTooLongError",
    # Identity migration
    "IdentityMigrationBody",
    # Audit attestation
    "AuditAttestationBody", "verify_attestation",
    # Encryption
    "EncryptedBody", "EncryptionKeyOfferBody", "EncryptionKeyAcceptBody",
    "EncryptionDowngradeError", "CONTENT_ENCRYPTION_HEADER",
    "enforce_encryption_requirement",
    # Trust proof
    "TrustProofBody",
    # Certifications
    "CertificationLink",
    # Negotiation & versioning
    "NegotiationResult", "CapabilityNegotiator",
    "SUPPORTED_VERSIONS", "CURRENT_VERSION", "check_version", "negotiate_version",
    # Wire binding (HTTP transport contract)
    "ConformanceLevel", "EndpointSpec", "ALL_ENDPOINTS", "endpoints_for_level",
    "ProblemDetail", "ErrorType",
    "WireConfig", "WIRE_DEFAULTS",
    "ResponseMode", "BodyTypeBinding", "BODY_TYPE_BINDINGS", "binding_for",
    # AMPI
    "AgentApp", "AMPContext",
    "AMPError", "StreamLimitExceeded", "BackpressureError",
    "AMPIServer", "AMPIApp", "HandlerFunc", "MiddlewareFunc",
    "AgentServer", "TestServer",
]
