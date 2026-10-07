"""Delegation chains, cost receipts, and tracing."""

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
from ampro.delegation.cost_receipt import (
    CostReceipt,
    CostReceiptChain,
    CostReceiptVerificationError,
)
from ampro.delegation.tracing import (
    TraceContext,
    TraceContextError,
    TraceParent,
    extract_trace_context,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    inject_trace_headers,
    parse_traceparent,
    parse_tracestate,
    sign_trace_context,
    verify_trace_context,
)
from ampro.delegation.v2 import (
    AmountConstraint,
    BudgetConstraint,
    CountConstraint,
    CredentialRef,
    DelegationLinkV2,
    Principal,
    ResourceConstraint,
    VerificationKey,
    authorize_action,
    canonical_link_v2_bytes,
    intent_digest,
    minor_units,
    new_link_id,
    sign_delegation_v2,
    validate_chain_v2,
)

__all__ = [
    # Chain
    "DelegationLink", "DelegationChain",
    "validate_chain", "validate_scope_narrowing", "sign_delegation",
    "parse_chain_budget", "parse_visited_agents", "normalize_agent_uri",
    "check_visited_agents_loop", "check_visited_agents_limit",
    # Delegation v2
    "DelegationLinkV2", "Principal", "CredentialRef", "VerificationKey", "AmountConstraint", "BudgetConstraint",
    "CountConstraint", "ResourceConstraint", "validate_chain_v2", "sign_delegation_v2", "authorize_action", "intent_digest", "minor_units", "new_link_id", "canonical_link_v2_bytes",
    # Cost receipts
    "CostReceipt", "CostReceiptChain", "CostReceiptVerificationError",
    # Tracing
    "TraceContext", "generate_trace_id", "generate_span_id",
    "inject_trace_headers", "extract_trace_context",
    "sign_trace_context", "verify_trace_context",
    # W3C Trace Context
    "TraceParent", "TraceContextError", "parse_traceparent", "parse_tracestate",
    "format_traceparent",
]
