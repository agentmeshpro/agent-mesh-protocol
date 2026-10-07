"""AMPContext — the single object handlers read from.

Every AMP protocol feature a handler needs is accessible here.
The server populates all fields before calling the handler.
Methods raise NotImplementedError in the base class — each server
adapter provides real implementations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ampro.compliance.types import ContentClassification
from ampro.core.capabilities import CapabilitySet
from ampro.identity.auth_methods import AuthMethod
from ampro.session.types import SessionContext, SessionState
from ampro.trust.tiers import TrustTier

if TYPE_CHECKING:
    from ampro.agent.schema import AgentJson
    from ampro.agent.tool_consent import ToolDefinition
    from ampro.core.envelope import AgentMessage
    from ampro.delegation.chain import DelegationChain
    from ampro.identity.types import ConsentGrant, IdentityProof
    from ampro.registry.search import RegistrySearchMatch
    from ampro.streaming.events import StreamingEvent


@dataclass
class AMPContext:
    """Handler's view of the incoming message and its context."""

    # --- Identity ---
    agent_address: str
    sender_address: str
    request_id: str

    # --- Trust ---
    trust_tier: TrustTier
    trust_score: int | None = None
    auth_method: AuthMethod | None = None

    # --- Session ---
    session: SessionContext | None = None
    session_state: SessionState | None = None

    # --- Capabilities ---
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    level: int = 1

    # --- Delegation ---
    delegation_chain: DelegationChain | None = None
    delegation_depth_remaining: int = 5
    remaining_budget: str | None = None
    visited_agents: list[str] = field(default_factory=list)

    # --- Compliance ---
    content_classification: ContentClassification = ContentClassification.PUBLIC
    jurisdiction: str | None = None
    data_residency: str | None = None
    retention_policy: str | None = None

    # --- Tracing ---
    trace_id: str = ""
    span_id: str = ""

    # --- Routing / correlation ---
    transaction_id: str | None = None
    correlation_group: str | None = None
    commitment_level: str = "informational"
    priority: str = "normal"
    in_reply_to: str | None = None

    # --- Tools ---
    available_tools: list[ToolDefinition] = field(default_factory=list)
    tool_grants: list[ConsentGrant] = field(default_factory=list)

    # --- Raw access ---
    headers: dict[str, str] = field(default_factory=dict)

    # --- Caller / wire protocol ---
    # ``principal`` is the authenticated caller as resolved by the transport
    # (e.g. ``ampro.interop.a2a.Principal``); ``None`` when unauthenticated.
    principal: Any = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    # Wire protocol that delivered the message: ``"amp"``, ``"a2a"``, ``"mcp"``.
    protocol: str = "amp"
    # Protocol-specific extras (e.g. ``"a2a.message"`` — the raw A2A Message).
    metadata: dict[str, Any] = field(default_factory=dict)

    # === Methods — server provides real implementations ===

    async def emit(self, event: StreamingEvent) -> None:
        raise NotImplementedError("Server must provide emit()")

    async def emit_audit(
        self,
        action: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        raise NotImplementedError("Server must provide emit_audit()")

    async def emit_event(self, topic: str, data: dict) -> None:
        raise NotImplementedError("Server must provide emit_event()")

    async def send(
        self,
        to: str,
        body: dict,
        body_type: str = "message",
        headers: dict | None = None,
    ) -> AgentMessage:
        raise NotImplementedError("Server must provide send()")

    async def discover(self, uri: str) -> AgentJson:
        raise NotImplementedError("Server must provide discover()")

    async def delegate(
        self,
        to: str,
        body: dict,
        scopes: list[str],
        budget: str | None = None,
    ) -> AgentMessage:
        raise NotImplementedError("Server must provide delegate()")

    async def search_registry(
        self,
        capability: str | None = None,
        min_trust: int | None = None,
    ) -> list[RegistrySearchMatch]:
        raise NotImplementedError("Server must provide search_registry()")

    async def verify_identity(self, proof: IdentityProof) -> bool:
        raise NotImplementedError("Server must provide verify_identity()")

    async def check_consent(self, grant_id: str, scope: str) -> bool:
        raise NotImplementedError("Server must provide check_consent()")

    async def request_trust_upgrade(self, to_tier: TrustTier) -> bool:
        raise NotImplementedError("Server must provide request_trust_upgrade()")

    async def pause_session(self) -> None:
        raise NotImplementedError("Server must provide pause_session()")

    async def resume_session(self) -> None:
        raise NotImplementedError("Server must provide resume_session()")

    async def close_session(self) -> None:
        raise NotImplementedError("Server must provide close_session()")
