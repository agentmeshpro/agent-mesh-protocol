"""
Agent Protocol — agent.json Schema.

The complete schema for /.well-known/agent.json as defined in the spec.
Used for validation when fetching and serving agent.json.

This module is PURE — no platform-specific imports.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from ampro.errors import MigrationChainTooLongError

#: Bound on agent.json ``foreign_identifiers`` (mirrors
#: ``ampro.identity.link.MAX_FOREIGN_IDENTIFIERS``; checked at import).
MAX_FOREIGN_IDENTIFIERS = 16

logger = logging.getLogger(__name__)

MAX_MIGRATION_HOPS = 5
"""Maximum depth of ``moved_to`` references that callers SHOULD follow.

Agents MUST refuse to follow migration chains beyond this limit to prevent
unbounded resolution work and redirect-loop attacks through forged
``moved_to`` pointers.
"""


class AgentJson(BaseModel):
    """Complete agent.json schema per protocol spec Section 1.5."""

    protocol_version: str = Field(description="Protocol version (e.g. '1.0.0')")
    identifiers: list[str] = Field(description="All agent:// URIs for this agent")
    # v0.4.1 — Foreign identifiers (WIRE-BINDING Appendix E.4)
    foreign_identifiers: list[ForeignIdentifier] = Field(
        default_factory=list,
        max_length=MAX_FOREIGN_IDENTIFIERS,
        description=(
            "Names for this agent in other ecosystems (MCP client ID metadata URL, "
            "did:web / did:wba / did:key, Web Bot Auth key directory). Confer no "
            "trust unless their identity-link proof verifies."
        ),
    )
    endpoint: str = Field(description="HTTPS endpoint for POST /agent/message")
    jwks_url: str | None = Field(default=None, description="JWKS endpoint URL")
    capabilities: dict[str, Any] = Field(
        default_factory=lambda: {"groups": [], "level": 0}
    )
    constraints: dict[str, Any] = Field(default_factory=dict)
    security: dict[str, Any] = Field(default_factory=dict)
    billing: dict[str, Any] = Field(default_factory=dict)
    streaming: dict[str, Any] = Field(default_factory=dict)
    compliance: dict[str, Any] = Field(default_factory=dict)
    languages: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=3600, ge=1)
    # v0.1.1 — Visibility & context schemas
    visibility: dict[str, Any] = Field(
        default_factory=lambda: {"level": "public", "contact_policy": "open"},
        description="Visibility and contact policy configuration",
    )
    supported_schemas: list[str] = Field(
        default_factory=list,
        description="Context schema URNs this agent understands (e.g. urn:schema:purchase-order:v1)",
    )

    # v0.1.3 — Agent lifecycle
    status: str = Field(
        default="active",
        description="Agent lifecycle status: active, deactivating, or decommissioned",
    )
    # v0.1.8 — Identity migration
    moved_to: str | None = Field(
        default=None,
        description="agent:// URI this agent has migrated to. "
        "Consumers MUST validate this is a valid agent:// URI before following.",
    )
    # v0.1.9 — Certifications
    certifications: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Compliance certifications (SOC2, ISO27001, etc.)",
    )

    model_config = {"extra": "allow"}

    @field_validator("foreign_identifiers", mode="before")
    @classmethod
    def _tolerant_foreign_identifiers(cls, value: Any) -> Any:
        """Drop entries that do not parse instead of rejecting the document.

        Foreign identifiers confer no trust on their own, and a future
        ``kind`` must not make older consumers reject the whole agent.json.
        The list itself is still bounded and must be a list.
        """
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("foreign_identifiers must be a list")
        if len(value) > MAX_FOREIGN_IDENTIFIERS:
            raise ValueError(
                f"foreign_identifiers allows at most {MAX_FOREIGN_IDENTIFIERS} entries"
            )
        kept: list[ForeignIdentifier] = []
        for index, item in enumerate(value):
            try:
                kept.append(
                    item if isinstance(item, ForeignIdentifier)
                    else ForeignIdentifier.model_validate(item)
                )
            except (PydanticValidationError, ValueError, TypeError) as exc:
                logger.warning("agent.json foreign_identifiers[%d] ignored: %s", index, exc)
        return kept


def follow_migration_chain(
    agent_json: AgentJson,
    resolver: Callable[[str], AgentJson | None],
    max_hops: int = MAX_MIGRATION_HOPS,
) -> AgentJson:
    """Follow ``moved_to`` pointers until a terminal agent.json is reached.

    Args:
        agent_json: Starting agent.json record.
        resolver:   Callable mapping an ``agent://`` URI to its resolved
                    :class:`AgentJson`, or ``None`` if the URI cannot be
                    resolved. Callers typically pass a registry lookup
                    closure.
        max_hops:   Maximum number of ``moved_to`` redirects to follow before
                    raising :class:`MigrationChainTooLongError`. Defaults to
                    :data:`MAX_MIGRATION_HOPS`.

    Returns:
        The terminal :class:`AgentJson` (first record encountered with no
        ``moved_to`` pointer or whose ``moved_to`` target cannot be resolved).

    Raises:
        MigrationChainTooLongError: when the chain would require more than
            ``max_hops`` redirects, or when a cycle is detected in the chain.
    """
    if max_hops < 1:
        raise ValueError("max_hops must be >= 1")

    current = agent_json
    hops = 0
    seen: set[str] = set()
    while current.moved_to:
        if hops >= max_hops:
            raise MigrationChainTooLongError(
                f"Migration chain exceeded max_hops={max_hops} "
                f"(last moved_to={current.moved_to!r})"
            )
        if current.moved_to in seen:
            raise MigrationChainTooLongError(
                f"Migration chain cycle detected at {current.moved_to!r}"
            )
        seen.add(current.moved_to)
        resolved = resolver(current.moved_to)
        if resolved is None:
            return current
        current = resolved
        hops += 1
    return current


# ---------------------------------------------------------------------------
# Cache invalidation push (issue #43)
# ---------------------------------------------------------------------------


class AgentMetadataInvalidateBody(BaseModel):
    """body.type = 'agent.metadata_invalidate'.

    Push notification: an agent's ``agent.json`` has changed; any peer that
    caches the record MUST drop its copy on receipt of this message.
    """

    agent_id: str = Field(description="agent:// URI whose metadata changed")
    changed_at: datetime = Field(
        description="UTC timestamp when the underlying agent.json was updated",
    )
    reason: Literal[
        "visibility_change",
        "endpoint_change",
        "migration",
        "revocation",
    ] = Field(description="Why the cached record must be dropped")

    model_config = {"extra": "ignore"}


# ``ForeignIdentifier`` is imported last: ``ampro.identity`` pulls in
# ``ampro.core``, whose body-type registry imports this module back, so the
# import must happen after every model above is defined.
from ampro.identity.link import MAX_FOREIGN_IDENTIFIERS as _LINK_MAX  # noqa: E402
from ampro.identity.link import ForeignIdentifier  # noqa: E402

assert _LINK_MAX == MAX_FOREIGN_IDENTIFIERS
AgentJson.model_rebuild()
