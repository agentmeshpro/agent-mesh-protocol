"""
AMP Wire Binding -- Body Type to HTTP Semantics Mapping.

Maps every canonical ``body.type`` string to its HTTP transport semantics:
which HTTP method to use, whether the response is synchronous or asynchronous,
what the expected response body_type is, and whether the operation supports
streaming.

This is the authoritative mapping.  Protocol implementations MUST use these
semantics when routing body types over HTTP.

Usage::

    from ampro.wire.body_type_map import binding_for, BODY_TYPE_BINDINGS

    b = binding_for("task.create")
    assert b.http_method == "POST"
    assert b.response_mode == ResponseMode.ASYNC
    assert b.streaming_capable is True

PURE -- zero platform-specific imports.  Only pydantic, enum, and stdlib.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ResponseMode(str, Enum):
    """How the server delivers the response for a given body type."""

    SYNC = "sync"       # 200 OK with response body inline
    ASYNC = "async"     # 202 Accepted; deliver via callback, poll, or stream
    FIRE = "fire"       # 202 Accepted; no response expected (notifications, acks)


# ---------------------------------------------------------------------------
# BodyTypeBinding
# ---------------------------------------------------------------------------


class BodyTypeBinding(BaseModel):
    """HTTP transport semantics for a specific AMP body type.

    Each canonical ``body.type`` maps to exactly one binding that tells
    the transport layer how to send and receive it.
    """

    body_type: str = Field(description="The canonical body.type string")
    http_method: str = Field(description="HTTP method (POST, PATCH, PUT, DELETE)")
    response_mode: ResponseMode = Field(description="sync, async, or fire-and-forget")
    expected_response: str | None = Field(
        default=None,
        description="Expected response body_type (None if fire-and-forget)",
    )
    error_response: str = Field(
        default="task.error",
        description="Body type used when the operation fails",
    )
    idempotent: bool = Field(
        default=False,
        description="Whether repeated identical sends produce the same effect",
    )
    streaming_capable: bool = Field(
        default=False,
        description="Whether this body type can be delivered over SSE",
    )
    requires_nonce: bool = Field(
        default=False,
        description="Whether this body type SHOULD include a Nonce header for replay protection",
    )

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Canonical body type bindings -- every registered body type
# ---------------------------------------------------------------------------

BODY_TYPE_BINDINGS: dict[str, BodyTypeBinding] = {

    # ------------------------------------------------------------------
    # POST types -- Creating work
    # ------------------------------------------------------------------

    "message": BodyTypeBinding(
        body_type="message",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.response",
        streaming_capable=True,
    ),
    "task.create": BodyTypeBinding(
        body_type="task.create",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
        streaming_capable=True,
        requires_nonce=True,
    ),
    "task.assign": BodyTypeBinding(
        body_type="task.assign",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
        requires_nonce=True,
    ),
    "task.delegate": BodyTypeBinding(
        body_type="task.delegate",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
        streaming_capable=True,
        requires_nonce=True,
    ),
    "task.spawn": BodyTypeBinding(
        body_type="task.spawn",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
    ),
    "task.quote": BodyTypeBinding(
        body_type="task.quote",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response=None,
        idempotent=True,
    ),
    "notification": BodyTypeBinding(
        body_type="notification",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # PATCH types -- Lifecycle updates
    # ------------------------------------------------------------------

    "task.progress": BodyTypeBinding(
        body_type="task.progress",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "task.input_required": BodyTypeBinding(
        body_type="task.input_required",
        http_method="PATCH",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.response",
        streaming_capable=True,
    ),
    "task.escalate": BodyTypeBinding(
        body_type="task.escalate",
        http_method="PATCH",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
        streaming_capable=True,
    ),
    "task.reroute": BodyTypeBinding(
        body_type="task.reroute",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "task.transfer": BodyTypeBinding(
        body_type="task.transfer",
        http_method="PATCH",
        response_mode=ResponseMode.ASYNC,
        expected_response="task.acknowledge",
    ),
    "task.acknowledge": BodyTypeBinding(
        body_type="task.acknowledge",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "task.reject": BodyTypeBinding(
        body_type="task.reject",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "task.complete": BodyTypeBinding(
        body_type="task.complete",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "task.error": BodyTypeBinding(
        body_type="task.error",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),

    # ------------------------------------------------------------------
    # PUT types -- Responding
    # ------------------------------------------------------------------

    "task.response": BodyTypeBinding(
        body_type="task.response",
        http_method="PUT",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Session handshake types
    # ------------------------------------------------------------------

    "session.init": BodyTypeBinding(
        body_type="session.init",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="session.established",
        requires_nonce=True,
    ),
    "session.established": BodyTypeBinding(
        body_type="session.established",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="session.confirm",
    ),
    "session.confirm": BodyTypeBinding(
        body_type="session.confirm",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "session.ping": BodyTypeBinding(
        body_type="session.ping",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="session.pong",
        idempotent=True,
    ),
    "session.pong": BodyTypeBinding(
        body_type="session.pong",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "session.pause": BodyTypeBinding(
        body_type="session.pause",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "session.resume": BodyTypeBinding(
        body_type="session.resume",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "session.close": BodyTypeBinding(
        body_type="session.close",
        http_method="DELETE",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),

    # ------------------------------------------------------------------
    # Compliance types
    # ------------------------------------------------------------------

    "data.consent_request": BodyTypeBinding(
        body_type="data.consent_request",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="data.consent_response",
        requires_nonce=True,
    ),
    "data.consent_response": BodyTypeBinding(
        body_type="data.consent_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "data.consent_revoke": BodyTypeBinding(
        body_type="data.consent_revoke",
        http_method="DELETE",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "data.erasure_request": BodyTypeBinding(
        body_type="data.erasure_request",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="data.erasure_response",
        requires_nonce=True,
    ),
    "data.erasure_response": BodyTypeBinding(
        body_type="data.erasure_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "data.export_request": BodyTypeBinding(
        body_type="data.export_request",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="data.export_response",
    ),
    "data.export_response": BodyTypeBinding(
        body_type="data.export_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "erasure.propagation_status": BodyTypeBinding(
        body_type="erasure.propagation_status",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Security types
    # ------------------------------------------------------------------

    "task.challenge": BodyTypeBinding(
        body_type="task.challenge",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="task.challenge_response",
    ),
    "task.challenge_response": BodyTypeBinding(
        body_type="task.challenge_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "key.revocation": BodyTypeBinding(
        body_type="key.revocation",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        requires_nonce=True,
    ),

    # ------------------------------------------------------------------
    # Trust types
    # ------------------------------------------------------------------

    "trust.upgrade_request": BodyTypeBinding(
        body_type="trust.upgrade_request",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="trust.upgrade_response",
        requires_nonce=True,
    ),
    "trust.upgrade_response": BodyTypeBinding(
        body_type="trust.upgrade_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "trust.proof": BodyTypeBinding(
        body_type="trust.proof",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Tool types
    # ------------------------------------------------------------------

    "tool.consent_request": BodyTypeBinding(
        body_type="tool.consent_request",
        http_method="POST",
        response_mode=ResponseMode.ASYNC,
        expected_response="tool.consent_grant",
        requires_nonce=True,
    ),
    "tool.consent_grant": BodyTypeBinding(
        body_type="tool.consent_grant",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Agent lifecycle types
    # ------------------------------------------------------------------

    "agent.deactivation_notice": BodyTypeBinding(
        body_type="agent.deactivation_notice",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Routing types
    # ------------------------------------------------------------------

    "task.redirect": BodyTypeBinding(
        body_type="task.redirect",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "task.revoke": BodyTypeBinding(
        body_type="task.revoke",
        http_method="PATCH",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),

    # ------------------------------------------------------------------
    # Identity types
    # ------------------------------------------------------------------

    "identity.link_proof": BodyTypeBinding(
        body_type="identity.link_proof",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "identity.migration": BodyTypeBinding(
        body_type="identity.migration",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Audit types
    # ------------------------------------------------------------------

    "audit.attestation": BodyTypeBinding(
        body_type="audit.attestation",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),

    # ------------------------------------------------------------------
    # Registry federation types
    # ------------------------------------------------------------------

    "registry.federation_request": BodyTypeBinding(
        body_type="registry.federation_request",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="registry.federation_response",
    ),
    "registry.federation_response": BodyTypeBinding(
        body_type="registry.federation_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
    ),
    "registry.federation_revoke": BodyTypeBinding(
        body_type="registry.federation_revoke",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
    "registry.federation_sync": BodyTypeBinding(
        body_type="registry.federation_sync",
        http_method="POST",
        response_mode=ResponseMode.SYNC,
        expected_response="registry.federation_sync_response",
        idempotent=True,
    ),
    "registry.federation_sync_response": BodyTypeBinding(
        body_type="registry.federation_sync_response",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),

    # ------------------------------------------------------------------
    # Cache invalidation
    # ------------------------------------------------------------------

    "agent.metadata_invalidate": BodyTypeBinding(
        body_type="agent.metadata_invalidate",
        http_method="POST",
        response_mode=ResponseMode.FIRE,
        expected_response=None,
        idempotent=True,
    ),
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def binding_for(body_type: str | None) -> BodyTypeBinding | None:
    """Look up the HTTP binding for a body type.

    Args:
        body_type: The canonical ``body.type`` string, or ``None``.

    Returns:
        The ``BodyTypeBinding`` if found, else ``None``.
        Returns ``None`` for ``None``, empty strings, and
        extension types (``x-*``, reverse-domain).
    """
    if not body_type:
        return None
    return BODY_TYPE_BINDINGS.get(body_type)


def is_canonical(body_type: str) -> bool:
    """Return ``True`` if the body type is a canonical AMP type with a binding."""
    return body_type in BODY_TYPE_BINDINGS


def streaming_body_types() -> list[str]:
    """Return all body types that support SSE streaming delivery."""
    return [bt for bt, b in BODY_TYPE_BINDINGS.items() if b.streaming_capable]


def idempotent_body_types() -> list[str]:
    """Return all body types whose operations are idempotent."""
    return [bt for bt, b in BODY_TYPE_BINDINGS.items() if b.idempotent]
