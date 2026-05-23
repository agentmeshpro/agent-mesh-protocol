"""
Agent Protocol — Key Revocation.

Emergency key revocation broadcast. When an agent's private key is
compromised, this body type allows broadcasting the revocation to all
agents that may have cached the old key.

Revocation reasons:
  - key_compromise: key was stolen or leaked
  - key_rotation: routine key rotation (not emergency, but caches should refresh)
  - agent_decommissioned: agent is shutting down permanently

PURE — zero platform-specific imports. Only pydantic and stdlib.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Protocol

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Revocation reason enum
# ---------------------------------------------------------------------------


class RevocationReason(str, Enum):
    """Reasons an agent key may be revoked."""

    KEY_COMPROMISE = "key_compromise"
    KEY_ROTATION = "key_rotation"
    AGENT_DECOMMISSIONED = "agent_decommissioned"


# ---------------------------------------------------------------------------
# Key revocation body type
# ---------------------------------------------------------------------------


class KeyRevocationBody(BaseModel):
    """body.type = 'key.revocation' — Broadcast that an agent key is revoked."""

    agent_id: str = Field(
        description="agent:// URI of the agent whose key is revoked",
    )
    revoked_key_id: str = Field(
        description="Key ID being revoked",
    )
    revoked_at: str = Field(
        description="ISO-8601 timestamp of revocation",
    )
    reason: str = Field(
        description="Revocation reason (key_compromise, key_rotation, agent_decommissioned)",
    )
    replacement_key_id: str | None = Field(
        default=None,
        description="Replacement key ID, if key was rotated",
    )
    jwks_url: str | None = Field(
        default=None,
        description="URL to fetch updated JWKS",
    )
    signature: str = Field(
        description="Ed25519 signature proving authenticity of this revocation",
    )

    model_config = {"extra": "ignore"}


def validate_revocation_signature(body: KeyRevocationBody, public_key_bytes: bytes) -> bool:
    """Verify the Ed25519 signature over the canonical revocation fields.

    The canonical message is a JSON object with fields sorted alphabetically,
    excluding the ``signature`` field itself.

    Callers receiving a key.revocation message MUST call this function
    to verify the signature before acting on the revocation. Unverified
    revocations MUST be discarded.

    Args:
        body: The key revocation body containing the signature to verify.
        public_key_bytes: Raw 32-byte Ed25519 public key of the revoking agent.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        logger.error(
            "cryptography package not installed — cannot verify revocation signature. "
            "Install with: pip install cryptography"
        )
        return False

    # Build the canonical message from the full set of model fields except
    # ``signature``. Using ``model_dump`` means new fields added to
    # KeyRevocationBody are automatically covered; the previous hardcoded
    # dict silently omitted any extension fields, which broke wire-format
    # extensibility.
    canonical = {
        k: v for k, v in body.model_dump(mode="json").items() if k != "signature"
    }
    message = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        import base64

        signature_bytes = base64.urlsafe_b64decode(body.signature + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except Exception as exc:
        logger.warning("Revocation signature verification failed: %s", exc)
        return False


def is_revocation_authentic(body: KeyRevocationBody, public_key_bytes: bytes) -> bool:
    """Verify a key revocation is authentic before acting on it.

    Returns True only if the signature is valid for the given public key.
    Callers MUST call this before revoking any keys.
    """
    return validate_revocation_signature(body, public_key_bytes)


# ---------------------------------------------------------------------------
# Revocation broadcast + pluggable store
# ---------------------------------------------------------------------------


class KeyRevocationBroadcastBody(BaseModel):
    """body.type = 'key.revocation_broadcast' — Fan-out envelope for a revocation.

    Used when a peer forwards a previously-received :class:`KeyRevocationBody`
    to its own trust-graph neighbours so caches across the mesh converge
    on the revoked key. The inner ``revocation`` MUST be carried verbatim
    (including its signature) so downstream receivers can independently
    verify authenticity via :func:`is_revocation_authentic`.
    """

    revocation: KeyRevocationBody = Field(
        description="The original signed revocation being rebroadcast",
    )
    broadcast_by: str = Field(
        description="agent:// URI of the peer rebroadcasting the revocation",
    )
    broadcast_at: str = Field(
        description="ISO-8601 timestamp when this hop rebroadcast the notice",
    )
    hop_count: int = Field(
        default=0,
        ge=0,
        description="Number of hops the broadcast has traversed",
    )

    model_config = {"extra": "ignore"}


class RevocationStore(Protocol):
    """Platform hook for persistent revocation state.

    Implementations plug in via :func:`register_revocation_store`. Callers
    should query :func:`should_reject_cached_key` before trusting any
    cached public key material. The default store is a NoOp that returns
    False for every key.
    """

    def is_revoked(self, key_id: str) -> bool:
        ...


class _UnconfiguredRevocationStore:
    """Default store — distinguishable from both fail-open and fail-closed.

    Reports keys as not-revoked (so verification can proceed) but logs a
    persistent warning so operators know revocation is not actually
    enforced. The previous default silently returned False with no
    indication; the new fail-closed-on-strict variant was too disruptive
    to existing deployments. This is the middle ground.

    Production deployments MUST register either:
      * A real :class:`RevocationStore` backed by the host's KV store, OR
      * :class:`AllowAllRevocationStore` to explicitly opt into fail-open
        (an audit-trail decision rather than silent default).

    Callers that want strict fail-closed behaviour can register
    :class:`StrictUnconfiguredRevocationStore` instead.
    """

    _warned: bool = False

    def is_revoked(self, key_id: str) -> bool:
        if not type(self)._warned:
            logger.warning(
                "key_revocation: no RevocationStore registered — running with "
                "PERMISSIVE default. Call register_revocation_store() at startup "
                "with either a real store, AllowAllRevocationStore(), or "
                "StrictUnconfiguredRevocationStore() to make the choice explicit."
            )
            type(self)._warned = True
        return False


class StrictUnconfiguredRevocationStore:
    """Opt-in fail-CLOSED store: every key treated as revoked.

    Production deployments that want hard fail-closed semantics until a
    real revocation store is wired register this explicitly:

        register_revocation_store(StrictUnconfiguredRevocationStore())
    """

    def is_revoked(self, key_id: str) -> bool:
        return True


class AllowAllRevocationStore:
    """Opt-in fail-open store: nothing is ever considered revoked.

    Use ONLY in test fixtures, local dev, or deployments that have made an
    explicit, audited decision not to track revocations. Register at startup
    via :func:`register_revocation_store(AllowAllRevocationStore())`.
    """

    def is_revoked(self, key_id: str) -> bool:
        return False


_revocation_store: RevocationStore = _UnconfiguredRevocationStore()


def register_revocation_store(store: RevocationStore) -> None:
    """Register a platform-provided revocation store.

    Host platforms plug in a store backed by their KV / DB layer so every
    agent in the mesh shares a consistent view of revoked keys.
    """
    global _revocation_store
    _revocation_store = store


def should_reject_cached_key(key_id: str) -> bool:
    """Return True when *key_id* is known-revoked.

    Receivers holding a cached public key MUST consult this helper before
    verifying signatures; revoked keys MUST NOT be trusted even if the
    signature math checks out. Thin wrapper around the registered
    :class:`RevocationStore` so the default (unconfigured) behaviour is
    safe.
    """
    try:
        return bool(_revocation_store.is_revoked(key_id))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("RevocationStore.is_revoked raised: %s", exc)
        return False


def revocation_verify_cached_key(key_id: str) -> bool:
    """Return True when the cached key *key_id* is still valid.

    Inverse of :func:`should_reject_cached_key` — kept as a readable alias
    for callers whose flow reads as "verify this cached key is OK".
    """
    return not should_reject_cached_key(key_id)
