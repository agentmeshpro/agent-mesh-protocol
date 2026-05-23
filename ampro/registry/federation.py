"""
Agent Protocol — Registry Federation.

Inter-registry trust establishment. Two registries negotiate mutual
trust so agents registered in one can be discovered through the other.

Federation sync
---------------

Sync is poll-based; receivers push an incremental delta. Each registry
implementation defines its own change-record shape, so
:class:`RegistryFederationSyncResponseBody.changes` carries opaque dicts
(typically ``{"op": "upsert"|"delete", "agent_uri": "...", ...}``) plus a
``next_cursor`` for paging through large deltas.
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import logging
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

_TRUST_PROOF_MIN_LENGTH = 64  # Base64-encoded Ed25519 signature minimum


class RegistryFederationRequest(BaseModel):
    """Request to establish federation between two registries."""

    registry_id: str = Field(description="agent:// URI of the requesting registry")
    capabilities: list[str] = Field(
        description="Capabilities offered (resolve, search, presence)",
    )
    trust_proof: str = Field(
        description="Signed proof of registry identity",
        min_length=1,
    )

    model_config = {"extra": "ignore"}

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, v: list[str]) -> list[str]:
        """Bound and sanitize capability names.

        * Length: each capability must be 1..128 chars. The canonical bytes
          used for federation trust proofs concatenate every capability;
          unbounded capability strings would let an attacker amplify a
          tiny request into multi-MB canonical work for the verifier.
        * Charset: no control characters. The canonical encoding uses
          0x00 between registry_id and capabilities and 0x1F to join
          capabilities, so a capability containing those bytes could be
          confused with a structural delimiter.
        * Count: at most 64 capabilities (well above any real spec set).
        """
        if len(v) > 64:
            raise ValueError("too many capabilities (max 64)")
        for cap in v:
            if not cap:
                raise ValueError("capability names must be non-empty")
            if len(cap) > 128:
                raise ValueError(
                    f"capability name too long ({len(cap)} > 128 chars)"
                )
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cap):
                raise ValueError(
                    f"capability {cap!r} contains control characters — forbidden"
                )
        return v

    @field_validator("trust_proof")
    @classmethod
    def validate_trust_proof(cls, v: str) -> str:
        """Validate trust_proof is non-empty and meets minimum length for Ed25519 sig."""
        if not v or not v.strip():
            raise ValueError("trust_proof must be a non-empty string")
        if len(v) < _TRUST_PROOF_MIN_LENGTH:
            raise ValueError(
                f"trust_proof must be at least {_TRUST_PROOF_MIN_LENGTH} characters "
                f"(base64-encoded Ed25519 signature minimum), got {len(v)}"
            )
        return v


class RegistryFederationResponse(BaseModel):
    """Response to a registry federation request."""

    accepted: bool = Field(description="Whether federation was accepted")
    federation_id: str | None = Field(
        default=None,
        description="Unique federation ID (required when accepted)",
    )
    terms: dict[str, Any] = Field(
        default_factory=dict,
        description="Federation terms (rate limits, retention, etc.)",
    )

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Issue #39 — Federation revocation
# ---------------------------------------------------------------------------


class RegistryFederationRevokeBody(BaseModel):
    """body.type = 'registry.federation_revoke' — Tear down a federation link."""

    model_config = {"extra": "ignore"}

    revoking_registry: str = Field(..., description="Registry initiating the revoke")
    revoked_registry: str = Field(..., description="Registry being revoked")
    reason: str = Field(..., max_length=1024)
    effective_at: datetime = Field(
        ..., description="UTC; revocation effective from this time"
    )
    signature: str = Field(
        ..., description="Ed25519 signature by revoking_registry's key"
    )


# ---------------------------------------------------------------------------
# Issue #40 — Federation sync protocol
# ---------------------------------------------------------------------------


class RegistryFederationSyncBody(BaseModel):
    """body.type = 'registry.federation_sync' — Request a delta from a peer registry."""

    model_config = {"extra": "ignore"}

    since: datetime = Field(
        ..., description="UTC; return changes after this timestamp"
    )
    registry_id: str
    cursor: str | None = Field(
        default=None,
        description="Opaque pagination cursor from previous sync response",
    )


class RegistryFederationSyncResponseBody(BaseModel):
    """body.type = 'registry.federation_sync_response' — Delta + cursor."""

    model_config = {"extra": "ignore"}

    changes: list[dict] = Field(
        ...,
        max_length=500,
        description=(
            "Opaque change records — each registry defines its own "
            "schema (typically includes an op: insert|update|delete field)."
        ),
    )
    next_cursor: str | None = None
    has_more: bool = False


# ---------------------------------------------------------------------------
# Issue #41 — Federation conflict resolution
# ---------------------------------------------------------------------------

# Coarse ordering of trust tiers — higher index wins.
_TRUST_TIER_ORDER: dict[str, int] = {
    "external": 0,
    "verified": 1,
    "owner": 2,
    "internal": 3,
}


def _tier_rank(value: Any) -> int:
    """Return a comparable integer for a trust-tier value."""
    if value is None:
        return -1
    if isinstance(value, int):
        return value
    return _TRUST_TIER_ORDER.get(str(value).lower(), -1)


def _get_field(record: Any, name: str) -> Any:
    """Read ``name`` from either a dict-like or attribute-based record."""
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _parse_ts(value: Any) -> datetime | None:
    """Best-effort parse of a datetime or ISO-8601 string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            raw = value.replace("Z", "+00:00") if value.endswith("Z") else value
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    return None


def resolve_federation_conflict(
    local_record: Any,
    remote_record: Any,
    *,
    max_future_skew_seconds: int = 60,
) -> Literal["local", "remote"]:
    """Determine precedence when the same agent_uri exists in two federated registries.

    Returns ``'local'`` if the local record wins; ``'remote'`` otherwise.

    Security properties (changed from earlier revisions):

    1. **Remote tier is NEVER load-bearing.** A peer registry can claim
       ``trust_tier='internal'`` for any agent; that claim is a self-assertion
       and must not promote the agent on this side. Tier comparison applies
       only when the **local** record asserts the tier — i.e. tier acts as
       a tiebreaker that favours locally-trusted records, never one that
       lets a remote escalate.
    2. **Clock skew is bounded.** ``last_seen`` values from the remote
       that lie more than ``max_future_skew_seconds`` in the future of the
       local clock are clamped to "now", preventing forward-skew hijacks.
    3. **Deterministic lex fallback** on agent_uri when all signals are
       equal.
    """
    # 1. Local tier dominates only if the local record sits higher than
    #    the remote claim. We never let a higher remote claim win.
    local_tier = _tier_rank(_get_field(local_record, "trust_tier"))
    remote_tier = _tier_rank(_get_field(remote_record, "trust_tier"))
    if local_tier > remote_tier:
        return "local"
    # If remote_tier > local_tier, ignore the claim entirely (do NOT
    # return "remote") and fall through to the timestamp comparison.

    local_seen = _parse_ts(_get_field(local_record, "last_seen"))
    remote_seen = _parse_ts(_get_field(remote_record, "last_seen"))

    # Detect and penalise forward-skewed remote timestamps. A claim that
    # lies more than ``max_future_skew_seconds`` ahead of the local clock
    # is treated as adversarial: we discard the remote timestamp entirely
    # so that the comparison falls back to local-wins logic.
    if remote_seen is not None:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        if remote_seen.tzinfo is None:
            remote_seen = remote_seen.replace(tzinfo=timezone.utc)
        skew_cap = now + timedelta(seconds=max_future_skew_seconds)
        if remote_seen > skew_cap:
            remote_seen = None  # discard — adversarial future timestamp

    if local_seen is not None and remote_seen is not None and local_seen != remote_seen:
        return "local" if local_seen > remote_seen else "remote"
    if local_seen is not None and remote_seen is None:
        return "local"
    if local_seen is None and remote_seen is not None:
        return "remote"

    # Final tiebreak: prefer LOCAL over remote. The previous lex fallback
    # let an attacker pick a registry_id that sorts earlier than the legit
    # local one and win pure ties. "Local wins ties" is the safer default:
    # the local registry has authoritative knowledge of its own state.
    return "local"


# ---------------------------------------------------------------------------
# Existing trust-proof verification
# ---------------------------------------------------------------------------


class FederationTrustProofResolver(Protocol):
    """Resolve a federation registry_id to its registered public key.

    Returns 32-byte Ed25519 public key bytes, or None when the registry
    is unknown / unregistered. Implementations MUST consult an out-of-band
    trust source (signed federation directory, DNS-anchored key list, etc.).
    """

    def __call__(self, registry_id: str) -> bytes | None: ...


_TRUST_PROOF_RESOLVER: FederationTrustProofResolver | None = None


def register_federation_trust_proof_resolver(
    resolver: FederationTrustProofResolver,
) -> None:
    """Register the host's federation trust resolver.

    Without a resolver, ``verify_federation_trust_proof`` fails CLOSED —
    a deployment that forgets to wire trust roots cannot accept any
    federation request. Default fail-closed is the only safe behaviour
    for inter-registry trust establishment.
    """
    global _TRUST_PROOF_RESOLVER
    _TRUST_PROOF_RESOLVER = resolver


def verify_federation_trust_proof(request: RegistryFederationRequest) -> bool:
    """Cryptographically verify a federation trust proof.

    The proof MUST be a base64-encoded Ed25519 signature over the canonical
    bytes ``registry_id || NUL || sorted(capabilities)``. The signing key is
    resolved via the host-registered :class:`FederationTrustProofResolver`.

    Returns True only when:
      1. A trust-proof resolver is registered, AND
      2. The resolver returns a public key for ``request.registry_id``, AND
      3. The signature verifies against the canonical bytes.

    Default (no resolver registered): returns False — fail closed.

    Format-only validation (the previous behaviour) is intentionally removed
    because it accepted any 64+ char base64 string as a "trust proof",
    letting any attacker establish federation.
    """
    if _TRUST_PROOF_RESOLVER is None:
        logger.warning(
            "Federation trust_proof from %s rejected — no resolver registered. "
            "Call register_federation_trust_proof_resolver() at startup.",
            request.registry_id,
        )
        return False

    proof = request.trust_proof
    if not proof or len(proof) < _TRUST_PROOF_MIN_LENGTH:
        return False
    proof = proof.strip()

    try:
        padded = proof + "=" * (-len(proof) % 4)
        sig_bytes = base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception:
        logger.warning("Federation trust_proof base64 decode failed for %s", request.registry_id)
        return False

    public_key_bytes = _TRUST_PROOF_RESOLVER(request.registry_id)
    if public_key_bytes is None or len(public_key_bytes) != 32:
        logger.warning(
            "Federation trust_proof from %s: resolver returned no key",
            request.registry_id,
        )
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        logger.error("cryptography missing — cannot verify federation trust proof")
        return False

    canonical = (
        request.registry_id.encode("utf-8")
        + b"\x00"
        + b"\x1f".join(sorted(c.encode("utf-8") for c in request.capabilities))
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(sig_bytes, canonical)
        return True
    except Exception as exc:
        logger.warning(
            "Federation trust_proof signature invalid for %s: %s",
            request.registry_id, exc,
        )
        return False
