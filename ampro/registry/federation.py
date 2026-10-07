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
import json
import logging
import secrets
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

_TRUST_PROOF_MIN_LENGTH = 64  # Base64-encoded Ed25519 signature minimum

# Freshness window for federation trust proofs (seconds either side of now).
DEFAULT_TRUST_PROOF_MAX_AGE_SECONDS = 300

_TRUST_PROOF_TYPE = "ampro.registry.federation_request.v1"
_REVOKE_TYPE = "ampro.registry.federation_revoke.v1"


def _utc_z(value: datetime) -> str:
    """Canonical RFC 3339 UTC with ``Z``; naive datetimes are taken as UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    utc = value.astimezone(UTC)
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        base += f".{utc.microsecond:06d}"
    return base + "Z"


def _canonical_json(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class RegistryFederationRequest(BaseModel):
    """Request to establish federation between two registries."""

    registry_id: str = Field(description="agent:// URI of the requesting registry")
    capabilities: list[str] = Field(
        description="Capabilities offered (resolve, search, presence)",
    )
    trust_proof: str = Field(
        description=(
            "Base64 Ed25519 signature over the canonical proof payload "
            "(see federation_trust_proof_payload)"
        ),
        min_length=1,
    )
    audience: str | None = Field(
        default=None,
        description="agent:// URI of the registry this request is addressed to (signed)",
    )
    issued_at: datetime | None = Field(
        default=None,
        description="UTC issuance time of the proof (signed; freshness-checked)",
    )
    nonce: str | None = Field(
        default=None,
        min_length=16,
        max_length=256,
        description="Single-use random nonce (signed; replay-checked)",
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
    """Best-effort parse of a datetime or ISO-8601 string, normalised to aware UTC.

    Naive values (datetime objects or strings without an offset) are
    interpreted as UTC so that naive and aware timestamps can always be
    compared (previously this raised ``TypeError``).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            raw = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _tiebreak_uri(record: Any) -> str | None:
    """URI used for the deterministic tie-break: registry_id, else agent_uri."""
    for name in ("registry_id", "source_registry", "agent_uri"):
        value = _get_field(record, name)
        if isinstance(value, str) and value:
            return value
    return None


def resolve_federation_conflict(
    local_record: Any,
    remote_record: Any,
    *,
    max_future_skew_seconds: int = 60,
) -> Literal["local", "remote"]:
    """Determine precedence when the same agent_uri exists in two federated registries.

    Returns ``'local'`` if the local record wins; ``'remote'`` otherwise.
    Precedence (PROTOCOL-CONTRACTS §4): trust → recency → deterministic URI.

    Security properties:

    1. **Remote tier is NEVER load-bearing.** A higher local tier wins; a
       higher remote tier claim is ignored. When the remote record wins on
       recency, callers MUST apply it via :func:`merge_federation_record`,
       which caps the remote ``trust_tier`` at the local tier so a peer can
       never escalate an agent's tier by publishing a newer record.
    2. **Clock skew is bounded.** Remote ``last_seen`` values more than
       ``max_future_skew_seconds`` in the future are discarded.
    3. **Timestamps are normalised** to aware UTC (naive ⇒ UTC), so mixed
       naive/aware inputs never raise.
    4. **Deterministic URI fallback** on exact ties: the record whose
       ``registry_id`` (falling back to ``source_registry`` / ``agent_uri``)
       sorts lexicographically first wins, so all registries converge on
       the same record. If neither side carries a comparable URI, or the
       URIs are equal, local wins.
    """
    local_tier = _tier_rank(_get_field(local_record, "trust_tier"))
    remote_tier = _tier_rank(_get_field(remote_record, "trust_tier"))
    if local_tier > remote_tier:
        return "local"

    local_seen = _parse_ts(_get_field(local_record, "last_seen"))
    remote_seen = _parse_ts(_get_field(remote_record, "last_seen"))

    if remote_seen is not None:
        skew_cap = datetime.now(UTC) + timedelta(seconds=max_future_skew_seconds)
        if remote_seen > skew_cap:
            remote_seen = None  # discard — adversarial future timestamp

    if local_seen is not None and remote_seen is not None and local_seen != remote_seen:
        return "local" if local_seen > remote_seen else "remote"
    if local_seen is not None and remote_seen is None:
        return "local"
    if local_seen is None and remote_seen is not None:
        return "remote"

    local_uri = _tiebreak_uri(local_record)
    remote_uri = _tiebreak_uri(remote_record)
    if local_uri is not None and remote_uri is not None and remote_uri < local_uri:
        return "remote"
    return "local"


def merge_federation_record(
    local_record: Any,
    remote_record: Any,
    *,
    max_future_skew_seconds: int = 60,
) -> dict[str, Any]:
    """Return the record to store after resolving a federation conflict.

    If the local record wins it is returned unchanged (as a dict). If the
    remote record wins, its fields are returned but ``trust_tier`` is
    capped at the local record's tier: a remote peer can refresh an
    agent's data but can never raise its trust tier in the local view.
    """

    def _as_dict(record: Any) -> dict[str, Any]:
        if isinstance(record, Mapping):
            return dict(record)
        if hasattr(record, "model_dump"):
            return dict(record.model_dump())
        return dict(vars(record))

    winner = resolve_federation_conflict(
        local_record, remote_record, max_future_skew_seconds=max_future_skew_seconds
    )
    if winner == "local":
        return _as_dict(local_record)
    merged = _as_dict(remote_record)
    local_tier = _get_field(local_record, "trust_tier")
    if _tier_rank(merged.get("trust_tier")) > _tier_rank(local_tier):
        merged["trust_tier"] = local_tier
    return merged


# ---------------------------------------------------------------------------
# Trust-proof verification
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

    Without a resolver, ``verify_federation_trust_proof`` and
    ``verify_federation_revoke`` fail CLOSED.
    """
    global _TRUST_PROOF_RESOLVER
    _TRUST_PROOF_RESOLVER = resolver


class _NonceCache:
    """Bounded, TTL-based single-use nonce cache (thread-safe)."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max = max_entries

    def check_and_add(self, key: str, ttl_seconds: float) -> bool:
        """Return True if *key* was unseen (and record it); False on replay."""
        now = time.monotonic()
        with self._lock:
            if len(self._seen) >= self._max:
                self._seen = {k: t for k, t in self._seen.items() if t > now}
                if len(self._seen) >= self._max:
                    return False  # fail closed under nonce flooding
            expiry = self._seen.get(key)
            if expiry is not None and expiry > now:
                return False
            self._seen[key] = now + ttl_seconds
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


@runtime_checkable
class FederationNonceCache(Protocol):
    """Single-use store for federation ``trust_proof`` nonces.

    The default is per-process; several registry workers must share one
    (e.g. :class:`ampro.stores.redis.RedisFederationNonceCache`), otherwise
    a proof replayed to a different worker is accepted.
    """

    def check_and_add(self, key: str, ttl_seconds: float) -> bool:
        """Return True if *key* was unseen (and record it); False on replay."""
        ...


_FEDERATION_NONCES: FederationNonceCache = _NonceCache()


def register_federation_nonce_cache(cache: FederationNonceCache | None) -> None:
    """Install a shared federation nonce cache (``None`` restores the default)."""
    global _FEDERATION_NONCES
    _FEDERATION_NONCES = cache if cache is not None else _NonceCache()


def reset_federation_nonce_cache() -> None:
    """Clear the process-local federation nonce cache (tests / key rotation)."""
    clear = getattr(_FEDERATION_NONCES, "clear", None)
    if clear is not None:
        clear()


def federation_trust_proof_payload(
    registry_id: str,
    capabilities: list[str],
    audience: str,
    issued_at: datetime,
    nonce: str,
) -> bytes:
    """Canonical bytes signed by a federation trust proof.

    Canonical JSON (sorted keys, compact separators, UTF-8) of::

        {"type": "ampro.registry.federation_request.v1",
         "registry_id": ..., "audience": ..., "issued_at": "<RFC3339 Z>",
         "nonce": ..., "capabilities": sorted(capabilities)}
    """
    return _canonical_json(
        {
            "type": _TRUST_PROOF_TYPE,
            "registry_id": registry_id,
            "audience": audience,
            "issued_at": _utc_z(issued_at),
            "nonce": nonce,
            "capabilities": sorted(capabilities),
        }
    )


def sign_federation_trust_proof(
    private_key_bytes: bytes,
    registry_id: str,
    capabilities: list[str],
    *,
    audience: str,
    issued_at: datetime | None = None,
    nonce: str | None = None,
) -> RegistryFederationRequest:
    """Build a signed :class:`RegistryFederationRequest` addressed to *audience*."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issued = issued_at or datetime.now(UTC)
    nonce = nonce or secrets.token_urlsafe(24)
    payload = federation_trust_proof_payload(
        registry_id, capabilities, audience, issued, nonce
    )
    sig = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(payload)
    return RegistryFederationRequest(
        registry_id=registry_id,
        capabilities=capabilities,
        trust_proof=base64.b64encode(sig).decode("ascii"),
        audience=audience,
        issued_at=issued,
        nonce=nonce,
    )


def _decode_sig(value: str) -> bytes | None:
    value = value.strip()
    try:
        padded = value + "=" * (-len(value) % 4)
        if "-" in value or "_" in value:
            return base64.b64decode(padded, altchars=b"-_", validate=True)
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _verify_ed25519(registry_id: str, sig_b64: str, payload: bytes) -> bool:
    if _TRUST_PROOF_RESOLVER is None:
        logger.warning(
            "Federation signature from %s rejected — no resolver registered. "
            "Call register_federation_trust_proof_resolver() at startup.",
            registry_id,
        )
        return False
    sig_bytes = _decode_sig(sig_b64)
    if sig_bytes is None or len(sig_bytes) != 64:
        logger.warning("Federation signature decode failed for %s", registry_id)
        return False
    public_key_bytes = _TRUST_PROOF_RESOLVER(registry_id)
    if public_key_bytes is None or len(public_key_bytes) != 32:
        logger.warning("Federation signature from %s: resolver returned no key", registry_id)
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        logger.error("cryptography missing — cannot verify federation signature")
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(sig_bytes, payload)
        return True
    except Exception as exc:
        logger.warning("Federation signature invalid for %s: %s", registry_id, exc)
        return False


def verify_federation_trust_proof(
    request: RegistryFederationRequest,
    *,
    expected_audience: str | None = None,
    max_age_seconds: int = DEFAULT_TRUST_PROOF_MAX_AGE_SECONDS,
) -> bool:
    """Cryptographically verify a federation trust proof (single use).

    The proof MUST be a base64 Ed25519 signature over
    :func:`federation_trust_proof_payload` (registry_id, audience,
    issued_at, nonce, sorted capabilities). Returns True only when:

      1. A trust-proof resolver is registered and returns a key for
         ``request.registry_id``;
      2. ``request.audience`` equals *expected_audience* (this registry's
         own URI) — ``None`` fails closed;
      3. ``issued_at`` is within ±``max_age_seconds`` of now;
      4. ``nonce`` has not been seen within the freshness window;
      5. The signature verifies.

    The nonce is recorded only after the signature verifies, so forged
    requests cannot burn legitimate nonces.
    """
    if not expected_audience:
        logger.warning(
            "Federation trust_proof from %s rejected — expected_audience not supplied",
            request.registry_id,
        )
        return False
    if (
        request.audience is None
        or request.issued_at is None
        or not request.nonce
        or not request.trust_proof
        or len(request.trust_proof) < _TRUST_PROOF_MIN_LENGTH
    ):
        return False
    if request.audience != expected_audience:
        logger.warning(
            "Federation trust_proof from %s addressed to %s, not %s",
            request.registry_id, request.audience, expected_audience,
        )
        return False
    issued = _parse_ts(request.issued_at)
    if issued is None:
        return False
    window = timedelta(seconds=max_age_seconds)
    if abs(datetime.now(UTC) - issued) > window:
        logger.warning("Federation trust_proof from %s is stale", request.registry_id)
        return False

    payload = federation_trust_proof_payload(
        request.registry_id,
        request.capabilities,
        request.audience,
        issued,
        request.nonce,
    )
    if not _verify_ed25519(request.registry_id, request.trust_proof, payload):
        return False
    nonce_key = f"{request.registry_id}\x00{request.nonce}"
    if not _FEDERATION_NONCES.check_and_add(nonce_key, 2 * max_age_seconds):
        logger.warning("Federation trust_proof replay from %s", request.registry_id)
        return False
    return True


def federation_revoke_payload(fields: Mapping[str, Any]) -> bytes:
    """Canonical bytes signed for a ``registry.federation_revoke`` body.

    Canonical JSON of every body field except ``signature`` plus
    ``"type": "ampro.registry.federation_revoke.v1"``; ``effective_at`` is
    rendered as RFC 3339 UTC with ``Z``.
    """
    effective = _parse_ts(fields.get("effective_at"))
    if effective is None:
        raise ValueError("effective_at is required")
    return _canonical_json(
        {
            "type": _REVOKE_TYPE,
            "revoking_registry": fields["revoking_registry"],
            "revoked_registry": fields["revoked_registry"],
            "reason": fields["reason"],
            "effective_at": _utc_z(effective),
        }
    )


def sign_federation_revoke(private_key_bytes: bytes, fields: Mapping[str, Any]) -> str:
    """Sign a revoke body (all fields except ``signature``); returns base64."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sig = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(
        federation_revoke_payload(fields)
    )
    return base64.b64encode(sig).decode("ascii")


def verify_federation_revoke(
    body: RegistryFederationRevokeBody,
    *,
    expected_revoked_registry: str,
) -> bool:
    """Verify a federation revoke's Ed25519 signature. Never raises.

    Returns True only when ``body.revoked_registry`` equals
    *expected_revoked_registry* (this registry) and the signature by
    ``revoking_registry``'s resolver-registered key verifies over
    :func:`federation_revoke_payload`.
    """
    try:
        if body.revoked_registry != expected_revoked_registry:
            return False
        payload = federation_revoke_payload(body.model_dump())
        return _verify_ed25519(body.revoking_registry, body.signature, payload)
    except Exception:
        return False
