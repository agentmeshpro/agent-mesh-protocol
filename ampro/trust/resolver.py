"""
Agent Protocol — Multi-Method Trust Resolver.

Resolves trust tier from Authorization header using:
  1. Same organization → INTERNAL
  2. Bearer JWT with EdDSA + owner scope → OWNER
  3. Bearer JWT with EdDSA → VERIFIED
  4. did:key proof (signed, short-lived, audience- and sender-bound,
     single-use ``jti``) → VERIFIED
  5. API key registered via :func:`register_api_key` (or an injected
     store) → VERIFIED
  6. mTLS client-certificate identity supplied by the transport via
     ``client_cert_identity`` → VERIFIED
  7. Everything else → EXTERNAL
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time as _time
from collections import OrderedDict
from collections.abc import Iterable
from typing import Any, Protocol

from ampro.identity.auth_methods import AuthMethod, ParsedAuth, parse_authorization
from ampro.security.nonce_tracker import NonceTracker
from ampro.transport.api_key_store import ApiKeyStore
from ampro.trust.tiers import CLOCK_SKEW_SECONDS, TrustTier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JWT algorithm allow-list (P0.D — HIGH finding 2.4)
#
# Only asymmetric algorithms are permitted at the protocol level. Symmetric
# algorithms (HS256/HS384/HS512) are rejected because they require shared
# secrets, which are incompatible with agent-mesh trust. The "none" algorithm
# is an obvious attack vector (CVE-2015-9235 et al.).
# ---------------------------------------------------------------------------

ALLOWED_JWT_ALGS: frozenset[str] = frozenset({
    "EdDSA",
    "ES256",
    "ES384",
    "RS256",
    "RS384",
    "RS512",
})


def validate_jwt_algorithm(token: str) -> bool:
    """Check that a JWT uses an allowed asymmetric algorithm.

    Returns ``True`` if the token's ``alg`` header is in
    :data:`ALLOWED_JWT_ALGS`; ``False`` for ``none``, symmetric
    algorithms, malformed tokens, or any unlisted algorithm.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False

    header_b64 = parts[0]
    # Add padding for url-safe base64
    remainder = len(header_b64) % 4
    if remainder:
        header_b64 += "=" * (4 - remainder)

    try:
        header_json = base64.urlsafe_b64decode(header_b64)
        header = json.loads(header_json)
    except Exception:
        return False

    alg = header.get("alg")
    if not isinstance(alg, str):
        return False

    return alg in ALLOWED_JWT_ALGS


# Brute-force protection for API-key auth (per client IP). The key
# material itself lives in ``_API_KEYS`` (hashed) or an injected store.
_api_key_store = ApiKeyStore(max_failures=10, block_seconds=900)

# sha256(key) hex digest → (digest, agent_id, tier). Plaintext keys are never stored.
_API_KEYS: dict[str, tuple[str, str, TrustTier]] = {}
_API_KEYS_LOCK = threading.Lock()
_API_KEY_MAX_TIER = TrustTier(ParsedAuth(method=AuthMethod.API_KEY).max_trust_tier())


class ApiKeyValidator(Protocol):
    """Host-provided API-key store.

    ``validate(key)`` returns the agent_id owning *key*, or ``None``.
    Implementations MUST compare in constant time and SHOULD store only
    hashes. :class:`ampro.transport.api_key_store.ApiKeyStore` conforms.
    A matched key resolves to VERIFIED.
    """

    def validate(self, key: str) -> str | None: ...


_API_KEY_VALIDATOR: ApiKeyValidator | None = None


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def register_api_key(
    key: str, agent_id: str, tier: TrustTier = TrustTier.VERIFIED,
) -> None:
    """Allow-list an API key for ``Authorization: ApiKey <key>``.

    Only the SHA-256 digest of *key* is retained. *tier* may not exceed
    VERIFIED — API keys are bearer secrets and never confer OWNER or
    INTERNAL trust.
    """
    if not key:
        raise ValueError("API key must be non-empty")
    tier = TrustTier(tier)
    if tier > _API_KEY_MAX_TIER:
        raise ValueError(f"API keys cannot confer trust above {_API_KEY_MAX_TIER.value}")
    with _API_KEYS_LOCK:
        digest = _hash_api_key(key)
        _API_KEYS[digest] = (digest, agent_id, tier)


def unregister_api_key(key: str) -> None:
    """Remove a key registered with :func:`register_api_key`."""
    with _API_KEYS_LOCK:
        _API_KEYS.pop(_hash_api_key(key), None)


def register_api_key_store(store: ApiKeyValidator | None) -> None:
    """Inject a host-provided API-key store (``None`` removes it)."""
    global _API_KEY_VALIDATOR
    with _API_KEYS_LOCK:
        _API_KEY_VALIDATOR = store


def _reset_api_keys_for_tests() -> None:
    """Test-only: drop registered keys, injected store and IP blocks."""
    global _API_KEY_VALIDATOR, _api_key_store
    with _API_KEYS_LOCK:
        _API_KEYS.clear()
        _API_KEY_VALIDATOR = None
    _api_key_store = ApiKeyStore(max_failures=10, block_seconds=900)


async def resolve_trust_tier(
    authorization: str | None,
    caller_org_id: str | None,
    target_org_id: str | None,
    client_ip: str | None = None,
    *,
    sender_id: str | None = None,
    audience: str | None = None,
    sender_linked_dids: Iterable[str] | None = None,
    client_cert_identity: str | None = None,
) -> TrustTier:
    """Resolve the caller's trust tier.

    Args:
        authorization: Raw ``Authorization`` header value.
        caller_org_id / target_org_id: Server-derived org ids.
        client_ip: Caller IP (API-key brute-force protection).
        sender_id: The message sender identity (``agent://…`` or ``did:…``).
            A DID proof must be bound to it (see :func:`_resolve_did`).
        audience: This agent's identifier; DID proofs must name it in ``aud``.
        sender_linked_dids: DIDs verified (e.g. via an identity-link proof)
            to belong to a non-DID *sender_id*.
        client_cert_identity: Identity from a client certificate that the
            TRANSPORT has already verified (mTLS). Never derived from a
            header. When set, the tier is at least VERIFIED.
    """
    # Intentional: same org_id → INTERNAL trust. This is by design —
    # agents within the same organization skip external auth checks.
    # The org_id values are server-side derived, not user-supplied.
    if caller_org_id and target_org_id and caller_org_id == target_org_id:
        return TrustTier.INTERNAL

    parsed = parse_authorization(authorization)

    tier = TrustTier.EXTERNAL
    if parsed.method == AuthMethod.JWT:
        tier = await _resolve_jwt(parsed.token, caller_org_id, target_org_id)
    elif parsed.method == AuthMethod.DID:
        tier = await _resolve_did(
            parsed.token,
            audience=audience,
            sender=sender_id,
            linked_dids=sender_linked_dids,
        )
    elif parsed.method == AuthMethod.API_KEY:
        tier = _resolve_api_key(parsed.token, client_ip)

    # mTLS is a transport property, not an Authorization header: only an
    # identity the transport verified from the client certificate counts.
    if client_cert_identity and tier < TrustTier.VERIFIED:
        tier = TrustTier.VERIFIED

    return tier


async def _resolve_jwt(token: str, caller_org_id: str | None, target_org_id: str | None) -> TrustTier:
    """Resolve trust from JWT. Requires a runtime-provided jwt_trust_resolver.

    The jwt_trust_resolver module is NOT included in the ampro package
    because it requires platform-specific infrastructure (JWKS fetching,
    configuration). Platforms provide their own implementation.

    Falls back to EXTERNAL if no resolver is available.
    """
    # P0.D — reject dangerous JWT algorithms at the protocol level before
    # delegating to any platform resolver.
    if not validate_jwt_algorithm(token):
        logger.warning("JWT rejected: algorithm not in ALLOWED_JWT_ALGS")
        return TrustTier.EXTERNAL

    try:
        from ampro.jwt_trust_resolver import (
            resolve_trust_tier_from_jwt,  # type: ignore[import-not-found]
        )
        return await resolve_trust_tier_from_jwt(
            authorization=f"Bearer {token}",
            caller_org_id=caller_org_id,
            target_org_id=target_org_id,
        )
    except ImportError:
        # Fail-open: no JWT resolver installed → EXTERNAL (lowest trust).
        # This is acceptable because EXTERNAL triggers all safety checks.
        logger.warning("JWT resolver not available — install a platform-specific jwt_trust_resolver")
        return TrustTier.EXTERNAL
    except Exception as exc:
        # Fail-open: resolution error → EXTERNAL (lowest trust).
        logger.warning("JWT resolution failed: %s", exc)
        return TrustTier.EXTERNAL


# DID proof policy. A proof is a compact JWS (``header.payload.signature``,
# alg EdDSA) signed by the did:key's own key, with payload claims:
#   did  — the did:key being proven
#   aud  — the receiving agent (string or list)
#   iat  — issued-at (unix seconds)
#   exp  — expiry (unix seconds); exp - iat <= DID_PROOF_MAX_LIFETIME_SECONDS
#   jti  — unique id; each (did, jti) is accepted once
DID_PROOF_MAX_LIFETIME_SECONDS: int = 300

_DID_PROOF_NONCE_TRACKER = NonceTracker(
    window_seconds=DID_PROOF_MAX_LIFETIME_SECONDS + 2 * CLOCK_SKEW_SECONDS,
)


def set_did_proof_nonce_tracker(tracker: Any | None) -> None:
    """Install the replay cache for DID-proof ``jti`` values (process-wide).

    *tracker* is any :class:`~ampro.security.nonce_tracker.ReplayCache`.
    Several workers must share one (e.g.
    :class:`ampro.stores.redis.RedisNonceTracker`) or a proof replayed to
    another worker is accepted.  ``None`` restores a fresh in-memory one.
    """
    global _DID_PROOF_NONCE_TRACKER
    _DID_PROOF_NONCE_TRACKER = tracker if tracker is not None else NonceTracker(
        window_seconds=DID_PROOF_MAX_LIFETIME_SECONDS + 2 * CLOCK_SKEW_SECONDS,
    )


def set_api_key_failure_tracker(tracker: Any | None) -> None:
    """Install the brute-force tracker for API-key auth (process-wide).

    *tracker* is any :class:`~ampro.transport.api_key_store.ApiKeyFailureTracker`;
    ``None`` restores the in-memory default.
    """
    global _api_key_store
    _api_key_store = tracker if tracker is not None else ApiKeyStore(
        max_failures=10, block_seconds=900,
    )


def _b64url_decode(data: str) -> bytes:
    remainder = len(data) % 4
    if remainder:
        data += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(data)


def did_key_to_public_key(did: str) -> bytes:
    """Return the raw 32-byte Ed25519 public key embedded in a ``did:key``.

    Raises ``ValueError`` for anything that is not a well-formed Ed25519
    did:key.
    """
    if not did.startswith("did:key:"):
        raise ValueError("not a did:key")
    try:
        public_key_bytes = _multibase_decode_ed25519(did[len("did:key:"):])
    except (ValueError, KeyError) as exc:
        raise ValueError(f"invalid did:key encoding: {exc}") from exc
    if len(public_key_bytes) != 32:
        raise ValueError(
            f"did:key public key wrong length: {len(public_key_bytes)} bytes (expected 32)"
        )
    return public_key_bytes


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _strip_agent_scheme(identity: str) -> str:
    return identity[len("agent://"):] if identity.startswith("agent://") else identity


async def _resolve_did(
    token: str,
    *,
    audience: str | None = None,
    sender: str | None = None,
    linked_dids: Iterable[str] | None = None,
    nonce_tracker: NonceTracker | None = None,
) -> TrustTier:
    """Resolve a DID proof to a trust tier.

    Only ``did:key:`` is supported. A raw DID URI carries no proof of key
    possession and returns EXTERNAL. A JWT-style proof returns VERIFIED
    only when ALL of the following hold:

    * header ``alg`` is ``EdDSA`` and the signature verifies under the
      did:key's embedded Ed25519 key;
    * ``exp`` and ``iat`` are present, the proof is not expired (allowing
      :data:`CLOCK_SKEW_SECONDS`), ``iat`` is not in the future, and
      ``exp - iat`` ≤ :data:`DID_PROOF_MAX_LIFETIME_SECONDS`;
    * ``aud`` equals (or, if a list, contains) *audience* — this agent.
      With no *audience* configured the proof cannot be bound and is
      rejected;
    * the DID is bound to the message sender: *sender* is the same DID
      (``did:…`` or ``agent://did:…``), or *sender* is a non-DID identity
      and the DID appears in *linked_dids*. No *sender* → rejected;
    * ``jti`` is present and the ``(did, jti)`` pair has not been seen
      before (recorded only after every other check passes).

    Anything else returns EXTERNAL.
    """
    if token.startswith("did:"):
        # A raw DID URI carries no proof of key possession. Anyone can paste a
        # public DID. Reject — VERIFIED requires a signed JWT-style proof.
        logger.warning(
            "[trust] raw DID URI without proof — returning EXTERNAL (caller must "
            "supply a signed header.payload.signature proof for VERIFIED)"
        )
        return TrustTier.EXTERNAL

    parts = token.split(".")
    if len(parts) != 3:
        logger.debug("DID proof must be header.payload.signature")
        return TrustTier.EXTERNAL
    header_b64, payload_b64, signature_b64 = parts
    if len(payload_b64) > 10000:
        logger.warning("DID proof payload too large (%d bytes)", len(payload_b64))
        return TrustTier.EXTERNAL

    try:
        payload = json.loads(_b64url_decode(payload_b64))
        header = json.loads(_b64url_decode(header_b64))
        if not isinstance(payload, dict) or not isinstance(header, dict):
            raise ValueError("header/payload must be JSON objects")
    except Exception as exc:
        logger.debug("DID proof parsing failed: %s", exc)
        return TrustTier.EXTERNAL

    did = payload.get("did", "")
    if not isinstance(did, str) or not did:
        logger.debug("DID proof missing 'did' field")
        return TrustTier.EXTERNAL
    if header.get("alg") != "EdDSA":
        logger.warning(
            "[trust] DID proof algorithm must be EdDSA, got %r — returning EXTERNAL",
            header.get("alg"),
        )
        return TrustTier.EXTERNAL

    # --- DID method dispatch ---
    if not did.startswith("did:key:"):
        logger.info(
            "[trust] DID method not supported: %s — returning EXTERNAL",
            did.split(":", 2)[1] if ":" in did else "unknown",
        )
        return TrustTier.EXTERNAL
    try:
        public_key_bytes = did_key_to_public_key(did)
    except ValueError as exc:
        logger.warning("[trust] %s", exc)
        return TrustTier.EXTERNAL

    # --- Signature (proof of possession) ---
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        sig_bytes = _b64url_decode(signature_b64)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            sig_bytes, f"{header_b64}.{payload_b64}".encode("ascii"),
        )
    except Exception as exc:
        logger.warning(
            "[trust] DID proof signature invalid for %s (%s) — returning EXTERNAL",
            did, type(exc).__name__,
        )
        return TrustTier.EXTERNAL

    # --- Lifetime --- (wall clock: exp/iat are absolute unix timestamps)
    now = _time.time()
    exp, iat = payload.get("exp"), payload.get("iat")
    if not _is_number(exp) or not _is_number(iat):
        logger.warning("[trust] DID proof missing numeric exp/iat — returning EXTERNAL")
        return TrustTier.EXTERNAL
    if now > exp + CLOCK_SKEW_SECONDS:
        logger.warning("[trust] DID proof expired — returning EXTERNAL")
        return TrustTier.EXTERNAL
    if iat > now + CLOCK_SKEW_SECONDS:
        logger.warning("[trust] DID proof iat in the future — returning EXTERNAL")
        return TrustTier.EXTERNAL
    if exp - iat > DID_PROOF_MAX_LIFETIME_SECONDS or exp < iat:
        logger.warning(
            "[trust] DID proof lifetime exceeds %ds — returning EXTERNAL",
            DID_PROOF_MAX_LIFETIME_SECONDS,
        )
        return TrustTier.EXTERNAL

    # --- Audience ---
    aud = payload.get("aud")
    aud_values = aud if isinstance(aud, list) else [aud]
    if not audience or audience not in aud_values:
        logger.warning("[trust] DID proof audience mismatch — returning EXTERNAL")
        return TrustTier.EXTERNAL

    # --- Sender binding ---
    if not sender:
        logger.warning("[trust] DID proof without sender identity — returning EXTERNAL")
        return TrustTier.EXTERNAL
    sender_norm = _strip_agent_scheme(sender)
    if sender_norm.startswith("did:"):
        bound = hmac.compare_digest(sender_norm, did)
    else:
        bound = did in set(linked_dids or ())
    if not bound:
        logger.warning(
            "[trust] DID proof %s not bound to sender %s — returning EXTERNAL", did, sender,
        )
        return TrustTier.EXTERNAL

    # --- Replay (recorded last, only for otherwise-valid proofs) ---
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        logger.warning("[trust] DID proof missing jti — returning EXTERNAL")
        return TrustTier.EXTERNAL
    tracker = nonce_tracker if nonce_tracker is not None else _DID_PROOF_NONCE_TRACKER
    if tracker.is_replay(json.dumps([did, jti])):
        logger.warning("[trust] DID proof jti replay for %s — returning EXTERNAL", did)
        return TrustTier.EXTERNAL

    return TrustTier.VERIFIED


def _multibase_decode_ed25519(method_specific: str) -> bytes:
    """Decode a did:key method-specific identifier to raw 32-byte Ed25519 public key.

    Format: ``z`` prefix (base58btc) + multicodec varint ``0xed01`` + 32-byte key.
    See https://w3c-ccg.github.io/did-method-key/
    """
    if not method_specific.startswith("z"):
        raise ValueError("only base58btc (z) multibase encoding supported")

    import base58

    decoded = base58.b58decode(method_specific[1:])
    if len(decoded) < 2:
        raise ValueError("decoded payload too short")
    if decoded[0] != 0xED or decoded[1] != 0x01:
        raise ValueError("not an Ed25519 multicodec (expected 0xed01)")
    return decoded[2:]


def lookup_api_key_owner(key: str) -> tuple[str, TrustTier] | None:
    """Return ``(agent_id, tier)`` for a registered API key, else ``None``.

    The owning agent id is what callers must use as the authenticated
    identity: API keys are per-agent credentials, so two keys must never
    collapse into one principal.
    """
    presented = _hash_api_key(key)
    with _API_KEYS_LOCK:
        entry = _API_KEYS.get(presented)
        validator = _API_KEY_VALIDATOR
    # The dict lookup narrows by digest; confirm in constant time.
    if entry is not None and hmac.compare_digest(entry[0], presented):
        return entry[1], entry[2]
    if validator is not None:
        try:
            owner = validator.validate(key)
        except Exception as exc:
            logger.warning("API key store raised: %s", exc)
            return None
        if owner:
            return owner, TrustTier.VERIFIED
    return None


def _lookup_api_key(key: str) -> TrustTier | None:
    found = lookup_api_key_owner(key)
    return found[1] if found is not None else None


def _resolve_api_key(key: str, client_ip: str | None = None) -> TrustTier:
    if client_ip and _api_key_store.is_blocked(client_ip):
        logger.warning("API key auth blocked for IP %s (brute force)", client_ip)
        return TrustTier.EXTERNAL

    tier = _lookup_api_key(key)
    if tier is not None:
        if client_ip:
            _api_key_store.reset_failures(client_ip)
        return tier

    if client_ip:
        _api_key_store.record_failure(client_ip)
    return TrustTier.EXTERNAL


# ---------------------------------------------------------------------------
# Public-key resolution for envelope verification.
#
# AMP envelope verification needs to resolve a ``sig_kid`` (the sender's
# key_id from RFC 9421 ``Signature-Input``) to the raw Ed25519 public
# key bytes. The protocol is agnostic about WHERE keys live — the host
# platform plugs in a concrete lookup by registering a
# ``PublicKeyResolver`` at process startup.
#
# Default behaviour when no resolver is registered: return ``None``
# (fail closed). That causes the verifier to reject the envelope,
# which is the correct outcome for a standalone deployment that has
# not yet wired up trust.
#
# Cache: a 60s TTL window keyed by ``sig_kid``, bounded to
# ``_PUBLIC_KEY_CACHE_MAX_ENTRIES`` entries (LRU eviction). The cache uses
# ``time.monotonic()`` to prevent clock-manipulation attacks and a
# lock to serialise concurrent reads/writes.
# ---------------------------------------------------------------------------

from threading import Lock as _Lock

# Bounded LRU: ``sig_kid`` is attacker-controlled, so an unbounded dict
# would let a caller exhaust memory with unique key ids.
_PUBLIC_KEY_CACHE: OrderedDict[str, tuple[float, bytes | None]] = OrderedDict()
_PUBLIC_KEY_CACHE_LOCK = _Lock()
_PUBLIC_KEY_CACHE_TTL_SEC = 60.0
_PUBLIC_KEY_CACHE_MAX_ENTRIES = 1024


def _cache_put(sig_kid: str, entry: tuple[float, bytes | None]) -> None:
    """Insert into the LRU cache. Caller MUST hold ``_PUBLIC_KEY_CACHE_LOCK``."""
    _PUBLIC_KEY_CACHE[sig_kid] = entry
    _PUBLIC_KEY_CACHE.move_to_end(sig_kid)
    while len(_PUBLIC_KEY_CACHE) > _PUBLIC_KEY_CACHE_MAX_ENTRIES:
        _PUBLIC_KEY_CACHE.popitem(last=False)


_RESOLVER: PublicKeyResolver | None = None
_RESOLVER_LOCK = _Lock()


class PublicKeyResolver(Protocol):
    """Resolve a key_id (``sig_kid``) to raw Ed25519 public key bytes.

    Implementations MUST:

    - Return 32 raw bytes on success.
    - Return ``None`` when the key_id is unknown, revoked, or otherwise
      non-resolvable. Callers treat ``None`` as verification failure.
    - Be safe to call concurrently from any thread.

    Implementations SHOULD:

    - Complete in ≤ 5 seconds (this is on the verification hot path).
    - Not raise. Exceptions are caught and logged, and the result is
      cached as ``None`` for the current TTL window.
    """

    def __call__(self, sig_kid: str) -> bytes | None: ...


def register_public_key_resolver(resolver: PublicKeyResolver) -> None:
    """Register the host platform's public-key resolver.

    Called once at process startup from the host's app-init hook.
    Subsequent calls replace the previous resolver; callers should
    make this idempotent.
    """
    global _RESOLVER
    with _RESOLVER_LOCK:
        _RESOLVER = resolver


def get_public_key(sig_kid: str) -> bytes | None:
    """Resolve a ``sig_kid`` to raw Ed25519 public key bytes (32 bytes).

    Revocation is consulted first: a ``sig_kid`` flagged by the
    registered :class:`~ampro.security.key_revocation.RevocationStore`
    returns ``None`` regardless of cache state, so a compromised key
    stops verifying the moment the host registers the revocation.

    On a revocation-clear path the cache is checked (60s TTL), and on
    cache miss the host-registered :class:`PublicKeyResolver` is called.
    Returns ``None`` when no resolver is registered, the key is unknown,
    or the resolver raises — all of which cause envelope verification
    to reject.
    """
    # Revocation check must precede the cache lookup. A cached key that
    # was fine a second ago can be revoked in the middle of its TTL; we
    # MUST surface that immediately rather than wait for the entry to
    # expire.
    from ampro.security.key_revocation import should_reject_cached_key

    if should_reject_cached_key(sig_kid):
        return None

    now = _time.monotonic()
    with _PUBLIC_KEY_CACHE_LOCK:
        cached = _PUBLIC_KEY_CACHE.get(sig_kid)
        if cached is not None:
            expiry, value = cached
            if now < expiry:
                _PUBLIC_KEY_CACHE.move_to_end(sig_kid)
                return value
            del _PUBLIC_KEY_CACHE[sig_kid]

    with _RESOLVER_LOCK:
        resolver = _RESOLVER

    if resolver is None:
        # No host resolver registered — fail closed. Cache the miss so
        # we do not re-check within the TTL window.
        with _PUBLIC_KEY_CACHE_LOCK:
            _cache_put(sig_kid, (now + _PUBLIC_KEY_CACHE_TTL_SEC, None))
        return None

    try:
        raw = resolver(sig_kid)
    except Exception as exc:
        # Exceptions are TRANSIENT errors (network blip, DB timeout). Do
        # not negatively cache — caching None for the full TTL would let
        # a single flaky resolver call DoS verification for 60s. Return
        # None now; the next call retries the resolver.
        logger.warning("[trust] resolver raised for %s: %s", sig_kid, exc)
        return None

    # Re-check revocation after the resolver call — the host may have
    # revoked the key concurrently with the lookup.
    if raw is not None and should_reject_cached_key(sig_kid):
        with _PUBLIC_KEY_CACHE_LOCK:
            _cache_put(sig_kid, (now + _PUBLIC_KEY_CACHE_TTL_SEC, None))
        return None

    with _PUBLIC_KEY_CACHE_LOCK:
        _cache_put(sig_kid, (now + _PUBLIC_KEY_CACHE_TTL_SEC, raw))
    return raw


def _reset_public_key_cache_for_tests() -> None:
    """Test-only cache reset. Called from fixtures."""
    with _PUBLIC_KEY_CACHE_LOCK:
        _PUBLIC_KEY_CACHE.clear()


def _reset_resolver_for_tests() -> None:
    """Test-only resolver reset. Fixtures that want to verify
    fail-closed behaviour call this before asserting.
    """
    global _RESOLVER
    with _RESOLVER_LOCK:
        _RESOLVER = None
