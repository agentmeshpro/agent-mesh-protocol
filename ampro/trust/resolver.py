"""
Agent Protocol — Multi-Method Trust Resolver.

Resolves trust tier from Authorization header using:
  1. Same organization → INTERNAL
  2. Bearer JWT with EdDSA + owner scope → OWNER
  3. Bearer JWT with EdDSA → VERIFIED
  4. DID proof → VERIFIED (not yet implemented)
  5. API key in allowlist → VERIFIED
  6. mTLS → VERIFIED
  7. Everything else → EXTERNAL
"""

from __future__ import annotations

import base64
import json
import logging

from ampro.identity.auth_methods import AuthMethod, parse_authorization
from ampro.transport.api_key_store import ApiKeyStore
from ampro.trust.tiers import TrustTier

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


_api_key_store = ApiKeyStore(max_failures=10, block_seconds=900)


async def resolve_trust_tier(
    authorization: str | None,
    caller_org_id: str | None,
    target_org_id: str | None,
    client_ip: str | None = None,
) -> TrustTier:
    # Intentional: same org_id → INTERNAL trust. This is by design —
    # agents within the same organization skip external auth checks.
    # The org_id values are server-side derived, not user-supplied.
    if caller_org_id and target_org_id and caller_org_id == target_org_id:
        return TrustTier.INTERNAL

    parsed = parse_authorization(authorization)

    if parsed.method == AuthMethod.JWT:
        return await _resolve_jwt(parsed.token, caller_org_id, target_org_id)

    if parsed.method == AuthMethod.DID:
        return await _resolve_did(parsed.token)

    if parsed.method == AuthMethod.API_KEY:
        return _resolve_api_key(parsed.token, client_ip)

    if parsed.method == AuthMethod.MTLS:
        return TrustTier.VERIFIED

    return TrustTier.EXTERNAL


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


async def _resolve_did(token: str) -> TrustTier:
    """Resolve a DID to a trust tier.

    Only ``did:key:`` is supported in v1 (P0.C1). All other methods
    return EXTERNAL. The token can be either:

    1. A raw DID URI (e.g., ``did:key:z6Mk...``) — parsed directly.
    2. A JWT-like DID proof (``header.payload.signature``) — the ``did``
       field is extracted from the base64-decoded payload and the
       signature MUST verify under the did:key's embedded Ed25519
       public key. If verification fails or the algorithm is not
       EdDSA, EXTERNAL is returned.

    Returns VERIFIED if the DID is a valid did:key with parseable
    Ed25519 public key bytes (and a verified signature for JWT-style
    proofs); EXTERNAL otherwise.
    """
    # Determine the DID URI from the token format.
    did: str = ""
    is_jwt_proof: bool = False
    header_b64: str = ""
    payload_b64_raw: str = ""
    signature_b64: str = ""
    header_payload_signing_input: bytes = b""
    if token.startswith("did:"):
        # A raw DID URI carries no proof of key possession. Anyone can paste a
        # public DID. Reject — VERIFIED requires a signed JWT-style proof.
        logger.warning(
            "[trust] raw DID URI without proof — returning EXTERNAL (caller must "
            "supply a signed header.payload.signature proof for VERIFIED)"
        )
        return TrustTier.EXTERNAL
    elif "." in token:
        # JWT-like DID proof: base64(header).base64(payload).signature
        try:
            import base64
            import json

            parts = token.split(".")
            if len(parts) != 3:
                logger.debug("DID proof must be header.payload.signature")
                return TrustTier.EXTERNAL

            header_b64 = parts[0]
            payload_b64_raw = parts[1]
            signature_b64 = parts[2]
            is_jwt_proof = True
            # Signing input for JWS is "<header_b64>.<payload_b64>" (raw, no padding)
            header_payload_signing_input = f"{header_b64}.{payload_b64_raw}".encode("ascii")

            if len(payload_b64_raw) > 10000:
                logger.warning(
                    "DID proof payload too large (%d bytes)", len(payload_b64_raw),
                )
                return TrustTier.EXTERNAL

            # Decode payload
            payload_b64 = payload_b64_raw
            remainder = len(payload_b64) % 4
            if remainder:
                payload_b64 += "=" * (4 - remainder)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)

            did = payload.get("did", "")
            if not did:
                logger.debug("DID proof missing 'did' field")
                return TrustTier.EXTERNAL

            # Decode header, enforce EdDSA alg
            header_b64_padded = header_b64
            remainder = len(header_b64_padded) % 4
            if remainder:
                header_b64_padded += "=" * (4 - remainder)
            header_json = base64.urlsafe_b64decode(header_b64_padded)
            header = json.loads(header_json)
            alg = header.get("alg")
            if alg != "EdDSA":
                logger.warning(
                    "[trust] DID proof algorithm must be EdDSA, got %r — returning EXTERNAL",
                    alg,
                )
                return TrustTier.EXTERNAL
        except Exception as exc:
            logger.debug("DID proof parsing failed: %s", exc)
            return TrustTier.EXTERNAL
    else:
        logger.debug("DID token unrecognizable: %s", token[:40])
        return TrustTier.EXTERNAL

    # --- DID method dispatch ---
    if not did.startswith("did:key:"):
        logger.info(
            "[trust] DID method not supported: %s — returning EXTERNAL",
            did.split(":", 2)[1] if ":" in did else "unknown",
        )
        return TrustTier.EXTERNAL

    method_specific = did[len("did:key:"):]
    try:
        public_key_bytes = _multibase_decode_ed25519(method_specific)
    except (ValueError, KeyError) as exc:
        logger.warning("[trust] Invalid did:key encoding: %s", exc)
        return TrustTier.EXTERNAL

    if len(public_key_bytes) != 32:
        logger.warning(
            "[trust] did:key public key wrong length: %d bytes (expected 32)",
            len(public_key_bytes),
        )
        return TrustTier.EXTERNAL

    # For JWT-style DID proofs, verify the Ed25519 signature against the
    # embedded did:key public key. Raw DID URIs have no signature to check.
    if is_jwt_proof:
        try:
            import base64

            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            sig_padded = signature_b64
            remainder = len(sig_padded) % 4
            if remainder:
                sig_padded += "=" * (4 - remainder)
            sig_bytes = base64.urlsafe_b64decode(sig_padded)

            pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub_key.verify(sig_bytes, header_payload_signing_input)
        except InvalidSignature:
            logger.warning(
                "[trust] DID proof signature invalid for %s — returning EXTERNAL",
                did,
            )
            return TrustTier.EXTERNAL
        except Exception as exc:
            logger.warning(
                "[trust] DID proof signature verification error: %s — returning EXTERNAL",
                exc,
            )
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


def _resolve_api_key(key: str, client_ip: str | None = None) -> TrustTier:
    if client_ip and _api_key_store.is_blocked(client_ip):
        logger.warning("API key auth blocked for IP %s (brute force)", client_ip)
        return TrustTier.EXTERNAL

    agent_id = _api_key_store.validate(key)
    if agent_id is not None:
        if client_ip:
            _api_key_store.reset_failures(client_ip)
        return TrustTier.VERIFIED

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
# Cache: a 60s TTL window keyed by ``sig_kid``. The cache uses
# ``time.monotonic()`` to prevent clock-manipulation attacks and a
# lock to serialise concurrent reads/writes.
# ---------------------------------------------------------------------------

import time as _time
from threading import Lock as _Lock
from typing import Protocol

_PUBLIC_KEY_CACHE: dict[str, tuple[float, bytes | None]] = {}
_PUBLIC_KEY_CACHE_LOCK = _Lock()
_PUBLIC_KEY_CACHE_TTL_SEC = 60.0

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
                return value

    with _RESOLVER_LOCK:
        resolver = _RESOLVER

    if resolver is None:
        # No host resolver registered — fail closed. Cache the miss so
        # we do not re-check within the TTL window.
        with _PUBLIC_KEY_CACHE_LOCK:
            _PUBLIC_KEY_CACHE[sig_kid] = (now + _PUBLIC_KEY_CACHE_TTL_SEC, None)
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
            _PUBLIC_KEY_CACHE[sig_kid] = (now + _PUBLIC_KEY_CACHE_TTL_SEC, None)
        return None

    with _PUBLIC_KEY_CACHE_LOCK:
        _PUBLIC_KEY_CACHE[sig_kid] = (now + _PUBLIC_KEY_CACHE_TTL_SEC, raw)
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
