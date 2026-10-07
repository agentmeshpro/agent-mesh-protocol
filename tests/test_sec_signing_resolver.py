"""Regression tests for trust-resolver / revocation / cross-verification hardening.

Covers:
  * did:key proofs require exp/iat (bounded lifetime), aud == this agent,
    a DID bound to the sender, and a single-use jti;
  * revocation store errors fail closed;
  * the public-key cache is bounded (LRU);
  * API keys are registrable (hashed at rest) and mTLS is reachable via an
    explicit transport-supplied client-cert identity;
  * cross_verify_identifiers verifies did:key identifiers.
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from collections.abc import Generator
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.trust import resolver
from ampro.trust.resolver import _resolve_did, resolve_trust_tier
from ampro.trust.tiers import TrustTier

AUD = "agent://me.example.com"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _did_for(priv: Ed25519PrivateKey) -> str:
    import base58

    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return "did:key:z" + base58.b58encode(bytes([0xED, 0x01]) + raw).decode()


def _proof(priv: Ed25519PrivateKey, **overrides: Any) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "did": _did_for(priv),
        "aud": AUD,
        "iat": now,
        "exp": now + 120,
        "jti": secrets.token_hex(8),
    }
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    header = _b64(json.dumps({"alg": "EdDSA"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = _b64(priv.sign(f"{header}.{body}".encode()))
    return f"{header}.{body}.{sig}"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# DID proof claims
# ---------------------------------------------------------------------------


class TestDidProofClaims:
    def test_valid_bound_proof_verified(self) -> None:
        priv = Ed25519PrivateKey.generate()
        did = _did_for(priv)
        assert _run(_resolve_did(_proof(priv), audience=AUD, sender=did)) == TrustTier.VERIFIED
        # agent://did:... form of the sender is accepted too.
        assert _run(_resolve_did(_proof(priv), audience=AUD,
                                 sender=f"agent://{did}")) == TrustTier.VERIFIED

    def test_bare_self_signed_proof_rejected(self) -> None:
        """The pre-fix proof shape (only ``did``) must no longer be VERIFIED."""
        priv = Ed25519PrivateKey.generate()
        tok = _proof(priv, aud=None, iat=None, exp=None, jti=None)
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_missing_exp_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        assert _run(_resolve_did(_proof(priv, exp=None), audience=AUD,
                                 sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_expired_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        now = int(time.time())
        tok = _proof(priv, iat=now - 400, exp=now - 200)
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_excessive_lifetime_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        now = int(time.time())
        tok = _proof(priv, iat=now, exp=now + 86400)
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_future_iat_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        now = int(time.time())
        tok = _proof(priv, iat=now + 600, exp=now + 700)
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_wrong_audience_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        tok = _proof(priv, aud="agent://someone-else.example.com")
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_audience_list_accepted(self) -> None:
        priv = Ed25519PrivateKey.generate()
        tok = _proof(priv, aud=["agent://x", AUD])
        assert _run(_resolve_did(tok, audience=AUD, sender=_did_for(priv))) == TrustTier.VERIFIED

    def test_no_audience_configured_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        assert _run(_resolve_did(_proof(priv), sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_sender_mismatch_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        other = _did_for(Ed25519PrivateKey.generate())
        assert _run(_resolve_did(_proof(priv), audience=AUD, sender=other)) == TrustTier.EXTERNAL

    def test_missing_sender_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        assert _run(_resolve_did(_proof(priv), audience=AUD)) == TrustTier.EXTERNAL

    def test_non_did_sender_requires_link(self) -> None:
        priv = Ed25519PrivateKey.generate()
        did = _did_for(priv)
        sender = "agent://alice.example.com"
        assert _run(_resolve_did(_proof(priv), audience=AUD, sender=sender)) == TrustTier.EXTERNAL
        assert _run(_resolve_did(_proof(priv), audience=AUD, sender=sender,
                                 linked_dids=[did])) == TrustTier.VERIFIED

    def test_replayed_jti_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        did = _did_for(priv)
        tok = _proof(priv)
        assert _run(_resolve_did(tok, audience=AUD, sender=did)) == TrustTier.VERIFIED
        assert _run(_resolve_did(tok, audience=AUD, sender=did)) == TrustTier.EXTERNAL

    def test_missing_jti_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        assert _run(_resolve_did(_proof(priv, jti=None), audience=AUD,
                                 sender=_did_for(priv))) == TrustTier.EXTERNAL

    def test_resolve_trust_tier_threads_context(self) -> None:
        priv = Ed25519PrivateKey.generate()
        did = _did_for(priv)
        tier = _run(resolve_trust_tier(
            f"DID {_proof(priv)}", None, None, audience=AUD, sender_id=did,
        ))
        assert tier == TrustTier.VERIFIED
        # Without the receiver context the proof cannot be bound -> EXTERNAL.
        assert _run(resolve_trust_tier(f"DID {_proof(priv)}", None, None)) == TrustTier.EXTERNAL


# ---------------------------------------------------------------------------
# Revocation fail-closed
# ---------------------------------------------------------------------------


@pytest.fixture
def _clean_resolver() -> Generator[None, None, None]:
    from ampro.security.key_revocation import (
        AllowAllRevocationStore,
        register_revocation_store,
    )

    resolver._reset_public_key_cache_for_tests()
    resolver._reset_resolver_for_tests()
    register_revocation_store(AllowAllRevocationStore())
    yield
    resolver._reset_public_key_cache_for_tests()
    resolver._reset_resolver_for_tests()
    register_revocation_store(AllowAllRevocationStore())


@pytest.mark.usefixtures("_clean_resolver")
class TestRevocationFailClosed:
    def test_store_error_treated_as_revoked(self) -> None:
        from ampro.security.key_revocation import (
            register_revocation_store,
            revocation_verify_cached_key,
            should_reject_cached_key,
        )

        class Broken:
            def is_revoked(self, key_id: str) -> bool:
                raise ConnectionError("kv down")

        register_revocation_store(Broken())
        assert should_reject_cached_key("k") is True
        assert revocation_verify_cached_key("k") is False

    def test_store_error_blocks_public_key(self) -> None:
        from ampro.security.key_revocation import register_revocation_store

        class Broken:
            def is_revoked(self, key_id: str) -> bool:
                raise RuntimeError("boom")

        resolver.register_public_key_resolver(lambda kid: b"\x01" * 32)
        register_revocation_store(Broken())
        assert resolver.get_public_key("k") is None


# ---------------------------------------------------------------------------
# Bounded public-key cache
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_clean_resolver")
class TestPublicKeyCacheBounded:
    def test_cache_is_bounded(self) -> None:
        resolver.register_public_key_resolver(lambda kid: None)
        for i in range(resolver._PUBLIC_KEY_CACHE_MAX_ENTRIES + 500):
            resolver.get_public_key(f"attacker-kid-{i}")
        assert len(resolver._PUBLIC_KEY_CACHE) == resolver._PUBLIC_KEY_CACHE_MAX_ENTRIES

    def test_lru_keeps_recently_used(self) -> None:
        calls: list[str] = []

        def res(kid: str) -> bytes:
            calls.append(kid)
            return b"\x02" * 32

        resolver.register_public_key_resolver(res)
        resolver.get_public_key("hot")
        for i in range(resolver._PUBLIC_KEY_CACHE_MAX_ENTRIES - 1):
            resolver.get_public_key(f"k{i}")
            if i % 100 == 0:
                resolver.get_public_key("hot")
        resolver.get_public_key("overflow")
        calls.clear()
        resolver.get_public_key("hot")
        assert calls == [], "recently used entry must survive eviction"


# ---------------------------------------------------------------------------
# API keys + mTLS
# ---------------------------------------------------------------------------


@pytest.fixture
def _clean_api_keys() -> Generator[None, None, None]:
    resolver._reset_api_keys_for_tests()
    yield
    resolver._reset_api_keys_for_tests()


@pytest.mark.usefixtures("_clean_api_keys")
class TestApiKeyAuth:
    def test_registered_key_verifies(self) -> None:
        resolver.register_api_key("s3cret-key", "agent://bob.example.com")
        assert _run(resolve_trust_tier("ApiKey s3cret-key", None, None)) == TrustTier.VERIFIED

    def test_unknown_key_external(self) -> None:
        resolver.register_api_key("s3cret-key", "agent://bob.example.com")
        assert _run(resolve_trust_tier("ApiKey nope", None, None)) == TrustTier.EXTERNAL

    def test_plaintext_not_stored(self) -> None:
        resolver.register_api_key("plaintext-should-not-appear", "agent://bob")
        assert "plaintext-should-not-appear" not in repr(resolver._API_KEYS)

    def test_unregister(self) -> None:
        resolver.register_api_key("k-1", "agent://bob")
        resolver.unregister_api_key("k-1")
        assert _run(resolve_trust_tier("ApiKey k-1", None, None)) == TrustTier.EXTERNAL

    def test_tier_above_verified_refused(self) -> None:
        with pytest.raises(ValueError):
            resolver.register_api_key("k-2", "agent://bob", TrustTier.INTERNAL)

    def test_injected_store(self) -> None:
        class Store:
            def validate(self, key: str) -> str | None:
                return "agent://carol" if key == "from-store" else None

        resolver.register_api_key_store(Store())
        assert _run(resolve_trust_tier("ApiKey from-store", None, None)) == TrustTier.VERIFIED
        assert _run(resolve_trust_tier("ApiKey other", None, None)) == TrustTier.EXTERNAL

    def test_brute_force_still_blocks(self) -> None:
        resolver.register_api_key("good", "agent://bob")
        for _ in range(10):
            _run(resolve_trust_tier("ApiKey bad", None, None, client_ip="9.9.9.9"))
        assert _run(resolve_trust_tier("ApiKey good", None, None,
                                       client_ip="9.9.9.9")) == TrustTier.EXTERNAL


class TestMtls:
    def test_client_cert_identity_yields_verified(self) -> None:
        tier = _run(resolve_trust_tier(None, None, None,
                                       client_cert_identity="agent://bob.example.com"))
        assert tier == TrustTier.VERIFIED

    def test_no_cert_identity_external(self) -> None:
        assert _run(resolve_trust_tier(None, None, None)) == TrustTier.EXTERNAL
        assert _run(resolve_trust_tier(None, None, None, client_cert_identity="")) == TrustTier.EXTERNAL


# ---------------------------------------------------------------------------
# Cross-verification did:key
# ---------------------------------------------------------------------------


class TestCrossVerifyDidKey:
    def _pub(self, priv: Ed25519PrivateKey) -> bytes:
        return priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def test_matching_key_verified(self) -> None:
        from ampro import cross_verify_identifiers

        priv = Ed25519PrivateKey.generate()
        expected = base64.b64encode(self._pub(priv)).decode()
        res = _run(cross_verify_identifiers(
            [f"agent://{_did_for(priv)}"], "https://e/x", expected_public_key=expected,
        ))
        assert res[0].verified is True

    def test_urlsafe_unpadded_key_accepted(self) -> None:
        from ampro import cross_verify_identifiers

        priv = Ed25519PrivateKey.generate()
        res = _run(cross_verify_identifiers(
            [f"agent://{_did_for(priv)}"], "https://e/x",
            expected_public_key=_b64(self._pub(priv)),
        ))
        assert res[0].verified is True

    def test_mismatched_key_rejected(self) -> None:
        from ampro import cross_verify_identifiers

        priv = Ed25519PrivateKey.generate()
        other = base64.b64encode(self._pub(Ed25519PrivateKey.generate())).decode()
        res = _run(cross_verify_identifiers(
            [f"agent://{_did_for(priv)}"], "https://e/x", expected_public_key=other,
        ))
        assert res[0].verified is False
        assert "mismatch" in res[0].reason.lower()

    def test_no_expected_key_rejected(self) -> None:
        from ampro import cross_verify_identifiers

        priv = Ed25519PrivateKey.generate()
        res = _run(cross_verify_identifiers([f"agent://{_did_for(priv)}"], "https://e/x"))
        assert res[0].verified is False

    def test_invalid_did_key_rejected(self) -> None:
        from ampro import cross_verify_identifiers

        res = _run(cross_verify_identifiers(["agent://did:key:z6MkTest"], "https://e/x",
                                            expected_public_key="AAAA"))
        assert res[0].verified is False
        assert "invalid did:key" in res[0].reason.lower()
