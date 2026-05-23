"""Replay-protection and revocation-wiring tests for the security path.

These tests exercise two hardening invariants added after the 0.3.1 audit:

1. RFC 9421 signatures must be rejected when the ``created`` timestamp is
   outside a bounded freshness window. Without this, a captured request
   can be replayed indefinitely.

2. When a caller supplies a :class:`NonceTracker`, signatures that reuse
   a ``nonce`` parameter must be rejected on the second use.

3. :func:`ampro.trust.resolver.get_public_key` must consult the
   registered :class:`RevocationStore` before returning bytes, both on
   cache miss and on cache hit. A revoked key must not verify regardless
   of cache state.
"""
from __future__ import annotations

import time
from collections.abc import Generator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def _sign_at(
    priv_bytes: bytes,
    when: float,
    url: str = "https://a.example.com/x",
    *,
    nonce: str | None = None,
) -> dict[str, str]:
    """Produce signature headers with ``created`` frozen to *when*.

    Always emits a fresh nonce by default so that the module-level default
    replay tracker (added in the v0.3.4 hardening) does not falsely reject
    signatures across consecutive test cases.
    """
    import secrets
    from unittest.mock import patch

    from ampro.security.rfc9421 import sign_request

    nonce = nonce or secrets.token_hex(16)
    with patch("ampro.security.rfc9421.time.time", return_value=when):
        headers: dict[str, str] = {"content-type": "application/json"}
        sig_headers = sign_request(
            priv_bytes, "test-key", "POST", url, headers, body=b"{}", nonce=nonce,
        )
    headers.update(sig_headers)
    return headers


# ---------------------------------------------------------------------------
# Freshness window
# ---------------------------------------------------------------------------


class TestSignatureFreshnessWindow:
    """A verified signature must have a recent ``created`` timestamp."""

    def test_fresh_signature_verifies(self) -> None:
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time())
        ok = verify_request(
            pub, "POST", "https://a.example.com/x", headers, body=b"{}"
        )
        assert ok is True

    def test_stale_signature_rejected_by_default(self) -> None:
        """A 2-hour-old signature must not verify under default freshness."""
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time() - 7200)
        ok = verify_request(
            pub, "POST", "https://a.example.com/x", headers, body=b"{}"
        )
        assert ok is False, "stale signature must not verify"

    def test_future_signature_rejected(self) -> None:
        """A ``created`` 2h in the future must not verify — possible clock attack."""
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time() + 7200)
        ok = verify_request(
            pub, "POST", "https://a.example.com/x", headers, body=b"{}"
        )
        assert ok is False

    def test_signature_inside_window_verifies(self) -> None:
        """A 60-second-old signature must verify with default 300s window."""
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time() - 60)
        ok = verify_request(
            pub, "POST", "https://a.example.com/x", headers, body=b"{}"
        )
        assert ok is True

    def test_custom_max_age_tightens_window(self) -> None:
        """Callers can narrow the default 300s freshness window."""
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time() - 120)
        ok = verify_request(
            pub,
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            max_age_seconds=60,
        )
        assert ok is False

    def test_disable_freshness_check(self) -> None:
        """``max_age_seconds=None`` opts out — for test fixtures only."""
        from ampro.security.rfc9421 import verify_request

        priv, pub = _keypair()
        headers = _sign_at(priv, time.time() - 86400)
        ok = verify_request(
            pub,
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            max_age_seconds=None,
        )
        assert ok is True


# ---------------------------------------------------------------------------
# Nonce replay guard
# ---------------------------------------------------------------------------


class TestNonceReplay:
    """When a NonceTracker is supplied, reused nonces must be rejected."""

    def test_first_use_accepted(self) -> None:
        from ampro.security.nonce_tracker import NonceTracker
        from ampro.security.rfc9421 import sign_request, verify_request

        priv, pub = _keypair()
        tracker = NonceTracker()
        headers = {"content-type": "application/json"}
        sig = sign_request(
            priv,
            "test-key",
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            nonce="unique-nonce-1",
        )
        headers.update(sig)
        ok = verify_request(
            pub,
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            nonce_tracker=tracker,
        )
        assert ok is True

    def test_replayed_nonce_rejected(self) -> None:
        from ampro.security.nonce_tracker import NonceTracker
        from ampro.security.rfc9421 import sign_request, verify_request

        priv, pub = _keypair()
        tracker = NonceTracker()
        headers = {"content-type": "application/json"}
        sig = sign_request(
            priv,
            "test-key",
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            nonce="unique-nonce-2",
        )
        headers.update(sig)

        first = verify_request(
            pub, "POST", "https://a.example.com/x", dict(headers),
            body=b"{}", nonce_tracker=tracker,
        )
        second = verify_request(
            pub, "POST", "https://a.example.com/x", dict(headers),
            body=b"{}", nonce_tracker=tracker,
        )
        assert first is True
        assert second is False, "replayed nonce must be rejected"

    def test_tracker_requires_nonce_in_signature(self) -> None:
        """If a tracker is supplied but the signature carries no nonce, reject."""
        from ampro.security.nonce_tracker import NonceTracker
        from ampro.security.rfc9421 import sign_request, verify_request

        priv, pub = _keypair()
        tracker = NonceTracker()
        headers = {"content-type": "application/json"}
        sig = sign_request(
            priv, "test-key", "POST", "https://a.example.com/x", headers, body=b"{}"
        )
        headers.update(sig)
        ok = verify_request(
            pub,
            "POST",
            "https://a.example.com/x",
            headers,
            body=b"{}",
            nonce_tracker=tracker,
        )
        assert ok is False


# ---------------------------------------------------------------------------
# Revocation wiring in resolver
# ---------------------------------------------------------------------------


class TestRevocationWiredIntoResolver:
    """``get_public_key`` must consult the revocation store before returning bytes."""

    @pytest.fixture(autouse=True)
    def _reset(self) -> Generator[None, None, None]:
        from ampro.security.key_revocation import (
            AllowAllRevocationStore as _NoOpRevocationStore,
            register_revocation_store,
        )
        from ampro.trust.resolver import (
            _reset_public_key_cache_for_tests,
            _reset_resolver_for_tests,
        )

        _reset_public_key_cache_for_tests()
        _reset_resolver_for_tests()
        register_revocation_store(_NoOpRevocationStore())
        yield
        _reset_public_key_cache_for_tests()
        _reset_resolver_for_tests()
        register_revocation_store(_NoOpRevocationStore())

    def test_revoked_key_not_returned_on_cold_lookup(self) -> None:
        from ampro.security.key_revocation import register_revocation_store
        from ampro.trust.resolver import (
            get_public_key,
            register_public_key_resolver,
        )

        fake_key = b"\x01" * 32

        def resolver(sig_kid: str):
            return fake_key

        class RevokeAll:
            def is_revoked(self, key_id: str) -> bool:
                return True

        register_public_key_resolver(resolver)
        register_revocation_store(RevokeAll())

        assert get_public_key("leaked") is None

    def test_revoked_key_not_returned_from_cache(self) -> None:
        """A previously-cached key that is later revoked must stop resolving."""
        from ampro.security.key_revocation import register_revocation_store
        from ampro.trust.resolver import (
            get_public_key,
            register_public_key_resolver,
        )

        fake_key = b"\x02" * 32

        def resolver(sig_kid: str):
            return fake_key

        class ToggleableStore:
            def __init__(self) -> None:
                self.revoked = False

            def is_revoked(self, key_id: str) -> bool:
                return self.revoked

        store = ToggleableStore()
        register_public_key_resolver(resolver)
        register_revocation_store(store)

        assert get_public_key("rotating") == fake_key
        store.revoked = True
        assert get_public_key("rotating") is None, (
            "cached key must be rejected once revoked"
        )

    def test_unrevoked_key_still_resolves(self) -> None:
        from ampro.trust.resolver import (
            get_public_key,
            register_public_key_resolver,
        )

        fake_key = b"\x03" * 32

        def resolver(sig_kid: str):
            return fake_key

        register_public_key_resolver(resolver)
        assert get_public_key("fine") == fake_key
