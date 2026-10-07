"""Tests for DID resolution — did:key verification (C6).

Covers W3C test vectors, unsupported methods, garbage input, JWT wrapper,
and round-trip key extraction. 10 tests per spec Section 5 W2.B.1-10.
"""
from __future__ import annotations

import base64
import json

import pytest

from ampro.trust.resolver import _multibase_decode_ed25519, _resolve_did
from ampro.trust.tiers import TrustTier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_did_key_from_raw_pub(raw_pub_bytes: bytes) -> str:
    """Build a did:key URI from raw 32-byte Ed25519 public key bytes."""
    import base58

    multicodec = bytes([0xED, 0x01]) + raw_pub_bytes
    encoded = base58.b58encode(multicodec).decode()
    return f"did:key:z{encoded}"


def _make_jwt_proof(did: str) -> str:
    """Wrap a DID URI in a JWT-like proof structure (header.payload.signature).

    This helper produces a structurally-valid proof with a placeholder
    signature. It is suitable ONLY for tests that expect EXTERNAL (e.g.,
    forged-signature rejection). Use ``_make_signed_jwt_proof`` for
    tests that expect the proof to verify.
    """
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"did": did}).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"fake-signature-for-test").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


AUDIENCE = "agent://receiver.example.com"


def _make_signed_jwt_proof(private_key, did: str) -> str:
    """Build a JWT-style DID proof with a real Ed25519 signature over header.payload.

    Carries the claims the resolver requires: aud, iat, exp (short-lived)
    and a unique jti.
    """
    import secrets
    import time

    now = int(time.time())
    claims = {"did": did, "aud": AUDIENCE, "iat": now, "exp": now + 60,
              "jti": secrets.token_hex(8)}
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    signing_input = f"{header}.{payload}".encode("ascii")
    sig_bytes = private_key.sign(signing_input)
    sig = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


# ---------------------------------------------------------------------------
# W3C test vector — the canonical example from the did:key spec
# did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
# This encodes a well-known Ed25519 public key.
# ---------------------------------------------------------------------------

W3C_DID_KEY = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
W3C_METHOD_SPECIFIC = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_w3c_vector_raw_uri_returns_external():
    """W2.B.1 (v0.3.4 hardening) — A raw did:key URI carries no proof of
    key possession. The resolver returns EXTERNAL until a signed JWT-style
    proof is supplied. Previously this returned VERIFIED, which let any
    attacker present any public DID and be trusted."""
    result = await _resolve_did(W3C_DID_KEY)
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_w3c_vector_extracts_32_byte_key():
    """W2.B.2 — W3C test vector decodes to exactly 32 bytes."""
    pub_bytes = _multibase_decode_ed25519(W3C_METHOD_SPECIFIC)
    assert len(pub_bytes) == 32
    assert isinstance(pub_bytes, bytes)


@pytest.mark.asyncio
async def test_did_web_returns_external():
    """W2.B.3 — did:web is unsupported and returns EXTERNAL."""
    result = await _resolve_did("did:web:example.com")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_did_ion_returns_external():
    """W2.B.4 — did:ion (unsupported method) returns EXTERNAL."""
    result = await _resolve_did("did:ion:EiDJe_something_long")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_garbage_input_returns_external():
    """W2.B.5 — Non-DID garbage input returns EXTERNAL."""
    result = await _resolve_did("not-a-did-at-all")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_empty_string_returns_external():
    """W2.B.6 — Empty string returns EXTERNAL."""
    result = await _resolve_did("")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_invalid_multibase_prefix_returns_external():
    """W2.B.7 — did:key with wrong multibase prefix (not 'z') returns EXTERNAL."""
    # Use 'f' prefix (hex) instead of 'z' (base58btc)
    result = await _resolve_did("did:key:f68656c6c6f")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_wrong_multicodec_prefix_returns_external():
    """W2.B.8 — did:key with valid base58btc but wrong multicodec (not Ed25519) returns EXTERNAL."""
    import base58

    # Use P-256 multicodec prefix (0x8024) instead of Ed25519 (0xed01)
    fake_key = bytes([0x80, 0x24]) + b"\x00" * 32
    encoded = base58.b58encode(fake_key).decode()
    result = await _resolve_did(f"did:key:z{encoded}")
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_jwt_wrapped_did_key_returns_verified():
    """W2.B.9 — DID key wrapped in JWT proof with VALID signature returns VERIFIED.

    The signature must verify under the did:key's embedded public key, and
    the proof must be fresh, addressed to this agent and bound to the sender.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    did = _make_did_key_from_raw_pub(raw_pub)
    jwt_proof = _make_signed_jwt_proof(priv, did)
    result = await _resolve_did(jwt_proof, audience=AUDIENCE, sender=did)
    assert result == TrustTier.VERIFIED


@pytest.mark.asyncio
async def test_did_proof_forged_signature_rejected():
    """Forged/garbage signature on a did:key JWT proof must NOT verify."""
    jwt_proof = _make_jwt_proof(W3C_DID_KEY)  # uses a fake signature
    result = await _resolve_did(jwt_proof)
    assert result == TrustTier.EXTERNAL


@pytest.mark.asyncio
async def test_round_trip_key_extraction():
    """W2.B.10 — Round-trip: generate did:key from raw bytes, then decode back and compare."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw_pub = pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    assert len(raw_pub) == 32

    # Encode as did:key
    did = _make_did_key_from_raw_pub(raw_pub)
    assert did.startswith("did:key:z")

    # Decode back
    method_specific = did[len("did:key:"):]
    recovered = _multibase_decode_ed25519(method_specific)
    assert recovered == raw_pub

    # Resolve trust — raw DID URI returns EXTERNAL (no proof). To get
    # VERIFIED the caller must supply a signed JWT-style DID proof.
    result = await _resolve_did(did)
    assert result == TrustTier.EXTERNAL
