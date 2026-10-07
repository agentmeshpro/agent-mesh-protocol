"""RFC 9421 request signing for the conformance suite (WIRE-BINDING 12.15).

The suite signs with its own small signer so it can also produce the
deliberately broken signatures the negative checks need (stale ``created``,
no nonce, wrong ``alg``).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.security.rfc9421 import create_signature_base


def load_signing_key(value: str) -> bytes:
    """Load a raw 32-byte Ed25519 seed.

    *value* is a path to a file, or the key itself.  Accepted encodings:
    PEM (PKCS#8), 64 hex characters, or base64 / base64url of 32 bytes.
    """
    path = Path(value)
    try:
        is_file = path.is_file()
    except OSError:
        is_file = False
    text = path.read_text(encoding="utf-8").strip() if is_file else value.strip()
    if text.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(text.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PEM key is not an Ed25519 private key")
        return key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signing key is not hex, base64 or PEM") from exc
    if len(raw) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(raw)}")
    return raw


def content_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


@dataclass
class Signer:
    seed: bytes
    keyid: str

    def sign(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        created: int | None = None,
        nonce: str | None = "auto",
        alg: str = "ed25519",
        seed: bytes | None = None,
        keyid: str | None = None,
    ) -> dict[str, str]:
        """Return ``headers`` plus Content-Digest, Signature-Input and Signature."""
        out = dict(headers)
        covered = ["@method", "@target-uri", "@authority"]
        if body:
            out["Content-Digest"] = content_digest(body)
            covered.append("content-digest")
        if any(k.lower() == "content-type" for k in out):
            covered.append("content-type")
        created = int(time.time()) if created is None else created
        if nonce == "auto":
            nonce = "conf-" + secrets.token_hex(12)
        kid = keyid or self.keyid
        base = create_signature_base(
            method, url, out, covered, created=created, keyid=kid, nonce=nonce,
        )
        if alg != "ed25519":
            base = base.replace('alg="ed25519"', f'alg="{alg}"')
        key = Ed25519PrivateKey.from_private_bytes(seed or self.seed)
        sig = base64.b64encode(key.sign(base.encode("utf-8"))).decode()
        comps = " ".join(f'"{c}"' for c in covered)
        sig_input = f'sig1=({comps});created={created};keyid="{kid}";alg="{alg}"'
        if nonce is not None:
            sig_input += f';nonce="{nonce}"'
        out["Signature-Input"] = sig_input
        out["Signature"] = f"sig1=:{sig}:"
        return out
