"""Minimal JOSE helpers for PACT (ES256 / RS256 only).

PyJWT (``pip install 'ampro[pact]'``) is imported lazily so ``import ampro``
never needs it.  Every helper here is deliberately narrow:

* only ``ES256`` and ``RS256`` are ever accepted or produced;
* a JWK must match the algorithm (``EC``/``P-256`` for ES256, ``RSA`` with a
  modulus of at least 2048 bits for RS256) and, when it says so, ``use: sig``;
* claim checks are done by the callers with an injectable clock, so PyJWT is
  used for signatures only.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

ALLOWED_ALGS = ("ES256", "RS256")
MAX_TOKEN_BYTES = 8192


class JoseError(Exception):
    """A token, signature or key failed validation.  Never shown to clients."""


def _jwt() -> Any:
    try:
        import jwt  # noqa: F811
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "PACT needs PyJWT with crypto support: pip install 'ampro[pact]'"
        ) from exc
    return jwt


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or len(data) > MAX_TOKEN_BYTES * 2:
        raise JoseError("bad base64url")
    pad = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except (ValueError, TypeError) as exc:
        raise JoseError("bad base64url") from exc


def sha256_b64url(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return b64url_encode(hashlib.sha256(raw).digest())


def split_compact(token: str) -> tuple[dict[str, Any], dict[str, Any] | bytes, str]:
    """``(header, payload, signing_input)`` of a compact JWS, unverified."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise JoseError("token missing or too large")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise JoseError("not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except ValueError as exc:
        raise JoseError("bad header") from exc
    if not isinstance(header, dict):
        raise JoseError("bad header")
    raw_payload = b64url_decode(parts[1])
    try:
        payload: dict[str, Any] | bytes = json.loads(raw_payload)
    except ValueError:
        payload = raw_payload
    return header, payload, f"{parts[0]}.{parts[1]}"


def check_header_alg(header: dict[str, Any], allowed: tuple[str, ...] = ALLOWED_ALGS) -> str:
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed:
        raise JoseError("algorithm not allowed")
    if "crit" in header or "jku" in header or "x5u" in header or "jwk" in header:
        # Never follow header-supplied keys or unknown critical extensions.
        raise JoseError("unsupported header parameter")
    return alg


def jwk_matches_alg(jwk: dict[str, Any], alg: str) -> bool:
    """Whether *jwk* is a public signing key usable with *alg*."""
    if not isinstance(jwk, dict):
        return False
    if jwk.get("use") not in (None, "sig"):
        return False
    if jwk.get("alg") not in (None, alg):
        return False
    ops = jwk.get("key_ops")
    if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
        return False
    if alg == "ES256":
        return jwk.get("kty") == "EC" and jwk.get("crv") == "P-256"
    if alg == "RS256":
        if jwk.get("kty") != "RSA" or not isinstance(jwk.get("n"), str):
            return False
        try:
            return len(b64url_decode(jwk["n"]).lstrip(b"\x00")) * 8 >= 2048
        except JoseError:
            return False
    return False


def public_key_from_jwk(jwk: dict[str, Any], alg: str) -> Any:
    if not jwk_matches_alg(jwk, alg):
        raise JoseError("key does not match algorithm")
    jwt = _jwt()
    public = {k: v for k, v in jwk.items() if k not in ("d", "p", "q", "dp", "dq", "qi")}
    try:
        return jwt.PyJWK(public, algorithm=alg).key
    except Exception as exc:  # PyJWT raises several types for bad keys
        raise JoseError("unusable key") from exc


def private_key_from_jwk(jwk: dict[str, Any]) -> tuple[Any, str]:
    """``(private_key, alg)`` for an ES256 (P-256) or RS256 private JWK."""
    jwt = _jwt()
    if not isinstance(jwk, dict) or "d" not in jwk:
        raise JoseError("not a private JWK")
    if jwk.get("kty") == "EC":
        if jwk.get("crv") != "P-256":
            raise JoseError("EC keys must be P-256")
        alg = "ES256"
    elif jwk.get("kty") == "RSA":
        alg = "RS256"
    else:
        raise JoseError("unsupported key type")
    if jwk.get("alg") not in (None, alg):
        raise JoseError("JWK alg does not match key type")
    try:
        key = jwt.PyJWK(jwk, algorithm=alg).key
    except Exception as exc:
        raise JoseError("unusable private key") from exc
    if alg == "RS256" and key.key_size < 2048:
        raise JoseError("RSA keys must be at least 2048 bits")
    return key, alg


def public_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    """The public half of a JWK (members per RFC 7517/7518)."""
    if jwk.get("kty") == "EC":
        return {"kty": "EC", "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    if jwk.get("kty") == "RSA":
        return {"kty": "RSA", "n": jwk["n"], "e": jwk["e"]}
    raise JoseError("unsupported key type")


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url)."""
    pub = public_jwk(jwk)
    canonical = json.dumps(pub, sort_keys=True, separators=(",", ":"))
    return sha256_b64url(canonical)


def generate_es256_jwk(kid: str | None = None) -> dict[str, Any]:
    """A fresh P-256 private JWK (with ``kid`` = thumbprint unless given)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers()
    pub = nums.public_numbers

    def enc(i: int) -> str:
        return b64url_encode(i.to_bytes(32, "big"))

    jwk = {"kty": "EC", "crv": "P-256", "x": enc(pub.x), "y": enc(pub.y), "d": enc(nums.private_value)}
    jwk["kid"] = kid or thumbprint(jwk)
    return jwk


def sign_compact(payload: bytes, key: Any, alg: str, headers: dict[str, Any]) -> str:
    """Compact JWS over raw *payload* bytes."""
    jwt = _jwt()
    if alg not in ALLOWED_ALGS:
        raise JoseError("algorithm not allowed")
    hdr = {k: v for k, v in headers.items() if k != "alg"}
    return jwt.api_jws.PyJWS().encode(payload, key, algorithm=alg, headers=hdr)


def sign_jwt(claims: dict[str, Any], key: Any, alg: str, headers: dict[str, Any]) -> str:
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return sign_compact(payload, key, alg, {"typ": "JWT", **headers})


def verify_signature(token: str, key: Any, alg: str) -> bytes:
    """Verify a compact JWS signature; returns the raw payload bytes."""
    jwt = _jwt()
    try:
        return jwt.api_jws.PyJWS().decode(token, key=key, algorithms=[alg])
    except Exception as exc:
        raise JoseError("bad signature") from exc


__all__ = [
    "ALLOWED_ALGS",
    "JoseError",
    "MAX_TOKEN_BYTES",
    "b64url_decode",
    "b64url_encode",
    "check_header_alg",
    "generate_es256_jwk",
    "jwk_matches_alg",
    "private_key_from_jwk",
    "public_jwk",
    "public_key_from_jwk",
    "sha256_b64url",
    "sign_compact",
    "sign_jwt",
    "split_compact",
    "thumbprint",
    "verify_signature",
]
