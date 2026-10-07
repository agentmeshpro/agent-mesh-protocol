"""Provider signing keys (delegation tokens, receipts — PACT §5.4, §5.6).

A :class:`ProviderKeySet` holds one **active** private key (used to sign)
plus any number of older keys kept for verification while tokens they
signed are still live.  All public keys are published in the JWKS at the
authorization server's ``jwks_uri``, each with its ``kid``.

Rotation: add the new key as active, keep the old one as *retired* for at
least the access-token lifetime (1 h), then drop it.

Loading::

    ProviderKeySet.from_env()            # PACT_PROVIDER_JWKS / PACT_PROVIDER_JWKS_FILE
    ProviderKeySet.from_jwks({"keys": [active_private_jwk, retired_private_jwk]})
    ProviderKeySet.generate()            # ephemeral, development only

The first key in a JWKS document is the active one.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from ampro.interop.pact._jwt import (
    JoseError,
    check_header_alg,
    generate_es256_jwk,
    private_key_from_jwk,
    public_jwk,
    sign_compact,
    split_compact,
    thumbprint,
    verify_signature,
)

logger = logging.getLogger("ampro.interop.pact.keys")

ENV_JWKS = "PACT_PROVIDER_JWKS"
ENV_JWKS_FILE = "PACT_PROVIDER_JWKS_FILE"


@dataclass(frozen=True)
class _Key:
    kid: str
    alg: str
    private: Any
    public: Any
    public_jwk: dict[str, Any]


class ProviderKeySet:
    def __init__(self, private_jwks: list[dict[str, Any]]) -> None:
        if not private_jwks:
            raise ValueError("at least one signing key is required")
        self._keys: list[_Key] = []
        seen: set[str] = set()
        for jwk in private_jwks:
            key, alg = private_key_from_jwk(jwk)
            kid = jwk.get("kid") or thumbprint(jwk)
            if not isinstance(kid, str) or kid in seen:
                raise ValueError("signing keys need unique string kids")
            seen.add(kid)
            pub = {**public_jwk(jwk), "kid": kid, "alg": alg, "use": "sig"}
            self._keys.append(_Key(kid, alg, key, key.public_key(), pub))

    # -- loading --------------------------------------------------------

    @classmethod
    def from_jwks(cls, doc: dict[str, Any] | str) -> ProviderKeySet:
        if isinstance(doc, str):
            doc = json.loads(doc)
        if isinstance(doc, dict) and "keys" in doc:
            return cls(list(doc["keys"]))
        if isinstance(doc, dict):
            return cls([doc])
        raise ValueError("expected a JWK or a JWKS")

    @classmethod
    def from_file(cls, path: str) -> ProviderKeySet:
        with open(path, encoding="utf-8") as fh:
            return cls.from_jwks(fh.read())

    @classmethod
    def from_env(cls, *, allow_generate: bool = False) -> ProviderKeySet:
        """Load from ``PACT_PROVIDER_JWKS`` (JSON) or ``PACT_PROVIDER_JWKS_FILE``."""
        raw = os.environ.get(ENV_JWKS)
        if raw:
            return cls.from_jwks(raw)
        path = os.environ.get(ENV_JWKS_FILE)
        if path:
            return cls.from_file(path)
        if allow_generate:
            logger.warning("pact.keys.ephemeral: no provider key configured; generated an "
                           "ephemeral key (tokens and receipts die with this process)",
                           extra={"event": "pact.keys.ephemeral"})
            return cls.generate()
        raise RuntimeError(f"Set {ENV_JWKS} or {ENV_JWKS_FILE} to the provider's private JWK(S)")

    @classmethod
    def generate(cls) -> ProviderKeySet:
        """An ephemeral ES256 key (tokens die with the process)."""
        return cls([generate_es256_jwk()])

    # -- use ------------------------------------------------------------

    @property
    def active_kid(self) -> str:
        return self._keys[0].kid

    def jwks(self) -> dict[str, Any]:
        """Public JWKS (every key, active first)."""
        return {"keys": [dict(k.public_jwk) for k in self._keys]}

    def sign(self, payload: bytes, typ: str) -> str:
        k = self._keys[0]
        return sign_compact(payload, k.private, k.alg, {"kid": k.kid, "typ": typ})

    def sign_json(self, claims: dict[str, Any], typ: str) -> str:
        payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
        return self.sign(payload, typ)

    def verify(self, token: str, *, typ: str | None = None) -> dict[str, Any]:
        """Verify a token signed by one of these keys; returns its JSON payload."""
        header, payload, _ = split_compact(token)
        alg = check_header_alg(header)
        if typ is not None and header.get("typ") != typ:
            raise JoseError("unexpected typ")
        kid = header.get("kid")
        key = next((k for k in self._keys if k.kid == kid and k.alg == alg), None)
        if key is None:
            raise JoseError("unknown kid")
        verify_signature(token, key.public, alg)
        if not isinstance(payload, dict):
            raise JoseError("payload is not a JSON object")
        return payload


__all__ = ["ENV_JWKS", "ENV_JWKS_FILE", "ProviderKeySet"]
