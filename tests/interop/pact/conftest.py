"""Shared fixtures for the PACT tests."""
from __future__ import annotations

import json
import time
from typing import Any

import pytest

pytest.importorskip("jwt")

from ampro.interop.pact import (  # noqa: E402
    InMemoryPersonalAgentRegistry,
    PAJwtAuthenticator,
    PersonalAgentRegistration,
)
from ampro.interop.pact._jwt import (  # noqa: E402
    b64url_encode,
    generate_es256_jwk,
    private_key_from_jwk,
    public_jwk,
    sign_compact,
)

ISSUER = "https://pa.example"
AUDIENCE = "provider-aud"


class FakeClock:
    def __init__(self, now: float | None = None) -> None:
        self.now = float(now if now is not None else int(time.time()))

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class PAKey:
    """A personal agent's key pair with a flexible token minting helper."""

    def __init__(self, kid: str | None = None) -> None:
        self.jwk = generate_es256_jwk(kid)
        self.kid = self.jwk["kid"]
        self.key, self.alg = private_key_from_jwk(self.jwk)

    @property
    def jwks(self) -> dict[str, Any]:
        return {"keys": [{**public_jwk(self.jwk), "kid": self.kid, "alg": "ES256", "use": "sig"}]}

    def token(self, clock: Any = None, *, header: dict[str, Any] | None = None,
              drop: tuple[str, ...] = (), **claims: Any) -> str:
        now = int(clock() if clock else time.time())
        body = {"iss": ISSUER, "sub": "user-1", "aud": AUDIENCE, "iat": now, "exp": now + 120}
        body.update(claims)
        for k in drop:
            body.pop(k, None)
        hdr = {"kid": self.kid, "typ": "JWT", **(header or {})}
        return sign_compact(json.dumps(body).encode(), self.key, "ES256", hdr)


def unsigned_token(header: dict[str, Any], claims: dict[str, Any], sig: bytes = b"x") -> str:
    return ".".join([b64url_encode(json.dumps(header).encode()),
                     b64url_encode(json.dumps(claims).encode()), b64url_encode(sig)])


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def pa_key() -> PAKey:
    return PAKey()


@pytest.fixture
def registry(pa_key: PAKey) -> InMemoryPersonalAgentRegistry:
    return InMemoryPersonalAgentRegistry([
        PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks, audience=AUDIENCE),
        PersonalAgentRegistration(issuer=ISSUER + "/disabled", jwks=pa_key.jwks, enabled=False),
    ])


@pytest.fixture
def authenticator(registry: InMemoryPersonalAgentRegistry, clock: FakeClock) -> PAJwtAuthenticator:
    return PAJwtAuthenticator(registry, audience=AUDIENCE, clock=clock)
