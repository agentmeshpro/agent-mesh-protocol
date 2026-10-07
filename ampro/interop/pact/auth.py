"""Personal-agent JWT verification (PACT §3.2).

Every rule from the spec, in order:

* ``Authorization: Bearer <jwt>`` present, at most 8 KiB;
* header ``alg`` is ``ES256`` or ``RS256`` (``none``/``HS*``/others rejected
  before any key lookup), no header-supplied keys (``jwk``/``jku``/``x5u``)
  and no ``crit``;
* ``iss`` is a registered, **enabled** personal agent (exact string match);
* signature verifies with a key from that agent's JWKS (by ``kid``; the
  cache refetches once per rate-limit window on an unknown ``kid``);
* ``aud`` is exactly the assigned audience — one string, not a list;
* ``sub`` is a non-empty string;
* ``iat`` and ``exp`` are integers, ``iat <= now + 30``, ``exp > now - 30``
  and ``exp - iat <= 300``;
* optional ``jti`` replay tracking (off by default — the spec says
  Providers need not track replay).

Any failure raises :class:`~ampro.server.auth.Unauthorized`; the reason
goes to the log, never to the client, who gets ``401`` +
``WWW-Authenticate: Bearer realm="a2a"`` and no body.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ampro.interop.pact._compat import Principal, Unauthorized
from ampro.interop.pact._jwt import (
    MAX_TOKEN_BYTES,
    JoseError,
    check_header_alg,
    public_key_from_jwk,
    split_compact,
    verify_signature,
)
from ampro.interop.pact.jwks import FetchError, JSONFetcher, JWKSCache
from ampro.interop.pact.registry import PersonalAgentRegistry
from ampro.interop.pact.stores import Clock, NonceStore
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

logger = logging.getLogger("ampro.interop.pact.auth")

CLOCK_SKEW = 30
MAX_LIFETIME = 300
MAX_SUB_LEN = 256
AUTH_METHOD = "pact-pa-jwt"


@dataclass(frozen=True)
class PAIdentity:
    """A verified personal-agent call: the User is ``(issuer, sub)``."""

    issuer: str
    sub: str
    audience: str
    claims: dict[str, Any]

    @property
    def principal_id(self) -> str:
        return principal_id(self.issuer, self.sub)


def principal_id(issuer: str, sub: str) -> str:
    return f"pact:{issuer}#{sub}"


def bearer_token(value: str | None) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` value (or ``None``)."""
    if not value or len(value) > MAX_TOKEN_BYTES + 16:
        return None
    scheme, _, token = value.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


def _int_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Unauthorized(f"{name} missing or not numeric")
    if value != value or value in (float("inf"), float("-inf")):
        raise Unauthorized(f"{name} not finite")
    return int(value)


class PAJwtAuthenticator:
    """``Authenticator`` for PACT personal-agent JWTs.

    Args:
        registry: who may call (issuer -> jwks_uri, audience, enabled).
        audience: the Provider's default audience, used for registrations
            without their own ``audience``.
        http_client: a :class:`~ampro.interop.pact.jwks.JSONFetcher` for
            JWKS (default: SSRF-safe HTTPS fetcher).
        jwks_cache: share a cache between authenticators (optional).
        clock: ``() -> unix seconds`` (tests).
        replay_store: optional :class:`NonceStore`; when given, a token's
            ``jti`` (if present) is accepted once.
        trust_tier: tier for verified callers (default ``VERIFIED``).
    """

    def __init__(
        self,
        registry: PersonalAgentRegistry,
        *,
        audience: str | None = None,
        http_client: JSONFetcher | None = None,
        jwks_cache: JWKSCache | None = None,
        clock: Clock = time.time,
        replay_store: NonceStore | None = None,
        trust_tier: TrustTier = TrustTier.VERIFIED,
    ) -> None:
        self.registry = registry
        self.audience = audience
        self.clock = clock
        self.jwks = jwks_cache or JWKSCache(http_client, clock=clock)
        self.replay_store = replay_store
        self.trust_tier = trust_tier

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        """``None`` without a bearer token; :class:`Unauthorized` if it is bad."""
        header = request.header("authorization")
        if header is None:
            return None
        identity = await self.verify(bearer_token(header))
        return self.principal(identity)

    def principal(self, identity: PAIdentity, scopes: frozenset[str] = frozenset()) -> Principal:
        return Principal(
            id=identity.principal_id,
            trust_tier=self.trust_tier,
            scopes=scopes,
            claims={"iss": identity.issuer, "sub": identity.sub, "aud": identity.audience,
                    "pact.claims": dict(identity.claims)},
            auth_method=AUTH_METHOD,
        )

    async def verify(self, token: str | None) -> PAIdentity:
        """Verify a PA JWT; returns the identity or raises :class:`Unauthorized`."""
        try:
            return await self._verify(token)
        except Unauthorized as exc:
            logger.info("pact.auth.rejected", extra={"reason": str(exc)})
            raise
        except (JoseError, FetchError) as exc:
            logger.info("pact.auth.rejected", extra={"reason": str(exc)})
            raise Unauthorized(str(exc)) from None

    async def _verify(self, token: str | None) -> PAIdentity:
        if not token:
            raise Unauthorized("missing bearer token")
        header, payload, _ = split_compact(token)
        alg = check_header_alg(header)
        if header.get("typ") not in (None, "JWT", "jwt") and not str(header.get("typ")).endswith("+jwt"):
            raise Unauthorized("unexpected typ")
        if not isinstance(payload, dict):
            raise Unauthorized("payload is not a JSON object")
        iss = payload.get("iss")
        if not isinstance(iss, str) or not iss:
            raise Unauthorized("missing iss")
        reg = await self.registry.lookup(iss)
        if reg is None or not reg.enabled or reg.issuer != iss:
            raise Unauthorized("unknown or disabled personal agent")
        kid = header.get("kid")
        if kid is not None and (not isinstance(kid, str) or len(kid) > 256):
            raise Unauthorized("bad kid")

        uri = reg.jwks_uri or f"static:{reg.issuer}"
        if reg.jwks is not None and not self.jwks.has(uri):
            self.jwks.put(uri, reg.jwks)
        candidates = await self.jwks.keys(uri, kid)
        raw: bytes | None = None
        for jwk in candidates[:8]:
            try:
                key = public_key_from_jwk(jwk, alg)
            except JoseError:
                continue
            try:
                raw = verify_signature(token, key, alg)
                break
            except JoseError:
                continue
        if raw is None:
            raise Unauthorized("signature did not verify with any published key")

        claims = payload
        audience = reg.audience if reg.audience is not None else self.audience
        aud = claims.get("aud")
        if audience is None or not isinstance(aud, str) or aud != audience:
            raise Unauthorized("aud mismatch")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > MAX_SUB_LEN:
            raise Unauthorized("missing sub")
        iat = _int_claim(claims, "iat")
        exp = _int_claim(claims, "exp")
        now = self.clock()
        if iat > now + CLOCK_SKEW:
            raise Unauthorized("iat in the future")
        if exp <= now - CLOCK_SKEW:
            raise Unauthorized("expired")
        if exp - iat > MAX_LIFETIME:
            raise Unauthorized("lifetime exceeds 300 s")
        if exp <= iat:
            raise Unauthorized("exp before iat")
        nbf = claims.get("nbf")
        if nbf is not None and _int_claim(claims, "nbf") > now + CLOCK_SKEW:
            raise Unauthorized("not yet valid")
        jti = claims.get("jti")
        if self.replay_store is not None and jti is not None:
            if not isinstance(jti, str) or len(jti) > 256:
                raise Unauthorized("bad jti")
            if not await self.replay_store.use(f"pa-jti:{iss}", jti, exp + CLOCK_SKEW):
                raise Unauthorized("jti replayed")
        return PAIdentity(issuer=iss, sub=sub, audience=aud, claims=dict(claims))


__all__ = ["AUTH_METHOD", "PAIdentity", "PAJwtAuthenticator", "bearer_token", "principal_id"]
