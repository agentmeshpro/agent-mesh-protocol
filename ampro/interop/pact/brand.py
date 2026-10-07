"""Brand configuration and the Brand-login hook (PACT §1, §5.2, §5.3)."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ampro.interop.pact._jwt import (
    JoseError,
    check_header_alg,
    public_key_from_jwk,
    split_compact,
    verify_signature,
)
from ampro.interop.pact.jwks import JSONFetcher, JWKSCache
from ampro.interop.pact.stores import Clock, InMemoryNonceStore, NonceStore

if TYPE_CHECKING:
    from ampro.ampi.app import AgentApp

BRAND_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SCOPE_ID_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,128}$")
USER_CODE_RE = re.compile(r"^[A-Z]{4}-[A-Z]{4}$")


@dataclass(frozen=True)
class Scope:
    """A Brand-defined delegation scope (§5.2); ``description`` is shown verbatim."""

    id: str
    description: str

    def __post_init__(self) -> None:
        if not SCOPE_ID_RE.match(self.id):
            raise ValueError(f"invalid scope id {self.id!r}")
        if not self.description or len(self.description) > 512:
            raise ValueError("scope description must be 1-512 characters")


@dataclass(frozen=True)
class BrandUser:
    """The User as the Brand authenticated them."""

    id: str
    display: str


class BrandAssertionError(Exception):
    """A Brand login assertion was rejected (reason is logged only)."""


@runtime_checkable
class BrandLogin(Protocol):
    """The Brand's own login, plugged into the device flow.

    1. :meth:`login_url` — where ``verification_uri(_complete)`` points: the
       Brand's login page, told to come back to *return_to* (the Provider's
       consent endpoint, carrying ``user_code``).
    2. After authenticating the User, the Brand POSTs ``assertion=...`` to
       *return_to*; :meth:`verify_assertion` checks it — single use, bound to
       the ``user_code`` and to that consent URL — and returns the User and
       the ``user_code``.
    3. :meth:`completion_url` (optional, may return ``None``) — where the
       browser goes after the consent decision.
    """

    def login_url(self, return_to: str) -> str: ...

    async def verify_assertion(self, assertion: str, *, audience: str) -> tuple[BrandUser, str]: ...

    def completion_url(self, status: str, scopes: list[str]) -> str | None: ...


class JWTBrandLogin:
    """:class:`BrandLogin` for Brands that sign a short-lived JWT assertion.

    The assertion is a compact JWS (``ES256``/``RS256``) with claims
    ``iss`` (= *issuer*), ``aud`` (= the consent URL), ``sub`` (Brand user
    id), ``user_code``, ``jti`` (single use), ``iat``/``exp`` (at most
    *max_age* seconds apart) and optionally ``email``/``name`` for display.

    Args:
        login_page: the Brand's login URL; ``return_to`` is appended.
        issuer: the Brand's assertion issuer.
        jwks / jwks_uri: the Brand's public keys (static or fetched).
        completion_page: optional Brand URL for after the decision
            (``status`` and ``scope`` query parameters are appended).
    """

    def __init__(
        self,
        *,
        login_page: str,
        issuer: str,
        jwks: dict[str, Any] | None = None,
        jwks_uri: str | None = None,
        fetcher: JSONFetcher | None = None,
        completion_page: str | None = None,
        nonce_store: NonceStore | None = None,
        max_age: int = 300,
        clock: Clock = time.time,
    ) -> None:
        if jwks is None and jwks_uri is None:
            raise ValueError("JWTBrandLogin needs jwks or jwks_uri")
        self.login_page = login_page
        self.issuer = issuer
        self.completion_page = completion_page
        self.max_age = max_age
        self.clock = clock
        self.nonces = nonce_store or InMemoryNonceStore(clock=clock)
        self._cache = JWKSCache(fetcher, clock=clock)
        self._uri = jwks_uri or f"static:{issuer}"
        if jwks is not None:
            self._cache.put(self._uri, jwks)

    def login_url(self, return_to: str) -> str:
        from urllib.parse import urlencode

        sep = "&" if "?" in self.login_page else "?"
        return f"{self.login_page}{sep}{urlencode({'return_to': return_to})}"

    def completion_url(self, status: str, scopes: list[str]) -> str | None:
        if not self.completion_page:
            return None
        from urllib.parse import urlencode

        sep = "&" if "?" in self.completion_page else "?"
        query: dict[str, str] = {"status": status}
        if scopes:
            query["scope"] = " ".join(scopes)
        return f"{self.completion_page}{sep}{urlencode(query)}"

    async def verify_assertion(self, assertion: str, *, audience: str) -> tuple[BrandUser, str]:
        try:
            header, payload, _ = split_compact(assertion)
            alg = check_header_alg(header)
        except JoseError as exc:
            raise BrandAssertionError(str(exc)) from None
        kid = header.get("kid")
        verified = False
        for jwk in (await self._cache.keys(self._uri, kid if isinstance(kid, str) else None))[:8]:
            try:
                verify_signature(assertion, public_key_from_jwk(jwk, alg), alg)
                verified = True
                break
            except JoseError:
                continue
        if not verified or not isinstance(payload, dict):
            raise BrandAssertionError("bad signature")
        c = payload
        now = self.clock()
        if c.get("iss") != self.issuer or c.get("aud") != audience:
            raise BrandAssertionError("iss/aud mismatch")
        sub, code, jti = c.get("sub"), c.get("user_code"), c.get("jti")
        if not (isinstance(sub, str) and 0 < len(sub) <= 256):
            raise BrandAssertionError("bad sub")
        if not (isinstance(code, str) and isinstance(jti, str) and 0 < len(jti) <= 256):
            raise BrandAssertionError("missing user_code/jti")
        iat, exp = c.get("iat"), c.get("exp")
        if not isinstance(iat, int) or not isinstance(exp, int) or isinstance(iat, bool):
            raise BrandAssertionError("bad iat/exp")
        if iat > now + 30 or exp <= now - 30 or exp - iat > self.max_age:
            raise BrandAssertionError("assertion expired or too long-lived")
        if not await self.nonces.use(f"brand-assertion:{self.issuer}", jti, exp + 60):
            raise BrandAssertionError("assertion replayed")
        display = c.get("email") or c.get("name") or sub
        return BrandUser(id=sub, display=str(display)[:256]), code.strip().upper()


@dataclass
class Brand:
    """One Brand hosted by a :class:`~ampro.interop.pact.provider.PACTProvider`.

    ``app`` is the Brand's AMPI agent; a new A2A message arrives as AMP
    ``task.create`` (``body["text"]``, ``headers["Session-Id"]`` = contextId).
    Delegation (§5) is offered when both ``scopes`` and ``login`` are set.
    """

    brand_id: str
    app: AgentApp
    name: str
    description: str = ""
    skills: list[dict[str, Any]] = field(default_factory=list)
    scopes: list[Scope] = field(default_factory=list)
    login: BrandLogin | None = None
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not BRAND_ID_RE.match(self.brand_id):
            raise ValueError(f"invalid brand id {self.brand_id!r}")
        if len({s.id for s in self.scopes}) != len(self.scopes):
            raise ValueError("duplicate scope ids")

    @property
    def delegation_enabled(self) -> bool:
        return bool(self.scopes) and self.login is not None

    def scope(self, scope_id: str) -> Scope | None:
        return next((s for s in self.scopes if s.id == scope_id), None)


__all__ = ["Brand", "BrandAssertionError", "BrandLogin", "BrandUser", "JWTBrandLogin", "Scope", "USER_CODE_RE"]
