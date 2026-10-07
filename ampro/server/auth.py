"""Request authentication for every protocol the server speaks.

One contract shared by the native AMP route and the interop adapters
(A2A, PACT, MCP): an :class:`Authenticator` looks at an
:class:`~ampro.server.http.HTTPRequest` and returns the
:class:`Principal` it proves, ``None`` when the request carries no
credential it understands, or raises :class:`Unauthorized` when a
credential is present but invalid.

PURE — zero platform-specific imports.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urljoin

from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of a request."""

    id: str
    trust_tier: TrustTier = TrustTier.EXTERNAL
    scopes: frozenset[str] = field(default_factory=frozenset)
    claims: dict[str, Any] = field(default_factory=dict)
    auth_method: str | None = None


ANONYMOUS = Principal(id="anonymous", trust_tier=TrustTier.EXTERNAL, auth_method=None)


class Unauthorized(Exception):
    """A credential was presented but is invalid.

    The message is for server-side logs only; it is never sent to clients.
    """


@runtime_checkable
class Authenticator(Protocol):
    async def authenticate(self, request: HTTPRequest) -> Principal | None: ...


async def authenticate(
    request: HTTPRequest, authenticators: Iterable[Authenticator]
) -> Principal | None:
    """Run *authenticators* in order; first principal wins.

    Raises :class:`Unauthorized` as soon as one rejects a credential, so
    an invalid credential is never silently downgraded to anonymous.
    """
    for authenticator in authenticators:
        principal = await authenticator.authenticate(request)
        if principal is not None:
            return principal
    return None


class SignatureAuthenticator:
    """RFC 9421 HTTP Message Signatures (Ed25519).

    Args:
        public_url: The externally visible base URL of this server; the
            signature covers the full target URI, which the server cannot
            reconstruct reliably behind proxies.
        key_resolver: ``keyid -> raw Ed25519 public key`` (``None`` if
            unknown or revoked).  Defaults to the host-registered resolver
            in :mod:`ampro.trust.resolver`.
        key_owner: ``keyid -> agent address`` that owns the key.  When
            given, it becomes the principal id, and the server rejects
            messages whose ``sender`` differs.
        trust_tier: Tier granted to verified callers.
    """

    def __init__(
        self,
        public_url: str,
        *,
        key_resolver: Callable[[str], bytes | None] | None = None,
        key_owner: Callable[[str], str | None] | None = None,
        trust_tier: TrustTier = TrustTier.VERIFIED,
        nonce_tracker: Any = None,
    ) -> None:
        if key_resolver is None:
            from ampro.trust.resolver import get_public_key

            key_resolver = get_public_key
        self._public_url = public_url.rstrip("/") + "/"
        self._key_resolver = key_resolver
        self._key_owner = key_owner
        self._tier = trust_tier
        self._nonce_tracker = nonce_tracker

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        from ampro.security.rfc9421 import verify_request

        sig_input = request.header("signature-input")
        if not sig_input or not request.header("signature"):
            return None
        keyid = _parse_keyid(sig_input)
        if keyid is None:
            raise Unauthorized("Signature-Input without keyid")
        key = self._key_resolver(keyid)
        if key is None:
            raise Unauthorized(f"unknown or revoked keyid {keyid!r}")

        url = urljoin(self._public_url, request.path.lstrip("/"))
        if request.query:
            from urllib.parse import urlencode

            url = f"{url}?{urlencode(request.query)}"
        ok = verify_request(
            key,
            request.method,
            url,
            request.headers,
            request.body or None,
            nonce_tracker=self._nonce_tracker,
        )
        if not ok:
            raise Unauthorized("RFC 9421 signature verification failed")
        owner = self._key_owner(keyid) if self._key_owner else None
        return Principal(
            id=owner or keyid,
            trust_tier=self._tier,
            claims={"keyid": keyid, "bound_sender": owner is not None},
            auth_method="rfc9421",
        )


class TrustResolverAuthenticator:
    """``Authorization`` header via :func:`ampro.trust.resolver.resolve_trust_tier`.

    Supports the AMP auth methods (JWT via a host-registered resolver,
    DID proofs, API keys) and a transport-verified mTLS identity.
    """

    def __init__(self, audience: str) -> None:
        self._audience = audience

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        from ampro.trust.resolver import resolve_trust_tier

        authorization = request.header("authorization")
        if not authorization and not request.client_cert_identity:
            return None
        sender = _peek_sender(request)
        tier = await resolve_trust_tier(
            authorization,
            None,
            None,
            request.client,
            sender_id=sender,
            audience=self._audience,
            client_cert_identity=request.client_cert_identity,
        )
        if tier == TrustTier.EXTERNAL:
            raise Unauthorized("credential did not resolve to a trusted tier")
        from ampro.identity.auth_methods import AuthMethod, parse_authorization

        parsed = parse_authorization(authorization)
        if request.client_cert_identity:
            return Principal(
                id=request.client_cert_identity,
                trust_tier=tier,
                claims={"bound_sender": True},
                auth_method="mtls",
            )
        if parsed.method == AuthMethod.DID:
            # The resolver verified the DID proof is bound to ``sender``.
            if not sender:
                raise Unauthorized("DID proof without an envelope sender")
            return Principal(
                id=sender, trust_tier=tier, claims={"bound_sender": True}, auth_method="did",
            )
        if parsed.method == AuthMethod.API_KEY:
            from ampro.trust.resolver import lookup_api_key_owner

            found = lookup_api_key_owner(parsed.token)
            if found is None:
                raise Unauthorized("API key has no owning agent")
            # API keys are per-agent credentials: the key's owner is the
            # caller, and it may only send as itself.
            return Principal(
                id=found[0], trust_tier=tier, claims={"bound_sender": True}, auth_method="api_key",
            )
        if parsed.method == AuthMethod.JWT:
            # The host's JWT resolver has verified the token; identify the
            # caller by its (issuer, subject) so callers never share an id.
            claims = _jwt_claims(parsed.token)
            iss, sub = claims.get("iss"), claims.get("sub")
            if not isinstance(iss, str) or not isinstance(sub, str) or not iss or not sub:
                raise Unauthorized("JWT lacks iss/sub; cannot identify the caller")
            return Principal(
                id=f"jwt:{iss}#{sub}",
                trust_tier=tier,
                claims={"bound_sender": False, "iss": iss, "sub": sub},
                auth_method="jwt",
            )
        raise Unauthorized("credential did not yield a caller identity")


def _jwt_claims(token: str) -> dict[str, Any]:
    """Decode the payload of an already-verified compact JWT."""
    import base64
    import json

    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError, RecursionError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _parse_keyid(signature_input: str) -> str | None:
    marker = 'keyid="'
    start = signature_input.find(marker)
    if start < 0:
        return None
    start += len(marker)
    end = signature_input.find('"', start)
    if end < 0:
        return None
    return signature_input[start:end] or None


def _peek_sender(request: HTTPRequest) -> str | None:
    try:
        payload = request.json()
    except ValueError:
        return None
    if isinstance(payload, dict) and isinstance(payload.get("sender"), str):
        return payload["sender"]
    return None
