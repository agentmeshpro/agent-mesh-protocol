"""Authentication hook for the A2A adapter.

An :class:`Authenticator` turns an incoming :class:`HTTPRequest` into a
:class:`Principal`::

    class BearerJWT:
        async def authenticate(self, request: HTTPRequest) -> Principal | None:
            header = request.header("authorization")
            if not header or not header.lower().startswith("bearer "):
                return None                      # not my credential — try the next one
            claims = verify(header[7:])          # your verification
            if claims is None:
                raise Unauthorized()             # bad credential -> 401, stop
            return Principal(id=f"pa:{claims['iss']}#{claims['sub']}",
                             trust_tier=TrustTier.VERIFIED,
                             scopes=frozenset(claims.get("scope", "").split()),
                             claims=claims, auth_method="jwt")

    A2AAdapter.for_server(server, authenticators=[BearerJWT()], require_auth=True)

Rules applied by the adapter:

* Authenticators run in order; the first that returns a ``Principal`` wins.
* ``None`` means "no credential I recognise"; raising :class:`Unauthorized`
  means "a credential was presented and it is bad" — the request is
  rejected with ``401`` and ``WWW-Authenticate: Bearer realm="a2a"`` (plus
  ``error="..."`` when given) and **no body**.
* If nobody claims the request: an anonymous ``EXTERNAL`` principal, or
  ``401`` when ``require_auth=True``.
* Routing happens before authentication, so unknown routes are ``404``
  regardless of credentials; the agent card is never authenticated.

The principal is copied into the handler's ``AMPContext``: ``sender_address``
(``principal.id``), ``trust_tier``, ``scopes``, ``auth_method`` and
``principal`` itself.  Tasks and contexts are owned by ``principal.id``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ampro.trust.tiers import TrustTier

if TYPE_CHECKING:
    from ampro.server.http import HTTPRequest

ANONYMOUS_ID = "a2a://anonymous"


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of an A2A request.

    ``id`` is the stable owner key and the AMP ``sender`` address; it must be
    unique per caller (e.g. ``"pa:https://pa.example#user-42"``).
    """

    id: str
    trust_tier: TrustTier = TrustTier.EXTERNAL
    scopes: frozenset[str] = field(default_factory=frozenset)
    claims: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    auth_method: str | None = None

    @property
    def is_anonymous(self) -> bool:
        return self.id == ANONYMOUS_ID

    def with_scopes(self, scopes: Iterable[str]) -> Principal:
        return Principal(self.id, self.trust_tier, frozenset(scopes), self.claims, self.auth_method)


ANONYMOUS = Principal(id=ANONYMOUS_ID, trust_tier=TrustTier.EXTERNAL, auth_method="none")


class Unauthorized(Exception):
    """Raised by an authenticator for a credential that is present but invalid.

    ``error`` is the RFC 6750 ``error`` attribute for ``WWW-Authenticate``
    (e.g. ``"invalid_token"``).  The message is logged, never sent.
    """

    def __init__(self, message: str = "unauthorized", *, error: str | None = None) -> None:
        self.error = error
        super().__init__(message)


@runtime_checkable
class Authenticator(Protocol):
    """Resolve the caller of a request.  See the module docstring for the rules."""

    async def authenticate(self, request: HTTPRequest) -> Principal | None: ...


class AuthRequired(Exception):
    """Raise from a handler or middleware when the caller lacks authority.

    The A2A adapter answers with a Task in ``TASK_STATE_AUTH_REQUIRED``
    whose status message is *message* and whose metadata carries the
    missing scopes and the verification URI under the adapter's configured
    keys (see :class:`AuthRequiredKeys`; the PACT profile uses
    :data:`PACT_AUTH_KEYS`).  The conversation stays open.
    """

    def __init__(
        self,
        missing_scopes: Iterable[str] = (),
        verification_uri: str | None = None,
        *,
        message: str = "Additional authorization is required.",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.missing_scopes = list(missing_scopes)
        self.verification_uri = verification_uri
        self.message = message
        self.metadata = dict(metadata or {})
        super().__init__(message)


@dataclass(frozen=True)
class AuthRequiredKeys:
    """Metadata keys used on an ``AUTH_REQUIRED`` task."""

    missing_scopes: str = "missingScopes"
    verification_uri: str = "verificationUriComplete"


PACT_AUTH_KEYS = AuthRequiredKeys("pact.missingScopes", "pact.verificationUriComplete")


def www_authenticate(error: str | None = None, realm: str = "a2a") -> str:
    value = f'Bearer realm="{realm}"'
    error = re.sub(r"[^A-Za-z0-9_.-]", "", error or "")
    if error:
        value += f', error="{error}"'
    return value


__all__ = [
    "ANONYMOUS",
    "ANONYMOUS_ID",
    "AuthRequired",
    "AuthRequiredKeys",
    "Authenticator",
    "PACT_AUTH_KEYS",
    "Principal",
    "Unauthorized",
    "www_authenticate",
]
