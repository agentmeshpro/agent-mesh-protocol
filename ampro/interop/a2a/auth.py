"""Authentication hook for the A2A adapter.

The contract is the server-wide one from :mod:`ampro.server.auth`
(re-exported here): an :class:`Authenticator` turns an incoming
:class:`HTTPRequest` into a :class:`Principal`::

    class BearerJWT:
        async def authenticate(self, request: HTTPRequest) -> Principal | None:
            header = request.header("authorization")
            if not header or not header.lower().startswith("bearer "):
                return None                      # not my credential: try the next one
            claims = verify(header[7:])          # your verification
            if claims is None:
                raise InvalidToken()             # bad credential -> 401, stop
            return Principal(id=f"pa:{claims['iss']}#{claims['sub']}",
                             trust_tier=TrustTier.VERIFIED,
                             scopes=frozenset(claims.get("scope", "").split()),
                             claims=claims, auth_method="jwt")

    A2AAdapter.for_server(server, authenticators=[BearerJWT()], require_auth=True)

Rules applied by the adapter:

* Authenticators run in order; the first that returns a ``Principal`` wins.
  Without ``authenticators=`` the adapter uses ``server.security.authenticators``.
* ``None`` means "no credential I recognise"; raising :class:`Unauthorized`
  means "a credential was presented and it is bad": the request is
  rejected with ``401`` and ``WWW-Authenticate: Bearer realm="a2a"`` (plus
  ``error="..."`` for :class:`InvalidToken` or any ``Unauthorized`` with an
  ``error`` attribute) and **no body**.
* If nobody claims the request: :data:`ANONYMOUS` (``EXTERNAL`` tier), or
  ``401`` when ``require_auth`` is set.
* Routing happens before authentication, and authentication before the
  body is parsed.  Unknown routes are ``404``/``405`` regardless of
  credentials; the agent card is never authenticated.

The principal is copied into the handler's ``AMPContext``:
``sender_address`` (``principal.id``; ``a2a://anonymous`` when anonymous),
``trust_tier``, ``scopes``, ``auth_method`` and ``principal`` itself.
Tasks and contexts are owned by ``principal.id``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# The canonical auth contract shared by every protocol the server speaks.
from ampro.server.auth import ANONYMOUS, Authenticator, Principal, Unauthorized, authenticate
from ampro.wire.errors import AuthorityRequiredProblem, authority_required

ANONYMOUS_ID = ANONYMOUS.id
#: AMP ``sender`` address used for anonymous A2A callers.
ANONYMOUS_SENDER = "a2a://anonymous"


def is_anonymous(principal: Principal) -> bool:
    return principal is ANONYMOUS or principal.id == ANONYMOUS_ID


class InvalidToken(Unauthorized):
    """:class:`Unauthorized` carrying an RFC 6750 ``error`` code.

    The adapter puts it in ``WWW-Authenticate`` (e.g.
    ``Bearer realm="a2a", error="invalid_token"``).  Any ``Unauthorized``
    with an ``error`` attribute is treated the same way.
    """

    def __init__(self, message: str = "invalid token", *, error: str = "invalid_token") -> None:
        self.error = error
        super().__init__(message)


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

    def to_problem(self) -> AuthorityRequiredProblem:
        """The equivalent AMP 403 ``urn:amp:error:authority-required`` problem.

        ``missing_scopes`` map one-to-one; ``verification_uri`` becomes
        ``human_approval.verification_uri``.  Does not change what the A2A
        adapter puts on the wire.  Raises ``ValueError`` if a scope or the
        URI is not acceptable in the AMP problem (for example a non-https
        URI); the caller must not fall back to a weaker problem silently.
        """
        return authority_required(
            self.message,
            missing_scopes=self.missing_scopes,
            human_approval=(
                {"verification_uri": self.verification_uri} if self.verification_uri else None
            ),
        )

    @classmethod
    def from_problem(cls, problem: AuthorityRequiredProblem) -> AuthRequired:
        """Build an ``AuthRequired`` from an AMP authority-required problem.

        Raises ``ValueError`` when the problem asks for something an A2A
        ``AUTH_REQUIRED`` task cannot express (constraints or payment): the
        requirement must not be silently dropped.
        """
        if not isinstance(problem, AuthorityRequiredProblem):
            raise ValueError("problem must be an AuthorityRequiredProblem")
        if problem.required_constraints or problem.payment_required is not None:
            raise ValueError(
                "required_constraints / payment_required have no A2A AUTH_REQUIRED mapping"
            )
        uri = problem.human_approval.verification_uri if problem.human_approval else None
        return cls(problem.missing_scopes, uri,
                   message=problem.detail or "Additional authorization is required.")


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
    "ANONYMOUS_SENDER",
    "InvalidToken",
    "authenticate",
    "is_anonymous",
    "AuthRequired",
    "AuthRequiredKeys",
    "Authenticator",
    "PACT_AUTH_KEYS",
    "Principal",
    "Unauthorized",
    "www_authenticate",
]
