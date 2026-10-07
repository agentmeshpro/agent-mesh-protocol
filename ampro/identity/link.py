"""
Agent Protocol — Identity Linking.

Cryptographic proof that two agent:// addresses belong to the same
entity. Used when an agent operates under multiple addresses and
needs to prove equivalence to other agents.

Also defines agent.json ``foreign_identifiers`` entries
(:class:`ForeignIdentifier`): the same agent's MCP client ID metadata
URL, ``did:web`` / ``did:wba`` / ``did:key`` DID, or Web Bot Auth key
directory.  A foreign identifier confers no trust by itself; only
:func:`verified_foreign_aliases` (an identity link proof that verifies)
makes it an alias.

This module contains NO platform-specific imports.
It is designed for extraction as part of `pip install agent-protocol`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from ampro.core.addressing import (
    MAX_FOREIGN_URL_LENGTH,
    normalize_foreign_did,
    normalize_foreign_https_id,
)

logger = logging.getLogger(__name__)

DEFAULT_LINK_PROOF_LIFETIME = timedelta(days=365)
"""Default lifetime for newly minted identity link proofs (1 year)."""


def _parse_any_ts(value: str | datetime) -> datetime:
    """Best-effort parse of an ISO-8601 / datetime into an aware ``datetime``."""
    if isinstance(value, datetime):
        dt = value
    else:
        # Accept trailing "Z" as UTC.
        raw = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class IdentityLinkProofBody(BaseModel):
    """Payload proving two agent addresses share the same controlling entity."""

    source_id: str = Field(description="First agent:// URI")
    target_id: str = Field(description="Second agent:// URI to link")
    proof_type: str = Field(
        description="Proof method (e.g. ed25519_cross_sign)",
    )
    proof: str = Field(description="Cryptographic proof of shared control")
    timestamp: str = Field(
        description="ISO-8601 timestamp when proof was generated",
    )
    expires_at: datetime = Field(
        description="When the link proof is no longer valid",
    )

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _expires_after_timestamp(self) -> IdentityLinkProofBody:
        """A freshly minted proof MUST NOT already be expired.

        ``expires_at`` is required to be strictly after ``timestamp``; if the
        ``timestamp`` field cannot be parsed we fall back to "not allowed to be
        in the past" so malformed timestamps can't bypass the check.
        """
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
            object.__setattr__(self, "expires_at", expires_at)

        try:
            issued_at = _parse_any_ts(self.timestamp)
        except (ValueError, TypeError):
            issued_at = datetime.now(tz=UTC)

        if expires_at <= issued_at:
            raise ValueError(
                "expires_at must be strictly after timestamp "
                f"(got expires_at={expires_at.isoformat()}, "
                f"timestamp={issued_at.isoformat()})"
            )
        return self


def is_link_proof_valid(
    body: IdentityLinkProofBody,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` iff ``now`` is before ``body.expires_at``.

    Args:
        body: The link proof body to check.
        now:  Override for the current time (defaults to ``datetime.now(UTC)``).

    Returns:
        ``False`` once the proof has expired, ``True`` otherwise.
    """
    current = now if now is not None else datetime.now(tz=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    expires = body.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return current <= expires


# ---------------------------------------------------------------------------
# Foreign identifiers (agent.json ``foreign_identifiers``, WIRE-BINDING E.4)
# ---------------------------------------------------------------------------

#: Maximum number of ``foreign_identifiers`` entries in one agent.json.
MAX_FOREIGN_IDENTIFIERS = 16

#: Allowed clock skew for a link proof's ``timestamp`` being in the future.
_PROOF_FUTURE_SKEW = timedelta(minutes=5)

ForeignIdentifierKind = Literal["oauth-client-id", "did", "http-signature-directory"]

_KIND_SCHEME: dict[str, str] = {
    "oauth-client-id": "https",
    "http-signature-directory": "https",
    "did": "did",
}

#: Verifies the cryptographic ``proof`` of an identity link; MUST return
#: ``True`` only for a proof it actually checked.
LinkProofVerifier = Callable[[IdentityLinkProofBody], bool]


def normalize_foreign_identifier(scheme: str, value: str) -> str:
    """Canonical form of a foreign identifier, or ``ValueError``."""
    if scheme == "https":
        return normalize_foreign_https_id(value)
    if scheme == "did":
        return normalize_foreign_did(value)
    raise ValueError(f"unsupported foreign identifier scheme {scheme!r}")


class ForeignIdentifier(BaseModel):
    """One agent.json ``foreign_identifiers`` entry.

    Names the same agent in another ecosystem: an MCP client ID metadata
    document URL (``oauth-client-id``), an ANP / did:web DID (``did``), or
    a Web Bot Auth ``Signature-Agent`` key directory
    (``http-signature-directory``).

    A foreign identifier confers NO trust by itself.  It is treated as the
    same entity only when ``proof`` (an identity link between one of the
    agent's ``agent://`` identifiers and this ``id``) verifies; see
    :func:`verified_foreign_aliases`.  ``id`` is stored in canonical form.
    """

    scheme: Literal["https", "did"] = Field(description="Identifier scheme")
    id: str = Field(
        max_length=MAX_FOREIGN_URL_LENGTH,
        description=(
            "The foreign identifier (https URL or DID), canonicalised per "
            "WIRE-BINDING Appendix E.4"
        ),
    )
    kind: ForeignIdentifierKind = Field(
        description="What the identifier is: oauth-client-id, did or http-signature-directory",
    )
    proof: IdentityLinkProofBody | None = Field(
        default=None,
        description=(
            "Identity link proof binding one of the agent's agent:// identifiers "
            "to this id. Without a verifying proof the entry MUST be ignored."
        ),
    )

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _check(self) -> ForeignIdentifier:
        if _KIND_SCHEME[self.kind] != self.scheme:
            raise ValueError(f"kind {self.kind!r} requires scheme {_KIND_SCHEME[self.kind]!r}")
        prefix = "https://" if self.scheme == "https" else "did:"
        if not self.id[: len(prefix)].lower() == prefix:
            raise ValueError(f"id does not match scheme {self.scheme!r}")
        object.__setattr__(self, "id", normalize_foreign_identifier(self.scheme, self.id))
        return self


def _canonical_amp_id(value: str) -> str | None:
    """Comparable form of one of the agent's own ``agent://`` identifiers."""
    from ampro.security.key_revocation import canonical_agent_id

    try:
        return canonical_agent_id(value)
    except (ValueError, TypeError):
        return None


def verified_foreign_aliases(
    own_identifiers: Iterable[str],
    foreign_identifiers: Iterable[ForeignIdentifier | dict[str, Any]],
    *,
    verify_proof: LinkProofVerifier,
    now: datetime | None = None,
) -> frozenset[str]:
    """Return the canonical foreign ids whose identity-link proof verifies.

    An entry counts only if ALL of the following hold; otherwise it is
    ignored (never an error, never partially trusted):

    * it parses as a :class:`ForeignIdentifier`;
    * it carries a ``proof``;
    * the proof links one of *own_identifiers* (the agent's ``agent://``
      ids, compared after normalisation) with exactly this foreign id, in
      either direction;
    * the proof has not expired and its ``timestamp`` is a parseable
      instant no more than 5 minutes in the future;
    * ``verify_proof(proof)`` returns ``True`` (exceptions and any other
      return value count as failure).

    Raises ``ValueError`` if more than :data:`MAX_FOREIGN_IDENTIFIERS`
    entries are supplied (a malformed document, not something to trim).
    """
    current = now if now is not None else datetime.now(tz=UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    own = {c for c in (_canonical_amp_id(i) for i in own_identifiers) if c is not None}
    entries = list(foreign_identifiers)
    if len(entries) > MAX_FOREIGN_IDENTIFIERS:
        raise ValueError(f"at most {MAX_FOREIGN_IDENTIFIERS} foreign identifiers are allowed")
    if not own:
        return frozenset()

    verified: set[str] = set()
    for raw in entries:
        try:
            entry = (
                raw if isinstance(raw, ForeignIdentifier)
                else ForeignIdentifier.model_validate(raw)
            )
        except (ValueError, TypeError) as exc:
            logger.warning("foreign identifier ignored (invalid): %s", exc)
            continue
        proof = entry.proof
        if proof is None:
            continue
        if not _proof_binds(proof, own, entry):
            logger.warning("foreign identifier %s ignored: proof does not bind it", entry.id)
            continue
        if not is_link_proof_valid(proof, now=current):
            continue
        try:
            issued = _parse_any_ts(proof.timestamp)
        except (ValueError, TypeError):
            continue
        if issued > current + _PROOF_FUTURE_SKEW:
            continue
        try:
            ok = verify_proof(proof)
        except Exception as exc:  # fail closed on verifier errors
            logger.warning("foreign identifier %s ignored: verifier raised %s", entry.id, exc)
            continue
        if ok is True:
            verified.add(entry.id)
    return frozenset(verified)


def _proof_binds(proof: IdentityLinkProofBody, own: set[str], entry: ForeignIdentifier) -> bool:
    for amp_side, foreign_side in (
        (proof.source_id, proof.target_id),
        (proof.target_id, proof.source_id),
    ):
        if _canonical_amp_id(amp_side) not in own:
            continue
        try:
            if normalize_foreign_identifier(entry.scheme, foreign_side) == entry.id:
                return True
        except ValueError:
            continue
    return False
