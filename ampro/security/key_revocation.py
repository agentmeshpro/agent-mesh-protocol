"""
Agent Protocol — Key Revocation.

Emergency key revocation broadcast. When an agent's private key is
compromised, this body type allows broadcasting the revocation to all
agents that may have cached the old key.

Revocation reasons:
  - key_compromise: key was stolen or leaked
  - key_rotation: routine key rotation (not emergency, but caches should refresh)
  - agent_decommissioned: agent is shutting down permanently

Compromise semantics (WIRE-BINDING section 12.12.1):

A thief holding a stolen key can put any ``created_at`` / ``signed_at``
it likes on what it signs, so a timestamp cut-off can never rescue a
signature made with a compromised key.  Verifiers therefore map each
revocation onto a :class:`KeyStatus` and decide with
:func:`signature_allowed`:

  - ``key_compromise`` / ``agent_decommissioned`` -> every signature made
    by that key id is invalid, whatever timestamp it claims, effective
    immediately.  ``compromised_at`` is audit data only and MUST NOT be
    used to keep any signature valid.
  - ``key_rotation`` -> the key may not sign anything new at or after
    ``revoked_at``; artefacts it signed before then stay valid until
    their own expiry (rotation is not compromise).
  - a key the verifier knows nothing about (``UNKNOWN``) is never
    accepted (fail closed).

:class:`KeyStatusResolver` is the lookup interface verifiers call (for
example from delegation-chain validation); :class:`InMemoryKeyStatusResolver`
is a bounded reference implementation fed only with authenticated
revocations.

PURE — zero platform-specific imports. Only pydantic and stdlib.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import unicodedata
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Revocation reason enum
# ---------------------------------------------------------------------------


class RevocationReason(str, Enum):
    """Reasons an agent key may be revoked."""

    KEY_COMPROMISE = "key_compromise"
    KEY_ROTATION = "key_rotation"
    AGENT_DECOMMISSIONED = "agent_decommissioned"


# ---------------------------------------------------------------------------
# Key revocation body type
# ---------------------------------------------------------------------------


#: RFC 3339 ``date-time`` with a mandatory UTC offset (``Z`` or ``+hh:mm``).
#: ASCII digits only; leap second ``60`` is not accepted (``datetime`` cannot
#: represent it).  Published in the JSON Schema as the ``pattern`` of
#: ``revoked_at`` / ``compromised_at``.
RFC3339_TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?"
    r"([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$"
)
_RFC3339_RE = re.compile(RFC3339_TIMESTAMP_PATTERN)

#: Size bounds for ``key.revocation`` fields.
MAX_REVOCATION_AGENT_ID_LENGTH = 2048
MAX_KEY_ID_LENGTH = 256
MAX_REVOCATION_URL_LENGTH = 2048
MAX_REVOCATION_SIGNATURE_LENGTH = 256
_MAX_TIMESTAMP_LENGTH = 64


def parse_rfc3339_timestamp(value: str) -> datetime:
    """Parse a strict RFC 3339 timestamp into an aware UTC ``datetime``.

    Raises ``ValueError`` for anything that is not a timezone-qualified
    RFC 3339 ``date-time``: naive timestamps, bare dates, ``T``-less forms,
    impossible calendar dates, non-ASCII digits, trailing garbage.
    """
    if not isinstance(value, str) or len(value) > _MAX_TIMESTAMP_LENGTH:
        raise ValueError("timestamp must be an RFC 3339 string of at most 64 characters")
    if _RFC3339_RE.fullmatch(value) is None:
        raise ValueError(
            f"timestamp must be RFC 3339 with an explicit UTC offset (got {value!r})"
        )
    raw = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    raw = raw[:10] + "T" + raw[11:]
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:  # e.g. 2026-02-30
        raise ValueError(f"invalid RFC 3339 timestamp {value!r}: {exc}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:  # pragma: no cover - regex forbids
        raise ValueError(f"timestamp {value!r} is not timezone-aware")
    return parsed.astimezone(UTC)


def _check_token(value: str, what: str, max_len: int) -> str:
    """Reject empty, oversized, whitespace- or control-character-bearing tokens."""
    if not value or len(value) > max_len:
        raise ValueError(f"{what} must be 1..{max_len} characters")
    if any(ch.isspace() or unicodedata.category(ch)[0] == "C" for ch in value):
        raise ValueError(f"{what} must not contain whitespace or control characters")
    return value


class KeyRevocationBody(BaseModel):
    """body.type = 'key.revocation' — Broadcast that an agent key is revoked."""

    # What each ``reason`` means to a verifier: see the module docstring.

    agent_id: str = Field(
        max_length=MAX_REVOCATION_AGENT_ID_LENGTH,
        description="agent:// URI of the agent whose key is revoked",
    )
    revoked_key_id: str = Field(
        max_length=MAX_KEY_ID_LENGTH,
        description="Key ID being revoked",
    )
    revoked_at: str = Field(
        max_length=_MAX_TIMESTAMP_LENGTH,
        pattern=RFC3339_TIMESTAMP_PATTERN,
        description=(
            "RFC 3339 timestamp (with UTC offset) from which the key is revoked. "
            "key_rotation: the key may not sign anything at or after this instant. "
            "key_compromise / agent_decommissioned: every signature by the key is "
            "invalid regardless of this value."
        ),
    )
    reason: str = Field(
        description="Revocation reason (key_compromise, key_rotation, agent_decommissioned)",
    )
    replacement_key_id: str | None = Field(
        default=None,
        max_length=MAX_KEY_ID_LENGTH,
        description="Replacement key ID, if key was rotated",
    )
    jwks_url: str | None = Field(
        default=None,
        max_length=MAX_REVOCATION_URL_LENGTH,
        description="URL to fetch updated JWKS",
    )
    compromised_at: str | None = Field(
        default=None,
        max_length=_MAX_TIMESTAMP_LENGTH,
        pattern=RFC3339_TIMESTAMP_PATTERN,
        description=(
            "key_compromise only: informational RFC 3339 estimate of when the key "
            "was compromised, for audit. Verifiers MUST NOT use it to keep any "
            "signature valid. Omitted from the signed canonical form when absent."
        ),
    )
    signature: str = Field(
        max_length=MAX_REVOCATION_SIGNATURE_LENGTH,
        description="Ed25519 signature proving authenticity of this revocation",
    )

    model_config = {"extra": "ignore"}

    @field_validator("reason")
    @classmethod
    def _known_reason(cls, value: str) -> str:
        allowed = {r.value for r in RevocationReason}
        if value not in allowed:
            raise ValueError(f"reason must be one of {sorted(allowed)}")
        return value

    @field_validator("agent_id")
    @classmethod
    def _agent_id_shape(cls, value: str) -> str:
        return _check_token(value, "agent_id", MAX_REVOCATION_AGENT_ID_LENGTH)

    @field_validator("revoked_key_id")
    @classmethod
    def _kid_shape(cls, value: str) -> str:
        return _check_token(value, "revoked_key_id", MAX_KEY_ID_LENGTH)

    @field_validator("replacement_key_id")
    @classmethod
    def _replacement_kid_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_token(value, "replacement_key_id", MAX_KEY_ID_LENGTH)

    @field_validator("revoked_at", "compromised_at")
    @classmethod
    def _rfc3339(cls, value: str | None) -> str | None:
        if value is not None:
            parse_rfc3339_timestamp(value)
        return value

    @model_validator(mode="after")
    def _cross_field(self) -> KeyRevocationBody:
        if self.replacement_key_id is not None and self.replacement_key_id == self.revoked_key_id:
            raise ValueError("replacement_key_id must differ from revoked_key_id")
        if self.compromised_at is not None:
            if self.reason != RevocationReason.KEY_COMPROMISE.value:
                raise ValueError("compromised_at is only allowed with reason key_compromise")
            if parse_rfc3339_timestamp(self.compromised_at) > self.revoked_at_datetime():
                raise ValueError("compromised_at must not be after revoked_at")
        return self

    def revoked_at_datetime(self) -> datetime:
        """``revoked_at`` as an aware UTC ``datetime``."""
        return parse_rfc3339_timestamp(self.revoked_at)


def canonical_revocation_bytes(body: KeyRevocationBody) -> bytes:
    """The exact bytes a ``key.revocation`` signature covers.

    Every model field except ``signature``, absent optionals as ``null``,
    sorted keys, compact separators.  The one exception is
    ``compromised_at``: it is omitted when absent, so revocations signed
    before the field existed keep verifying byte-for-byte.  When present
    it is covered like every other field, so it cannot be added or
    stripped without breaking the signature.
    """
    canonical = {
        k: v for k, v in body.model_dump(mode="json").items() if k != "signature"
    }
    if canonical.get("compromised_at") is None:
        canonical.pop("compromised_at", None)
    # Same canonical JSON as every other signed AMP artefact: sorted keys,
    # compact separators, UTF-8 (no \\u escaping).
    return json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def validate_revocation_signature(body: KeyRevocationBody, public_key_bytes: bytes) -> bool:
    """Verify the Ed25519 signature over the canonical revocation fields.

    The canonical message is a JSON object with fields sorted alphabetically,
    excluding the ``signature`` field itself.

    Callers receiving a key.revocation message MUST call this function
    to verify the signature before acting on the revocation. Unverified
    revocations MUST be discarded.

    Args:
        body: The key revocation body containing the signature to verify.
        public_key_bytes: Raw 32-byte Ed25519 public key of the revoking agent.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        logger.error(
            "cryptography package not installed — cannot verify revocation signature. "
            "Install with: pip install cryptography"
        )
        return False

    # Build the canonical message from the full set of model fields except
    # ``signature`` (see :func:`canonical_revocation_bytes`). Using
    # ``model_dump`` means new fields added to KeyRevocationBody are
    # automatically covered.
    message = canonical_revocation_bytes(body)

    try:
        import base64

        signature_bytes = base64.urlsafe_b64decode(body.signature + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except Exception as exc:
        logger.warning("Revocation signature verification failed: %s", exc)
        return False


def is_revocation_authentic(body: KeyRevocationBody, public_key_bytes: bytes) -> bool:
    """Verify a key revocation is authentic before acting on it.

    Returns True only if the signature is valid for the given public key.
    Callers MUST call this before revoking any keys.
    """
    return validate_revocation_signature(body, public_key_bytes)


# ---------------------------------------------------------------------------
# Revocation broadcast + pluggable store
# ---------------------------------------------------------------------------


class KeyRevocationBroadcastBody(BaseModel):
    """body.type = 'key.revocation_broadcast' — Fan-out envelope for a revocation.

    Used when a peer forwards a previously-received :class:`KeyRevocationBody`
    to its own trust-graph neighbours so caches across the mesh converge
    on the revoked key. The inner ``revocation`` MUST be carried verbatim
    (including its signature) so downstream receivers can independently
    verify authenticity via :func:`is_revocation_authentic`.
    """

    revocation: KeyRevocationBody = Field(
        description="The original signed revocation being rebroadcast",
    )
    broadcast_by: str = Field(
        description="agent:// URI of the peer rebroadcasting the revocation",
    )
    broadcast_at: str = Field(
        description="ISO-8601 timestamp when this hop rebroadcast the notice",
    )
    hop_count: int = Field(
        default=0,
        ge=0,
        description="Number of hops the broadcast has traversed",
    )

    model_config = {"extra": "ignore"}


class RevocationStore(Protocol):
    """Platform hook for persistent revocation state.

    Implementations plug in via :func:`register_revocation_store`. Callers
    should query :func:`should_reject_cached_key` before trusting any
    cached public key material. The default (unconfigured) store is
    permissive — it returns False for every key — and logs a one-time
    warning. If a store's ``is_revoked`` raises, the key is treated as
    revoked (fail closed).
    """

    def is_revoked(self, key_id: str) -> bool:
        ...


class _UnconfiguredRevocationStore:
    """Default store — distinguishable from both fail-open and fail-closed.

    Reports keys as not-revoked (so verification can proceed) but logs a
    persistent warning so operators know revocation is not actually
    enforced. The previous default silently returned False with no
    indication; the new fail-closed-on-strict variant was too disruptive
    to existing deployments. This is the middle ground.

    Production deployments MUST register either:
      * A real :class:`RevocationStore` backed by the host's KV store, OR
      * :class:`AllowAllRevocationStore` to explicitly opt into fail-open
        (an audit-trail decision rather than silent default).

    Callers that want strict fail-closed behaviour can register
    :class:`StrictUnconfiguredRevocationStore` instead.
    """

    _warned: bool = False

    def is_revoked(self, key_id: str) -> bool:
        if not type(self)._warned:
            logger.warning(
                "key_revocation: no RevocationStore registered — running with "
                "PERMISSIVE default. Call register_revocation_store() at startup "
                "with either a real store, AllowAllRevocationStore(), or "
                "StrictUnconfiguredRevocationStore() to make the choice explicit."
            )
            type(self)._warned = True
        return False


class StrictUnconfiguredRevocationStore:
    """Opt-in fail-CLOSED store: every key treated as revoked.

    Production deployments that want hard fail-closed semantics until a
    real revocation store is wired register this explicitly:

        register_revocation_store(StrictUnconfiguredRevocationStore())
    """

    def is_revoked(self, key_id: str) -> bool:
        return True


class AllowAllRevocationStore:
    """Opt-in fail-open store: nothing is ever considered revoked.

    Use ONLY in test fixtures, local dev, or deployments that have made an
    explicit, audited decision not to track revocations. Register at startup
    via :func:`register_revocation_store(AllowAllRevocationStore())`.
    """

    def is_revoked(self, key_id: str) -> bool:
        return False


_revocation_store: RevocationStore = _UnconfiguredRevocationStore()


def register_revocation_store(store: RevocationStore) -> None:
    """Register a platform-provided revocation store.

    Host platforms plug in a store backed by their KV / DB layer so every
    agent in the mesh shares a consistent view of revoked keys.
    """
    global _revocation_store
    _revocation_store = store


def should_reject_cached_key(key_id: str) -> bool:
    """Return True when *key_id* is known-revoked.

    Receivers holding a cached public key MUST consult this helper before
    verifying signatures; revoked keys MUST NOT be trusted even if the
    signature math checks out. Thin wrapper around the registered
    :class:`RevocationStore`.

    Fail-closed: if the store raises (backend unavailable, timeout, bug),
    the key is treated as revoked. An outage of the revocation backend must
    never silently re-enable a compromised key.
    """
    try:
        return bool(_revocation_store.is_revoked(key_id))
    except Exception as exc:
        logger.error(
            "RevocationStore.is_revoked raised for %s — treating key as "
            "revoked (fail closed): %s", key_id, exc,
        )
        return True


def revocation_verify_cached_key(key_id: str) -> bool:
    """Return True when the cached key *key_id* is still valid.

    Inverse of :func:`should_reject_cached_key` — kept as a readable alias
    for callers whose flow reads as "verify this cached key is OK".
    """
    return not should_reject_cached_key(key_id)


# ---------------------------------------------------------------------------
# Key status: compromise vs rotation semantics (WIRE-BINDING 12.12.1)
# ---------------------------------------------------------------------------


class KeyStatus(str, Enum):
    """What a verifier knows about one ``(agent_id, kid)`` signing key."""

    ACTIVE = "active"
    """Key is known and not revoked."""
    ROTATED = "rotated"
    """Revoked with ``key_rotation``: valid only for signatures made before ``revoked_at``."""
    COMPROMISED = "compromised"
    """Revoked with ``key_compromise``: no signature by this key is valid."""
    DECOMMISSIONED = "decommissioned"
    """Revoked with ``agent_decommissioned``: no signature by this key is valid."""
    UNKNOWN = "unknown"
    """Verifier has no record of this key: never accepted (fail closed)."""


_REASON_TO_STATUS: dict[str, KeyStatus] = {
    RevocationReason.KEY_ROTATION.value: KeyStatus.ROTATED,
    RevocationReason.KEY_COMPROMISE.value: KeyStatus.COMPROMISED,
    RevocationReason.AGENT_DECOMMISSIONED.value: KeyStatus.DECOMMISSIONED,
}

#: Relative strength, so that a weaker status never replaces a stronger one.
_STRENGTH: dict[KeyStatus, int] = {
    KeyStatus.ACTIVE: 0,
    KeyStatus.ROTATED: 1,
    KeyStatus.DECOMMISSIONED: 2,
    KeyStatus.COMPROMISED: 3,
}


def key_status_for_reason(reason: str | RevocationReason) -> KeyStatus:
    """Map a revocation ``reason`` to the :class:`KeyStatus` it implies.

    Raises ``ValueError`` for an unknown reason (never guesses a weaker status).
    """
    value = reason.value if isinstance(reason, RevocationReason) else reason
    try:
        return _REASON_TO_STATUS[value]
    except (KeyError, TypeError):
        raise ValueError(f"unknown revocation reason {reason!r}") from None


def _aware(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return None
    return value


def signature_allowed(
    status: KeyStatus,
    *,
    signed_at: datetime,
    revoked_at: datetime | None,
) -> bool:
    """Decide whether a signature by a key in *status* may be accepted.

    * ``ACTIVE``: yes.
    * ``ROTATED``: only if ``signed_at < revoked_at`` (strictly before).  A
      missing ``revoked_at`` fails closed.  Rotation is not compromise, so
      the key holder's own ``signed_at`` is trusted here; the artefact's
      own expiry still applies and is the caller's job.
    * ``COMPROMISED`` / ``DECOMMISSIONED`` / ``UNKNOWN``: never, whatever
      ``signed_at`` claims (a thief can back-date it).

    Naive (timezone-less) datetimes, non-``datetime`` values and
    unrecognised statuses all return ``False``.
    """
    if not isinstance(status, KeyStatus):
        return False
    if _aware(signed_at) is None:
        return False
    if status is KeyStatus.ACTIVE:
        return True
    if status is KeyStatus.ROTATED:
        revoked = _aware(revoked_at)
        if revoked is None:
            return False
        return signed_at < revoked
    return False


def delegation_key_check(
    resolver: Any,
    *,
    unknown_is_active: bool = False,
) -> Callable[[str, str, datetime], bool]:
    """Adapt a key-status resolver to ``validate_chain_v2(key_status=...)``.

    The returned callable answers "may (agent, kid) be relied on for a
    signature made at ``signed_at``?" using :func:`signature_allowed`.
    *resolver* needs ``key_status(agent_id, kid)``; when it also has
    ``record(agent_id, kid)`` (as :class:`InMemoryKeyStatusResolver`
    does), the record's ``revoked_at`` lets rotated keys keep validating
    older links.

    Keys with no record are ``UNKNOWN`` and rejected, so verifiers should
    ``mark_active`` keys as they fetch them. Pass
    ``unknown_is_active=True`` only when the key itself comes from a source
    you already trust to drop revoked keys; a revoked key is still
    rejected either way, and so is an agent id with no canonical form.
    """

    def check(agent_id: str, kid: str, signed_at: datetime) -> bool:
        try:
            # A spelling with no canonical form could dodge a revocation
            # stored under the canonical one: refuse it outright.
            canonical_agent_id(agent_id)
            _check_token(kid, "kid", MAX_KEY_ID_LENGTH)
            revoked_at = None
            record_fn = getattr(resolver, "record", None)
            if callable(record_fn):
                record = record_fn(agent_id, kid)
                status = record.status if record is not None else KeyStatus.UNKNOWN
                revoked_at = record.revoked_at if record is not None else None
            else:
                status = resolver.key_status(agent_id, kid)
        except Exception:
            return False
        if status is KeyStatus.UNKNOWN and unknown_is_active:
            status = KeyStatus.ACTIVE
        return signature_allowed(status, signed_at=signed_at, revoked_at=revoked_at)

    return check


@runtime_checkable
class KeyStatusResolver(Protocol):
    """Lookup interface verifiers call before trusting a signing key.

    Implementations MUST return :attr:`KeyStatus.UNKNOWN` (never ``ACTIVE``)
    for keys they have no record of, MUST NOT let a later observation
    downgrade a ``COMPROMISED`` / ``DECOMMISSIONED`` / ``ROTATED`` record,
    and SHOULD return ``UNKNOWN`` rather than raise; callers MUST treat an
    exception as ``UNKNOWN``.
    """

    def key_status(self, agent_id: str, kid: str) -> KeyStatus:
        ...


@dataclass(frozen=True)
class KeyStatusRecord:
    """One entry of :class:`InMemoryKeyStatusResolver`."""

    status: KeyStatus
    revoked_at: datetime | None = None


def canonical_agent_id(agent_id: str) -> str:
    """Canonical lookup key for *agent_id*; raises ``ValueError`` when malformed.

    ``agent://`` host and registry names are NFKC + IDNA normalised (the
    rules of :mod:`ampro.core.addressing`) and the whole id is lowercased,
    so ``agent://Bücher.example`` and ``agent://xn--bcher-kva.example``
    share one record.  Otherwise a revocation stored under one spelling
    could be sidestepped by asking about another.

    Spellings that DNS or URL parsers fold together but a string compare
    would not are refused rather than guessed at: a trailing ``.`` on the
    host or registry, and any path, query or fragment.  A port is dropped,
    because an agent's keys are published per host (``agent.json`` lives
    at ``https://<host>/.well-known/``), so ``agent://h:8443`` and
    ``agent://h`` are the same signer for revocation purposes.
    """
    if not isinstance(agent_id, str):
        raise ValueError("agent_id must be a string")
    _check_token(agent_id, "agent_id", MAX_REVOCATION_AGENT_ID_LENGTH)
    from urllib.parse import unquote

    from ampro.core.addressing import AddressType, _normalize_host, parse_agent_uri

    if agent_id[:8].lower() == "agent://":
        authority = agent_id[8:]
        if any(ch in unquote(authority) for ch in "/?#\\"):
            raise ValueError("agent_id must not carry a path, query or fragment")
        address = parse_agent_uri("agent://" + authority)
        if address.address_type is AddressType.SLUG:
            registry = address.registry or ""
            if registry.endswith(".") or (address.slug or "").endswith("."):
                raise ValueError("agent_id must not end with '.'")
            address = address.model_copy(update={"registry": _normalize_host(registry)})
        elif address.address_type is AddressType.HOST:
            if (address.host or "").endswith("."):
                raise ValueError("agent_id host must not end with '.'")
            address = address.model_copy(update={"port": None})
        return address.to_uri().lower()
    return unicodedata.normalize("NFKC", agent_id).lower()


class InMemoryKeyStatusResolver:
    """Bounded, thread-safe :class:`KeyStatusResolver` reference implementation.

    * :meth:`mark_active` records a key seen in the agent's current key set
      (for example its JWKS), optionally with its raw public key.  It never
      downgrades a revoked key.
    * :meth:`add_revocation` records a ``key.revocation`` only after its
      signature verifies against a key *of the agent being revoked*,
      looked up by ``signer_kid`` (never a key the caller merely hands in).
    * Unknown or malformed keys resolve to :attr:`KeyStatus.UNKNOWN`.

    Memory is split into three independently bounded pools, so no one of
    them can be flooded to block another:

    ``max_entries`` ACTIVE keys
        Least recently used first out.  An evicted key reads as
        ``UNKNOWN`` (fails closed) until it is seen again.
    ``max_revocations`` revocations of keys this store knew as ACTIVE
        These are the revocations that matter: they stop a key the
        verifier was relying on.  Revoking an ACTIVE key moves it here.
        When full, the oldest ``ROTATED`` record goes first, then
        ``DECOMMISSIONED``, then ``COMPROMISED``; every eviction is logged
        at ERROR.  An evicted record reads as ``UNKNOWN`` (refused), and
        only the agent's own live key set can make it ACTIVE again.
    ``max_unsolicited`` revocations of keys this store never saw ACTIVE
        Best effort, least recently used first out.  Such keys are already
        ``UNKNOWN`` and refused unless a caller opts into
        ``unknown_is_active``, so anyone able to mint identities can only
        churn this pool, never the other two.

    An agent with more than ``max_revocations_per_agent`` revocations in the
    second pool is collapsed into one agent-wide ``COMPROMISED`` record
    (every key of that agent is then refused).  Nothing ever raises because
    the store is full.
    """

    DEFAULT_MAX_ENTRIES = 100_000
    DEFAULT_MAX_REVOCATIONS = 25_000
    DEFAULT_MAX_UNSOLICITED = 10_000
    DEFAULT_MAX_REVOCATIONS_PER_AGENT = 64

    #: Eviction order for the revocation pool: weakest status first.
    _EVICTION_ORDER = (KeyStatus.ROTATED, KeyStatus.DECOMMISSIONED, KeyStatus.COMPROMISED)

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        *,
        max_revocations: int = DEFAULT_MAX_REVOCATIONS,
        max_unsolicited: int = DEFAULT_MAX_UNSOLICITED,
        max_revocations_per_agent: int = DEFAULT_MAX_REVOCATIONS_PER_AGENT,
    ) -> None:
        for name, value in (
            ("max_entries", max_entries),
            ("max_revocations", max_revocations),
            ("max_unsolicited", max_unsolicited),
            ("max_revocations_per_agent", max_revocations_per_agent),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self._max_active = max_entries
        self._max_revoked = max_revocations
        self._max_unsolicited = max_unsolicited
        self._max_per_agent = max_revocations_per_agent
        #: ACTIVE keys in LRU order (oldest first) -> raw public key or None.
        self._active: OrderedDict[tuple[str, str], bytes | None] = OrderedDict()
        #: Revocations of known keys, one insertion-ordered dict per status.
        self._revoked: dict[KeyStatus, OrderedDict[tuple[str, str], KeyStatusRecord]] = {
            status: OrderedDict() for status in self._EVICTION_ORDER
        }
        #: Raw public keys of revoked keys, kept so a key can still sign its
        #: own (repeated or upgraded) revocation.
        self._revoked_keys: dict[tuple[str, str], bytes] = {}
        self._revoked_per_agent: dict[str, int] = {}
        #: Agent-wide COMPROMISED records, oldest first; share the revocation budget.
        self._agent_tombstones: OrderedDict[str, None] = OrderedDict()
        #: Revocations of keys never seen ACTIVE; LRU, best effort.
        self._unsolicited: OrderedDict[tuple[str, str], KeyStatusRecord] = OrderedDict()
        self._lock = threading.Lock()

    # -- queries -------------------------------------------------------

    def key_status(self, agent_id: str, kid: str) -> KeyStatus:
        """Status of ``(agent_id, kid)``; ``UNKNOWN`` when malformed or unseen."""
        record = self.record(agent_id, kid)
        return record.status if record is not None else KeyStatus.UNKNOWN

    def record(self, agent_id: str, kid: str) -> KeyStatusRecord | None:
        """The full record (status and ``revoked_at``), or ``None`` when unknown."""
        try:
            key = self._key(agent_id, kid)
        except (ValueError, TypeError):
            return None
        with self._lock:
            if key[0] in self._agent_tombstones:
                return KeyStatusRecord(KeyStatus.COMPROMISED)
            revoked = self._find_revoked(key)
            if revoked is not None:
                return revoked
            unsolicited = self._unsolicited.get(key)
            if unsolicited is not None:
                self._unsolicited.move_to_end(key)
                return unsolicited
            if key in self._active:
                self._active.move_to_end(key)
                return KeyStatusRecord(KeyStatus.ACTIVE)
            return None

    def __len__(self) -> int:
        with self._lock:
            return (
                len(self._active)
                + sum(len(pool) for pool in self._revoked.values())
                + len(self._agent_tombstones)
                + len(self._unsolicited)
            )

    # -- updates -------------------------------------------------------

    def mark_active(
        self, agent_id: str, kid: str, *, public_key: bytes | None = None,
    ) -> bool:
        """Record ``(agent_id, kid)`` as a key in the agent's current key set.

        Pass the raw 32-byte Ed25519 *public_key* when you have it: it is
        what :meth:`add_revocation` later verifies that agent's revocations
        against.  Only call this with keys fetched from the agent's own
        key set (its JWKS or ``agent.json``), never with a key a message
        carried.

        Returns ``True`` when the key is (now) ``ACTIVE`` and ``False``
        (store unchanged) when it is already revoked or the agent is
        tombstoned.  Raises ``ValueError`` for malformed input.
        """
        key = self._key(agent_id, kid)
        if public_key is not None:
            public_key = _raw_ed25519(public_key)
        with self._lock:
            if (
                key[0] in self._agent_tombstones
                or self._find_revoked(key) is not None
                or key in self._unsolicited
            ):
                logger.warning(
                    "key_revocation: refusing to mark revoked key %s/%s active", *key,
                )
                return False
            if key in self._active:
                self._active.move_to_end(key)
                known = self._active[key]
                if public_key is not None and known != public_key:
                    if known is not None:
                        logger.warning(
                            "key_revocation: key material for %s/%s changed", *key,
                        )
                    self._active[key] = public_key
                return True
            if len(self._active) >= self._max_active:
                self._active.popitem(last=False)
            self._active[key] = public_key
            return True

    def add_revocation(
        self,
        body: KeyRevocationBody,
        revoked_at_dt: datetime,
        *,
        signer_kid: str,
        key_lookup: Callable[[str, str], bytes | None] | None = None,
    ) -> KeyStatus:
        """Record an authenticated revocation and return the resulting status.

        The signature is checked here, against a key that belongs to
        ``body.agent_id``: the key with id *signer_kid* of that same agent.
        That key comes from *key_lookup* (``(agent_id, kid) -> raw Ed25519
        public key or None``, which MUST resolve from the agent's own key
        set) when given, else from the key recorded by :meth:`mark_active`.
        So a revocation can never be ingested on the strength of a key that
        is not the revoked agent's own.

        The signing key must itself be usable: ACTIVE here (or, with
        *key_lookup*, at least not revoked here), unless it is the key being
        revoked (a key may always revoke itself).  A compromised key cannot
        revoke its agent's other keys.

        ``revoked_at_dt`` MUST be timezone-aware and equal ``body.revoked_at``.
        A stronger status is never replaced by a weaker one (``COMPROMISED``
        beats ``DECOMMISSIONED`` beats ``ROTATED`` beats ``ACTIVE``); of two
        ``ROTATED`` records the earlier ``revoked_at`` wins.

        Raises ``ValueError`` for bad input, an unknown or unusable signing
        key, or a signature that does not verify.
        """
        if not isinstance(body, KeyRevocationBody):
            raise ValueError("body must be a KeyRevocationBody")
        if _aware(revoked_at_dt) is None:
            raise ValueError("revoked_at_dt must be a timezone-aware datetime")
        if revoked_at_dt != body.revoked_at_datetime():
            raise ValueError("revoked_at_dt does not match body.revoked_at")
        target = self._key(body.agent_id, body.revoked_key_id)
        signer = self._key(body.agent_id, signer_kid)
        self_revocation = signer == target

        if key_lookup is not None:
            try:
                looked_up = key_lookup(body.agent_id, signer_kid)
            except Exception:
                looked_up = None
            if looked_up is None:
                raise ValueError("signing key not found in the agent's key set")
            public_key = _raw_ed25519(looked_up)
            with self._lock:
                if not self_revocation and self._is_revoked(signer):
                    raise ValueError("signing key is itself revoked")
        else:
            with self._lock:
                if signer in self._active:
                    public_key = self._active[signer]
                elif self_revocation:
                    public_key = self._revoked_keys.get(signer)
                else:
                    public_key = None
            if public_key is None:
                raise ValueError(
                    "no recorded public key for the signing key; mark_active() it "
                    "from the agent's key set or pass key_lookup"
                )

        if not is_revocation_authentic(body, public_key):
            raise ValueError("key.revocation signature does not verify; refusing to ingest")

        status = key_status_for_reason(body.reason)
        new = KeyStatusRecord(status, revoked_at_dt.astimezone(UTC))
        agent = target[0]

        with self._lock:
            if agent in self._agent_tombstones:
                self._agent_tombstones.move_to_end(agent)
                return KeyStatus.COMPROMISED
            current = self._find_revoked(target)
            if current is not None:
                merged = self._merge(current, new)
                if merged is not current:
                    del self._revoked[current.status][target]
                    self._revoked[merged.status][target] = merged
                return merged.status

            if target not in self._active:
                # Never seen ACTIVE here: best-effort pool only.
                current = self._unsolicited.get(target)
                merged = new if current is None else self._merge(current, new)
                self._unsolicited[target] = merged
                self._unsolicited.move_to_end(target)
                while len(self._unsolicited) > self._max_unsolicited:
                    self._unsolicited.popitem(last=False)
                return merged.status

            if self._revoked_per_agent.get(agent, 0) >= self._max_per_agent:
                self._tombstone(agent)
                logger.error(
                    "key_revocation: %s exceeded %d revoked keys; treating every key "
                    "of this agent as compromised",
                    agent, self._max_per_agent,
                )
                return KeyStatus.COMPROMISED
            key_bytes = self._active.pop(target)
            if key_bytes is not None:
                self._revoked_keys[target] = key_bytes
            self._revoked[status][target] = new
            self._revoked_per_agent[agent] = self._revoked_per_agent.get(agent, 0) + 1
            self._enforce_revocation_budget()
            return status

    # -- internals (caller holds the lock unless noted) ----------------

    @staticmethod
    def _key(agent_id: str, kid: str) -> tuple[str, str]:
        """Canonical ``(agent, kid)``; lock not needed.  Raises ``ValueError``."""
        agent = canonical_agent_id(agent_id)
        if not isinstance(kid, str):
            raise ValueError("kid must be a string")
        _check_token(kid, "kid", MAX_KEY_ID_LENGTH)
        return agent, kid

    def _find_revoked(self, key: tuple[str, str]) -> KeyStatusRecord | None:
        for pool in self._revoked.values():
            record = pool.get(key)
            if record is not None:
                return record
        return None

    def _is_revoked(self, key: tuple[str, str]) -> bool:
        return (
            key[0] in self._agent_tombstones
            or self._find_revoked(key) is not None
            or key in self._unsolicited
        )

    @staticmethod
    def _merge(current: KeyStatusRecord, new: KeyStatusRecord) -> KeyStatusRecord:
        if _STRENGTH[new.status] != _STRENGTH[current.status]:
            return new if _STRENGTH[new.status] > _STRENGTH[current.status] else current
        if current.revoked_at is None:
            return new
        if new.revoked_at is not None and new.revoked_at < current.revoked_at:
            return new
        return current

    def _revocation_count(self) -> int:
        return sum(len(pool) for pool in self._revoked.values()) + len(self._agent_tombstones)

    def _enforce_revocation_budget(self) -> None:
        while self._revocation_count() > self._max_revoked:
            for status in self._EVICTION_ORDER:
                pool = self._revoked[status]
                if pool:
                    key, _ = pool.popitem(last=False)
                    self._revoked_keys.pop(key, None)
                    self._decrement(key[0])
                    logger.error(
                        "key_revocation: revocation store full; evicted %s record "
                        "for %s/%s (it now reads as unknown)", status.value, *key,
                    )
                    break
            else:
                agent, _ = self._agent_tombstones.popitem(last=False)
                logger.error(
                    "key_revocation: revocation store full; evicted agent-wide "
                    "compromise record for %s (its keys now read as unknown)", agent,
                )

    def _decrement(self, agent: str) -> None:
        left = self._revoked_per_agent.get(agent, 0) - 1
        if left > 0:
            self._revoked_per_agent[agent] = left
        else:
            self._revoked_per_agent.pop(agent, None)

    def _tombstone(self, agent: str) -> None:
        for pool in self._revoked.values():
            for key in [k for k in pool if k[0] == agent]:
                del pool[key]
        for key in [k for k in self._revoked_keys if k[0] == agent]:
            del self._revoked_keys[key]
        for key in [k for k in self._active if k[0] == agent]:
            del self._active[key]
        for key in [k for k in self._unsolicited if k[0] == agent]:
            del self._unsolicited[key]
        self._revoked_per_agent.pop(agent, None)
        self._agent_tombstones[agent] = None
        self._enforce_revocation_budget()


def _raw_ed25519(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError("public key must be a raw 32-byte Ed25519 public key")
    return bytes(value)
