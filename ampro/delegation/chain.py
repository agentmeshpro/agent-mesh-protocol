"""
Agent Protocol — Delegation Chain Validation.

Supports multi-hop delegation where agent A delegates authority to agent B,
who may further delegate to agent C, with cryptographically verified scope
narrowing at each hop.

This module is PURE — only stdlib + pydantic + cryptography.
No platform-specific imports (app.*, etc.).
Designed for extraction as part of `pip install ampro`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field, field_validator

from ampro.delegation.v2 import (
    DEFAULT_MAX_LIFETIME,
    DEFAULT_MAX_UNREVOCABLE_LIFETIME,
    MAX_CHAIN_LINKS,
    DelegationLinkV2,
    ExtensionNarrowing,
    KeyResolver,
    KeyStatusCheck,
    RevocationCheck,
    VerificationKey,
    check_raw_link_size,
    validate_chain_v2,
)

# Clock skew tolerance — imported from canonical constant in trust.tiers.
from ampro.trust.tiers import CLOCK_SKEW_SECONDS

_SKEW = timedelta(seconds=CLOCK_SKEW_SECONDS)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DelegationLink(BaseModel):
    """A single hop in a delegation chain.

    Every field except ``signature`` is covered by the delegator's Ed25519
    signature (see :func:`canonical_link_payload`). Timestamps MUST carry
    an explicit UTC offset; naive datetimes are rejected at validation.
    """

    delegator: str = Field(description="Agent ID of the delegating agent")
    delegate: str = Field(description="Agent ID receiving the delegation")
    scopes: list[str] = Field(
        description="Scopes granted (e.g. ['tool:read', 'tool:execute'])"
    )
    max_depth: int = Field(
        default=3,
        description=(
            "Maximum number of links (including this one) permitted from "
            "this link onward. Each child MUST set max_depth <= parent - 1."
        ),
    )
    created_at: datetime = Field(description="When this link was created (tz-aware)")
    expires_at: datetime = Field(description="When this link expires (tz-aware)")
    signature: str = Field(
        default="",
        description="Base64-encoded Ed25519 signature by the delegator",
    )
    max_fan_out: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum parallel sub-delegations from this link",
    )
    trust_tier: str = Field(
        default="external",
        description="Effective trust tier at this link",
    )
    jwks_url: str = Field(
        default="",
        description="JWKS endpoint for the delegator's public key",
    )
    chain_budget: str = Field(
        default="",
        description="Chain budget string, e.g. 'remaining=3.50USD;max=5.00USD'",
    )

    model_config = {"extra": "ignore"}

    @field_validator("created_at", "expires_at")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError(
                "delegation timestamps must be timezone-aware (RFC 3339 with "
                "'Z' or an explicit offset); naive datetimes are rejected"
            )
        return v


class DelegationChain(BaseModel):
    """An ordered sequence of delegation links forming a chain of trust.

    Links are parsed as v2 (:class:`~ampro.delegation.v2.DelegationLinkV2`)
    when they carry ``"v": 2`` and as v1 when they carry no ``v``. Any
    other ``v`` is rejected, and a chain may not mix versions.
    """

    links: list[DelegationLink | DelegationLinkV2] = Field(
        default_factory=list,
        description="Ordered delegation links (root first)",
    )

    @field_validator("links", mode="before")
    @classmethod
    def _parse_versions(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        out: list[Any] = []
        for raw in value:
            if isinstance(raw, DelegationLink | DelegationLinkV2):
                out.append(raw)
                continue
            if isinstance(raw, Mapping) and "v" in raw:
                if raw["v"] != 2 or isinstance(raw["v"], bool):
                    raise ValueError("unsupported delegation link version")
                if len(value) > MAX_CHAIN_LINKS:
                    raise ValueError(f"a chain may have at most {MAX_CHAIN_LINKS} links")
                check_raw_link_size(raw)
                out.append(DelegationLinkV2.model_validate(raw))
            else:
                out.append(DelegationLink.model_validate(raw))
        if len({type(link) for link in out}) > 1:
            raise ValueError("a delegation chain must not mix link versions")
        return out

    @property
    def version(self) -> int:
        """1 or 2; an empty chain reports 1."""
        return 2 if self.links and isinstance(self.links[0], DelegationLinkV2) else 1

    @property
    def depth(self) -> int:
        """Number of hops in the chain."""
        return len(self.links)

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Canonical serialization (for signing)
# ---------------------------------------------------------------------------


def canonical_timestamp(value: datetime) -> str:
    """Render a tz-aware datetime as canonical RFC 3339 UTC with ``Z``.

    Format: ``YYYY-MM-DDTHH:MM:SSZ``, or ``YYYY-MM-DDTHH:MM:SS.ffffffZ``
    when the value has a non-zero microsecond component.

    Raises:
        ValueError: If *value* is naive.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetime cannot be canonicalised")
    utc = value.astimezone(UTC)
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        base += f".{utc.microsecond:06d}"
    return base + "Z"


def canonical_link_payload(
    link: DelegationLink,
    parent_delegate: str | None = None,
) -> dict:
    """Return the dict that is signed for *link*.

    Contains **every** model field except ``signature`` (so trust_tier,
    chain_budget, jwks_url, max_fan_out, ... are all tamper-evident), plus
    ``parent_delegate`` binding the link to its chain position. Scopes are
    sorted and timestamps canonicalised via :func:`canonical_timestamp`.
    """
    data = link.model_dump(exclude={"signature"})
    data["created_at"] = canonical_timestamp(link.created_at)
    data["expires_at"] = canonical_timestamp(link.expires_at)
    data["scopes"] = sorted(link.scopes)
    data["parent_delegate"] = parent_delegate
    return data


def _canonical_link_bytes(
    link: DelegationLink,
    parent_delegate: str | None = None,
) -> bytes:
    """
    Produce deterministic JSON bytes for a delegation link,
    excluding the ``signature`` field.

    Keys are sorted, no whitespace, ``ensure_ascii=False`` and UTF-8, so
    that any compliant implementation can reproduce the same bytes.

    Args:
        link: The delegation link to serialize.
        parent_delegate: The ``delegate`` field of the parent link (or
            ``None`` for the root link).  Including this value in the
            canonical payload binds the signature to a specific position
            in a specific chain, preventing cross-chain transplant attacks.
    """
    return json.dumps(
        canonical_link_payload(link, parent_delegate),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def delegation_link_id(link: DelegationLink) -> str:
    """Stable identifier for a link, used as the key in ``fan_out_counts``.

    SHA-256 (hex) over the link's canonical signed bytes (root-position
    form) concatenated with its signature, so distinct grants never share
    an id.
    """
    h = hashlib.sha256()
    h.update(_canonical_link_bytes(link, None))
    h.update(b"\x00")
    h.update(link.signature.encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------


def validate_scope_narrowing(
    parent_scopes: list[str], child_scopes: list[str]
) -> bool:
    """
    Check that *child_scopes* is a subset of *parent_scopes*.

    Supports wildcard matching with strict prefix hierarchy:

    - ``*`` (universal wildcard) in the parent allows any child scope.
    - ``tool:*`` in the parent allows ``tool:read``, ``tool:execute``,
      ``tool:sub:read``, and ``tool:*`` (any scope starting with ``tool:``).
    - ``tool:*`` does NOT permit ``admin:*``, ``data:read``, or any scope
      whose prefix differs from ``tool``.
    - An explicit scope like ``tool:read`` only permits ``tool:read``
      (exact match).

    An empty child scope list is considered invalid (useless delegation).

    Returns True if the child scopes are a valid narrowing.
    """
    MAX_SCOPES = 100
    if len(child_scopes) > MAX_SCOPES or len(parent_scopes) > MAX_SCOPES:
        return False

    if not child_scopes:
        return False

    parent_set = set(parent_scopes)

    # Universal wildcard — parent grants everything.
    has_universal = "*" in parent_set

    # Pre-compute wildcard prefixes for efficient matching.
    # "tool:*" → prefix "tool:" so that "tool:read", "tool:sub:x" all match.
    wildcard_prefixes: list[str] = []
    for ps in parent_scopes:
        if ps.endswith(":*"):
            wildcard_prefixes.append(ps[:-1])  # "tool:*" → "tool:"

    for scope in child_scopes:
        # Universal wildcard in parent → everything allowed
        if has_universal:
            continue

        # Direct / exact match
        if scope in parent_set:
            continue

        # Wildcard prefix match: child scope must start with one of the
        # parent's wildcard prefixes (e.g. parent "tool:*" → prefix
        # "tool:" covers child "tool:read", "tool:sub:read", "tool:*").
        if any(scope.startswith(wp) for wp in wildcard_prefixes):
            continue

        # No match found
        return False

    return True


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_delegation(
    private_key_bytes: bytes,
    link_data: dict | DelegationLink,
    parent_delegate: str | None = None,
) -> str:
    """
    Sign the canonical form of a delegation link with Ed25519.

    *link_data* is first validated as a :class:`DelegationLink` (so model
    defaults are filled in and timestamps normalised) and then serialised
    via :func:`canonical_link_payload` — exactly the bytes the verifier in
    :func:`validate_chain` reconstructs. Every field except ``signature``
    is signed.

    The ``parent_delegate`` is injected into the canonical payload before
    signing so that the resulting signature is bound to a specific chain
    position, preventing cross-chain transplant attacks.

    Args:
        private_key_bytes: Raw 32-byte Ed25519 private key seed.
        link_data: Dict (or model) representing the delegation link fields.
            Timestamps may be tz-aware datetimes or RFC 3339 strings with
            ``Z`` / an explicit offset.
        parent_delegate: The ``delegate`` of the parent link, or ``None``
            for the root link.

    Returns:
        Base64-encoded signature string.
    """
    if isinstance(link_data, DelegationLink):
        link = link_data
    else:
        link = DelegationLink.model_validate(
            {k: v for k, v in link_data.items() if k != "signature"}
        )
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    payload = _canonical_link_bytes(link, parent_delegate=parent_delegate)
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("ascii")


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


def validate_chain(
    chain: DelegationChain,
    public_keys: dict[str, bytes] | None = None,
    *,
    fan_out_counts: Mapping[str, int] | None = None,
    allow_v1: bool = False,
    holder: str | None = None,
    keys: KeyResolver | Mapping[tuple[str, str], VerificationKey] | None = None,
    audience: str | None = None,
    understood_extensions: (
        tuple[str, ...] | frozenset[str] | Mapping[str, ExtensionNarrowing]
    ) = (),
    key_status: KeyStatusCheck | None = None,
    is_revoked: RevocationCheck | None = None,
    max_lifetime: timedelta = DEFAULT_MAX_LIFETIME,
    max_unrevocable_lifetime: timedelta = DEFAULT_MAX_UNREVOCABLE_LIFETIME,
) -> tuple[bool, str]:
    """
    Validate every link in a delegation chain.

    A v2 chain is handed to :func:`ampro.delegation.v2.validate_chain_v2`
    with *keys*, *audience*, *understood_extensions*, *key_status*,
    *is_revoked*, *fan_out_counts* and the lifetime caps; it fails if
    *keys* or *holder* is not given. *holder* is the agent that
    exercises the authority and must be the chain's final delegate (see
    :func:`ampro.delegation.v2.validate_chain_v2`).

    A v1 chain uses *public_keys* and is refused unless *allow_v1* is
    true: v1 links cannot carry an audience, a principal, typed limits or
    must-understand extensions, and their unknown fields are unsigned.
    When *holder* is given it is checked against v1 chains too.

    Checks performed for each link (in order):
      0. No self-delegation.
      1. Delegator's public key is available.
      2. Ed25519 signature over the canonical link (ALL fields except
         ``signature``, plus ``parent_delegate``) is valid.
      3. Link has not expired / is not from the future.
      4. Depth: ``max_depth >= 1``; for children
         ``max_depth <= parent.max_depth - 1``; and the total chain length
         MUST NOT exceed the root's ``max_depth``.
      5. Scopes are a valid narrowing of the parent link's scopes.
      6. Chain continuity: each link's delegator equals the previous
         link's delegate.
      7. Temporal nesting: each link's validity window is within
         its parent's.
      8. Fan-out: when *fan_out_counts* is supplied, every non-terminal
         link's recorded sub-delegation count MUST be below its
         ``max_fan_out``.
      9. Budget (fail-closed): ``chain_budget`` must parse, satisfy
         ``0 < remaining <= max``, and both values must be
         non-increasing along the chain. Once a link carries a budget,
         all descendants MUST carry one.

    Args:
        chain: The delegation chain to validate.
        public_keys: Mapping of agent_id -> raw 32-byte Ed25519 public key.
        fan_out_counts: Optional mapping of :func:`delegation_link_id` ->
            number of sub-delegations ALREADY issued under that link,
            excluding the chain being validated. When provided, a
            non-terminal link whose count is ``>= max_fan_out`` fails the
            chain. Callers increment the count after accepting the chain.
            When ``None`` the fan-out limit cannot be checked (stateless
            validation) and is skipped.

    Returns:
        ``(True, "valid")`` on success, or ``(False, reason)`` on failure.
    """
    if not chain.links:
        return False, "empty chain"

    if chain.version == 2:
        if keys is None:
            return False, "v2 chain needs a key resolver (keys=...)"
        if holder is None:
            return False, "v2 chain needs the holder (holder=...)"
        return validate_chain_v2(
            chain.links,  # type: ignore[arg-type]
            keys,
            holder=holder,
            audience=audience,
            understood_extensions=understood_extensions,
            key_status=key_status,
            is_revoked=is_revoked,
            fan_out_counts=fan_out_counts,
            max_lifetime=max_lifetime,
            max_unrevocable_lifetime=max_unrevocable_lifetime,
        )

    if not allow_v1:
        return False, "v1 delegation links are not accepted (pass allow_v1=True)"
    if public_keys is None:
        return False, "v1 chain needs public_keys"
    if holder is not None and chain.links[-1].delegate != holder:
        return False, "chain was not issued to the holder"

    now = datetime.now(UTC)

    root = chain.links[0]
    if len(chain.links) > root.max_depth:
        return (
            False,
            f"chain depth {len(chain.links)} exceeds root max_depth {root.max_depth}",
        )

    for i, link in enumerate(chain.links):
        parent = chain.links[i - 1] if i > 0 else None

        # --- 0. Self-delegation check ---
        if link.delegator == link.delegate:
            return False, f"link {i}: self-delegation not allowed ({link.delegator})"

        # --- 1. Public key lookup ---
        pub_bytes = public_keys.get(link.delegator)
        if pub_bytes is None:
            return False, f"link {i}: unknown delegator '{link.delegator}'"

        # --- 2. Signature verification (all fields, context-bound) ---
        parent_delegate = parent.delegate if parent is not None else None
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            payload = _canonical_link_bytes(link, parent_delegate=parent_delegate)
            sig_bytes = base64.b64decode(link.signature, validate=True)
            pub_key.verify(sig_bytes, payload)
        except Exception as exc:
            return False, f"link {i}: invalid signature ({type(exc).__name__})"

        # --- 3. Expiry check (with clock skew tolerance) ---
        if link.expires_at <= now - _SKEW:
            return (
                False,
                f"link {i}: expired (expires_at={canonical_timestamp(link.expires_at)})",
            )

        if link.created_at > now + _SKEW:
            return False, f"link {i}: created_at is in the future"

        # --- 4. Depth check ---
        if link.max_depth < 1:
            return False, f"link {i}: max_depth {link.max_depth} must be >= 1"
        if parent is not None and link.max_depth > parent.max_depth - 1:
            return (
                False,
                f"link {i}: max_depth {link.max_depth} must be <= parent "
                f"max_depth - 1 ({parent.max_depth - 1})",
            )

        # --- 5. Scope narrowing ---
        if not link.scopes:
            return False, f"link {i}: a delegation must grant at least one scope"
        if parent is not None and not validate_scope_narrowing(
            parent.scopes, link.scopes
        ):
            return (
                False,
                f"link {i}: scopes {link.scopes} not subset of parent {parent.scopes}",
            )

        # --- 6. Chain continuity ---
        if parent is not None and link.delegator != parent.delegate:
            return (
                False,
                f"link {i}: delegator '{link.delegator}' != "
                f"previous delegate '{parent.delegate}'",
            )

        # --- 7. Temporal nesting ---
        if parent is not None:
            if link.created_at < parent.created_at - _SKEW:
                return (
                    False,
                    f"link {i}: created_at precedes parent's created_at",
                )
            if link.expires_at > parent.expires_at + _SKEW:
                return (
                    False,
                    f"link {i}: expires_at exceeds parent's expires_at",
                )

        # --- 8. Fan-out check (stateful; needs a counter store) ---
        if fan_out_counts is not None and i < len(chain.links) - 1:
            issued = fan_out_counts.get(delegation_link_id(link), 0)
            if issued >= link.max_fan_out:
                return (
                    False,
                    f"link {i}: max_fan_out {link.max_fan_out} exhausted "
                    f"({issued} sub-delegations already issued)",
                )

        # --- 9. Budget check (fail-closed) ---
        if link.chain_budget:
            try:
                remaining, max_b = parse_chain_budget(link.chain_budget)
            except ValueError as e:
                return False, f"link {i}: invalid chain_budget ({e})"
            if remaining <= 0:
                return False, f"link {i}: chain budget exhausted (remaining={remaining})"
            if remaining > max_b:
                return (
                    False,
                    f"link {i}: chain budget remaining ({remaining}) exceeds max ({max_b})",
                )
            if parent is not None and parent.chain_budget:
                # Parent already parsed successfully on the previous iteration.
                parent_remaining, parent_max = parse_chain_budget(parent.chain_budget)
                if remaining > parent_remaining:
                    return (
                        False,
                        f"link {i}: child budget ({remaining}) "
                        f"exceeds parent budget ({parent_remaining})",
                    )
                if max_b > parent_max:
                    return (
                        False,
                        f"link {i}: child budget max ({max_b}) "
                        f"exceeds parent budget max ({parent_max})",
                    )
        elif parent is not None and parent.chain_budget:
            return (
                False,
                f"link {i}: chain_budget dropped (parent budget "
                f"{parent.chain_budget!r} must be carried forward)",
            )

    return True, "valid"


# ---------------------------------------------------------------------------
# Chain budget + visited agents helpers
# ---------------------------------------------------------------------------

# Pre-compiled regex for chain budget parsing (non-backtracking pattern)
_BUDGET_RE = re.compile(r"remaining=(\d+(?:\.\d+)?)USD;max=(\d+(?:\.\d+)?)USD")


def parse_chain_budget(budget: str) -> tuple[float, float]:
    """Parse a Chain-Budget header value into (remaining, max) floats."""
    match = _BUDGET_RE.fullmatch(budget)
    if not match:
        raise ValueError(f"Invalid chain budget format: {budget!r}")
    return float(match.group(1)), float(match.group(2))


def normalize_agent_uri(uri: str) -> str:
    """
    Normalize an agent URI for consistent comparison.

    Strips leading/trailing whitespace and lowercases the URI so that
    ``agent://A`` and ``agent://a `` are treated as the same agent.
    """
    return uri.strip().lower()


def parse_visited_agents(header: str) -> set[str]:
    """
    Parse Visited-Agents header into a set of **normalized** agent URIs.

    Each URI is stripped and lowercased so that case/whitespace variations
    are collapsed into a single canonical form.
    """
    if not header:
        return set()
    return {normalize_agent_uri(a) for a in header.split(",") if a.strip()}


def check_visited_agents_loop(header: str, self_uri: str) -> bool:
    """
    Check if *self_uri* is already in the Visited-Agents list.

    Both the header entries and *self_uri* are normalized before comparison
    so that case and whitespace differences do not bypass loop detection.

    Returns True if a loop is detected.
    """
    agents = parse_visited_agents(header)
    return normalize_agent_uri(self_uri) in agents


def check_visited_agents_limit(header: str, max_agents: int = 20) -> bool:
    """Check if the Visited-Agents count is within limits. Returns True if within limit."""
    agents = parse_visited_agents(header)
    return len(agents) <= max_agents
