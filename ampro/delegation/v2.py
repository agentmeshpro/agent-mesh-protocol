"""
Agent Protocol — Delegation link format v2.

Version 1 links (``ampro.delegation.chain.DelegationLink``) sign a fixed
list of fields and ignore everything else, so any restriction added later
is silently dropped by an older verifier. Version 2 closes that gap and
adds the fields every bridge to another agent protocol needs:

* **Whole-link signing.** Every member except ``signature`` is signed,
  extension members included, plus the parent's ``link_id`` and
  ``delegate``.
* **Must-understand.** ``crit`` names extension members a verifier MUST
  understand; a verifier that does not understand one rejects the chain.
* **Algorithm agility.** ``alg`` (``EdDSA`` or ``ES256``) and ``kid`` name
  the signing key. The key's own algorithm must match ``alg``.
* **Human principal.** ``principal`` names the person whose authority the
  chain carries, whether they were present, and how strongly they were
  authenticated. ``origin`` says where the root authority came from.
* **Audience.** ``aud`` limits where the authority may be exercised.
* **Typed constraints.** Money is integer minor units plus an ISO 4217
  currency. Constraints only ever narrow down a chain.
* **Revocable links.** ``link_id`` identifies every link; ``status_url``
  points at its revocation status; lifetimes are capped.
* **Presence and intent.** ``principal.present`` and ``intent_hash``
  record whether the person approved this specific intent.
* **Foreign credentials by reference.** ``credential_refs`` cite an OAuth
  grant, payment mandate or token by opaque id and digest, never the
  secret itself, and no link may outlive what it cites.

v2 links never appear in the same chain as v1 links.

This module is PURE — only stdlib + pydantic + cryptography.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from ampro.trust.tiers import CLOCK_SKEW_SECONDS
from ampro.wire.extensions import is_extension_name

_SKEW = timedelta(seconds=CLOCK_SKEW_SECONDS)

#: Signature algorithms a v2 link may name.
SUPPORTED_ALGS: frozenset[str] = frozenset({"EdDSA", "ES256"})

#: Hard limits. They bound the work a verifier does for one chain.
MAX_CHAIN_LINKS = 10
MAX_SCOPES = 100
MAX_SCOPE_LEN = 256
MAX_ID_LEN = 512
MAX_AUDIENCE = 20
MAX_CONSTRAINTS = 20
MAX_RESOURCE_IDS = 100
MAX_CREDENTIAL_REFS = 10
MAX_CRIT = 20
MAX_EXTENSION_MEMBERS = 20
MAX_LINK_BYTES = 16 * 1024
MAX_JSON_DEPTH = 8
MAX_MINOR_UNITS = 10**15
_MAX_SAFE_INT = 2**53 - 1

#: Default lifetime caps. A link without ``status_url`` cannot be revoked
#: before it expires, so it must be short-lived.
DEFAULT_MAX_LIFETIME = timedelta(days=90)
DEFAULT_MAX_UNREVOCABLE_LIFETIME = timedelta(hours=24)

_LINK_ID = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_KID = re.compile(r"^[\x21-\x7e]{1,128}$")
_SCOPE = re.compile(r"^[\x21-\x7e]{1,256}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_DIGEST = re.compile(r"^sha-256:[A-Za-z0-9_-]{43}$")
_TOKEN_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}$")
_OPAQUE_REF = re.compile(r"^[\x21-\x7e]{1,256}$")
_ACR = re.compile(r"^[\x21-\x7e]{1,256}$")
# A JWS / JWT in compact form: three base64url segments.
_COMPACT_JWS = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")

_HOST_PORT = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?::[0-9]{1,5})?$"
)
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)

_TRUST_TIERS = frozenset({"internal", "owner", "verified", "external"})


def _check_https_url(value: str, name: str) -> str:
    if len(value) > 2048:
        raise ValueError(f"{name} is too long")
    if not value.startswith("https://"):
        raise ValueError(f"{name} must be an https URL")
    if not value.isascii() or any(c.isspace() or ord(c) < 0x21 for c in value):
        raise ValueError(f"{name} must be ASCII without spaces (use punycode)")
    rest = value[len("https://"):]
    authority = re.split(r"[/?]", rest, maxsplit=1)[0]
    if "#" in value or not _HOST_PORT.fullmatch(authority):
        raise ValueError(f"{name} must be an https URL with a plain host, no userinfo or fragment")
    return value


def _check_identifier(value: str, name: str) -> str:
    if not value or len(value) > MAX_ID_LEN:
        raise ValueError(f"{name} must be 1..{MAX_ID_LEN} characters")
    if not value.isprintable() or any(c.isspace() for c in value):
        raise ValueError(f"{name} must not contain whitespace or control characters")
    return value


def _require_aware(v: datetime | None) -> datetime | None:
    if v is not None and (v.tzinfo is None or v.utcoffset() is None):
        raise ValueError(
            "timestamps must be timezone-aware (RFC 3339 with 'Z' or an offset)"
        )
    return v


def _parse_timestamp(v: Any) -> Any:
    """Accept only RFC 3339 strings with an offset, or aware datetimes.

    Pydantic would otherwise accept Unix numbers and other formats, and
    two implementations could then disagree on the signed value.
    """
    if isinstance(v, datetime):
        return _require_aware(v)
    if isinstance(v, str) and _RFC3339.fullmatch(v):
        return v
    raise ValueError("timestamps must be RFC 3339 strings with 'Z' or an explicit offset")


Timestamp = Annotated[datetime, BeforeValidator(_parse_timestamp)]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class Principal(BaseModel):
    """The human (or organisation) whose authority a chain carries.

    ``sub`` SHOULD be pairwise: a different subject value for each
    counterparty, so that merchants cannot correlate one person across
    sites.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    iss: str = Field(description="Who authenticated the principal (https URL or agent:// URI)")
    sub: str = Field(description="Subject identifier at the issuer; SHOULD be pairwise")
    acr: str | None = Field(default=None, description="Authentication context class")
    present: bool = Field(
        strict=True,
        description="True if the principal approved this delegation interactively",
    )

    @field_validator("iss")
    @classmethod
    def _iss(cls, v: str) -> str:
        if v.startswith("agent://"):
            return _check_identifier(v, "principal.iss")
        return _check_https_url(v, "principal.iss")

    @field_validator("sub")
    @classmethod
    def _sub(cls, v: str) -> str:
        if not 1 <= len(v) <= 256 or not v.isprintable():
            raise ValueError("principal.sub must be 1..256 printable characters")
        return v

    @field_validator("acr")
    @classmethod
    def _acr(cls, v: str | None) -> str | None:
        if v is not None and not _ACR.fullmatch(v):
            raise ValueError("principal.acr must be 1..256 visible ASCII characters")
        return v


class CredentialRef(BaseModel):
    """A foreign credential the root authority rests on, by reference only.

    ``ref`` is an opaque identifier (a grant id, mandate id, token
    reference). It MUST NOT be the credential itself: compact JWS/JWT
    values and bearer strings are rejected.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str = Field(description="Credential type, e.g. 'oauth-grant', 'ap2-mandate'")
    ref: str = Field(description="Opaque reference; never the secret")
    digest: str | None = Field(
        default=None,
        description="'sha-256:' + base64url digest of the credential, for audit",
    )
    expires_at: Timestamp | None = Field(
        default=None,
        description="When the referenced credential expires",
    )

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        if not _TOKEN_TYPE.fullmatch(v):
            raise ValueError("credential_refs[].type must be a lowercase token")
        return v

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not _OPAQUE_REF.fullmatch(v):
            raise ValueError("credential_refs[].ref must be 1..256 visible ASCII characters")
        if _COMPACT_JWS.fullmatch(v) or v.lower().startswith(("bearer", "basic")):
            raise ValueError(
                "credential_refs[].ref looks like a credential; pass a reference, not the secret"
            )
        return v

    @field_validator("digest")
    @classmethod
    def _digest(cls, v: str | None) -> str | None:
        if v is not None and not _DIGEST.fullmatch(v):
            raise ValueError("digest must be 'sha-256:' + 43 base64url characters")
        return v

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _require_aware(v)


class AmountConstraint(BaseModel):
    """Per-action spending cap, in integer minor units of ``currency``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["amount"]
    currency: str
    max_minor: int = Field(ge=0, le=MAX_MINOR_UNITS, strict=True)

    @field_validator("currency")
    @classmethod
    def _currency(cls, v: str) -> str:
        if not _CURRENCY.fullmatch(v):
            raise ValueError("currency must be an ISO 4217 code (three upper-case letters)")
        return v


class BudgetConstraint(BaseModel):
    """Total spend left for the chain, in integer minor units."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["budget"]
    currency: str
    remaining_minor: int = Field(ge=0, le=MAX_MINOR_UNITS, strict=True)
    max_minor: int = Field(ge=0, le=MAX_MINOR_UNITS, strict=True)

    @field_validator("currency")
    @classmethod
    def _currency(cls, v: str) -> str:
        if not _CURRENCY.fullmatch(v):
            raise ValueError("currency must be an ISO 4217 code (three upper-case letters)")
        return v

    @model_validator(mode="after")
    def _ordered(self) -> BudgetConstraint:
        if self.remaining_minor > self.max_minor:
            raise ValueError("budget remaining_minor must not exceed max_minor")
        return self


class CountConstraint(BaseModel):
    """Maximum number of actions the delegate may take under this link."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["count"]
    max: int = Field(ge=1, le=1_000_000, strict=True)


class ResourceConstraint(BaseModel):
    """Authority applies only to these resource ids (orders, accounts, ...)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["resource"]
    ids: list[str] = Field(min_length=1, max_length=MAX_RESOURCE_IDS)

    @field_validator("ids")
    @classmethod
    def _ids(cls, v: list[str]) -> list[str]:
        for item in v:
            _check_identifier(item, "resource id")
        if len(set(v)) != len(v):
            raise ValueError("resource ids must be unique")
        return v


Constraint = Annotated[
    AmountConstraint | BudgetConstraint | CountConstraint | ResourceConstraint,
    Field(discriminator="type"),
]


def _constraint_key(c: Any) -> tuple[str, str]:
    return (c.type, getattr(c, "currency", ""))


# ---------------------------------------------------------------------------
# The link
# ---------------------------------------------------------------------------

#: Members defined by v2. Anything else in a link is an extension member.
V2_MEMBERS: frozenset[str] = frozenset({
    "v", "link_id", "delegator", "delegate", "scopes", "max_depth",
    "max_fan_out", "created_at", "expires_at", "trust_tier", "alg", "kid",
    "jwks_url", "aud", "principal", "origin", "intent_hash",
    "credential_refs", "constraints", "status_url", "crit", "signature",
})

#: Members that are fixed at the root and MUST be identical on every link.
ROOT_BOUND_MEMBERS: tuple[str, ...] = (
    "principal", "origin", "intent_hash", "credential_refs",
)

Origin = Literal[
    "agent", "oauth", "pact", "pap", "ap2", "acp", "ucp", "network-token", "other",
]


def _check_json_value(value: Any, depth: int = 0) -> None:
    """Extension values: JSON with integers only, bounded depth.

    Floats are refused so that the canonical form is unambiguous across
    implementations.
    """
    if depth > MAX_JSON_DEPTH:
        raise ValueError("extension member nests too deeply")
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError("extension integers must fit in 53 bits")
        return
    if isinstance(value, float):
        raise ValueError("floating-point numbers are not allowed in signed links")
    if isinstance(value, list):
        for item in value:
            _check_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for k, item in value.items():
            if not isinstance(k, str):
                raise ValueError("extension object keys must be strings")
            _check_json_value(item, depth + 1)
        return
    raise ValueError(f"unsupported value type in extension member: {type(value).__name__}")


class DelegationLinkV2(BaseModel):
    """One hop in a v2 delegation chain. See the module docstring."""

    model_config = ConfigDict(extra="allow")

    v: Literal[2]
    link_id: str = Field(description="Unique id, >= 128 bits of base64url randomness")
    delegator: str
    delegate: str
    scopes: list[str] = Field(min_length=1, max_length=MAX_SCOPES)
    max_depth: int = Field(default=3, ge=1, le=MAX_CHAIN_LINKS, strict=True)
    max_fan_out: int = Field(default=3, ge=1, le=10, strict=True)
    created_at: Timestamp
    expires_at: Timestamp
    trust_tier: str = "external"
    alg: str
    kid: str
    jwks_url: str | None = None
    aud: list[str] | None = Field(default=None, min_length=1, max_length=MAX_AUDIENCE)
    principal: Principal | None = None
    origin: Origin = "agent"
    intent_hash: str | None = None
    credential_refs: list[CredentialRef] = Field(
        default_factory=list, max_length=MAX_CREDENTIAL_REFS
    )
    constraints: list[Constraint] = Field(default_factory=list, max_length=MAX_CONSTRAINTS)
    status_url: str | None = None
    crit: list[str] = Field(default_factory=list, max_length=MAX_CRIT)
    signature: str = ""

    @field_validator("link_id")
    @classmethod
    def _link_id(cls, v: str) -> str:
        if not _LINK_ID.fullmatch(v):
            raise ValueError("link_id must be 22..128 base64url characters (>= 128 bits)")
        return v

    @field_validator("delegator", "delegate")
    @classmethod
    def _agent(cls, v: str) -> str:
        return _check_identifier(v, "delegator/delegate")

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        for s in v:
            if not _SCOPE.fullmatch(s):
                raise ValueError("each scope must be 1..256 visible ASCII characters")
        if len(set(v)) != len(v):
            raise ValueError("scopes must be unique")
        return v

    @field_validator("created_at", "expires_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        _require_aware(v)
        return v

    @field_validator("trust_tier")
    @classmethod
    def _tier(cls, v: str) -> str:
        if v not in _TRUST_TIERS:
            raise ValueError(f"trust_tier must be one of {sorted(_TRUST_TIERS)}")
        return v

    @field_validator("alg")
    @classmethod
    def _alg(cls, v: str) -> str:
        if v not in SUPPORTED_ALGS:
            raise ValueError(f"alg must be one of {sorted(SUPPORTED_ALGS)}")
        return v

    @field_validator("kid")
    @classmethod
    def _kid(cls, v: str) -> str:
        if not _KID.fullmatch(v):
            raise ValueError("kid must be 1..128 visible ASCII characters")
        return v

    @field_validator("jwks_url", "status_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return None if v is None else _check_https_url(v, "url")

    @field_validator("aud")
    @classmethod
    def _aud(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for a in v:
            _check_identifier(a, "aud")
        if len(set(v)) != len(v):
            raise ValueError("aud entries must be unique")
        return v

    @field_validator("intent_hash")
    @classmethod
    def _intent(cls, v: str | None) -> str | None:
        if v is not None and not _DIGEST.fullmatch(v):
            raise ValueError("intent_hash must be 'sha-256:' + 43 base64url characters")
        return v

    @field_validator("constraints")
    @classmethod
    def _unique_constraints(cls, v: list[Any]) -> list[Any]:
        keys = [_constraint_key(c) for c in v]
        if len(set(keys)) != len(keys):
            raise ValueError("at most one constraint per (type, currency)")
        return v

    @field_validator("credential_refs")
    @classmethod
    def _unique_refs(cls, v: list[CredentialRef]) -> list[CredentialRef]:
        keys = [(r.type, r.ref) for r in v]
        if len(set(keys)) != len(keys):
            raise ValueError("credential_refs must be unique")
        return v

    @field_validator("crit")
    @classmethod
    def _crit(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("crit entries must be unique")
        for name in v:
            if name in V2_MEMBERS:
                raise ValueError(f"crit must not list a v2 member ({name})")
            if not is_extension_name(name):
                raise ValueError(f"crit entry {name!r} is not a valid extension name")
        return v

    @model_validator(mode="after")
    def _structure(self) -> DelegationLinkV2:
        if self.delegator == self.delegate:
            raise ValueError("self-delegation is not allowed")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        extras = self.model_extra or {}
        if len(extras) > MAX_EXTENSION_MEMBERS:
            raise ValueError(f"at most {MAX_EXTENSION_MEMBERS} extension members")
        for name, value in extras.items():
            if not is_extension_name(name):
                raise ValueError(
                    f"unknown member {name!r}: extension members need a namespaced name"
                )
            _check_json_value(value)
        for name in self.crit:
            if name not in extras:
                raise ValueError(f"crit names {name!r}, which the link does not carry")
        if self.origin != "agent":
            if self.principal is None:
                raise ValueError("a non-agent origin requires a principal")
            if not self.credential_refs:
                raise ValueError("a non-agent origin requires at least one credential_ref")
        if self.intent_hash is not None and self.principal is None:
            raise ValueError("intent_hash requires a principal")
        return self

    @property
    def extension_members(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def _ts(value: datetime) -> str:
    utc = value.astimezone(UTC)
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        base += f".{utc.microsecond:06d}"
    return base + "Z"


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return {k: _dump(v) for k, v in value.model_dump().items() if v is not None}
    if isinstance(value, datetime):
        return _ts(value)
    if isinstance(value, dict):
        return {k: _dump(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_dump(v) for v in value]
    return value


def canonical_link_v2_payload(
    link: DelegationLinkV2,
    parent: DelegationLinkV2 | None = None,
) -> dict[str, Any]:
    """Return the object that is signed for *link*.

    Every member except ``signature`` (extension members included), with
    absent optional members omitted, defaults filled in, ``scopes``
    sorted, timestamps in canonical UTC form, plus ``parent_link_id`` and
    ``parent_delegate`` (``null`` for the root) binding the link to its
    exact parent.
    """
    data: dict[str, Any] = {}
    for name in DelegationLinkV2.model_fields:
        if name == "signature":
            continue
        value = getattr(link, name)
        if value is None:
            continue
        data[name] = _dump(value)
    data["scopes"] = sorted(link.scopes)
    for name, value in (link.model_extra or {}).items():
        data[name] = value
    data["parent_link_id"] = parent.link_id if parent is not None else None
    data["parent_delegate"] = parent.delegate if parent is not None else None
    return data


def canonical_link_v2_bytes(
    link: DelegationLinkV2,
    parent: DelegationLinkV2 | None = None,
) -> bytes:
    """Canonical UTF-8 JSON bytes (sorted keys, no whitespace) for signing."""
    raw = json.dumps(
        canonical_link_v2_payload(link, parent),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_LINK_BYTES:
        raise ValueError(f"link exceeds {MAX_LINK_BYTES} bytes")
    return raw


def intent_digest(intent: Mapping[str, Any]) -> str:
    """Digest of an approved intent (cart, mandate, instruction) for ``intent_hash``.

    The intent is canonicalised like a link (sorted keys, no whitespace,
    UTF-8, integers only) and hashed with SHA-256.
    """
    _check_json_value(dict(intent))
    raw = json.dumps(
        dict(intent), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha-256:" + _b64url(hashlib.sha256(raw).digest())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("signature must be base64url without padding")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# ---------------------------------------------------------------------------
# Keys and signing
# ---------------------------------------------------------------------------


class VerificationKey(NamedTuple):
    """A public key and the one algorithm it may be used with.

    ``public_key`` is the raw 32-byte Ed25519 key for ``EdDSA``, or the
    65-byte uncompressed SEC1 P-256 point for ``ES256``.
    """

    alg: str
    public_key: bytes


#: ``(agent_id, kid) -> VerificationKey`` or ``None`` when unknown.
KeyResolver = Callable[[str, str], VerificationKey | None]

#: ``(agent_id, kid, signed_at) -> bool``: may this key still be relied on
#: for a signature made at ``signed_at``? A compromised key returns False
#: whatever the timestamp says.
KeyStatusCheck = Callable[[str, str, datetime], bool]

#: ``link_id -> bool``: True if the link has been revoked.
RevocationCheck = Callable[[str], bool]


def new_link_id() -> str:
    """A fresh 256-bit link id."""
    import secrets

    return secrets.token_urlsafe(32)


def sign_delegation_v2(
    private_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    link: DelegationLinkV2 | Mapping[str, Any],
    parent: DelegationLinkV2 | None = None,
) -> DelegationLinkV2:
    """Sign *link* (bound to *parent*) and return a copy carrying the signature.

    The key type must match ``link.alg``: Ed25519 for ``EdDSA``, P-256 for
    ``ES256``.
    """
    if not isinstance(link, DelegationLinkV2):
        data = {k: v for k, v in dict(link).items() if k != "signature"}
        link = DelegationLinkV2.model_validate(data)
    payload = canonical_link_v2_bytes(link, parent)
    if link.alg == "EdDSA":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("alg EdDSA requires an Ed25519 private key")
        sig = private_key.sign(payload)
    elif link.alg == "ES256":
        if not (
            isinstance(private_key, ec.EllipticCurvePrivateKey)
            and isinstance(private_key.curve, ec.SECP256R1)
        ):
            raise ValueError("alg ES256 requires a P-256 private key")
        der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:  # pragma: no cover - rejected by the model
        raise ValueError(f"unsupported alg {link.alg!r}")
    return link.model_copy(update={"signature": _b64url(sig)})


def _verify_signature(key: VerificationKey, alg: str, payload: bytes, signature: str) -> bool:
    if key.alg != alg:
        return False  # never let a link pick a different algorithm for a key
    try:
        sig = _b64url_decode(signature)
        if alg == "EdDSA":
            if len(key.public_key) != 32 or len(sig) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(sig, payload)
            return True
        if alg == "ES256":
            if len(key.public_key) != 65 or len(sig) != 64:
                return False
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key.public_key)
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            pub.verify(encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False


# ---------------------------------------------------------------------------
# Narrowing rules
# ---------------------------------------------------------------------------


def _scopes_narrow(parent: list[str], child: list[str]) -> bool:
    parent_set = set(parent)
    if "*" in parent_set:
        return True
    prefixes = [p[:-1] for p in parent if p.endswith(":*")]
    return all(s in parent_set or any(s.startswith(p) for p in prefixes) for s in child)


def _constraints_narrow(parent: list[Any], child: list[Any]) -> str | None:
    """Return why *child* widens *parent*, or None if it narrows it."""
    by_key = {_constraint_key(c): c for c in child}
    for pc in parent:
        cc = by_key.get(_constraint_key(pc))
        if cc is None:
            return f"drops parent constraint {pc.type!r}"
        if pc.type == "amount" and cc.max_minor > pc.max_minor:
            return "raises the amount cap"
        if pc.type == "budget" and (
            cc.remaining_minor > pc.remaining_minor or cc.max_minor > pc.max_minor
        ):
            return "raises the budget"
        if pc.type == "count" and cc.max > pc.max:
            return "raises the count limit"
        if pc.type == "resource" and not set(cc.ids) <= set(pc.ids):
            return "adds resources"
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def parse_links_v2(raw_links: list[Any]) -> list[DelegationLinkV2]:
    """Parse raw link objects as v2. Raises ``ValueError`` on any problem."""
    if not isinstance(raw_links, list) or not raw_links:
        raise ValueError("a chain needs at least one link")
    if len(raw_links) > MAX_CHAIN_LINKS:
        raise ValueError(f"a chain may have at most {MAX_CHAIN_LINKS} links")
    out: list[DelegationLinkV2] = []
    for i, raw in enumerate(raw_links):
        if isinstance(raw, DelegationLinkV2):
            out.append(raw)
            continue
        try:
            out.append(DelegationLinkV2.model_validate(raw))
        except ValidationError as exc:
            raise ValueError(f"link {i}: invalid ({exc.error_count()} errors)") from None
    return out


def validate_chain_v2(
    links: list[DelegationLinkV2],
    keys: KeyResolver | Mapping[tuple[str, str], VerificationKey],
    *,
    audience: str | None = None,
    understood_extensions: Collection[str] = (),
    key_status: KeyStatusCheck | None = None,
    is_revoked: RevocationCheck | None = None,
    fan_out_counts: Mapping[str, int] | None = None,
    max_lifetime: timedelta = DEFAULT_MAX_LIFETIME,
    max_unrevocable_lifetime: timedelta = DEFAULT_MAX_UNREVOCABLE_LIFETIME,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Validate a v2 chain. Returns ``(True, "valid")`` or ``(False, reason)``.

    Fail-closed rules beyond v1:

    * ``crit`` members the caller does not list in *understood_extensions*
      reject the chain.
    * The key is looked up by ``(delegator, kid)`` and its algorithm must
      equal ``alg``. With *key_status*, a key that may not be relied on
      for a signature made at ``created_at`` rejects the chain.
    * A link with ``status_url`` needs *is_revoked*; without it the chain
      is rejected rather than trusted. Any revoked link rejects the chain.
    * If any link carries ``aud``, *audience* is required and must appear
      in every ``aud``; a child's ``aud`` must be a subset of its parent's
      and may not be dropped.
    * ``principal``, ``origin``, ``intent_hash`` and ``credential_refs``
      are set at the root and must be identical on every link.
    * Constraints narrow: every parent constraint reappears on the child,
      equal or tighter.
    * No link outlives a referenced credential, and lifetimes are capped.
    """
    if not links:
        return False, "empty chain"
    if len(links) > MAX_CHAIN_LINKS:
        return False, f"chain longer than {MAX_CHAIN_LINKS} links"
    if not all(isinstance(link, DelegationLinkV2) for link in links):
        return False, "chain mixes link versions"
    if now is None:
        now = datetime.now(UTC)
    resolve: KeyResolver = (
        keys if callable(keys) else (lambda agent, kid: keys.get((agent, kid)))  # type: ignore[union-attr]
    )
    understood = frozenset(understood_extensions)
    root = links[0]
    if len(links) > root.max_depth:
        return False, f"chain depth {len(links)} exceeds root max_depth {root.max_depth}"
    seen_ids: set[str] = set()

    for i, link in enumerate(links):
        parent = links[i - 1] if i > 0 else None

        if link.link_id in seen_ids:
            return False, f"link {i}: duplicate link_id"
        seen_ids.add(link.link_id)

        # Must-understand.
        for name in link.crit:
            if name not in understood:
                return False, f"link {i}: critical extension {name!r} not understood"

        # Key, algorithm, key status, signature.
        try:
            key = resolve(link.delegator, link.kid)
        except Exception:
            return False, f"link {i}: key lookup failed"
        if key is None:
            return False, f"link {i}: unknown key {link.kid!r} for '{link.delegator}'"
        if key.alg != link.alg:
            return False, f"link {i}: alg {link.alg} does not match the key's algorithm"
        if key_status is not None:
            try:
                usable = key_status(link.delegator, link.kid, link.created_at)
            except Exception:
                usable = False
            if not usable:
                return False, f"link {i}: signing key {link.kid!r} is revoked or unusable"
        try:
            payload = canonical_link_v2_bytes(link, parent)
        except ValueError as exc:
            return False, f"link {i}: {exc}"
        if not _verify_signature(key, link.alg, payload, link.signature):
            return False, f"link {i}: invalid signature"

        # Time.
        if link.expires_at <= now - _SKEW:
            return False, f"link {i}: expired"
        if link.created_at > now + _SKEW:
            return False, f"link {i}: created_at is in the future"
        lifetime = link.expires_at - link.created_at
        cap = max_lifetime if link.status_url else min(max_lifetime, max_unrevocable_lifetime)
        if lifetime > cap:
            return False, (
                f"link {i}: lifetime {lifetime} exceeds {cap}"
                + ("" if link.status_url else " (no status_url, so it cannot be revoked)")
            )

        # Revocation.
        if link.status_url is not None and is_revoked is None:
            return False, f"link {i}: revocable link but no revocation check configured"
        if is_revoked is not None:
            try:
                revoked = is_revoked(link.link_id)
            except Exception:
                return False, f"link {i}: revocation check failed"
            if revoked:
                return False, f"link {i}: revoked"

        # Credentials it rests on.
        for ref in link.credential_refs:
            if ref.expires_at is not None:
                if ref.expires_at <= now - _SKEW:
                    return False, f"link {i}: referenced credential {ref.type} has expired"
                if link.expires_at > ref.expires_at + _SKEW:
                    return False, f"link {i}: outlives referenced credential {ref.type}"

        # Audience.
        if link.aud is not None:
            if audience is None:
                return False, f"link {i}: carries aud but the verifier gave no audience"
            if audience not in link.aud:
                return False, f"link {i}: audience {audience!r} not permitted"

        if parent is None:
            continue

        # Structure relative to the parent.
        if link.delegator != parent.delegate:
            return False, f"link {i}: delegator does not equal previous delegate"
        if link.max_depth > parent.max_depth - 1:
            return False, f"link {i}: max_depth must be <= parent max_depth - 1"
        if not _scopes_narrow(parent.scopes, link.scopes):
            return False, f"link {i}: scopes widen the parent's"
        if link.created_at < parent.created_at - _SKEW:
            return False, f"link {i}: created_at precedes parent's"
        if link.expires_at > parent.expires_at + _SKEW:
            return False, f"link {i}: expires_at exceeds parent's"
        for name in ROOT_BOUND_MEMBERS:
            if getattr(link, name) != getattr(root, name):
                return False, f"link {i}: {name} differs from the root"
        if parent.aud is not None:
            if link.aud is None or not set(link.aud) <= set(parent.aud):
                return False, f"link {i}: aud widens the parent's"
        why = _constraints_narrow(parent.constraints, link.constraints)
        if why is not None:
            return False, f"link {i}: {why}"
        for name in parent.crit:
            # A critical restriction cannot be dropped further down the chain.
            if name not in link.extension_members:
                return False, f"link {i}: drops critical extension {name!r}"

        # Fan-out (stateful).
        if fan_out_counts is not None:
            issued = fan_out_counts.get(parent.link_id, 0)
            if issued >= parent.max_fan_out:
                return False, f"link {i - 1}: max_fan_out {parent.max_fan_out} exhausted"

    return True, "valid"


# ---------------------------------------------------------------------------
# Using a validated chain
# ---------------------------------------------------------------------------


def authorize_action(
    links: list[DelegationLinkV2],
    *,
    scope: str,
    amount_minor: int | None = None,
    currency: str | None = None,
    resource_id: str | None = None,
) -> tuple[bool, str]:
    """Check one action against an ALREADY VALIDATED chain.

    Every link's scopes and constraints must allow the action (narrowing
    makes the last link the tightest, but all are checked). Money must be
    given whenever any money constraint exists, in the same currency.
    Count limits need a counter store and are left to the caller.
    """
    if not links:
        return False, "empty chain"
    if amount_minor is not None:
        if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
            return False, "amount_minor must be an integer"
        if amount_minor < 0 or amount_minor > MAX_MINOR_UNITS:
            return False, "amount_minor out of range"
        if currency is None or not _CURRENCY.fullmatch(currency):
            return False, "a valid currency is required with an amount"
    for i, link in enumerate(links):
        if not _scopes_narrow(link.scopes, [scope]):
            return False, f"link {i}: scope {scope!r} not granted"
        for c in link.constraints:
            if c.type in ("amount", "budget"):
                if amount_minor is None:
                    return False, f"link {i}: a {c.type} limit applies; amount required"
                if currency != c.currency:
                    return False, f"link {i}: currency {currency} not allowed ({c.currency})"
                limit = c.max_minor if c.type == "amount" else c.remaining_minor
                if amount_minor > limit:
                    return False, f"link {i}: amount exceeds the {c.type} limit"
            elif c.type == "resource":
                if resource_id is None or resource_id not in c.ids:
                    return False, f"link {i}: resource not permitted"
    if amount_minor is not None and not any(
        c.type in ("amount", "budget") for link in links for c in link.constraints
    ):
        # Spending with no money limit anywhere in the chain is refused.
        return False, "no amount or budget limit authorises spending"
    return True, "authorized"


def minor_units(amount: str, exponent: int) -> int:
    """Convert a decimal string (e.g. ``"12.34"``) to integer minor units.

    *exponent* is the currency's ISO 4217 minor-unit exponent (2 for USD,
    0 for JPY, 3 for BHD). Rejects more fractional digits than the
    exponent allows rather than rounding.
    """
    if not re.fullmatch(r"\d{1,15}(\.\d{1,4})?", amount):
        raise ValueError("amount must be a plain non-negative decimal")
    if not 0 <= exponent <= 4:
        raise ValueError("exponent must be 0..4")
    whole, _, frac = amount.partition(".")
    if len(frac) > exponent:
        raise ValueError("amount has more decimal places than the currency allows")
    value = int(whole) * 10**exponent + (int(frac.ljust(exponent, "0")) if exponent else 0)
    if value > MAX_MINOR_UNITS:
        raise ValueError("amount too large")
    return value
