"""
Agent Protocol — Distributed Tracing.

W3C Trace Context (https://www.w3.org/TR/trace-context/) inspired
distributed tracing primitives for agent-to-agent message flows.

Provides trace/span ID generation, header injection/extraction for
propagating trace context across agent boundaries.

Trace contexts MAY be cryptographically signed (Ed25519) so that
receivers can verify the originator of a trace.  An unsigned context
is still valid but SHOULD be treated as unverified.

PURE — zero platform-specific imports. Only stdlib + cryptography.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_trace_id() -> str:
    """Generate a 32-character lowercase hex trace ID (128 bits)."""
    return os.urandom(16).hex()


def generate_span_id() -> str:
    """Generate a 16-character lowercase hex span ID (64 bits)."""
    return os.urandom(8).hex()


@dataclass
class TraceContext:
    """Immutable trace context propagated across agent boundaries."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    trace_flags: int = 1  # 1 = sampled
    signature: str | None = None

    def __post_init__(self) -> None:
        # IDs are W3C trace-context shaped: lowercase hex, not all zeros.
        # Validating them also keeps the ``|``-separated canonical form
        # used for signing unambiguous.
        _check_hex_id("trace_id", self.trace_id, 32)
        _check_hex_id("span_id", self.span_id, 16)
        if self.parent_span_id is not None:
            _check_hex_id("parent_span_id", self.parent_span_id, 16)


def _check_hex_id(name: str, value: str, length: int) -> None:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(c not in "0123456789abcdef" for c in value)
        or set(value) == {"0"}
    ):
        raise ValueError(f"{name} must be {length} lowercase hex characters, not all zero")


# ---------------------------------------------------------------------------
# Canonical form for signing
# ---------------------------------------------------------------------------


def _canonical_trace_bytes(ctx: TraceContext) -> bytes:
    """Return the canonical byte representation used for signing.

    Format: ``{trace_id}|{span_id}|{parent_span_id_or_empty}``
    """
    parent = ctx.parent_span_id or ""
    return f"{ctx.trace_id}|{ctx.span_id}|{parent}".encode()


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def sign_trace_context(ctx: TraceContext, private_key: bytes) -> TraceContext:
    """Sign *ctx* with an Ed25519 private key and return a new context.

    Args:
        ctx: The trace context to sign.
        private_key: Raw 32-byte Ed25519 private key seed.

    Returns:
        A **new** :class:`TraceContext` with ``signature`` set to the
        base64-encoded Ed25519 signature over the canonical trace bytes.
    """
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    payload = _canonical_trace_bytes(ctx)
    sig = key.sign(payload)
    return replace(ctx, signature=base64.b64encode(sig).decode("ascii"))


def verify_trace_context(ctx: TraceContext, public_key: bytes) -> bool:
    """Verify the Ed25519 signature on *ctx*.

    Args:
        ctx: The trace context whose signature to verify.
        public_key: Raw 32-byte Ed25519 public key bytes.

    Returns:
        ``True`` if the signature is present and valid, ``False``
        otherwise (missing signature or verification failure).
    """
    if ctx.signature is None:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        sig_bytes = base64.b64decode(ctx.signature)
        payload = _canonical_trace_bytes(ctx)
        key.verify(sig_bytes, payload)
        return True
    except Exception:  # InvalidSignature, ValueError, etc.
        return False


# ---------------------------------------------------------------------------
# Header injection / extraction
# ---------------------------------------------------------------------------


def inject_trace_headers(ctx: TraceContext) -> dict[str, str]:
    """Inject trace context into HTTP-style headers.

    Returns a dict with ``Trace-Id``, ``Span-Id``, and optionally
    ``Parent-Span-Id`` and ``Trace-Signature`` headers.
    """
    headers: dict[str, str] = {
        "Trace-Id": ctx.trace_id,
        "Span-Id": ctx.span_id,
    }
    if ctx.parent_span_id is not None:
        headers["Parent-Span-Id"] = ctx.parent_span_id
    if ctx.signature is not None:
        headers["Trace-Signature"] = ctx.signature
    return headers


def extract_trace_context(headers: dict[str, str]) -> TraceContext | None:
    """Extract trace context from HTTP-style headers.

    Returns ``None`` if the required ``Trace-Id`` or ``Span-Id`` headers
    are missing.
    """
    trace_id = headers.get("Trace-Id")
    span_id = headers.get("Span-Id")
    if trace_id is None or span_id is None:
        return None
    return TraceContext(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=headers.get("Parent-Span-Id"),
        signature=headers.get("Trace-Signature"),
    )


# ---------------------------------------------------------------------------
# W3C Trace Context (``traceparent`` / ``tracestate``)
# ---------------------------------------------------------------------------
#
# https://www.w3.org/TR/trace-context/ — the cross-protocol carrier used
# by the interop adapters (A2A, MCP, PACT) and the native HTTP route.
# Parsing is strict: anything that is not exactly what the spec allows is
# rejected with :class:`TraceContextError` rather than repaired.

TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"

#: Longest ``traceparent`` value accepted from the wire.  Version ``00``
#: is exactly 55 characters; a future version may append fields, so a
#: little headroom is allowed, but the input stays bounded.
MAX_TRACEPARENT_LENGTH = 256
#: W3C: ``tracestate`` carries at most 32 list-members.
MAX_TRACESTATE_MEMBERS = 32
#: W3C: vendors SHOULD propagate at least 512 characters of ``tracestate``;
#: this is also the most we propagate (longer values are truncated by
#: dropping whole list-members, as the spec prescribes).
MAX_TRACESTATE_LENGTH = 512
#: Hard cap on a ``tracestate`` value read from the wire (32 members of
#: the longest legal key and value, plus separators).  Anything longer
#: cannot be valid and is rejected before it is parsed.
MAX_TRACESTATE_INPUT_LENGTH = MAX_TRACESTATE_MEMBERS * (256 + 1 + 256) + 31 * 2

_TP_RE = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})")
_TS_KEY_RE = re.compile(
    r"[a-z][a-z0-9_\-*/]{0,255}"
    r"|[a-z0-9][a-z0-9_\-*/]{0,240}@[a-z][a-z0-9_\-*/]{0,13}"
)
# value = 0*255(chr) nblk-chr; chr = %x20 / nblk-chr;
# nblk-chr = %x21-2B / %x2D-3C / %x3E-7E  (no ',' and no '=')
_TS_VALUE_RE = re.compile(r"[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]")
_OWS = " \t"


class TraceContextError(ValueError):
    """A ``traceparent`` / ``tracestate`` value violates W3C Trace Context."""


@dataclass(frozen=True)
class TraceParent:
    """A parsed W3C ``traceparent`` header.

    ``version`` is the version the sender used; :meth:`to_header` always
    emits version ``00`` (the only version this implementation speaks).
    """

    trace_id: str
    parent_id: str
    trace_flags: int = 1
    version: int = 0

    def __post_init__(self) -> None:
        _check_hex_id("trace_id", self.trace_id, 32)
        _check_hex_id("parent_id", self.parent_id, 16)
        if not isinstance(self.trace_flags, int) or not 0 <= self.trace_flags <= 0xFF:
            raise ValueError("trace_flags must be an integer in 0..255")
        if not isinstance(self.version, int) or not 0 <= self.version < 0xFF:
            raise ValueError("version must be an integer in 0..254")

    @property
    def sampled(self) -> bool:
        return bool(self.trace_flags & 0x01)

    def to_header(self) -> str:
        return format_traceparent(self.trace_id, self.parent_id, self.trace_flags)


def format_traceparent(trace_id: str, parent_id: str, trace_flags: int = 1) -> str:
    """Render a version-``00`` ``traceparent`` value.

    Only the ``sampled`` flag is propagated: W3C version ``00`` requires
    flags this implementation does not understand to be cleared.
    """
    _check_hex_id("trace_id", trace_id, 32)
    _check_hex_id("parent_id", parent_id, 16)
    return f"00-{trace_id}-{parent_id}-{trace_flags & 0x01:02x}"


def parse_traceparent(value: str) -> TraceParent:
    """Parse a ``traceparent`` header value strictly.

    * version ``00``: exactly ``00-<32 hex>-<16 hex>-<2 hex>``, lowercase,
      neither id all zeros;
    * version ``ff``: invalid;
    * any other (future) version: the first 55 characters are parsed as
      version ``00`` and, if the value is longer, the next character MUST
      be ``-`` (the spec's forward-compatibility rule).

    Raises :class:`TraceContextError` on anything else; nothing is
    guessed or repaired.  Only HTTP optional whitespace (space / tab)
    around the value is ignored.
    """
    if not isinstance(value, str):
        raise TraceContextError("traceparent must be a string")
    if len(value) > MAX_TRACEPARENT_LENGTH:
        raise TraceContextError("traceparent is too long")
    value = value.strip(_OWS)
    m = _TP_RE.match(value)
    if m is None:
        raise TraceContextError("traceparent is malformed")
    version_hex, trace_id, parent_id, flags_hex = m.groups()
    version = int(version_hex, 16)
    if version == 0xFF:
        raise TraceContextError("traceparent version ff is invalid")
    if version == 0:
        if len(value) != 55:
            raise TraceContextError("traceparent is malformed")
    elif len(value) > 55 and value[55] != "-":
        raise TraceContextError("traceparent is malformed")
    if trace_id == "0" * 32:
        raise TraceContextError("traceparent trace-id must not be all zeros")
    if parent_id == "0" * 16:
        raise TraceContextError("traceparent parent-id must not be all zeros")
    return TraceParent(trace_id=trace_id, parent_id=parent_id,
                       trace_flags=int(flags_hex, 16), version=version)


def parse_tracestate(value: str) -> str | None:
    """Validate a ``tracestate`` header value and return its canonical form.

    Members are checked against the W3C key / value grammar; duplicate
    keys or more than :data:`MAX_TRACESTATE_MEMBERS` members are
    rejected.  Empty list-members (``a=1,,b=2``) are allowed by the
    grammar and dropped.  If the canonical form is longer than
    :data:`MAX_TRACESTATE_LENGTH`, members longer than 128 characters are
    dropped first, then members from the end, until it fits (the
    truncation the spec prescribes).  Returns ``None`` for an empty value.

    Raises :class:`TraceContextError` on a malformed value.
    """
    if not isinstance(value, str):
        raise TraceContextError("tracestate must be a string")
    if len(value) > MAX_TRACESTATE_INPUT_LENGTH:
        raise TraceContextError("tracestate is too long")
    members: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        member = raw.strip(_OWS)
        if not member:
            continue
        key, sep, val = member.partition("=")
        if not sep or not _TS_KEY_RE.fullmatch(key) or not _TS_VALUE_RE.fullmatch(val):
            raise TraceContextError("tracestate is malformed")
        if key in seen:
            raise TraceContextError("tracestate has a duplicate key")
        seen.add(key)
        members.append(f"{key}={val}")
        if len(members) > MAX_TRACESTATE_MEMBERS:
            raise TraceContextError("tracestate has too many members")
    if not members:
        return None
    if len(",".join(members)) > MAX_TRACESTATE_LENGTH:
        members = [m for m in members if len(m) <= 128]
        while members and len(",".join(members)) > MAX_TRACESTATE_LENGTH:
            members.pop()
    return ",".join(members) or None
