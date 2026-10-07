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
