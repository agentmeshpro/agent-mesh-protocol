"""Tests for trace context signing (Task 3.7).

Ensures trace contexts can be cryptographically signed with Ed25519
and that tampering is detected.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.delegation.tracing import (
    TraceContext,
    extract_trace_context,
    generate_span_id,
    generate_trace_id,
    inject_trace_headers,
    sign_trace_context,
    verify_trace_context,
)


def _keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair and return (private_seed, public_bytes)."""
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes_raw()
    return private_bytes, public_bytes


# -----------------------------------------------------------------------
# sign + verify round-trip
# -----------------------------------------------------------------------


class TestSignVerifyRoundTrip:
    """Sign a trace context, then verify it succeeds."""

    def test_sign_then_verify_succeeds(self) -> None:
        priv, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
            parent_span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)
        assert signed.signature is not None
        assert verify_trace_context(signed, pub)

    def test_sign_without_parent_span(self) -> None:
        priv, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)
        assert verify_trace_context(signed, pub)


# -----------------------------------------------------------------------
# Tamper detection
# -----------------------------------------------------------------------


class TestTamperDetection:
    """Tampering with any field after signing causes verification failure."""

    def test_tamper_trace_id_fails(self) -> None:
        priv, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)

        # Tamper with trace_id
        tampered = TraceContext(
            trace_id=generate_trace_id(),
            span_id=signed.span_id,
            parent_span_id=signed.parent_span_id,
            signature=signed.signature,
        )
        assert not verify_trace_context(tampered, pub)

    def test_tamper_span_id_fails(self) -> None:
        priv, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)

        tampered = TraceContext(
            trace_id=signed.trace_id,
            span_id="ff" * 8,
            parent_span_id=signed.parent_span_id,
            signature=signed.signature,
        )
        assert not verify_trace_context(tampered, pub)

    def test_wrong_public_key_fails(self) -> None:
        priv, _pub = _keypair()
        _, other_pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)
        assert not verify_trace_context(signed, other_pub)


# -----------------------------------------------------------------------
# Unsigned context
# -----------------------------------------------------------------------


class TestUnsignedContext:
    """An unsigned trace context must return False on verify."""

    def test_unsigned_verify_returns_false(self) -> None:
        _, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        assert ctx.signature is None
        assert not verify_trace_context(ctx, pub)


# -----------------------------------------------------------------------
# Header injection / extraction with signature
# -----------------------------------------------------------------------


class TestTraceHeaders:
    """inject/extract round-trip preserves the signature."""

    def test_inject_includes_signature(self) -> None:
        priv, _pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)
        headers = inject_trace_headers(signed)
        assert "Trace-Signature" in headers
        assert headers["Trace-Signature"] == signed.signature

    def test_inject_omits_signature_when_unsigned(self) -> None:
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
        )
        headers = inject_trace_headers(ctx)
        assert "Trace-Signature" not in headers

    def test_extract_reads_signature(self) -> None:
        priv, pub = _keypair()
        ctx = TraceContext(
            trace_id=generate_trace_id(),
            span_id=generate_span_id(),
            parent_span_id=generate_span_id(),
        )
        signed = sign_trace_context(ctx, priv)
        headers = inject_trace_headers(signed)

        restored = extract_trace_context(headers)
        assert restored is not None
        assert restored.signature == signed.signature
        assert verify_trace_context(restored, pub)

    def test_extract_without_signature(self) -> None:
        headers = {
            "Trace-Id": generate_trace_id(),
            "Span-Id": generate_span_id(),
        }
        ctx = extract_trace_context(headers)
        assert ctx is not None
        assert ctx.signature is None
