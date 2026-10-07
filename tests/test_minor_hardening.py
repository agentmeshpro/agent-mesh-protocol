"""Regression tests for the minor findings from the 0.4.0 spec review."""
from __future__ import annotations

import pytest

from ampro.delegation.tracing import TraceContext, generate_span_id, generate_trace_id


@pytest.mark.parametrize(
    "trace_id, span_id",
    [
        ("0" * 32, "1" * 16),            # all-zero trace id
        ("A" * 32, "1" * 16),            # uppercase
        ("a" * 31, "1" * 16),            # wrong length
        ("a" * 31 + "|", "1" * 16),      # separator injection into canonical bytes
        ("a" * 32, "0" * 16),            # all-zero span id
    ],
)
def test_trace_context_rejects_malformed_ids(trace_id, span_id):
    with pytest.raises(ValueError):
        TraceContext(trace_id=trace_id, span_id=span_id)


def test_trace_context_accepts_generated_ids():
    TraceContext(generate_trace_id(), generate_span_id(), parent_span_id=generate_span_id())


def test_key_revocation_reason_must_be_known():
    from pydantic import ValidationError

    from ampro.security.key_revocation import KeyRevocationBody

    base = dict(
        agent_id="agent://a.example.com",
        revoked_key_id="k1",
        revoked_at="2026-10-07T00:00:00Z",
        signature="sig",
    )
    KeyRevocationBody(reason="key_rotation", **base)
    with pytest.raises(ValidationError):
        KeyRevocationBody(reason="because", **base)


def test_delegation_link_without_scopes_is_rejected():
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from ampro.delegation.chain import (
        DelegationChain,
        DelegationLink,
        sign_delegation,
        validate_chain,
    )

    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    now = datetime.now(UTC)
    data = dict(
        delegator="agent://a.example.com",
        delegate="agent://b.example.com",
        scopes=[],
        max_depth=2,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        signature="placeholder",
    )
    data["signature"] = sign_delegation(raw, data)
    ok, reason = validate_chain(
        DelegationChain(links=[DelegationLink(**data)]),
        public_keys={"agent://a.example.com": sk.public_key().public_bytes_raw()},
        allow_v1=True,
    )
    assert not ok and "scope" in reason
