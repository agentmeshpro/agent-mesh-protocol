"""Security regression tests for delegation-chain validation.

Covers:
  * all link fields (trust_tier, chain_budget, jwks_url, max_fan_out) are
    covered by the Ed25519 signature — no relay escalation;
  * max_depth monotonic decrement + total chain length bound;
  * timestamp canonicalisation (``Z`` vs ``+00:00``) and naive datetimes;
  * max_fan_out enforcement via ``fan_out_counts``;
  * chain_budget fullmatch, remaining <= max, non-increasing budgets.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from ampro.delegation.chain import (
    DelegationChain,
    DelegationLink,
    delegation_link_id,
    parse_chain_budget,
    sign_delegation,
    validate_chain,
)

A, B, C, D = (
    "agent://a.example.com",
    "agent://b.example.com",
    "agent://c.example.com",
    "agent://d.example.com",
)


def _kp() -> tuple[bytes, bytes]:
    k = Ed25519PrivateKey.generate()
    return k.private_bytes_raw(), k.public_key().public_bytes_raw()


KEYS = {a: _kp() for a in (A, B, C, D)}
PUBS = {a: kp[1] for a, kp in KEYS.items()}
NOW = datetime.now(UTC).replace(microsecond=0)


def _link(delegator: str, delegate: str, parent: str | None, **kw) -> DelegationLink:
    data = {
        "delegator": delegator,
        "delegate": delegate,
        "scopes": kw.pop("scopes", ["tool:read"]),
        "max_depth": kw.pop("max_depth", 3),
        "created_at": kw.pop("created_at", NOW),
        "expires_at": kw.pop("expires_at", NOW + timedelta(hours=1)),
        **kw,
    }
    sig = sign_delegation(KEYS[delegator][0], data, parent_delegate=parent)
    return DelegationLink(**data, signature=sig)


def _chain(*links: DelegationLink) -> DelegationChain:
    return DelegationChain(links=list(links))


# ---------------------------------------------------------------------------
# Item 2 — every field is signed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("trust_tier", "internal"),
        ("chain_budget", "remaining=900.00USD;max=900.00USD"),
        ("jwks_url", "https://evil.example.com/jwks"),
        ("max_fan_out", 10),
    ],
)
def test_tampering_any_field_breaks_signature(field, value):
    link = _link(A, B, None, trust_tier="external", max_fan_out=2,
                 chain_budget="remaining=1.00USD;max=1.00USD")
    assert validate_chain(_chain(link), PUBS, allow_v1=True) == (True, "valid")
    tampered = link.model_copy(update={field: value})
    ok, reason = validate_chain(_chain(tampered), PUBS, allow_v1=True)
    assert ok is False
    assert "signature" in reason


def test_sign_with_z_timestamps_matches_wire_form():
    """A link signed with ``...Z`` strings (WIRE-BINDING §11.11) verifies
    after JSON round-trip through the model."""
    wire = {
        "delegator": A,
        "delegate": B,
        "scopes": ["tool:read"],
        "max_depth": 3,
        "created_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (NOW + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trust_tier": "verified",
    }
    wire["signature"] = sign_delegation(KEYS[A][0], wire)
    parsed = DelegationLink.model_validate(json.loads(json.dumps(wire)))
    assert validate_chain(_chain(parsed), PUBS, allow_v1=True) == (True, "valid")


def test_non_utc_offset_equivalent_instant_verifies():
    tz = timezone(timedelta(hours=5))
    link = _link(A, B, None, created_at=NOW.astimezone(tz),
                 expires_at=(NOW + timedelta(hours=1)).astimezone(tz))
    # Re-express timestamps in UTC — same instant, same signature payload.
    moved = link.model_copy(update={
        "created_at": link.created_at.astimezone(UTC),
        "expires_at": link.expires_at.astimezone(UTC),
    })
    assert validate_chain(_chain(moved), PUBS, allow_v1=True) == (True, "valid")


def test_naive_datetime_rejected_at_model_validation():
    with pytest.raises(ValidationError):
        DelegationLink(delegator=A, delegate=B, scopes=["x"],
                       created_at=datetime.now(), expires_at=datetime.now())
    with pytest.raises(ValidationError):
        DelegationLink(delegator=A, delegate=B, scopes=["x"],
                       created_at="2026-01-01T00:00:00",
                       expires_at="2026-01-01T01:00:00")


# ---------------------------------------------------------------------------
# Item 3 — depth + scope narrowing
# ---------------------------------------------------------------------------


def test_child_cannot_raise_max_depth():
    l1 = _link(A, B, None, max_depth=2)
    l2 = _link(B, C, B, max_depth=5)
    ok, reason = validate_chain(_chain(l1, l2), PUBS, allow_v1=True)
    assert ok is False and "max_depth" in reason


def test_child_must_decrement_max_depth():
    l1 = _link(A, B, None, max_depth=3)
    l2 = _link(B, C, B, max_depth=3)
    ok, reason = validate_chain(_chain(l1, l2), PUBS, allow_v1=True)
    assert ok is False and "max_depth" in reason


def test_chain_length_bounded_by_root_max_depth():
    l1 = _link(A, B, None, max_depth=2)
    l2 = _link(B, C, B, max_depth=1)
    assert validate_chain(_chain(l1, l2), PUBS, allow_v1=True) == (True, "valid")
    l3 = _link(C, D, C, max_depth=0)
    ok, reason = validate_chain(_chain(l1, l2, l3), PUBS, allow_v1=True)
    assert ok is False and "depth" in reason


def test_decrementing_chain_accepted():
    l1 = _link(A, B, None, max_depth=3, scopes=["tool:*"])
    l2 = _link(B, C, B, max_depth=2, scopes=["tool:read", "tool:write"])
    l3 = _link(C, D, C, max_depth=1, scopes=["tool:read"])
    assert validate_chain(_chain(l1, l2, l3), PUBS, allow_v1=True) == (True, "valid")


def test_scope_widening_rejected():
    l1 = _link(A, B, None, scopes=["tool:read"])
    l2 = _link(B, C, B, max_depth=2, scopes=["tool:read", "admin:*"])
    ok, reason = validate_chain(_chain(l1, l2), PUBS, allow_v1=True)
    assert ok is False and "scopes" in reason


# ---------------------------------------------------------------------------
# Item 5 — fan-out and budget
# ---------------------------------------------------------------------------


def test_fan_out_enforced_with_counts():
    l1 = _link(A, B, None, max_fan_out=2)
    l2 = _link(B, C, B, max_depth=2)
    lid = delegation_link_id(l1)
    assert validate_chain(_chain(l1, l2), PUBS, fan_out_counts={lid: 1}, allow_v1=True)[0] is True
    ok, reason = validate_chain(_chain(l1, l2), PUBS, fan_out_counts={lid: 2}, allow_v1=True)
    assert ok is False and "fan_out" in reason
    # Without a store the check cannot apply.
    assert validate_chain(_chain(l1, l2), PUBS, allow_v1=True)[0] is True


@pytest.mark.parametrize(
    "bad",
    [
        "remaining=1.00USD;max=5.00USDjunk",
        "remaining=1.00USD;max=5.00USD;remaining=99USD",
        "remaining=1USD;max=2USD ",
    ],
)
def test_budget_trailing_junk_rejected(bad):
    with pytest.raises(ValueError):
        parse_chain_budget(bad)


def test_budget_remaining_cannot_exceed_max():
    link = _link(A, B, None, chain_budget="remaining=9.00USD;max=5.00USD")
    ok, reason = validate_chain(_chain(link), PUBS, allow_v1=True)
    assert ok is False and "max" in reason


def test_budget_max_cannot_increase_along_chain():
    l1 = _link(A, B, None, chain_budget="remaining=2.00USD;max=5.00USD")
    l2 = _link(B, C, B, max_depth=2, chain_budget="remaining=2.00USD;max=50.00USD")
    ok, reason = validate_chain(_chain(l1, l2), PUBS, allow_v1=True)
    assert ok is False and "budget" in reason


def test_budget_cannot_be_dropped_by_child():
    l1 = _link(A, B, None, chain_budget="remaining=2.00USD;max=5.00USD")
    l2 = _link(B, C, B, max_depth=2)
    ok, reason = validate_chain(_chain(l1, l2), PUBS, allow_v1=True)
    assert ok is False and "budget" in reason


def test_signature_is_base64_of_64_bytes():
    link = _link(A, B, None)
    assert len(base64.b64decode(link.signature)) == 64
