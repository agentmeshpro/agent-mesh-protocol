"""Tests for Task 3.2: Budget parsing fail-closed behavior.

Ensures that malformed chain_budget values reject the chain instead of
silently skipping validation, and that child budgets cannot exceed parent
budgets.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.delegation.chain import (
    DelegationChain,
    DelegationLink,
    parse_chain_budget,
    sign_delegation,
    validate_chain,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair. Returns (private_seed, public_bytes)."""
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes_raw()
    pub = private_key.public_key().public_bytes_raw()
    return seed, pub


def _make_signed_link(
    private_seed: bytes,
    delegator: str,
    delegate: str,
    scopes: list[str],
    *,
    max_depth: int | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    chain_budget: str = "",
    parent_delegate: str | None = None,
) -> DelegationLink:
    """Create a DelegationLink with a real Ed25519 signature."""
    if max_depth is None:
        # Children must decrement max_depth (root=3, child=2).
        max_depth = 3 if parent_delegate is None else 2
    now = datetime.now(UTC)
    created = created_at or now
    expires = expires_at or (now + timedelta(hours=1))

    link_data = {
        "delegator": delegator,
        "delegate": delegate,
        "scopes": sorted(scopes),
        "max_depth": max_depth,
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "chain_budget": chain_budget,  # signed like every other field
    }
    sig = sign_delegation(private_seed, link_data, parent_delegate=parent_delegate)
    return DelegationLink(
        delegator=delegator,
        delegate=delegate,
        scopes=scopes,
        max_depth=max_depth,
        created_at=created,
        expires_at=expires,
        signature=sig,
        chain_budget=chain_budget,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBudgetFailClosed:
    """Budget validation must fail-closed on malformed data."""

    def test_valid_budget_format_passes(self):
        """A chain with a valid chain_budget should validate successfully."""
        seed_a, pub_a = _make_keypair()
        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=3.50USD;max=5.00USD",
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"Expected valid chain, got: {reason}"

    def test_malformed_budget_string_rejects(self):
        """A malformed chain_budget must cause chain validation to fail."""
        seed_a, pub_a = _make_keypair()
        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="GARBAGE_NOT_A_BUDGET",
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        assert "invalid chain_budget" in reason.lower()

    def test_child_budget_exceeds_parent_rejects(self):
        """If a child link's remaining budget exceeds the parent's, reject."""
        seed_a, pub_a = _make_keypair()
        seed_b, pub_b = _make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        link_a = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=2.00USD;max=5.00USD",
            created_at=now,
            expires_at=expires,
        )
        link_b = _make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=4.00USD;max=5.00USD",  # 4.00 > 2.00
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        assert "child budget" in reason.lower() or "exceeds parent" in reason.lower()

    def test_no_budget_none_passes(self):
        """A chain with no chain_budget (empty string) should validate fine."""
        seed_a, pub_a = _make_keypair()
        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="",  # No budget = unlimited
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"No budget should be fine, got: {reason}"

    def test_negative_budget_rejects(self):
        """A negative remaining budget must be rejected."""
        seed_a, pub_a = _make_keypair()
        # parse_chain_budget uses regex that only matches positive numbers,
        # so a negative value like "remaining=-1.00USD" would be a malformed
        # string and trigger the fail-closed path.
        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=-1.00USD;max=5.00USD",
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        # Should fail as malformed (negative not parseable by regex)
        assert "invalid chain_budget" in reason.lower() or "negative" in reason.lower()

    def test_zero_budget_rejects(self):
        """A zero remaining budget means exhausted — must be rejected."""
        seed_a, pub_a = _make_keypair()
        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=0.00USD;max=5.00USD",
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        assert "exhausted" in reason.lower() or "budget" in reason.lower()

    def test_child_budget_within_parent_passes(self):
        """If a child link's remaining budget is within the parent's, accept."""
        seed_a, pub_a = _make_keypair()
        seed_b, pub_b = _make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        link_a = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=5.00USD;max=10.00USD",
            created_at=now,
            expires_at=expires,
        )
        link_b = _make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            chain_budget="remaining=3.00USD;max=10.00USD",  # 3.00 <= 5.00
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"Child within parent budget should pass, got: {reason}"

    def test_parse_chain_budget_valid(self):
        """parse_chain_budget returns correct (remaining, max) for valid input."""
        remaining, max_b = parse_chain_budget("remaining=3.50USD;max=5.00USD")
        assert remaining == 3.50
        assert max_b == 5.00

    def test_parse_chain_budget_invalid_raises(self):
        """parse_chain_budget raises ValueError for invalid input."""
        with pytest.raises(ValueError):
            parse_chain_budget("not-a-budget")
