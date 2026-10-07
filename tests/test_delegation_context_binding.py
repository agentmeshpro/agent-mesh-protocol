"""Tests for Task 3.3: Delegation signature context binding.

Ensures that ``_canonical_link_bytes()`` includes ``parent_delegate`` so
that a valid signature cannot be transplanted from one delegation chain
into another.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from ampro.delegation.chain import (
    DelegationChain,
    DelegationLink,
    _canonical_link_bytes,
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
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestContextBinding:
    """Signature context binding prevents cross-chain transplant."""

    def test_sign_with_parent_context_verifies(self):
        """A link signed with parent context verifies when the same context is used."""
        seed_a, pub_a = _make_keypair()
        seed_b, pub_b = _make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        # Root link: no parent_delegate
        link_a = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate=None,
        )

        # Child link: parent_delegate = link_a's delegate
        link_b = _make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys, allow_v1=True)
        assert valid is True, f"Chain with correct context should verify, got: {reason}"

    def test_sign_with_wrong_parent_context_fails(self):
        """A link signed with one parent context fails if verified with a different parent."""
        seed_a, pub_a = _make_keypair()
        seed_b, pub_b = _make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        # Root link
        link_a = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate=None,
        )

        # Sign link_b with the WRONG parent_delegate context
        link_b = _make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://WRONG.example.com",  # Wrong context!
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys, allow_v1=True)
        assert valid is False
        assert "signature" in reason.lower()

    def test_root_link_no_parent_verifies(self):
        """A root link (no parent) should sign and verify correctly."""
        seed_a, pub_a = _make_keypair()

        link = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            parent_delegate=None,
        )

        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys, allow_v1=True)
        assert valid is True, f"Root link should verify, got: {reason}"

    def test_transplant_signature_between_chains_fails(self):
        """
        A valid signature from chain A cannot be transplanted into chain B.

        We build two chains with different root links (different parent
        delegates for link_b). Taking the signature from chain A's link_b
        and putting it into chain B must fail verification.
        """
        seed_a, pub_a = _make_keypair()
        seed_b, pub_b = _make_keypair()
        seed_x, pub_x = _make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        # --- Chain A ---
        link_a_root = _make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate=None,
        )
        link_a_child = _make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",  # Bound to chain A
        )

        # Verify chain A works
        chain_a = DelegationChain(links=[link_a_root, link_a_child])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
            "agent://x.example.com": pub_x,
        }
        valid_a, reason_a = validate_chain(chain_a, public_keys, allow_v1=True)
        assert valid_a is True, f"Chain A should verify, got: {reason_a}"

        # --- Chain B (different root) ---
        link_b_root = _make_signed_link(
            seed_x,
            delegator="agent://x.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate=None,
        )

        # Transplant: take link_a_child's signature and put it in chain B
        # The signature was signed with parent_delegate="agent://b.example.com"
        # (from chain A), but in chain B the parent delegate is also
        # "agent://b.example.com" — however the root is different.
        # Actually for this test to properly show transplant failure, we need
        # the parent delegate to differ. Let's create a chain where the
        # parent's delegate is different.

        # Build chain B with a different intermediate:
        # x.example.com delegates to y.example.com
        seed_y, pub_y = _make_keypair()
        link_b_root2 = _make_signed_link(
            seed_x,
            delegator="agent://x.example.com",
            delegate="agent://y.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate=None,
        )

        # Now transplant: create a link that was signed with parent_delegate
        # "agent://b.example.com" but place it after a parent whose delegate
        # is "agent://y.example.com"
        # We need the link to have the right delegator to pass continuity
        # So: y.example.com -> c.example.com, but signed with wrong parent
        link_transplant = _make_signed_link(
            seed_b,
            delegator="agent://y.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",  # WRONG: should be y.example.com
        )

        chain_b = DelegationChain(links=[link_b_root2, link_transplant])
        public_keys_b = {
            "agent://x.example.com": pub_x,
            "agent://y.example.com": pub_b,  # y uses B's key
        }
        valid_b, reason_b = validate_chain(chain_b, public_keys_b, allow_v1=True)
        assert valid_b is False, "Transplanted signature should fail verification"
        assert "signature" in reason_b.lower()

    def test_canonical_bytes_differ_with_parent(self):
        """_canonical_link_bytes produces different output with different parent_delegate."""
        now = datetime.now(UTC)
        link = DelegationLink(
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            max_depth=3,
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )

        bytes_none = _canonical_link_bytes(link, parent_delegate=None)
        bytes_parent = _canonical_link_bytes(link, parent_delegate="agent://x.example.com")
        bytes_other = _canonical_link_bytes(link, parent_delegate="agent://y.example.com")

        # All three should be different
        assert bytes_none != bytes_parent
        assert bytes_none != bytes_other
        assert bytes_parent != bytes_other

    def test_canonical_bytes_include_parent_delegate_key(self):
        """_canonical_link_bytes JSON includes 'parent_delegate' in keys."""
        import json

        now = datetime.now(UTC)
        link = DelegationLink(
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            max_depth=3,
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )

        raw = _canonical_link_bytes(link, parent_delegate="agent://x.example.com")
        parsed = json.loads(raw)
        assert "parent_delegate" in parsed
        assert parsed["parent_delegate"] == "agent://x.example.com"

        # None case
        raw_none = _canonical_link_bytes(link, parent_delegate=None)
        parsed_none = json.loads(raw_none)
        assert "parent_delegate" in parsed_none
        assert parsed_none["parent_delegate"] is None
