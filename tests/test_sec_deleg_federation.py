"""Security regression tests for registry federation.

Covers:
  * naive vs aware last_seen comparison must not raise;
  * remote record cannot raise its trust_tier by winning on recency;
  * deterministic URI tie-break (PROTOCOL-CONTRACTS §4);
  * federation trust proofs bind issued_at, nonce and audience and are
    not replayable;
  * RegistryFederationRevokeBody.signature is verified.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.registry.federation import (
    RegistryFederationRevokeBody,
    merge_federation_record,
    register_federation_trust_proof_resolver,
    reset_federation_nonce_cache,
    resolve_federation_conflict,
    sign_federation_revoke,
    sign_federation_trust_proof,
    verify_federation_revoke,
    verify_federation_trust_proof,
)

REG = "agent://registry-a.example.com"
LOCAL = "agent://registry-b.example.com"


@pytest.fixture()
def keys():
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes_raw()
    pub = sk.public_key().public_bytes_raw()
    register_federation_trust_proof_resolver(lambda rid: pub if rid == REG else None)
    reset_federation_nonce_cache()
    yield seed
    register_federation_trust_proof_resolver(lambda rid: None)
    reset_federation_nonce_cache()


# ---------------------------------------------------------------------------
# Conflict resolution
# ---------------------------------------------------------------------------


class TestConflict:
    def test_naive_vs_aware_does_not_raise(self):
        local = {"trust_tier": "verified", "last_seen": datetime(2026, 4, 1),
                 "agent_uri": "agent://x.example.com"}
        remote = {"trust_tier": "verified",
                  "last_seen": datetime(2026, 4, 2, tzinfo=UTC),
                  "agent_uri": "agent://x.example.com"}
        assert resolve_federation_conflict(local, remote) == "remote"
        assert resolve_federation_conflict(remote, local) == "local"
        # Naive ISO string vs aware datetime.
        local2 = dict(local, last_seen="2026-04-03T00:00:00")
        assert resolve_federation_conflict(local2, remote) == "local"

    def test_remote_tier_capped_when_remote_wins_on_recency(self):
        local = {"trust_tier": "external", "last_seen": "2026-04-01T00:00:00Z",
                 "agent_uri": "agent://x.example.com", "endpoint": "old"}
        remote = {"trust_tier": "internal", "last_seen": "2026-04-02T00:00:00Z",
                  "agent_uri": "agent://x.example.com", "endpoint": "new"}
        assert resolve_federation_conflict(local, remote) == "remote"
        merged = merge_federation_record(local, remote)
        assert merged["endpoint"] == "new"
        assert merged["trust_tier"] == "external"

    def test_remote_lower_tier_kept_when_remote_wins(self):
        local = {"trust_tier": "verified", "last_seen": "2026-04-01T00:00:00Z"}
        remote = {"trust_tier": "verified", "last_seen": "2026-04-02T00:00:00Z"}
        assert merge_federation_record(local, remote)["trust_tier"] == "verified"

    def test_tie_breaks_deterministically_by_uri(self):
        ts = "2026-04-10T00:00:00+00:00"
        a = {"trust_tier": "verified", "last_seen": ts, "registry_id": "agent://a.example.com"}
        b = {"trust_tier": "verified", "last_seen": ts, "registry_id": "agent://b.example.com"}
        # The lexicographically smaller URI wins regardless of which side
        # is local — every registry converges on the same record.
        assert resolve_federation_conflict(a, b) == "local"
        assert resolve_federation_conflict(b, a) == "remote"


# ---------------------------------------------------------------------------
# Trust proof replay
# ---------------------------------------------------------------------------


class TestTrustProof:
    def test_valid_proof_verifies_once(self, keys):
        req = sign_federation_trust_proof(keys, REG, ["resolve"], audience=LOCAL)
        assert verify_federation_trust_proof(req, expected_audience=LOCAL) is True
        # Replay of the identical request is rejected.
        assert verify_federation_trust_proof(req, expected_audience=LOCAL) is False

    def test_wrong_audience_rejected(self, keys):
        req = sign_federation_trust_proof(keys, REG, ["resolve"], audience=LOCAL)
        assert verify_federation_trust_proof(
            req, expected_audience="agent://other.example.com"
        ) is False

    def test_missing_audience_fails_closed(self, keys):
        req = sign_federation_trust_proof(keys, REG, ["resolve"], audience=LOCAL)
        assert verify_federation_trust_proof(req) is False

    def test_stale_proof_rejected(self, keys):
        req = sign_federation_trust_proof(
            keys, REG, ["resolve"], audience=LOCAL,
            issued_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert verify_federation_trust_proof(req, expected_audience=LOCAL) is False

    def test_tampered_fields_rejected(self, keys):
        req = sign_federation_trust_proof(keys, REG, ["resolve"], audience=LOCAL)
        for update in (
            {"nonce": "x" * 32},
            {"capabilities": ["resolve", "search"]},
            {"issued_at": datetime.now(UTC) + timedelta(seconds=1)},
        ):
            bad = req.model_copy(update=update)
            assert verify_federation_trust_proof(bad, expected_audience=LOCAL) is False

    def test_legacy_proof_without_nonce_rejected(self, keys):
        """The old canonical form (registry_id NUL caps) must no longer verify."""
        import base64

        sk = Ed25519PrivateKey.from_private_bytes(keys)
        canonical = REG.encode() + b"\x00" + b"resolve"
        sig = base64.b64encode(sk.sign(canonical)).decode()
        from ampro.registry.federation import RegistryFederationRequest

        req = RegistryFederationRequest(registry_id=REG, capabilities=["resolve"],
                                        trust_proof=sig)
        assert verify_federation_trust_proof(req, expected_audience=LOCAL) is False


# ---------------------------------------------------------------------------
# Revoke signature
# ---------------------------------------------------------------------------


class TestRevoke:
    def _body(self, seed, **kw):
        fields = {
            "revoking_registry": REG,
            "revoked_registry": LOCAL,
            "reason": "compromise",
            "effective_at": datetime(2026, 4, 1, tzinfo=UTC),
            **kw,
        }
        sig = sign_federation_revoke(seed, fields)
        return RegistryFederationRevokeBody(**fields, signature=sig)

    def test_valid_revoke_verifies(self, keys):
        body = self._body(keys)
        assert verify_federation_revoke(body, expected_revoked_registry=LOCAL) is True

    def test_forged_signature_rejected(self, keys):
        body = self._body(keys).model_copy(update={"signature": "A" * 88})
        assert verify_federation_revoke(body, expected_revoked_registry=LOCAL) is False

    def test_tampered_reason_rejected(self, keys):
        body = self._body(keys).model_copy(update={"reason": "other"})
        assert verify_federation_revoke(body, expected_revoked_registry=LOCAL) is False

    def test_revoke_for_other_registry_rejected(self, keys):
        body = self._body(keys)
        assert verify_federation_revoke(
            body, expected_revoked_registry="agent://c.example.com"
        ) is False

    def test_unknown_revoker_rejected(self, keys):
        other = Ed25519PrivateKey.generate().private_bytes_raw()
        body = self._body(other, revoking_registry="agent://evil.example.com")
        assert verify_federation_revoke(body, expected_revoked_registry=LOCAL) is False
