"""Tests for issues #39 (revoke), #40 (sync), #41 (conflict resolution)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ampro.registry.federation import (
    RegistryFederationRevokeBody,
    RegistryFederationSyncBody,
    RegistryFederationSyncResponseBody,
    resolve_federation_conflict,
)


class TestRegistryFederationRevokeBody:
    """Issue #39 — federation revocation body."""

    def test_all_fields(self):
        body = RegistryFederationRevokeBody(
            revoking_registry="agent://reg-a.example.com",
            revoked_registry="agent://reg-b.example.com",
            reason="policy_violation",
            effective_at=datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC),
            signature="ed25519-signature-base64",
        )
        assert body.revoking_registry == "agent://reg-a.example.com"
        assert body.revoked_registry == "agent://reg-b.example.com"

    def test_missing_required_raises(self):
        with pytest.raises(ValidationError):
            RegistryFederationRevokeBody(
                revoking_registry="agent://reg-a.example.com",
            )

    def test_reason_max_length(self):
        with pytest.raises(ValidationError):
            RegistryFederationRevokeBody(
                revoking_registry="agent://reg-a.example.com",
                revoked_registry="agent://reg-b.example.com",
                reason="x" * 1025,
                effective_at=datetime.now(tz=UTC),
                signature="sig",
            )

    def test_registered_in_body_schemas(self):
        from ampro import validate_body

        body = validate_body(
            "registry.federation_revoke",
            {
                "revoking_registry": "agent://reg-a.example.com",
                "revoked_registry": "agent://reg-b.example.com",
                "reason": "policy_violation",
                "effective_at": "2026-04-09T12:00:00+00:00",
                "signature": "sig",
            },
        )
        assert isinstance(body, RegistryFederationRevokeBody)


class TestRegistryFederationSyncBodies:
    """Issue #40 — federation sync protocol."""

    def test_sync_body_required_fields(self):
        body = RegistryFederationSyncBody(
            since=datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC),
            registry_id="agent://reg.example.com",
        )
        assert body.cursor is None

    def test_sync_body_with_cursor(self):
        body = RegistryFederationSyncBody(
            since=datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC),
            registry_id="agent://reg.example.com",
            cursor="opaque-cursor-token",
        )
        assert body.cursor == "opaque-cursor-token"

    def test_sync_response_empty(self):
        body = RegistryFederationSyncResponseBody(changes=[])
        assert body.changes == []
        assert body.next_cursor is None
        assert body.has_more is False

    def test_sync_response_with_changes(self):
        body = RegistryFederationSyncResponseBody(
            changes=[
                {"op": "upsert", "agent_uri": "agent://a.example.com"},
                {"op": "delete", "agent_uri": "agent://b.example.com"},
            ],
            next_cursor="next",
            has_more=True,
        )
        assert len(body.changes) == 2
        assert body.next_cursor == "next"
        assert body.has_more is True

    def test_sync_response_change_limit(self):
        with pytest.raises(ValidationError):
            RegistryFederationSyncResponseBody(changes=[{} for _ in range(501)])

    def test_registered_in_body_schemas(self):
        from ampro import validate_body

        sync = validate_body(
            "registry.federation_sync",
            {
                "since": "2026-04-09T12:00:00+00:00",
                "registry_id": "agent://reg.example.com",
            },
        )
        assert isinstance(sync, RegistryFederationSyncBody)

        resp = validate_body(
            "registry.federation_sync_response",
            {"changes": [{"op": "upsert"}]},
        )
        assert isinstance(resp, RegistryFederationSyncResponseBody)


class TestFederationConflictResolution:
    """Issue #41 — deterministic conflict resolution between federated registries."""

    def _record(self, **kw):
        return kw  # dict-shaped record is enough; resolver accepts either.

    def test_federation_conflict_resolves_by_trust_then_recency(self):
        # (1) local tier higher than remote → local wins regardless of recency.
        # The reversed direction (remote claims higher tier) does NOT promote
        # the remote: remote tier claims are never load-bearing. This is the
        # post-v0.3.4 security fix that closed the tier-self-claim hijack.
        local_high = self._record(
            trust_tier="verified",
            last_seen="2026-04-01T00:00:00+00:00",
            agent_uri="agent://a.example.com",
        )
        remote_low = self._record(
            trust_tier="external",
            last_seen="2026-04-10T00:00:00+00:00",
            agent_uri="agent://a.example.com",
        )
        assert resolve_federation_conflict(local_high, remote_low) == "local"
        # Reversed — local is lower-tier; remote's higher tier is IGNORED and
        # the resolver falls through to timestamps. Local's last_seen is
        # newer (2026-04-10 vs 2026-04-01) so local still wins.
        assert resolve_federation_conflict(remote_low, local_high) == "local"

        # (2) Same tier → more recent last_seen wins.
        same_tier_older = self._record(
            trust_tier="verified",
            last_seen="2026-04-01T00:00:00+00:00",
            agent_uri="agent://a.example.com",
        )
        same_tier_newer = self._record(
            trust_tier="verified",
            last_seen="2026-04-10T00:00:00+00:00",
            agent_uri="agent://a.example.com",
        )
        assert resolve_federation_conflict(same_tier_older, same_tier_newer) == "remote"
        assert resolve_federation_conflict(same_tier_newer, same_tier_older) == "local"

        # (3) Tier equal, last_seen equal → LOCAL wins. The previous lex
        # tiebreaker let an attacker pick a registry_id that sorted earlier
        # to win pure ties; "local wins ties" is the safer default.
        left = self._record(
            trust_tier="verified",
            last_seen="2026-04-10T00:00:00+00:00",
            agent_uri="agent://a.example.com",
        )
        right = self._record(
            trust_tier="verified",
            last_seen="2026-04-10T00:00:00+00:00",
            agent_uri="agent://b.example.com",
        )
        assert resolve_federation_conflict(left, right) == "local"
        assert resolve_federation_conflict(right, left) == "local"

    def test_handles_attribute_records(self):
        class Rec:
            def __init__(self, trust_tier, last_seen, agent_uri):
                self.trust_tier = trust_tier
                self.last_seen = last_seen
                self.agent_uri = agent_uri

        local = Rec("verified", datetime(2026, 4, 10, tzinfo=UTC), "agent://a.example.com")
        remote = Rec("external", datetime(2026, 4, 11, tzinfo=UTC), "agent://a.example.com")
        assert resolve_federation_conflict(local, remote) == "local"
