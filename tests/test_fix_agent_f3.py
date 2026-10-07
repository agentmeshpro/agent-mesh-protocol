"""Tests for Fix Agent AMP-F3 changes.

Covers 13 issues across security, session, streaming and middleware:
  #10  non-dict body in middleware raises TypeError
  #11  ApiKeyStore is thread-safe under concurrent writes
  #28  stream checkpoint rejects oversized state_snapshot
  #29  encryption key-offer/accept bodies round-trip
  #30  encryption downgrade is blocked when session requires it
  #31  revocation store is pluggable and gate rejects revoked keys
  #32  challenge solution validators dispatch per challenge_type
  #33  handshake times out after configured interval
  #34  per-session channel registry enforces quota
  #44  StreamingEvent accepts cross_channel_seq
  #45  SSE event rejects oversized payload
  #49  stream-auth refresh token format is constrained
  #50  cross-verification policy can be enforced
"""

from __future__ import annotations

import hashlib
import threading
import time

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# #10 — validate_message_body rejects non-dict / non-str / non-None body
# ---------------------------------------------------------------------------


class TestNonDictBodyMiddleware:
    def test_non_dict_non_str_body_raises_typeerror(self):
        from ampro import AgentMessage, validate_message_body

        for bad in ([1, 2, 3], 42, True, 3.14):
            msg = AgentMessage(
                sender="agent://a.example.com",
                recipient="agent://b.example.com",
                body_type="message",
                body=bad,
            )
            with pytest.raises(TypeError, match="body must be dict, str, or None"):
                validate_message_body(msg)

    def test_dict_body_still_works(self):
        from ampro import AgentMessage, validate_message_body

        msg = AgentMessage(
            sender="agent://a.example.com",
            recipient="agent://b.example.com",
            body_type="message",
            body={"text": "hello"},
        )
        validated = validate_message_body(msg)
        assert getattr(validated, "text", None) == "hello" or isinstance(validated, dict)

    def test_none_body_returns_empty(self):
        from ampro import AgentMessage, validate_message_body

        msg = AgentMessage(
            sender="agent://a.example.com",
            recipient="agent://b.example.com",
            body_type="message",
            body=None,
        )
        assert validate_message_body(msg) == {}


# ---------------------------------------------------------------------------
# #11 — ApiKeyStore thread-safety
# ---------------------------------------------------------------------------


class TestApiKeyStoreRaceSafety:
    def test_api_key_store_concurrent_access_does_not_crash(self):
        from ampro import ApiKeyStore

        store = ApiKeyStore(max_failures=10_000, block_seconds=60)
        errors: list[BaseException] = []

        def hammer(base_ip: str) -> None:
            try:
                for i in range(200):
                    ip = f"{base_ip}.{i % 7}"
                    store.record_failure(ip)
                    store.is_blocked(ip)
                    if i % 13 == 0:
                        store.reset_failures(ip)
            except BaseException as exc:  # noqa: BLE001 — test-surface catch
                errors.append(exc)

        threads = [
            threading.Thread(target=hammer, args=(f"10.0.{n}",)) for n in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent access raised: {errors!r}"


# ---------------------------------------------------------------------------
# #28 — Checkpoint state_snapshot size limit
# ---------------------------------------------------------------------------


class TestCheckpointSizeLimit:
    def test_checkpoint_rejects_oversized_state(self):
        from ampro import StreamCheckpointEvent

        # Build a snapshot whose JSON encoding exceeds 1 MiB.
        big_blob = "x" * (1_048_577)
        with pytest.raises(ValidationError, match="state_snapshot exceeds 1 MiB"):
            StreamCheckpointEvent(
                checkpoint_id="cp-big",
                seq=1,
                state_snapshot={"blob": big_blob},
                timestamp="2026-04-21T00:00:00Z",
            )

    def test_checkpoint_accepts_small_state(self):
        from ampro import StreamCheckpointEvent

        cp = StreamCheckpointEvent(
            checkpoint_id="cp-small",
            seq=1,
            state_snapshot={"cursor": "abc"},
            timestamp="2026-04-21T00:00:00Z",
        )
        assert cp.state_snapshot == {"cursor": "abc"}


# ---------------------------------------------------------------------------
# #29 — Encryption key offer / accept round-trip
# #30 — Downgrade-to-plaintext rejected when required
# ---------------------------------------------------------------------------


class TestEncryptionKeyExchange:
    def test_encryption_key_offer_roundtrip(self):
        from ampro import EncryptionKeyAcceptBody, EncryptionKeyOfferBody

        offer = EncryptionKeyOfferBody(
            agent_id="agent://alice.example.com",
            supported_schemes=["x25519-chacha20poly1305"],
            wrapping_keys={"x25519-chacha20poly1305": "base64pubkey=="},
        )
        restored = EncryptionKeyOfferBody.model_validate_json(offer.model_dump_json())
        assert restored.supported_schemes == ["x25519-chacha20poly1305"]
        assert restored.wrapping_keys["x25519-chacha20poly1305"] == "base64pubkey=="

        accept = EncryptionKeyAcceptBody(
            chosen_scheme="x25519-chacha20poly1305",
            ephemeral_key="base64-ephemeral==",
        )
        restored_accept = EncryptionKeyAcceptBody.model_validate_json(
            accept.model_dump_json()
        )
        assert restored_accept.chosen_scheme == "x25519-chacha20poly1305"
        assert restored_accept.ephemeral_key == "base64-ephemeral=="

    def test_encrypted_body_has_required_encryption_flag(self):
        from ampro import EncryptedBody

        body = EncryptedBody(
            ciphertext="c", iv="i", tag="t",
            algorithm="A256GCM", recipient_key_id="k-1",
            required_encryption=True,
        )
        assert body.required_encryption is True


class TestEncryptionDowngradeRejected:
    def test_downgrade_to_plaintext_rejected_when_required(self):
        from ampro import (
            AgentMessage,
            EncryptionDowngradeError,
            enforce_encryption_requirement,
        )

        # Plaintext message arriving on a session that pinned required_encryption.
        plain_msg = AgentMessage(
            sender="agent://a.example.com",
            recipient="agent://b.example.com",
            body_type="message",
            body={"text": "hello"},
        )
        with pytest.raises(EncryptionDowngradeError):
            enforce_encryption_requirement(plain_msg, session_requires_encryption=True)

    def test_encrypted_body_passes_through(self):
        from ampro import AgentMessage, enforce_encryption_requirement

        encrypted_msg = AgentMessage(
            sender="agent://a.example.com",
            recipient="agent://b.example.com",
            body_type="encrypted",
            body={
                "ciphertext": "c", "iv": "i", "tag": "t",
                "algorithm": "A256GCM", "recipient_key_id": "k-1",
            },
        )
        # Should not raise.
        enforce_encryption_requirement(encrypted_msg, session_requires_encryption=True)

    def test_unrequired_session_allows_plaintext(self):
        from ampro import AgentMessage, enforce_encryption_requirement

        msg = AgentMessage(
            sender="agent://a.example.com",
            recipient="agent://b.example.com",
            body_type="message",
            body={"text": "hello"},
        )
        enforce_encryption_requirement(msg, session_requires_encryption=False)

    def test_session_context_carries_requires_encryption_flag(self):
        from ampro import SessionContext

        ctx = SessionContext(
            session_id="s-1",
            session_requires_encryption=True,
        )
        assert ctx.session_requires_encryption is True


# ---------------------------------------------------------------------------
# #31 — Key revocation propagation
# ---------------------------------------------------------------------------


class TestRevocationStore:
    def test_revocation_broadcast_body_roundtrip(self):
        from ampro import KeyRevocationBody, KeyRevocationBroadcastBody

        rev = KeyRevocationBody(
            agent_id="agent://alice.example.com",
            revoked_key_id="key-123",
            revoked_at="2026-04-21T00:00:00Z",
            reason="key_compromise",
            signature="sig==",
        )
        broadcast = KeyRevocationBroadcastBody(
            revocation=rev,
            broadcast_by="agent://relay.example.com",
            broadcast_at="2026-04-21T00:00:01Z",
            hop_count=1,
        )
        restored = KeyRevocationBroadcastBody.model_validate_json(
            broadcast.model_dump_json()
        )
        assert restored.hop_count == 1
        assert restored.revocation.revoked_key_id == "key-123"

    def test_revocation_store_pluggable(self):
        from ampro import (
            register_revocation_store,
            revocation_verify_cached_key,
            should_reject_cached_key,
        )
        from ampro.security.key_revocation import (
            _UnconfiguredRevocationStore as _NoOpRevocationStore,
        )

        class Store:
            def __init__(self) -> None:
                self.revoked = {"bad-key"}

            def is_revoked(self, key_id: str) -> bool:
                return key_id in self.revoked

        try:
            register_revocation_store(Store())
            assert should_reject_cached_key("bad-key") is True
            assert should_reject_cached_key("good-key") is False
            assert revocation_verify_cached_key("good-key") is True
            assert revocation_verify_cached_key("bad-key") is False
        finally:
            register_revocation_store(_NoOpRevocationStore())


# ---------------------------------------------------------------------------
# #32 — Challenge solution validators
# ---------------------------------------------------------------------------


class TestChallengeSolution:
    def test_validate_challenge_solution_dispatches_correctly(self):
        from ampro import (
            ChallengeType,
            TaskChallengeBody,
            TaskChallengeResponseBody,
            validate_challenge_solution,
        )

        # Shared secret — matches
        challenge = TaskChallengeBody(
            challenge_id="ch-1",
            challenge_type=ChallengeType.SHARED_SECRET.value,
            parameters={"expected_solution": "open-sesame"},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        ok = TaskChallengeResponseBody(challenge_id="ch-1", solution="open-sesame")
        bad = TaskChallengeResponseBody(challenge_id="ch-1", solution="nope")
        assert validate_challenge_solution(challenge, ok) is True
        assert validate_challenge_solution(challenge, bad) is False

        # Echo
        echo_challenge = TaskChallengeBody(
            challenge_id="ch-2",
            challenge_type=ChallengeType.ECHO.value,
            parameters={"echo": "hello"},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        echo_ok = TaskChallengeResponseBody(challenge_id="ch-2", solution="hello")
        assert validate_challenge_solution(echo_challenge, echo_ok) is True

        # Proof of work with difficulty < MIN_POW_DIFFICULTY is rejected.
        # Previously difficulty=0 was accepted — a no-op challenge — which
        # was patched in v0.3.4 (see security/challenge.py::MIN_POW_DIFFICULTY).
        pow_too_easy = TaskChallengeBody(
            challenge_id="ch-3",
            challenge_type=ChallengeType.PROOF_OF_WORK.value,
            parameters={"difficulty": 0},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        pow_any = TaskChallengeResponseBody(challenge_id="ch-3", solution="deadbeef")
        assert validate_challenge_solution(pow_too_easy, pow_any) is False

        # Proof of work with a reasonable difficulty — search for a solution
        difficulty = 8
        pow_tough = TaskChallengeBody(
            challenge_id="ch-4",
            challenge_type=ChallengeType.PROOF_OF_WORK.value,
            parameters={"difficulty": difficulty},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        # Search a solution (8-bit difficulty → expected ~256 tries)
        found = None
        for i in range(50_000):
            candidate = format(i, "x")
            digest = hashlib.sha256(("ch-4" + candidate).encode()).digest()
            if digest[0] == 0:
                found = candidate
                break
        assert found is not None
        pow_solved = TaskChallengeResponseBody(challenge_id="ch-4", solution=found)
        assert validate_challenge_solution(pow_tough, pow_solved) is True

        # Mismatched challenge_id → always False
        mismatched = TaskChallengeResponseBody(challenge_id="other", solution="hello")
        assert validate_challenge_solution(echo_challenge, mismatched) is False

        # Unknown challenge type → False
        unknown = TaskChallengeBody(
            challenge_id="ch-9",
            challenge_type="not-a-real-type",
            parameters={},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        resp = TaskChallengeResponseBody(challenge_id="ch-9", solution="anything")
        assert validate_challenge_solution(unknown, resp) is False


# ---------------------------------------------------------------------------
# #33 — Handshake timeout
# ---------------------------------------------------------------------------


class TestHandshakeTimeout:
    def test_handshake_times_out_after_configured_interval(self):
        from ampro import HandshakeStateMachine, HandshakeTimeoutError

        sm = HandshakeStateMachine(timeout_seconds=0.05)
        # The clock starts at the first transition (send_init), not at
        # construction. Sleep past the deadline after it; the next
        # transition MUST raise.
        sm.transition("send_init")
        time.sleep(0.1)
        with pytest.raises(HandshakeTimeoutError):
            sm.transition("receive_established")

    def test_handshake_timeout_default(self):
        from ampro import HandshakeStateMachine

        sm = HandshakeStateMachine()
        assert sm.timeout_seconds == 30.0

    def test_handshake_timeout_custom(self):
        from ampro import HandshakeStateMachine

        sm = HandshakeStateMachine(timeout_seconds=5.0)
        assert sm.timeout_seconds == 5.0


# ---------------------------------------------------------------------------
# #34 — Per-session channel registry
# ---------------------------------------------------------------------------


class TestChannelRegistry:
    def test_channel_registry_enforces_per_session_limit(self):
        from ampro import ChannelQuotaExceededError, ChannelRegistry
        from ampro.streaming.channel import MAX_CHANNELS_PER_SESSION

        reg = ChannelRegistry()
        session = "sess-1"
        for i in range(MAX_CHANNELS_PER_SESSION):
            reg.register_channel(session, f"ch-{i}")
        assert reg.count(session) == MAX_CHANNELS_PER_SESSION

        with pytest.raises(ChannelQuotaExceededError):
            reg.register_channel(session, "ch-overflow")

        # Release one → can open one more
        reg.release_channel(session, "ch-0")
        reg.register_channel(session, "ch-new")
        assert reg.count(session) == MAX_CHANNELS_PER_SESSION

    def test_channel_registry_scopes_per_session(self):
        from ampro import ChannelRegistry

        reg = ChannelRegistry(max_per_session=2)
        reg.register_channel("s-a", "ch-1")
        reg.register_channel("s-a", "ch-2")
        # Different session — fresh budget
        reg.register_channel("s-b", "ch-1")
        assert reg.count("s-a") == 2
        assert reg.count("s-b") == 1

    def test_channel_registry_release_idempotent(self):
        from ampro import ChannelRegistry

        reg = ChannelRegistry()
        reg.register_channel("s", "c")
        reg.release_channel("s", "c")
        reg.release_channel("s", "c")  # no-op
        assert reg.count("s") == 0


# ---------------------------------------------------------------------------
# #44 — Cross-channel seq on StreamingEvent
# ---------------------------------------------------------------------------


class TestCrossChannelSeq:
    def test_streaming_event_accepts_cross_channel_seq(self):
        from ampro import StreamingEvent, StreamingEventType

        ev = StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"text": "x"},
            cross_channel_seq=42,
        )
        assert ev.cross_channel_seq == 42

    def test_streaming_event_cross_channel_seq_optional(self):
        from ampro import StreamingEvent, StreamingEventType

        ev = StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"text": "x"},
        )
        assert ev.cross_channel_seq is None

    def test_streaming_event_cross_channel_seq_ge_zero(self):
        from ampro import StreamingEvent, StreamingEventType

        with pytest.raises(ValidationError):
            StreamingEvent(
                type=StreamingEventType.TEXT_DELTA,
                data={},
                cross_channel_seq=-1,
            )


# ---------------------------------------------------------------------------
# #45 — SSE event size limit
# ---------------------------------------------------------------------------


class TestSseSizeLimit:
    def test_sse_event_rejects_oversized(self):
        from ampro import StreamingEvent, StreamingEventType

        ev = StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"text": "x" * 300_000},
        )
        with pytest.raises(ValueError, match="SSE event exceeds"):
            ev.to_sse()

    def test_sse_event_small_passes(self):
        from ampro import StreamingEvent, StreamingEventType

        ev = StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"text": "hi"},
            id="e-1",
        )
        sse = ev.to_sse()
        assert "event: text_delta" in sse


# ---------------------------------------------------------------------------
# #49 — Stream auth refresh token format
# ---------------------------------------------------------------------------


class TestStreamAuthRefreshFormat:
    def test_stream_auth_refresh_rejects_malformed_token(self):
        from ampro import StreamAuthRefreshEvent

        # Too short
        with pytest.raises(ValidationError):
            StreamAuthRefreshEvent(
                method="bearer",
                token="short",
                expires_at="2099-01-01T00:00:00Z",
            )
        # Invalid charset
        with pytest.raises(ValidationError):
            StreamAuthRefreshEvent(
                method="bearer",
                token="not a valid token!!",
                expires_at="2099-01-01T00:00:00Z",
            )
        # Unknown method
        with pytest.raises(ValidationError):
            StreamAuthRefreshEvent(
                method="mystery-method",
                token="abcdefghijklmnop",
                expires_at="2099-01-01T00:00:00Z",
            )

    def test_stream_auth_refresh_accepts_valid_token(self):
        from ampro import StreamAuthRefreshEvent

        ev = StreamAuthRefreshEvent(
            method="bearer",
            token="abcdefghijklmnop.more-stuff_here",
            expires_at="2099-01-01T00:00:00Z",
        )
        assert ev.method == "bearer"


# ---------------------------------------------------------------------------
# #50 — Cross-verification enforcement
# ---------------------------------------------------------------------------


class TestCrossVerificationPolicy:
    def test_cross_verification_policy_enforced_when_required(self):
        import asyncio

        from ampro import (
            CrossVerificationRequiredError,
            cross_verify_identifiers,
            register_cross_verification_policy,
        )

        try:
            register_cross_verification_policy(True)
            # Identifier with no fetcher → returns verified=False
            with pytest.raises(CrossVerificationRequiredError):
                asyncio.run(
                    cross_verify_identifiers(
                        identifiers=["agent://alice.example.com"],
                        expected_endpoint="https://alice.example.com/agent",
                        expected_public_key=None,
                        fetch_agent_json=None,
                    )
                )
        finally:
            register_cross_verification_policy(False)

    def test_cross_verification_default_policy_is_permissive(self):
        import asyncio

        from ampro import cross_verify_identifiers

        results = asyncio.run(
            cross_verify_identifiers(
                identifiers=["agent://alice.example.com"],
                expected_endpoint="https://alice.example.com/agent",
                expected_public_key=None,
                fetch_agent_json=None,
            )
        )
        # Without required policy, unverified results are returned silently.
        assert len(results) == 1
        assert results[0].verified is False
