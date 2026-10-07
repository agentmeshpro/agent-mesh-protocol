"""Tests for session handshake replay defense (C4) and binding token documentation (C5).

Covers:
  - confirm_nonce field presence on SessionEstablishedBody and SessionConfirmBody
  - HandshakeStateMachine nonce issuance and consumption
  - SessionReplayError on replay or unknown nonce
  - binding_token field preservation (AM-1)
  - TLS documentation comment existence (C5 reframe)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ampro.session.handshake import (
    HandshakeStateMachine,
    SessionConfirmBody,
    SessionEstablishedBody,
    SessionReplayError,
)

# ---------------------------------------------------------------------------
# C4: confirm_nonce field presence
# ---------------------------------------------------------------------------


class TestConfirmNonceFields:
    """Verify that confirm_nonce was added to both body types."""

    def test_confirm_nonce_issued_in_established_body(self) -> None:
        """SessionEstablishedBody has a confirm_nonce field."""
        assert "confirm_nonce" in SessionEstablishedBody.model_fields
        # Instantiate with all required fields to confirm it validates
        body = SessionEstablishedBody(
            session_id="sess-1",
            negotiated_capabilities=["messaging"],
            negotiated_version="1.0.0",
            trust_tier="external",
            trust_score=500,
            server_nonce="a" * 64,
            binding_token="tok-abc",
            confirm_nonce="nonce-xyz",
        )
        assert body.confirm_nonce == "nonce-xyz"

    def test_confirm_nonce_echoed_in_confirm_body(self) -> None:
        """SessionConfirmBody has a confirm_nonce field."""
        assert "confirm_nonce" in SessionConfirmBody.model_fields
        body = SessionConfirmBody(
            session_id="sess-1",
            binding_proof="proof-abc",
            confirm_nonce="nonce-xyz",
        )
        assert body.confirm_nonce == "nonce-xyz"


# ---------------------------------------------------------------------------
# C4: HandshakeStateMachine nonce tracking
# ---------------------------------------------------------------------------


class TestNonceTracking:
    """Verify issue/consume lifecycle on HandshakeStateMachine."""

    def test_valid_nonce_consumed_successfully(self) -> None:
        """issue -> consume -> returns True."""
        sm = HandshakeStateMachine()
        nonce = sm.issue_confirm_nonce()
        assert isinstance(nonce, str)
        assert len(nonce) == 32  # token_hex(16) => 32 hex chars
        result = sm.consume_confirm_nonce(nonce)
        assert result is True

    def test_replay_nonce_raises(self) -> None:
        """issue -> consume -> consume again -> SessionReplayError."""
        sm = HandshakeStateMachine()
        nonce = sm.issue_confirm_nonce()
        sm.consume_confirm_nonce(nonce)
        with pytest.raises(SessionReplayError, match="already been consumed"):
            sm.consume_confirm_nonce(nonce)

    def test_unknown_nonce_raises(self) -> None:
        """Consuming a nonce that was never issued -> SessionReplayError."""
        sm = HandshakeStateMachine()
        with pytest.raises(SessionReplayError, match="never issued"):
            sm.consume_confirm_nonce("totally-made-up-nonce")

    def test_multiple_nonces_independent(self) -> None:
        """Issue N1, issue N2, consume N2 -> N1 still valid."""
        sm = HandshakeStateMachine()
        n1 = sm.issue_confirm_nonce()
        n2 = sm.issue_confirm_nonce()
        # Consume N2 first
        assert sm.consume_confirm_nonce(n2) is True
        # N1 is still valid
        assert sm.consume_confirm_nonce(n1) is True
        # Both are now consumed — replaying either raises
        with pytest.raises(SessionReplayError):
            sm.consume_confirm_nonce(n1)
        with pytest.raises(SessionReplayError):
            sm.consume_confirm_nonce(n2)


# ---------------------------------------------------------------------------
# C5 / AM-1: binding_token field preserved + TLS documentation
# ---------------------------------------------------------------------------


class TestBindingTokenPreservation:
    """binding_token is kept only as a deprecated, never-populated field.

    The binding key is derived via X25519 key agreement and is never sent
    on the wire (it previously travelled in the clear, which made
    binding_proof meaningless).
    """

    def test_binding_token_field_is_deprecated_and_optional(self) -> None:
        assert "binding_token" in SessionEstablishedBody.model_fields
        field_info = SessionEstablishedBody.model_fields["binding_token"]
        assert field_info.default is None
        assert "DEPRECATED" in (field_info.description or "")

    def test_handshake_module_documents_key_is_never_sent(self) -> None:
        handshake_path = (
            Path(__file__).resolve().parents[2]
            / "ampro"
            / "session"
            / "handshake.py"
        )
        source = handshake_path.read_text()
        assert "NEVER sent on the wire" in source
