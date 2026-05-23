"""Tests for session pause/resume token helpers (Task 2.7).

Verifies create_resume_token / parse_resume_token round-trip,
HMAC signing, and tamper detection.
"""

from __future__ import annotations

import base64
import json

import pytest

from ampro.session.handshake import (
    allow_unsigned_resume_tokens,
    create_resume_token,
    parse_resume_token,
)


@pytest.fixture(autouse=True)
def _enable_unsigned_for_legacy_tests():
    """These tests exercise the unsigned-token path that v0.3.4 rejected
    by default. Tests opt-in explicitly via this fixture."""
    allow_unsigned_resume_tokens(True)
    yield
    allow_unsigned_resume_tokens(False)

# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestResumeTokenRoundTrip:
    """create_resume_token -> parse_resume_token round-trip."""

    def test_unsigned_round_trip(self) -> None:
        token = create_resume_token(
            session_id="sess-001",
            binding_token="bt-abc",
        )
        data = parse_resume_token(token)
        assert data["session_id"] == "sess-001"
        assert data["binding_token"] == "bt-abc"
        assert data["context"] is None
        assert "created_at" in data

    def test_unsigned_with_context(self) -> None:
        ctx = {"user": "alice", "role": "admin"}
        token = create_resume_token(
            session_id="sess-002",
            binding_token="bt-xyz",
            session_context=ctx,
        )
        data = parse_resume_token(token)
        assert data["session_id"] == "sess-002"
        assert data["binding_token"] == "bt-xyz"
        assert data["context"] == ctx

    def test_signed_round_trip(self) -> None:
        key = b"supersecretkey1234567890abcdef!!"
        token = create_resume_token(
            session_id="sess-003",
            binding_token="bt-signed",
            session_context={"env": "prod"},
            key=key,
        )
        # Token must contain a dot separator (payload.sig)
        assert "." in token

        data = parse_resume_token(token, key=key)
        assert data["session_id"] == "sess-003"
        assert data["binding_token"] == "bt-signed"
        assert data["context"] == {"env": "prod"}
        assert "created_at" in data


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


class TestResumeTokenHMAC:
    """HMAC signature verification edge cases."""

    def test_wrong_key_raises(self) -> None:
        key = b"correct-key-here-32-bytes-long!!"
        wrong = b"wrong-key-here-this-is-different!"
        token = create_resume_token(
            session_id="sess-hmac",
            binding_token="bt-hmac",
            key=key,
        )
        with pytest.raises(ValueError, match="signature verification failed"):
            parse_resume_token(token, key=wrong)

    def test_tampered_payload_raises(self) -> None:
        key = b"tamper-detect-key-32-bytes-long!"
        token = create_resume_token(
            session_id="sess-tamper",
            binding_token="bt-tamper",
            key=key,
        )
        # Tamper with the payload portion (before the dot)
        parts = token.rsplit(".", 1)
        assert len(parts) == 2
        payload_bytes = base64.urlsafe_b64decode(parts[0])
        payload = json.loads(payload_bytes)
        payload["session_id"] = "sess-hijacked"
        tampered_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        tampered_token = f"{tampered_b64}.{parts[1]}"

        with pytest.raises(ValueError, match="signature verification failed"):
            parse_resume_token(tampered_token, key=key)


# ---------------------------------------------------------------------------
# Unsigned mode
# ---------------------------------------------------------------------------


class TestResumeTokenUnsigned:
    """Unsigned (dev/test) mode."""

    def test_unsigned_parse_succeeds(self) -> None:
        token = create_resume_token(
            session_id="sess-unsigned",
            binding_token="bt-unsigned",
        )
        # No key on either side
        data = parse_resume_token(token, key=None)
        assert data["session_id"] == "sess-unsigned"
        assert data["binding_token"] == "bt-unsigned"


# ---------------------------------------------------------------------------
# Required fields
# ---------------------------------------------------------------------------


class TestResumeTokenRequiredFields:
    """Token must contain session_id and binding_token."""

    def test_contains_session_id(self) -> None:
        token = create_resume_token(
            session_id="sess-field",
            binding_token="bt-field",
        )
        data = parse_resume_token(token)
        assert "session_id" in data

    def test_contains_binding_token(self) -> None:
        token = create_resume_token(
            session_id="sess-field2",
            binding_token="bt-field2",
        )
        data = parse_resume_token(token)
        assert "binding_token" in data

    def test_malformed_payload_missing_fields_raises(self) -> None:
        """A hand-crafted token missing required fields should be rejected."""
        bad_payload = json.dumps({"foo": "bar"}).encode()
        bad_token = base64.urlsafe_b64encode(bad_payload).decode()
        with pytest.raises(ValueError, match="missing required field"):
            parse_resume_token(bad_token)


# ---------------------------------------------------------------------------
# Top-level export
# ---------------------------------------------------------------------------


class TestResumeTokenExports:
    """Functions should be accessible from the top-level ampro package."""

    def test_importable_from_ampro(self) -> None:
        from ampro import create_resume_token as crt
        from ampro import parse_resume_token as prt

        assert callable(crt)
        assert callable(prt)

    def test_importable_from_session(self) -> None:
        from ampro.session import create_resume_token as crt
        from ampro.session import parse_resume_token as prt

        assert callable(crt)
        assert callable(prt)
