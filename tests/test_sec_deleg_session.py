"""Security regression tests for the session handshake and binding.

Covers:
  * client echoes confirm_nonce in session.confirm;
  * binding key is derived via ephemeral X25519 + HKDF and never sent;
  * server verifies binding_proof (mandatory);
  * per-message HMAC covers the body;
  * verify_message_binding never raises on non-ASCII input;
  * resume tokens expire;
  * handshake timeout starts at the first transition.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ampro.core.envelope import AgentMessage
from ampro.session.binding import (
    create_message_binding,
    verify_message_binding,
)
from ampro.session.handshake import (
    HandshakeState,
    HandshakeStateMachine,
    HandshakeTimeoutError,
    SessionBindingError,
    SessionConfirmBody,
    SessionInitBody,
    SessionReplayError,
    client_finish_handshake,
    client_start_handshake,
    create_resume_token,
    parse_resume_token,
    server_accept_init,
    server_verify_confirm,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server_accept(init: SessionInitBody, sm: HandshakeStateMachine):
    return server_accept_init(
        init,
        sm,
        session_id="sess-1",
        negotiated_capabilities=["messaging"],
        negotiated_version="1.0.0",
        trust_tier="verified",
        trust_score=500,
    )


def _full_handshake():
    client_sm, server_sm = HandshakeStateMachine(), HandshakeStateMachine()
    init, client_state = client_start_handshake(["messaging"], "1.0.0", client_sm)
    est, server_binding = _server_accept(init, server_sm)
    confirm, client_binding = client_finish_handshake(client_state, est, client_sm)
    return init, est, confirm, server_binding, client_binding, server_sm, client_sm


# ---------------------------------------------------------------------------
# Item 6 — key agreement, proof verification
# ---------------------------------------------------------------------------


class TestKeyAgreement:
    def test_both_sides_derive_same_key_without_transmitting_it(self):
        init, est, confirm, sb, cb, server_sm, _ = _full_handshake()
        assert sb.binding_token == cb.binding_token
        assert len(sb.binding_token) == 64
        wire = json.dumps(
            [init.model_dump(), est.model_dump(), confirm.model_dump()]
        )
        assert sb.binding_token not in wire
        assert est.binding_token is None
        assert init.client_ephemeral_key and est.server_ephemeral_key

    def test_server_verifies_valid_confirm(self):
        _, _, confirm, sb, _, server_sm, _ = _full_handshake()
        assert server_verify_confirm(confirm, sb, server_sm) is True
        assert server_sm.state == HandshakeState.CONFIRMED

    def test_forged_proof_rejected(self):
        _, _, confirm, sb, _, server_sm, _ = _full_handshake()
        forged = confirm.model_copy(update={"binding_proof": "00" * 32})
        with pytest.raises(SessionBindingError):
            server_verify_confirm(forged, sb, server_sm)
        assert server_sm.state == HandshakeState.ESTABLISHED

    def test_eavesdropper_cannot_compute_proof(self):
        """A passive observer of init+established (all public values) who
        guesses binding_token from the wire cannot produce a valid proof."""
        init, est, confirm, sb, _, server_sm, _ = _full_handshake()
        from ampro.session.binding import compute_binding_proof

        guess = compute_binding_proof(
            est.server_nonce,  # attacker tries public values as the key
            session_id=est.session_id,
            client_nonce=init.client_nonce,
            server_nonce=est.server_nonce,
            confirm_nonce=est.confirm_nonce,
            client_public_key=init.client_ephemeral_key,
            server_public_key=est.server_ephemeral_key,
        )
        bad = confirm.model_copy(update={"binding_proof": guess})
        with pytest.raises(SessionBindingError):
            server_verify_confirm(bad, sb, server_sm)

    def test_confirm_replay_rejected(self):
        _, _, confirm, sb, _, server_sm, _ = _full_handshake()
        server_verify_confirm(confirm, sb, server_sm)
        with pytest.raises((SessionReplayError, SessionBindingError, ValueError)):
            server_verify_confirm(confirm, sb, server_sm)

    def test_init_without_ephemeral_key_rejected(self):
        init = SessionInitBody(
            proposed_capabilities=["messaging"],
            proposed_version="1.0.0",
            client_nonce="a" * 64,
        )
        with pytest.raises(SessionBindingError):
            _server_accept(init, HandshakeStateMachine())

    def test_client_rejects_established_without_server_key(self):
        client_sm = HandshakeStateMachine()
        init, state = client_start_handshake(["messaging"], "1.0.0", client_sm)
        est, _ = _server_accept(init, HandshakeStateMachine())
        legacy = est.model_copy(
            update={"server_ephemeral_key": None, "binding_token": "leaked"}
        )
        with pytest.raises(SessionBindingError):
            client_finish_handshake(state, legacy, client_sm)

    def test_wrong_session_id_rejected(self):
        _, _, confirm, sb, _, server_sm, _ = _full_handshake()
        bad = confirm.model_copy(update={"session_id": "sess-other"})
        with pytest.raises(SessionBindingError):
            server_verify_confirm(bad, sb, server_sm)


# ---------------------------------------------------------------------------
# Item 1 + 6 — client connect() wire behaviour
# ---------------------------------------------------------------------------


@pytest.fixture
def _fake_public_dns(monkeypatch):
    """The client resolves and pins target hosts; keep tests off real DNS."""
    import asyncio
    import socket

    async def fake_getaddrinfo(self, host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_fake_public_dns")
async def test_client_connect_echoes_confirm_nonce_and_server_verifies():
    from ampro.client.session import connect

    server_sm = HandshakeStateMachine()
    captured: dict = {}
    calls: list[dict] = []

    async def mock_post(url, *args, **kwargs):
        payload = kwargs["json"]
        calls.append(payload)
        if payload["body_type"] == "session.init":
            init = SessionInitBody.model_validate(payload["body"])
            est, binding = _server_accept(init, server_sm)
            captured["binding"] = binding
            reply = AgentMessage(
                sender="agent://target.example.com",
                recipient=payload["sender"],
                body_type="session.established",
                body=est.model_dump(mode="json"),
            )
        elif payload["body_type"] == "session.confirm":
            confirm = SessionConfirmBody.model_validate(payload["body"])
            server_verify_confirm(confirm, captured["binding"], server_sm)
            reply = AgentMessage(
                sender="agent://target.example.com",
                recipient=payload["sender"],
                body_type="session.active",
                body={"status": "active"},
            )
        else:
            b = captured["binding"]
            assert verify_message_binding(
                b.session_id,
                payload["id"],
                b.binding_token,
                kwargs["headers"]["Session-Binding"],
                body=payload["body"],
            )
            reply = AgentMessage(
                sender="agent://target.example.com",
                recipient=payload["sender"],
                body_type="message",
                body={"ok": True},
            )
        return httpx.Response(200, json=reply.model_dump(mode="json"),
                              request=httpx.Request("POST", url))

    with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        session = await connect("agent://target.example.com",
                                sender="agent://me.example.com")
        assert server_sm.state == HandshakeState.CONFIRMED
        confirm_body = calls[1]["body"]
        assert confirm_body["confirm_nonce"]
        reply = await session.send({"q": "hi"})
        assert reply.body == {"ok": True}


# ---------------------------------------------------------------------------
# Item 6 — per-message HMAC covers the body; Item 9 — never raises
# ---------------------------------------------------------------------------


class TestMessageBinding:
    def test_body_tamper_detected(self):
        tag = create_message_binding("s", "m", "tok", body={"amount": 1})
        assert verify_message_binding("s", "m", "tok", tag, body={"amount": 1})
        assert not verify_message_binding("s", "m", "tok", tag, body={"amount": 999})

    def test_key_order_irrelevant(self):
        tag = create_message_binding("s", "m", "tok", body={"a": 1, "b": 2})
        assert verify_message_binding("s", "m", "tok", tag, body={"b": 2, "a": 1})

    @pytest.mark.parametrize("bad", ["é" * 64, "☃", "ff\x00", "💥"])
    def test_non_ascii_hmac_returns_false(self, bad):
        assert verify_message_binding("s", "m", "tok", bad, body=None) is False

    def test_unserialisable_body_returns_false(self):
        tag = create_message_binding("s", "m", "tok", body={})
        assert verify_message_binding("s", "m", "tok", tag, body={"x": object()}) is False


# ---------------------------------------------------------------------------
# Item 7 — resume token expiry
# ---------------------------------------------------------------------------


class TestResumeTokenExpiry:
    KEY = b"k" * 32

    def _token_created_at(self, created: datetime) -> str:
        raw = {
            "v": "v1s",
            "session_id": "s",
            "binding_token": "b",
            "context": None,
            "created_at": created.isoformat(),
        }
        import hashlib
        import hmac as _h

        payload = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        sig = _h.new(self.KEY, payload, hashlib.sha256).digest()
        return (
            base64.urlsafe_b64encode(payload).decode()
            + "."
            + base64.urlsafe_b64encode(sig).decode()
        )

    def test_fresh_token_accepted(self):
        tok = create_resume_token("s", "b", key=self.KEY)
        assert parse_resume_token(tok, key=self.KEY)["session_id"] == "s"

    def test_old_token_rejected_by_default(self):
        tok = self._token_created_at(datetime.now(UTC) - timedelta(hours=2))
        with pytest.raises(ValueError, match="expired"):
            parse_resume_token(tok, key=self.KEY)

    def test_max_age_configurable(self):
        tok = self._token_created_at(datetime.now(UTC) - timedelta(minutes=10))
        parse_resume_token(tok, key=self.KEY)
        with pytest.raises(ValueError, match="expired"):
            parse_resume_token(tok, key=self.KEY, max_age_seconds=60)

    def test_future_token_rejected(self):
        tok = self._token_created_at(datetime.now(UTC) + timedelta(hours=1))
        with pytest.raises(ValueError):
            parse_resume_token(tok, key=self.KEY)


# ---------------------------------------------------------------------------
# Item 8 — timeout clock starts at first transition
# ---------------------------------------------------------------------------


def test_handshake_clock_starts_at_first_transition():
    sm = HandshakeStateMachine(timeout_seconds=0.05)
    time.sleep(0.1)  # idle time before the handshake begins must not count
    sm.transition("send_init")
    sm.transition("receive_established")
    time.sleep(0.1)
    with pytest.raises(HandshakeTimeoutError):
        sm.transition("send_confirm")
