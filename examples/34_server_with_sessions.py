"""
34 — AMP Server with Sessions

Demonstrates the 3-phase session handshake as server-side handler logic.
Sessions are stored in-memory. The server handles session.init,
session.confirm, and session-bound messages, proving that handshake
lifecycle is YOUR code — the server just routes messages.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git fastapi uvicorn
    python examples/34_server_with_sessions.py

Test session.init:
    curl -X POST http://localhost:8004/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://client","recipient":"agent://session.example.com","body_type":"session.init","body":{"proposed_capabilities":["messaging","tools"],"proposed_version":"1.0.0","client_nonce":"aabbccdd"}}'

Test session.confirm (use session_id and binding_proof from init response):
    curl -X POST http://localhost:8004/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://client","recipient":"agent://session.example.com","body_type":"session.confirm","body":{"session_id":"<SESSION_ID>","binding_proof":"<BINDING_TOKEN>"}}'

Test session-bound message (use Session-Id from established response):
    curl -X POST http://localhost:8004/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://client","recipient":"agent://session.example.com","body_type":"message","body":{"text":"hello via session"},"headers":{"Session-Id":"<SESSION_ID>"}}'
"""

import os
import secrets

from ampro import (
    AgentMessage,
    HandshakeStateMachine,
    derive_binding_token,
    verify_message_binding,
)
from ampro.server import AgentServer

server = AgentServer(
    agent_id="agent://session.example.com",
    endpoint="http://localhost:8004",
)

# ── In-memory session store ────────────────────────────────────────

SHARED_SECRET = "demo-server-secret"  # In production: from key exchange / JWT

sessions: dict[str, dict] = {}
# Each entry: { "state_machine": HandshakeStateMachine,
#                "binding_token": str,
#                "client_nonce": str,
#                "server_nonce": str,
#                "capabilities": list[str] }


# ── Phase 1: Client proposes a session ─────────────────────────────

@server.on("session.init")
def handle_init(msg: AgentMessage) -> dict:
    """Create a new session and return session.established."""
    body = msg.body if isinstance(msg.body, dict) else {}
    client_nonce = body.get("client_nonce", secrets.token_hex(16))
    proposed_caps = body.get("proposed_capabilities", [])

    # Generate server-side values.
    server_nonce = secrets.token_hex(32)
    session_id = f"sess-{secrets.token_hex(8)}"

    # Derive the binding token both sides can verify.
    binding_token = derive_binding_token(
        client_nonce, server_nonce, session_id, SHARED_SECRET,
    )

    # Track session state.
    sm = HandshakeStateMachine()
    sm.transition("receive_init")
    sm.transition("send_established")

    sessions[session_id] = {
        "state_machine": sm,
        "binding_token": binding_token,
        "client_nonce": client_nonce,
        "server_nonce": server_nonce,
        "capabilities": proposed_caps,
    }

    print(f"  [init] Created session {session_id} for {msg.sender}")

    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "session.established",
        "body": {
            "session_id": session_id,
            "negotiated_capabilities": proposed_caps,
            "negotiated_version": "1.0.0",
            "trust_tier": "external",
            "trust_score": 200,
            "session_ttl_seconds": 3600,
            "server_nonce": server_nonce,
            "binding_token": binding_token,
        },
        "headers": {"In-Reply-To": msg.id},
    }


# ── Phase 2: Client proves it holds the binding token ──────────────

@server.on("session.confirm")
def handle_confirm(msg: AgentMessage) -> dict:
    """Verify the client's binding proof and activate the session."""
    body = msg.body if isinstance(msg.body, dict) else {}
    session_id = body.get("session_id", "")
    binding_proof = body.get("binding_proof", "")

    sess = sessions.get(session_id)
    if sess is None:
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "task.error",
            "body": {"reason": "unknown_session", "detail": f"No session {session_id}"},
        }

    # Check the proof matches our binding token.
    if binding_proof != sess["binding_token"]:
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "task.error",
            "body": {"reason": "binding_failed", "detail": "Proof does not match"},
        }

    # Advance the state machine.
    sm = sess["state_machine"]
    sm.transition("receive_confirm")
    sm.transition("activate")

    print(f"  [confirm] Session {session_id} is now ACTIVE")

    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "message",
        "body": {"text": f"Session {session_id} activated"},
        "headers": {"Session-Id": session_id},
    }


# ── Session-bound messages ─────────────────────────────────────────

@server.on("message")
def handle_message(msg: AgentMessage) -> dict:
    """Handle a message, checking for a valid session binding."""
    session_id = msg.headers.get("Session-Id")

    if not session_id:
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "message",
            "body": {"text": "No session. Send session.init first."},
            "headers": {"In-Reply-To": msg.id},
        }

    sess = sessions.get(session_id)
    if sess is None:
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "task.error",
            "body": {"reason": "unknown_session", "detail": f"No session {session_id}"},
        }

    sm = sess["state_machine"]
    if sm.state.value != "active":
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "task.error",
            "body": {
                "reason": "session_not_active",
                "detail": f"Session is {sm.state.value}, not active",
            },
        }

    # Optionally verify per-message binding (Session-Binding header).
    binding_hmac = msg.headers.get("Session-Binding")
    if binding_hmac:
        valid = verify_message_binding(
            session_id, msg.id, sess["binding_token"], binding_hmac,
        )
        if not valid:
            return {
                "sender": server.agent_id,
                "recipient": msg.sender,
                "body_type": "task.error",
                "body": {"reason": "binding_invalid", "detail": "HMAC mismatch"},
            }

    text = ""
    if isinstance(msg.body, dict):
        text = msg.body.get("text", "")

    print(f"  [message] Session {session_id}: {text}")

    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "message",
        "body": {"text": f"[session {session_id}] Echo: {text}"},
        "headers": {"In-Reply-To": msg.id, "Session-Id": session_id},
    }


if __name__ == "__main__":
    print("=== AMP Server with Sessions ===\n")
    print(f"Agent: {server.agent_id}")
    print("Handshake: 3-phase (init → established → confirm)\n")
    print("Session lifecycle:")
    print("  1. POST session.init → get session_id + binding_token")
    print("  2. POST session.confirm → prove binding, activate session")
    print("  3. POST message with Session-Id header → session-bound messaging\n")
    print("Try session.init:\n")
    print("  curl -X POST http://localhost:8004/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://client\",\"recipient\":\"agent://session.example.com\",\"body_type\":\"session.init\",\"body\":{\"proposed_capabilities\":[\"messaging\"],\"proposed_version\":\"1.0.0\",\"client_nonce\":\"aabbccdd\"}}'")
    print()
    if os.environ.get("AMPRO_EXAMPLE_NO_SERVE"):
        # Smoke-test mode (tests/test_examples_run.py): everything above ran,
        # but don't block on a long-running server.
        print("AMPRO_EXAMPLE_NO_SERVE is set; not starting the server.")
    else:
        server.run(port=8004)
