"""
10 — Session Handshake

Simulates a 3-phase handshake between two agents, including
session binding, ping/pong keepalive, and graceful close.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/10_handshake.py
"""

import secrets

from ampro import (
    HandshakeStateMachine,
    SessionCloseBody,
    SessionPingBody,
    SessionPongBody,
    create_message_binding,
    verify_message_binding,
)
from ampro.session.handshake import (
    client_finish_handshake,
    client_start_handshake,
    server_accept_init,
    server_verify_confirm,
)

print("=== 3-Phase Session Handshake ===\n")

client_sm = HandshakeStateMachine()
server_sm = HandshakeStateMachine()

# --- Phase 1: Client sends session.init (with an ephemeral X25519 key) ---
init, client_state = client_start_handshake(
    ["messaging", "tools", "streaming"], "1.0.0", client_sm,
    conversation_id="conv-demo-001",
)
print("1. Client → Server: session.init")
print(f"   Capabilities: {init.proposed_capabilities}")
print(f"   Client nonce: {init.client_nonce[:16]}...")
print(f"   Client state: {client_sm.state.value}")

# --- Phase 2: Server answers with its own ephemeral key ---
session_id = f"sess-{secrets.token_hex(8)}"
established, server_binding = server_accept_init(
    init, server_sm,
    session_id=session_id,
    negotiated_capabilities=["messaging", "tools"],
    negotiated_version="1.0.0",
    trust_tier="verified",
    trust_score=450,
)
print("\n2. Server → Client: session.established")
print(f"   Session: {established.session_id}")
print(f"   Trust: {established.trust_tier} ({established.trust_score}/1000)")
print(f"   Capabilities: {established.negotiated_capabilities}")
print("   The binding key is derived on both sides; it is never sent.")
print(f"   Server state: {server_sm.state.value}")

# --- Phase 3: Client proves it derived the same key ---
confirm, client_binding = client_finish_handshake(client_state, established, client_sm)
assert server_verify_confirm(confirm, server_binding, server_sm)
client_sm.transition("activate")
server_sm.transition("activate")
print("\n3. Client → Server: session.confirm")
print(f"   Both sides hold the same key: {client_binding.binding_token == server_binding.binding_token}")
print(f"   Client state: {client_sm.state.value}")
print(f"   Server state: {server_sm.state.value}")

# --- Per-message binding (covers the message body) ---
print("\n=== Message Binding ===\n")
key = client_binding.binding_token
msg_id = "msg-001"
body = {"description": "hello"}
msg_hmac = create_message_binding(session_id, msg_id, key, body=body)
print(f"Message {msg_id} binding: {msg_hmac[:32]}...")
print(f"Valid: {verify_message_binding(session_id, msg_id, key, msg_hmac, body=body)}")
tampered = {"description": "transfer all funds"}
print(f"Tampered body: {verify_message_binding(session_id, msg_id, key, msg_hmac, body=tampered)}")
print(f"Forged: {verify_message_binding(session_id, msg_id, key, 'forged', body=body)}")

# --- Ping/pong ---
print("\n=== Keepalive ===\n")
ping = SessionPingBody(session_id=session_id, timestamp="2026-04-09T12:00:00Z")
pong = SessionPongBody(session_id=session_id, timestamp="2026-04-09T12:00:01Z", active_tasks=3)
print(f"Ping: session={ping.session_id}, ts={ping.timestamp}")
print(f"Pong: session={pong.session_id}, ts={pong.timestamp}, tasks={pong.active_tasks}")

# --- Close ---
print("\n=== Close ===\n")
close = SessionCloseBody(session_id=session_id, reason="demo complete")
client_sm.transition("close")
print(f"Close: {close.reason}")
print(f"Final state: {client_sm.state.value}")
