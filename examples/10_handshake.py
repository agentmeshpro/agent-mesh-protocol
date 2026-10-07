"""
10 — Session Handshake

Simulates a 3-phase handshake between two agents, including
session binding, ping/pong keepalive, and graceful close.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/10_handshake.py
"""

import secrets
from ampro import (
    SessionInitBody, SessionEstablishedBody, SessionConfirmBody,
    SessionPingBody, SessionPongBody, SessionCloseBody,
    HandshakeStateMachine, HandshakeState,
    derive_binding_token, create_message_binding, verify_message_binding,
)

print("=== 3-Phase Session Handshake ===\n")

# --- Phase 1: Client sends session.init ---
client_sm = HandshakeStateMachine()
server_sm = HandshakeStateMachine()

client_nonce = secrets.token_hex(32)
init = SessionInitBody(
    proposed_capabilities=["messaging", "tools", "streaming"],
    proposed_version="1.0.0",
    client_nonce=client_nonce,
    conversation_id="conv-demo-001",
)
client_sm.transition("send_init")
server_sm.transition("receive_init")
print(f"1. Client → Server: session.init")
print(f"   Capabilities: {init.proposed_capabilities}")
print(f"   Client nonce: {client_nonce[:16]}...")
print(f"   Client state: {client_sm.state.value}")
print(f"   Server state: {server_sm.state.value}")

# --- Phase 2: Server responds with session.established ---
server_nonce = secrets.token_hex(32)
session_id = f"sess-{secrets.token_hex(8)}"
shared_secret = "demo-shared-secret"  # In production, from JWT/DID/API-key exchange
binding_token = derive_binding_token(client_nonce, server_nonce, session_id, shared_secret)

established = SessionEstablishedBody(
        confirm_nonce="example-nonce",
    session_id=session_id,
    negotiated_capabilities=["messaging", "tools"],
    negotiated_version="1.0.0",
    trust_tier="verified",
    trust_score=450,
    session_ttl_seconds=3600,
    server_nonce=server_nonce,
    binding_token=binding_token,
)
server_sm.transition("send_established")
client_sm.transition("receive_established")
print(f"\n2. Server → Client: session.established")
print(f"   Session: {session_id}")
print(f"   Trust: {established.trust_tier} ({established.trust_score}/1000)")
print(f"   Capabilities: {established.negotiated_capabilities}")
print(f"   TTL: {established.session_ttl_seconds}s")
print(f"   Client state: {client_sm.state.value}")
print(f"   Server state: {server_sm.state.value}")

# --- Phase 3: Client sends session.confirm ---
client_binding = derive_binding_token(client_nonce, server_nonce, session_id, shared_secret)
confirm = SessionConfirmBody(
        confirm_nonce="example-nonce",
    session_id=session_id,
    binding_proof=client_binding,
)
client_sm.transition("send_confirm")
server_sm.transition("receive_confirm")
client_sm.transition("activate")
server_sm.transition("activate")
print(f"\n3. Client → Server: session.confirm")
print(f"   Binding proof matches: {client_binding == binding_token}")
print(f"   Client state: {client_sm.state.value}")
print(f"   Server state: {server_sm.state.value}")

# --- Per-message binding ---
print(f"\n=== Message Binding ===\n")
msg_id = "msg-001"
msg_hmac = create_message_binding(session_id, msg_id, binding_token)
print(f"Message {msg_id} binding: {msg_hmac[:32]}...")
print(f"Valid: {verify_message_binding(session_id, msg_id, binding_token, msg_hmac)}")
print(f"Forged: {verify_message_binding(session_id, msg_id, binding_token, 'forged')}")

# --- Ping/pong ---
print(f"\n=== Keepalive ===\n")
ping = SessionPingBody(session_id=session_id, timestamp="2026-04-09T12:00:00Z")
pong = SessionPongBody(session_id=session_id, timestamp="2026-04-09T12:00:01Z", active_tasks=3)
print(f"Ping: session={ping.session_id}, ts={ping.timestamp}")
print(f"Pong: session={pong.session_id}, ts={pong.timestamp}, tasks={pong.active_tasks}")

# --- Close ---
print(f"\n=== Close ===\n")
close = SessionCloseBody(session_id=session_id, reason="demo complete")
client_sm.transition("close")
print(f"Close: {close.reason}")
print(f"Final state: {client_sm.state.value}")
