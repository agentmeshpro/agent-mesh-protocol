"""
13 — Key Revocation

Demonstrates broadcasting a key revocation when an agent's private key
is compromised, rotated, or the agent is decommissioned. Shows all
three revocation reasons and how a receiver validates the broadcast.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/13_key_revocation.py
"""

from datetime import datetime, timezone

from ampro import (
    AgentMessage,
    KeyRevocationBody,
    RevocationReason,
    validate_body,
)

print("=== Revocation Reasons ===\n")

for reason in RevocationReason:
    print(f"  {reason.value}")

# ---------------------------------------------------------------------------
# Scenario 1: Key compromise — emergency broadcast
# ---------------------------------------------------------------------------

print("\n=== Scenario 1: Key Compromise (Emergency) ===\n")

compromise_body = KeyRevocationBody(
    agent_id="agent://data-processor.example.com",
    revoked_key_id="key-dp-2025-a1b2c3",
    revoked_at=datetime.now(timezone.utc).isoformat(),
    reason=RevocationReason.KEY_COMPROMISE.value,
    replacement_key_id=None,  # No replacement yet — key was stolen
    jwks_url="https://data-processor.example.com/.well-known/jwks.json",
    signature="ed25519-emergency-sig-placeholder",
)

msg = AgentMessage(
    sender="agent://data-processor.example.com",
    recipient="agent://registry.example.com",
    body_type="key.revocation",
    headers={"Key-Revoked-At": compromise_body.revoked_at},
    body=compromise_body.model_dump(),
)

print(f"  Broadcast from: {msg.sender}")
print(f"  Revoked key:    {compromise_body.revoked_key_id}")
print(f"  Reason:         {compromise_body.reason}")
print(f"  Replacement:    {compromise_body.replacement_key_id or '(none — emergency)'}")
print(f"  JWKS URL:       {compromise_body.jwks_url}")

# ---------------------------------------------------------------------------
# Scenario 2: Routine key rotation
# ---------------------------------------------------------------------------

print("\n=== Scenario 2: Key Rotation (Routine) ===\n")

rotation_body = KeyRevocationBody(
    agent_id="agent://monitor.example.com",
    revoked_key_id="key-mon-2025-old",
    revoked_at=datetime.now(timezone.utc).isoformat(),
    reason=RevocationReason.KEY_ROTATION.value,
    replacement_key_id="key-mon-2026-new",
    jwks_url="https://monitor.example.com/.well-known/jwks.json",
    signature="ed25519-rotation-sig-placeholder",
)

print(f"  Agent:          {rotation_body.agent_id}")
print(f"  Old key:        {rotation_body.revoked_key_id}")
print(f"  New key:        {rotation_body.replacement_key_id}")
print(f"  Reason:         {rotation_body.reason}")

# ---------------------------------------------------------------------------
# Scenario 3: Agent decommissioned
# ---------------------------------------------------------------------------

print("\n=== Scenario 3: Agent Decommissioned ===\n")

decommission_body = KeyRevocationBody(
    agent_id="agent://legacy-indexer.example.com",
    revoked_key_id="key-legacy-2024-final",
    revoked_at=datetime.now(timezone.utc).isoformat(),
    reason=RevocationReason.AGENT_DECOMMISSIONED.value,
    replacement_key_id=None,  # No replacement — agent is gone
    jwks_url=None,            # No JWKS — agent is shutting down
    signature="ed25519-decom-sig-placeholder",
)

print(f"  Agent:          {decommission_body.agent_id}")
print(f"  Revoked key:    {decommission_body.revoked_key_id}")
print(f"  Reason:         {decommission_body.reason}")
print(f"  Replacement:    {decommission_body.replacement_key_id or '(none — permanent)'}")
print(f"  JWKS URL:       {decommission_body.jwks_url or '(none — shutting down)'}")

# ---------------------------------------------------------------------------
# Receiver: validate a revocation broadcast
# ---------------------------------------------------------------------------

print("\n=== Receiver: Handling a Revocation ===\n")

incoming_body = validate_body("key.revocation", msg.body)
print(f"  Validated type: {type(incoming_body).__name__}")
print(f"  Agent:          {incoming_body.agent_id}")
print(f"  Revoked key:    {incoming_body.revoked_key_id}")

# Simulate receiver logic
reason = incoming_body.reason
if reason == RevocationReason.KEY_COMPROMISE.value:
    print("  Action:         PURGE cached key immediately, block messages signed with it")
elif reason == RevocationReason.KEY_ROTATION.value:
    print("  Action:         Fetch new JWKS, replace cached key")
elif reason == RevocationReason.AGENT_DECOMMISSIONED.value:
    print("  Action:         Remove agent from local registry, purge all cached keys")
else:
    print(f"  Action:         Unknown reason '{reason}' — log and ignore")
