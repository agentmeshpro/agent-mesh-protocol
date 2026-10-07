"""
17 — Agent Lifecycle (Orderly Shutdown)

Demonstrates the full lifecycle of an agent going from active to
decommissioned. The agent broadcasts a deactivation notice, drains
sessions, and the registry marks it as gone.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/17_agent_lifecycle.py
"""

from datetime import datetime, timezone, timedelta

from ampro import (
    AgentJson,
    AgentMessage,
    AgentLifecycleStatus,
    AgentDeactivationNoticeBody,
    RegistryResolution,
    validate_body,
)

# ---------------------------------------------------------------------------
# Step 1: Agent is active and serving requests
# ---------------------------------------------------------------------------

print("=== Step 1: Agent Active ===\n")

agent = AgentJson(
    protocol_version="0.1.3",
    identifiers=["agent://data-processor.example.com"],
    endpoint="https://data-processor.example.com/agent/message",
    jwks_url="https://data-processor.example.com/.well-known/jwks.json",
    capabilities={"groups": ["data-processing", "analytics"], "level": 3},
    status=AgentLifecycleStatus.ACTIVE.value,
    ttl_seconds=3600,
)

print(f"  Agent:     {agent.identifiers[0]}")
print(f"  Endpoint:  {agent.endpoint}")
print(f"  Status:    {agent.status}")
print(f"  Caps:      {agent.capabilities['groups']}")

# ---------------------------------------------------------------------------
# Step 2: Agent decides to deactivate — status changes
# ---------------------------------------------------------------------------

print("\n=== Step 2: Begin Deactivation ===\n")

agent.status = AgentLifecycleStatus.DEACTIVATING.value

now = datetime.now(timezone.utc)
final_time = now + timedelta(minutes=10)

print(f"  Status changed to: {agent.status}")
print(f"  Deactivation started: {now.isoformat()}")
print(f"  Expected offline at:  {final_time.isoformat()}")

# ---------------------------------------------------------------------------
# Step 3: Broadcast deactivation notice to peers
# ---------------------------------------------------------------------------

print("\n=== Step 3: Broadcast Deactivation Notice ===\n")

notice = AgentDeactivationNoticeBody(
    agent_id="agent://data-processor.example.com",
    reason="Scheduled maintenance — migrating to v2 infrastructure",
    deactivation_time=now.isoformat(),
    active_sessions=7,
    migration_endpoint="https://data-processor-v2.example.com/agent/message",
    final_at=final_time.isoformat(),
    metadata={"version": "1.4.2", "replacement_version": "2.0.0"},
)

print(f"  Agent:              {notice.agent_id}")
print(f"  Reason:             {notice.reason}")
print(f"  Active sessions:    {notice.active_sessions}")
print(f"  Migration endpoint: {notice.migration_endpoint}")
print(f"  Final at:           {notice.final_at}")

# Wrap in an AgentMessage envelope
notice_msg = AgentMessage(
    sender="agent://data-processor.example.com",
    recipient="agent://registry.amp-protocol.dev",
    body_type="agent.deactivation_notice",
    headers={
        "Protocol-Version": "0.1.3",
        "Priority": "high",
    },
    body=notice.model_dump(),
)

print(f"\n  Envelope:")
print(f"    From:      {notice_msg.sender}")
print(f"    To:        {notice_msg.recipient}")
print(f"    Body type: {notice_msg.body_type}")
print(f"    ID:        {notice_msg.id}")

# Validate the body round-trips correctly
validated = validate_body("agent.deactivation_notice", notice_msg.body)
print(f"\n  Validated:   {type(validated).__name__}")
print(f"  Agent match: {validated.agent_id == notice.agent_id}")

# ---------------------------------------------------------------------------
# Step 4: Sessions drain
# ---------------------------------------------------------------------------

print("\n=== Step 4: Draining Sessions ===\n")

sessions_remaining = notice.active_sessions
while sessions_remaining > 0:
    drained = min(3, sessions_remaining)
    sessions_remaining -= drained
    print(f"  Drained {drained} session(s) — {sessions_remaining} remaining")

print(f"  All sessions drained.")

# ---------------------------------------------------------------------------
# Step 5: Agent is now decommissioned
# ---------------------------------------------------------------------------

print("\n=== Step 5: Decommissioned ===\n")

agent.status = AgentLifecycleStatus.DECOMMISSIONED.value

print(f"  Status: {agent.status}")
print(f"  The agent will no longer accept new sessions or messages.")

# ---------------------------------------------------------------------------
# Step 6: Registry returns gone=True
# ---------------------------------------------------------------------------

print("\n=== Step 6: Registry Resolution (Gone) ===\n")

resolution = RegistryResolution(
    agent_uri="agent://data-processor.example.com",
    endpoint="https://data-processor.example.com/agent/message",
    agent_json_url="https://data-processor.example.com/.well-known/agent.json",
    ttl_seconds=86400,
    status=AgentLifecycleStatus.DECOMMISSIONED.value,
    gone=True,
)

print(f"  Agent URI:  {resolution.agent_uri}")
print(f"  Status:     {resolution.status}")
print(f"  Gone:       {resolution.gone}")
print(f"  TTL:        {resolution.ttl_seconds}s (cached so clients stop asking)")

# Show what clients should do
print("\n=== Client Behavior ===\n")

if resolution.gone:
    print(f"  Registry returned gone=True for {resolution.agent_uri}")
    print(f"  Client should:")
    print(f"    1. Stop sending messages to this agent")
    print(f"    2. Check deactivation notice for migration_endpoint")
    print(f"    3. Re-resolve through registry if a replacement exists")
    migration = notice.migration_endpoint
    if migration:
        print(f"    4. Redirect traffic to: {migration}")
