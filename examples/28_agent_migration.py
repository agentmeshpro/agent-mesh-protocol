"""
28 — Agent Migration

Demonstrates agent identity migration: announcing an address change with
IdentityMigrationBody, setting moved_to in AgentJson, wrapping in
AgentMessage, federation request/response flow, and audit attestation
for session agreement.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/28_agent_migration.py
"""

from ampro import (
    AgentJson,
    AgentMessage,
    AuditAttestationBody,
    IdentityMigrationBody,
    RegistryFederationRequest,
    RegistryFederationResponse,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

OLD_ADDRESS = "agent://assistant.old-host.example.com"
NEW_ADDRESS = "agent://assistant.new-host.example.com"
SESSION_ID = "sess-migration-001"

print("=== Agent Migration ===\n")
print(f"  Old address: {OLD_ADDRESS}")
print(f"  New address: {NEW_ADDRESS}")

# ---------------------------------------------------------------------------
# Step 1: Create IdentityMigrationBody (old -> new)
# ---------------------------------------------------------------------------

print("\n=== Step 1: Create Migration Body ===\n")

migration = IdentityMigrationBody(
    old_id=OLD_ADDRESS,
    new_id=NEW_ADDRESS,
    migration_proof="eyJhbGciOiJFZDI1NTE5In0.eyJvbGQiOiJhZ2VudDovL2Fzc2lzdGFudC5vbGQtaG9zdC5jb20iLCJuZXciOiJhZ2VudDovL2Fzc2lzdGFudC5uZXctaG9zdC5jb20ifQ.SIGNATURE",
    effective_at="2026-04-10T00:00:00Z",
)

print(f"  old_id:          {migration.old_id}")
print(f"  new_id:          {migration.new_id}")
print(f"  migration_proof: {migration.migration_proof[:50]}...")
print(f"  effective_at:    {migration.effective_at}")

# ---------------------------------------------------------------------------
# Step 2: AgentJson with moved_to field
# ---------------------------------------------------------------------------

print("\n=== Step 2: AgentJson with moved_to ===\n")

agent_json = AgentJson(
    protocol_version="0.1.8",
    identifiers=[OLD_ADDRESS],
    endpoint="https://old-host.example.com/agent/message",
    status="deactivating",
    moved_to=NEW_ADDRESS,
)

print(f"  protocol_version: {agent_json.protocol_version}")
print(f"  identifiers:      {agent_json.identifiers}")
print(f"  endpoint:         {agent_json.endpoint}")
print(f"  status:           {agent_json.status}")
print(f"  moved_to:         {agent_json.moved_to}")
print()
print("  Callers fetching /.well-known/agent.json at the old address")
print(f"  see moved_to={agent_json.moved_to!r} and follow the redirect.")

# ---------------------------------------------------------------------------
# Step 3: Wrap migration in AgentMessage
# ---------------------------------------------------------------------------

print("\n=== Step 3: Wrap Migration in AgentMessage ===\n")

migration_msg = AgentMessage(
    sender=OLD_ADDRESS,
    recipient=NEW_ADDRESS,
    body_type="identity.migration",
    headers={
        "Protocol-Version": "0.1.8",
        "Session-Id": SESSION_ID,
    },
    body=migration.model_dump(),
)

print(f"  sender:    {migration_msg.sender}")
print(f"  recipient: {migration_msg.recipient}")
print(f"  body_type: {migration_msg.body_type}")
print(f"  id:        {migration_msg.id}")

validated = validate_body("identity.migration", migration_msg.body)
print(f"\n  Validated type: {type(validated).__name__}")

# ---------------------------------------------------------------------------
# Step 4: Registry Federation Request/Response
# ---------------------------------------------------------------------------

print("\n=== Step 4: Registry Federation ===\n")

# Source registry requests federation with target registry
fed_request = RegistryFederationRequest(
    registry_id="agent://registry.old-host.example.com",
    capabilities=["resolve", "search"],
    trust_proof="eyJhbGciOiJFZDI1NTE5In0.eyJyZWdpc3RyeSI6InJlZ2lzdHJ5Lm9sZC1ob3N0LmNvbSJ9.SIGNATURE",
)

print("  Federation Request:")
print(f"    registry_id:  {fed_request.registry_id}")
print(f"    capabilities: {fed_request.capabilities}")
print(f"    trust_proof:  {fed_request.trust_proof[:50]}...")

fed_request_msg = AgentMessage(
    sender="agent://registry.old-host.example.com",
    recipient="agent://registry.new-host.example.com",
    body_type="registry.federation_request",
    headers={"Protocol-Version": "0.1.8"},
    body=fed_request.model_dump(),
)

validated_req = validate_body("registry.federation_request", fed_request_msg.body)
print(f"    Validated:    {type(validated_req).__name__}")

# Target registry accepts with terms
fed_response = RegistryFederationResponse(
    accepted=True,
    federation_id="fed-old-new-001",
    terms={
        "rate_limit_rps": 100,
        "ttl_seconds": 3600,
        "retention_days": 90,
    },
)

print("\n  Federation Response:")
print(f"    accepted:      {fed_response.accepted}")
print(f"    federation_id: {fed_response.federation_id}")
print(f"    terms:         {fed_response.terms}")

fed_response_msg = AgentMessage(
    sender="agent://registry.new-host.example.com",
    recipient="agent://registry.old-host.example.com",
    body_type="registry.federation_response",
    headers={"Protocol-Version": "0.1.8"},
    body=fed_response.model_dump(),
)

validated_resp = validate_body("registry.federation_response", fed_response_msg.body)
print(f"    Validated:     {type(validated_resp).__name__}")

# ---------------------------------------------------------------------------
# Step 5: Audit Attestation for Session Agreement
# ---------------------------------------------------------------------------

print("\n=== Step 5: Audit Attestation ===\n")

attestation = AuditAttestationBody(
    audit_id="att-migration-001",
    agents=[OLD_ADDRESS, NEW_ADDRESS],
    events_hash="a3f2b8c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8",
    attestation_signatures={
        OLD_ADDRESS: "SIG_OLD_KEY_abc123def456",
        NEW_ADDRESS: "SIG_NEW_KEY_ghi789jkl012",
    },
    timestamp="2026-04-09T12:00:00Z",
)

print(f"  audit_id:  {attestation.audit_id}")
print(f"  agents:    {attestation.agents}")
print(f"  events_hash: {attestation.events_hash[:32]}...")
print(f"  timestamp: {attestation.timestamp}")
print("  signatures:")
for agent, sig in attestation.attestation_signatures.items():
    print(f"    {agent}: {sig}")

attestation_msg = AgentMessage(
    sender=OLD_ADDRESS,
    recipient=NEW_ADDRESS,
    body_type="audit.attestation",
    headers={
        "Protocol-Version": "0.1.8",
        "Session-Id": SESSION_ID,
    },
    body=attestation.model_dump(),
)

validated_att = validate_body("audit.attestation", attestation_msg.body)
print(f"\n  Validated type: {type(validated_att).__name__}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== Summary ===\n")

print("  Agent migration involves four protocol primitives:")
print()
print(f"    {'Body Type':30s} {'Purpose'}")
print(f"    {'--------':30s} {'-------'}")
print(f"    {'identity.migration':30s} {'Announce old -> new address change'}")
print(f"    {'agent.json (moved_to)':30s} {'Redirect callers at old address'}")
print(f"    {'registry.federation_request':30s} {'Establish cross-registry trust'}")
print(f"    {'registry.federation_response':30s} {'Accept/reject federation terms'}")
print(f"    {'audit.attestation':30s} {'Multi-party session agreement proof'}")
