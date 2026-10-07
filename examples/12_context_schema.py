"""
12 — Context Schema Declaration

Shows how agents declare context schemas via URN and how
callers check schema support before sending structured tasks.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/12_context_schema.py
"""

from ampro import (
    AgentJson,
    AgentMessage,
    check_schema_supported,
    parse_schema_urn,
    validate_body,
)

print("=== Context Schema URN Parsing ===\n")

urns = [
    "urn:schema:status-report:v1",
    "urn:schema:com.example.metric:v2",
    "urn:domain:log-entry:v1",
]

for urn in urns:
    info = parse_schema_urn(urn)
    print(f"  {urn}")
    print(f"    namespace: {info.namespace}")
    print(f"    name:      {info.name}")
    print(f"    version:   {info.version}")
    print()


print("=== Schema Support Check ===\n")

agent_schemas = [
    "urn:schema:status-report:v1",
    "urn:schema:metric:v2",
    "urn:schema:alert:v1",
]

test_schemas = [
    "urn:schema:status-report:v1",
    "urn:schema:log-entry:v1",
    "URN:SCHEMA:METRIC:V2",  # case-insensitive
]

print(f"Agent supports: {agent_schemas}\n")
for urn in test_schemas:
    supported = check_schema_supported(urn, agent_schemas)
    status = "SUPPORTED" if supported else "NOT supported"
    print(f"  {urn:40s} → {status}")


print("\n=== Sending a Structured Task ===\n")

# Step 1: Check if receiver supports the schema
receiver = AgentJson(
    protocol_version="1.0.0",
    identifiers=["agent://monitor.example.com"],
    endpoint="https://monitor.example.com/agent/message",
    supported_schemas=["urn:schema:status-report:v1"],
)

schema_urn = "urn:schema:status-report:v1"
if check_schema_supported(schema_urn, receiver.supported_schemas):
    print(f"Receiver supports {schema_urn} — sending structured task")

    # Step 2: Create the task with Context-Schema header
    msg = AgentMessage(
        sender="agent://agent-a.example.com",
        recipient="agent://monitor.example.com",
        body_type="task.create",
        headers={
            "Context-Schema": schema_urn,
            "Protocol-Version": "1.0.0",
            "Transaction-Id": "txn-report-2026-042",
        },
        body={
            "description": "Status Report #SR-2026-042",
            "context": {
                "service": "auth-gateway",
                "status": "degraded",
                "uptime_pct": 99.2,
                "active_connections": 1423,
                "error_rate": 0.8,
            },
        },
    )

    print(f"  From: {msg.sender}")
    print(f"  To:   {msg.recipient}")
    print(f"  Type: {msg.body_type}")
    print(f"  Schema: {msg.headers['Context-Schema']}")
    print(f"  Transaction: {msg.headers['Transaction-Id']}")

    # Validate the body
    validated = validate_body("task.create", msg.body)
    print(f"  Body validated: {type(validated).__name__}")
    print(f"  Description: {validated.description}")
else:
    print(f"Receiver does NOT support {schema_urn} — sending conversationally")
