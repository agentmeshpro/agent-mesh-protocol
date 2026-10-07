"""
15 — Per-Tool Consent

Demonstrates fine-grained consent for tool invocation. An agent
requests consent to use a sensitive tool, the owner grants it with
restrictions, and the caller checks consent before invoking.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/15_tool_consent.py
"""

import secrets
from datetime import datetime, timedelta, timezone

from ampro import (
    AgentMessage,
    ToolConsentGrantBody,
    ToolConsentRequestBody,
    ToolDefinition,
    validate_body,
)

# ---------------------------------------------------------------------------
# Define tools — some require consent, others do not
# ---------------------------------------------------------------------------

print("=== Tool Definitions ===\n")

tools = [
    ToolDefinition(
        name="get_system_status",
        description="Read-only system health check",
        consent_required=False,
        parameters={"type": "object", "properties": {}},
        category="monitoring",
        tags=["read-only", "safe"],
    ),
    ToolDefinition(
        name="send_notification",
        description="Send push notification to external service",
        consent_required=True,
        consent_scopes=["notify:send", "notify:broadcast"],
        parameters={
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "message": {"type": "string"},
                "priority": {"type": "string", "enum": ["low", "normal", "high"]},
            },
            "required": ["channel", "message"],
        },
        category="actions",
        tags=["external", "side-effect"],
    ),
    ToolDefinition(
        name="delete_records",
        description="Permanently delete records from data store",
        consent_required=True,
        consent_scopes=["data:delete"],
        parameters={
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "filter": {"type": "object"},
            },
            "required": ["table", "filter"],
        },
        category="actions",
        tags=["destructive", "irreversible"],
    ),
]

for tool in tools:
    consent_label = "YES" if tool.consent_required else "no"
    scopes = ", ".join(tool.consent_scopes) if tool.consent_scopes else "(none)"
    print(f"  {tool.name:25s} consent={consent_label:3s}  scopes={scopes}")

# ---------------------------------------------------------------------------
# Check which tools need consent before use
# ---------------------------------------------------------------------------

print("\n=== Pre-Invocation Consent Check ===\n")

for tool in tools:
    if tool.consent_required:
        print(f"  {tool.name}: BLOCKED — consent required for {tool.consent_scopes}")
    else:
        print(f"  {tool.name}: OK — no consent needed")

# ---------------------------------------------------------------------------
# Step 1: Request consent for send_notification
# ---------------------------------------------------------------------------

print("\n=== Step 1: Request Consent ===\n")

session_id = f"sess-{secrets.token_hex(8)}"

consent_request = ToolConsentRequestBody(
    tool_name="send_notification",
    scopes=["notify:send"],  # Only requesting send, not broadcast
    reason="Need to send deployment status updates to the ops channel",
    session_id=session_id,
    ttl_seconds=1800,  # 30 minutes
)

request_msg = AgentMessage(
    sender="agent://deploy-agent.example.com",
    recipient="agent://platform-controller.example.com",
    body_type="tool.consent_request",
    headers={"Session-Id": session_id},
    body=consent_request.model_dump(),
)

print(f"  From:     {request_msg.sender}")
print(f"  To:       {request_msg.recipient}")
print(f"  Tool:     {consent_request.tool_name}")
print(f"  Scopes:   {consent_request.scopes}")
print(f"  Reason:   {consent_request.reason}")
print(f"  TTL:      {consent_request.ttl_seconds}s")

# ---------------------------------------------------------------------------
# Step 2: Owner grants consent with restrictions
# ---------------------------------------------------------------------------

print("\n=== Step 2: Grant Consent (with Restrictions) ===\n")

grant_id = f"grant-{secrets.token_hex(8)}"
expires = (datetime.now(timezone.utc) + timedelta(seconds=consent_request.ttl_seconds)).isoformat()

consent_grant = ToolConsentGrantBody(
    tool_name="send_notification",
    scopes=["notify:send"],  # Granted exactly what was requested
    grant_id=grant_id,
    valid_for_session=session_id,
    expires_at=expires,
    restrictions={
        "max_invocations": 10,
        "allowed_params": {
            "channel": ["ops-deploy", "ops-alerts"],  # Only these channels
            "priority": ["low", "normal"],             # No high-priority
        },
        "cooldown_seconds": 30,  # Minimum gap between invocations
    },
)

grant_msg = AgentMessage(
    sender="agent://platform-controller.example.com",
    recipient="agent://deploy-agent.example.com",
    body_type="tool.consent_grant",
    headers={"In-Reply-To": request_msg.id, "Session-Id": session_id},
    body=consent_grant.model_dump(),
)

print(f"  Grant ID:           {consent_grant.grant_id}")
print(f"  Tool:               {consent_grant.tool_name}")
print(f"  Scopes:             {consent_grant.scopes}")
print(f"  Expires:            {consent_grant.expires_at}")
print(f"  Max invocations:    {consent_grant.restrictions['max_invocations']}")
print(f"  Allowed channels:   {consent_grant.restrictions['allowed_params']['channel']}")
print(f"  Allowed priorities: {consent_grant.restrictions['allowed_params']['priority']}")
print(f"  Cooldown:           {consent_grant.restrictions['cooldown_seconds']}s")

# ---------------------------------------------------------------------------
# Step 3: Validate the grant
# ---------------------------------------------------------------------------

print("\n=== Step 3: Validate Grant ===\n")

validated = validate_body("tool.consent_grant", grant_msg.body)
print(f"  Validated type: {type(validated).__name__}")
print(f"  Grant ID:       {validated.grant_id}")
print(f"  Session match:  {validated.valid_for_session == session_id}")

# ---------------------------------------------------------------------------
# Simulate invocation checks against restrictions
# ---------------------------------------------------------------------------

print("\n=== Invocation Checks ===\n")

test_calls = [
    {"channel": "ops-deploy", "message": "Build #42 deployed", "priority": "normal"},
    {"channel": "ops-deploy", "message": "Build #43 deployed", "priority": "high"},
    {"channel": "marketing", "message": "New feature shipped", "priority": "low"},
]

allowed_channels = consent_grant.restrictions["allowed_params"]["channel"]
allowed_priorities = consent_grant.restrictions["allowed_params"]["priority"]

for call in test_calls:
    channel_ok = call["channel"] in allowed_channels
    priority_ok = call["priority"] in allowed_priorities
    allowed = channel_ok and priority_ok

    status = "ALLOWED" if allowed else "BLOCKED"
    reasons = []
    if not channel_ok:
        reasons.append(f"channel '{call['channel']}' not in {allowed_channels}")
    if not priority_ok:
        reasons.append(f"priority '{call['priority']}' not in {allowed_priorities}")

    detail = f" ({'; '.join(reasons)})" if reasons else ""
    print(f"  send_notification({call['channel']}, priority={call['priority']}) → {status}{detail}")
