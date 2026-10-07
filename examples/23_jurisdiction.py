"""
23 — Jurisdiction Declaration and Conflict Detection

Demonstrates cross-border jurisdiction declarations, conflict detection
between agents operating under incompatible regulatory frameworks, and
task rejection when jurisdiction constraints are violated.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/23_jurisdiction.py
"""

from ampro import (
    AgentMessage,
    JurisdictionInfo,
    TaskCreateBody,
    TaskRejectBody,
    check_jurisdiction_conflict,
    validate_body,
    validate_jurisdiction_code,
)

# ---------------------------------------------------------------------------
# Setup: Three agents in different jurisdictions
# ---------------------------------------------------------------------------

AGENT_A = "agent://agent-a.example.de"
AGENT_B = "agent://agent-b.example.us"
AGENT_C = "agent://agent-c.example.ie"
SESSION_ID = "sess-jurisdiction-demo-001"
TASK_ID = "task-jurisdiction-001"

print("=== Agent Jurisdictions ===\n")

jurisdiction_a = JurisdictionInfo(
    primary="DE",
    frameworks=["GDPR"],
)

jurisdiction_b = JurisdictionInfo(
    primary="US",
    frameworks=["CCPA"],
)

jurisdiction_c = JurisdictionInfo(
    primary="IE",
    frameworks=["GDPR"],
)

print(f"  Agent A: primary={jurisdiction_a.primary}, frameworks={jurisdiction_a.frameworks}")
print(f"  Agent B: primary={jurisdiction_b.primary}, frameworks={jurisdiction_b.frameworks}")
print(f"  Agent C: primary={jurisdiction_c.primary}, frameworks={jurisdiction_c.frameworks}")

# ---------------------------------------------------------------------------
# Step 1: Detect conflict between Agent A (DE/GDPR) and Agent B (US/CCPA)
# ---------------------------------------------------------------------------

print("\n=== Step 1: Check A -> B (DE/GDPR -> US/CCPA) ===\n")

has_conflict, detail = check_jurisdiction_conflict(jurisdiction_a, jurisdiction_b)

print(f"  Has conflict: {has_conflict}")
print(f"  Detail:       {detail}")

# ---------------------------------------------------------------------------
# Step 2: Agent A sends a task to Agent B — Agent B rejects
# ---------------------------------------------------------------------------

print("\n=== Step 2: Agent A Sends Task to Agent B ===\n")

create_body = TaskCreateBody(
    description="Process data subject access request",
    task_id=TASK_ID,
    priority="normal",
    timeout_seconds=120,
)

create_msg = AgentMessage(
    sender=AGENT_A,
    recipient=AGENT_B,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
        "Jurisdiction": jurisdiction_a.model_dump_json(),
    },
    body=create_body.model_dump(),
)

print(f"  From:      {create_msg.sender}")
print(f"  To:        {create_msg.recipient}")
print(f"  Body type: {create_msg.body_type}")
print(f"  Task ID:   {create_body.task_id}")

# Agent B detects the conflict and rejects
print("\n  Agent B detects jurisdiction conflict...")

reject_body = TaskRejectBody(
    task_id=TASK_ID,
    reason="jurisdiction_conflict",
    detail=detail,
    retry_eligible=False,
)

reject_msg = AgentMessage(
    sender=AGENT_B,
    recipient=AGENT_A,
    body_type="task.reject",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
        "Jurisdiction": jurisdiction_b.model_dump_json(),
    },
    body=reject_body.model_dump(),
)

print("\n  Rejection:")
print(f"    From:           {reject_msg.sender}")
print(f"    To:             {reject_msg.recipient}")
print(f"    Body type:      {reject_msg.body_type}")
print(f"    Reason:         {reject_body.reason}")
print(f"    Detail:         {reject_body.detail}")
print(f"    Retry eligible: {reject_body.retry_eligible}")

validated = validate_body("task.reject", reject_msg.body)
print(f"\n  Validated:        {type(validated).__name__}")

# ---------------------------------------------------------------------------
# Step 3: Check Agent A (DE/GDPR) vs Agent C (IE/GDPR) — no conflict
# ---------------------------------------------------------------------------

print("\n=== Step 3: Check A -> C (DE/GDPR -> IE/GDPR) ===\n")

has_conflict_ac, detail_ac = check_jurisdiction_conflict(jurisdiction_a, jurisdiction_c)

print(f"  Has conflict: {has_conflict_ac}")
print(f"  Detail:       {detail_ac}")
print("  Compatible:   Both operate under GDPR")

# Agent A sends the same task to Agent C successfully
create_msg_c = AgentMessage(
    sender=AGENT_A,
    recipient=AGENT_C,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
        "Jurisdiction": jurisdiction_a.model_dump_json(),
    },
    body=create_body.model_dump(),
)

print("\n  Task routed to Agent C:")
print(f"    From:      {create_msg_c.sender}")
print(f"    To:        {create_msg_c.recipient}")
print(f"    Body type: {create_msg_c.body_type}")
print(f"    Task ID:   {create_body.task_id}")
print("    Status:    Accepted (no jurisdiction conflict)")

# ---------------------------------------------------------------------------
# Step 4: Validate jurisdiction codes
# ---------------------------------------------------------------------------

print("\n=== Step 4: Validate Jurisdiction Codes ===\n")

test_codes = [
    ("DE", True),
    ("US", True),
    ("IE", True),
    ("GB", True),
    ("de", False),     # lowercase — invalid
    ("USA", False),    # three characters — invalid
    ("D", False),      # single character — invalid
    ("", False),       # empty — invalid
    ("1A", False),     # starts with digit — invalid
]

print(f"  {'Code':6s} {'Expected':10s} {'Result':10s} {'Match'}")
print(f"  {'----':6s} {'--------':10s} {'------':10s} {'-----'}")

for code, expected in test_codes:
    result = validate_jurisdiction_code(code)
    match = result == expected
    print(f"  {repr(code):6s} {str(expected):10s} {str(result):10s} {match}")

# ---------------------------------------------------------------------------
# Step 5: Same-jurisdiction agents — never conflict
# ---------------------------------------------------------------------------

print("\n=== Step 5: Same Primary Jurisdiction ===\n")

jurisdiction_d = JurisdictionInfo(
    primary="US",
    frameworks=["CCPA", "HIPAA"],
)

jurisdiction_e = JurisdictionInfo(
    primary="US",
    frameworks=["CCPA"],
)

has_conflict_de, detail_de = check_jurisdiction_conflict(jurisdiction_d, jurisdiction_e)

print(f"  Agent D: primary={jurisdiction_d.primary}, frameworks={jurisdiction_d.frameworks}")
print(f"  Agent E: primary={jurisdiction_e.primary}, frameworks={jurisdiction_e.frameworks}")
print(f"  Has conflict: {has_conflict_de}")
print(f"  Detail:       {detail_de}")
print("  Rule:         Same primary jurisdiction -> no conflict regardless of frameworks")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== Summary ===\n")

print(f"  {'Sender':12s} {'Receiver':12s} {'Conflict':10s} {'Why'}")
print(f"  {'------':12s} {'--------':12s} {'--------':10s} {'---'}")
print(f"  {'DE/GDPR':12s} {'US/CCPA':12s} {'Yes':10s} {'Different primary + unmatched frameworks'}")
print(f"  {'DE/GDPR':12s} {'IE/GDPR':12s} {'No':10s} {'Different primary but all frameworks match'}")
print(f"  {'US/CCPA+HIPAA':12s} {'US/CCPA':12s} {'No':10s} {'Same primary jurisdiction'}")
