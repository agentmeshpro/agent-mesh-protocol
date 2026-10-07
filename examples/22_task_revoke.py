"""
22 — Task Revocation (Cascade and Children)

Demonstrates revoking a parent task with cascade=True (follows
delegation chains) and revoke_children=True (follows spawned children).
Each revocation is wrapped in an AgentMessage envelope.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/22_task_revoke.py
"""

from ampro import (
    AgentMessage,
    TaskCreateBody,
    TaskSpawnBody,
    TaskRevokeBody,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup: Agents and tasks
# ---------------------------------------------------------------------------

ORCHESTRATOR = "agent://orchestrator.example.com"
SPECIALIST = "agent://specialist.example.com"
WORKER_A = "agent://worker-a.example.com"
WORKER_B = "agent://worker-b.example.com"
SESSION_ID = "sess-revoke-demo-001"

PARENT_TASK = "task-parent-001"
CHILD_TASK_A = "task-child-a-001"
CHILD_TASK_B = "task-child-b-001"

print("=== Task Tree ===\n")
print(f"  {PARENT_TASK}  ({ORCHESTRATOR})")
print(f"    |- {CHILD_TASK_A}  ({WORKER_A})")
print(f"    |- {CHILD_TASK_B}  ({WORKER_B})")

# ---------------------------------------------------------------------------
# Step 1: Create the parent task
# ---------------------------------------------------------------------------

print("\n=== Step 1: Create Parent Task ===\n")

parent_body = TaskCreateBody(
    description="Run full data pipeline for weekly report",
    task_id=PARENT_TASK,
    priority="normal",
    timeout_seconds=300,
)

parent_msg = AgentMessage(
    sender=ORCHESTRATOR,
    recipient=SPECIALIST,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
    },
    body=parent_body.model_dump(),
)

print(f"  From:      {parent_msg.sender}")
print(f"  To:        {parent_msg.recipient}")
print(f"  Task ID:   {parent_body.task_id}")
print(f"  Body type: {parent_msg.body_type}")

# ---------------------------------------------------------------------------
# Step 2: Specialist spawns two child tasks
# ---------------------------------------------------------------------------

print("\n=== Step 2: Spawn Child Tasks ===\n")

spawn_a = TaskSpawnBody(
    parent_task_id=PARENT_TASK,
    task_id=CHILD_TASK_A,
    description="Extract and transform raw data",
)

spawn_b = TaskSpawnBody(
    parent_task_id=PARENT_TASK,
    task_id=CHILD_TASK_B,
    description="Generate visualizations from transformed data",
)

for label, spawn, worker in [("A", spawn_a, WORKER_A), ("B", spawn_b, WORKER_B)]:
    msg = AgentMessage(
        sender=SPECIALIST,
        recipient=worker,
        body_type="task.spawn",
        headers={
            "Protocol-Version": "0.1.5",
            "Session-Id": SESSION_ID,
        },
        body=spawn.model_dump(),
    )
    print(f"  Child {label}:")
    print(f"    To:        {msg.recipient}")
    print(f"    Task ID:   {spawn.task_id}")
    print(f"    Parent:    {spawn.parent_task_id}")

# ---------------------------------------------------------------------------
# Step 3: Revoke parent with cascade=True
# ---------------------------------------------------------------------------

print("\n=== Step 3: Revoke with cascade=True ===\n")

revoke_cascade = TaskRevokeBody(
    task_id=PARENT_TASK,
    reason="Data source became unavailable during pipeline run",
    cascade=True,
    revoke_children=False,
)

revoke_cascade_msg = AgentMessage(
    sender=ORCHESTRATOR,
    recipient=SPECIALIST,
    body_type="task.revoke",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        "Priority": "urgent",
    },
    body=revoke_cascade.model_dump(),
)

print(f"  From:            {revoke_cascade_msg.sender}")
print(f"  To:              {revoke_cascade_msg.recipient}")
print(f"  Body type:       {revoke_cascade_msg.body_type}")
print(f"  Task ID:         {revoke_cascade.task_id}")
print(f"  Reason:          {revoke_cascade.reason}")
print(f"  cascade:         {revoke_cascade.cascade}")
print(f"  revoke_children: {revoke_cascade.revoke_children}")

# Validate the body
validated = validate_body("task.revoke", revoke_cascade_msg.body)
print(f"\n  Validated:       {type(validated).__name__}")
print(f"  Task match:      {validated.task_id == PARENT_TASK}")

print(f"\n  Effect:")
print(f"    {PARENT_TASK} -> REVOKED")
print(f"    Delegation chain from {SPECIALIST} -> REVOKED (cascade)")
print(f"    {CHILD_TASK_A} -> NOT revoked (revoke_children=False)")
print(f"    {CHILD_TASK_B} -> NOT revoked (revoke_children=False)")

# ---------------------------------------------------------------------------
# Step 4: Revoke with cascade=False, revoke_children=True
# ---------------------------------------------------------------------------

print("\n=== Step 4: Revoke with revoke_children=True ===\n")

revoke_children = TaskRevokeBody(
    task_id=PARENT_TASK,
    reason="Requirements changed, spawned work is no longer needed",
    cascade=False,
    revoke_children=True,
)

revoke_children_msg = AgentMessage(
    sender=ORCHESTRATOR,
    recipient=SPECIALIST,
    body_type="task.revoke",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        "Priority": "normal",
    },
    body=revoke_children.model_dump(),
)

print(f"  From:            {revoke_children_msg.sender}")
print(f"  To:              {revoke_children_msg.recipient}")
print(f"  Body type:       {revoke_children_msg.body_type}")
print(f"  Task ID:         {revoke_children.task_id}")
print(f"  Reason:          {revoke_children.reason}")
print(f"  cascade:         {revoke_children.cascade}")
print(f"  revoke_children: {revoke_children.revoke_children}")

validated2 = validate_body("task.revoke", revoke_children_msg.body)
print(f"\n  Validated:       {type(validated2).__name__}")

print(f"\n  Effect:")
print(f"    {PARENT_TASK} -> REVOKED")
print(f"    Delegation chain -> NOT followed (cascade=False)")
print(f"    {CHILD_TASK_A} -> REVOKED (revoke_children=True)")
print(f"    {CHILD_TASK_B} -> REVOKED (revoke_children=True)")

# ---------------------------------------------------------------------------
# Step 5: Revoke with both flags true
# ---------------------------------------------------------------------------

print("\n=== Step 5: Revoke with Both Flags True ===\n")

revoke_both = TaskRevokeBody(
    task_id=PARENT_TASK,
    reason="Entire operation cancelled by upstream coordinator",
    cascade=True,
    revoke_children=True,
)

revoke_both_msg = AgentMessage(
    sender=ORCHESTRATOR,
    recipient=SPECIALIST,
    body_type="task.revoke",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        "Priority": "critical",
    },
    body=revoke_both.model_dump(),
)

print(f"  Task ID:         {revoke_both.task_id}")
print(f"  cascade:         {revoke_both.cascade}")
print(f"  revoke_children: {revoke_both.revoke_children}")

validated3 = validate_body("task.revoke", revoke_both_msg.body)
print(f"\n  Validated:       {type(validated3).__name__}")

print(f"\n  Effect:")
print(f"    {PARENT_TASK} -> REVOKED")
print(f"    Delegation chain -> REVOKED (cascade=True)")
print(f"    {CHILD_TASK_A} -> REVOKED (revoke_children=True)")
print(f"    {CHILD_TASK_B} -> REVOKED (revoke_children=True)")
print(f"    All downstream work is cancelled.")

# ---------------------------------------------------------------------------
# Summary: The two flags are independent
# ---------------------------------------------------------------------------

print("\n=== Flag Summary ===\n")

print(f"  {'cascade':18s} {'revoke_children':18s} {'Delegation Chain':20s} {'Spawned Children'}")
print(f"  {'-------':18s} {'---------------':18s} {'----------------':20s} {'----------------'}")
print(f"  {'False':18s} {'False':18s} {'Not followed':20s} {'Not revoked'}")
print(f"  {'True':18s} {'False':18s} {'Revoked':20s} {'Not revoked'}")
print(f"  {'False':18s} {'True':18s} {'Not followed':20s} {'Revoked'}")
print(f"  {'True':18s} {'True':18s} {'Revoked':20s} {'Revoked'}")
