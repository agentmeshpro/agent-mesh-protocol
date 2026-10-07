"""
20 — Load-Aware Redirect (task.redirect)

Demonstrates load-based task routing. Agent A sends a task to Agent B,
which is overloaded (85% load) and responds with a task.redirect pointing
to Agent C. Agent A follows the redirect and Agent C completes the task
at low load (30%).

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/20_load_redirect.py
"""

from ampro import (
    AgentMessage,
    TaskCreateBody,
    TaskRedirectBody,
    TaskCompleteBody,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup: Three agents
# ---------------------------------------------------------------------------

AGENT_A = "agent://orchestrator.example.com"
AGENT_B = "agent://processor-b.example.com"
AGENT_C = "agent://processor-c.example.com"
TASK_ID = "task-redirect-demo-001"
SESSION_ID = "sess-redirect-demo-001"

print("=== Load-Aware Redirect Flow ===\n")
print(f"  Agent A (caller):   {AGENT_A}")
print(f"  Agent B (busy):     {AGENT_B}  [load: 85%]")
print(f"  Agent C (available):{AGENT_C}  [load: 30%]")

# ---------------------------------------------------------------------------
# Step 1: Agent A sends task.create to Agent B
# ---------------------------------------------------------------------------

print("\n=== Step 1: Agent A -> Agent B (task.create) ===\n")

task_body = TaskCreateBody(
    description="Analyze server access logs for anomaly detection",
    task_id=TASK_ID,
    priority="high",
    tools_required=["data-processing", "analytics"],
    context={"log_source": "nginx-access-2026-04", "window_hours": 24},
    timeout_seconds=120,
)

create_msg = AgentMessage(
    sender=AGENT_A,
    recipient=AGENT_B,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.4",
        "Session-Id": SESSION_ID,
        "X-Load-Level": "20",
    },
    body=task_body.model_dump(),
)

print(f"  From:         {create_msg.sender}")
print(f"  To:           {create_msg.recipient}")
print(f"  Body type:    {create_msg.body_type}")
print(f"  Task ID:      {task_body.task_id}")
print(f"  X-Load-Level: {create_msg.headers['X-Load-Level']}  (Agent A's own load)")

# ---------------------------------------------------------------------------
# Step 2: Agent B is at 85% load — responds with task.redirect
# ---------------------------------------------------------------------------

print("\n=== Step 2: Agent B -> Agent A (task.redirect) ===\n")

redirect_body = TaskRedirectBody(
    task_id=TASK_ID,
    redirect_to=AGENT_C,
    reason="overloaded",
    original_description=task_body.description,
    load_level=85,
    alternative_agents=[
        "agent://processor-d.example.com",
        "agent://processor-e.example.com",
    ],
    retry_after_seconds=300,
)

redirect_msg = AgentMessage(
    sender=AGENT_B,
    recipient=AGENT_A,
    body_type="task.redirect",
    headers={
        "Protocol-Version": "0.1.4",
        "Session-Id": SESSION_ID,
        "In-Reply-To": create_msg.id,
        "X-Load-Level": "85",
        "Retry-After": "300",
    },
    body=redirect_body.model_dump(),
)

print(f"  From:          {redirect_msg.sender}")
print(f"  To:            {redirect_msg.recipient}")
print(f"  Body type:     {redirect_msg.body_type}")
print(f"  X-Load-Level:  {redirect_msg.headers['X-Load-Level']}  (Agent B is overloaded)")
print(f"  Retry-After:   {redirect_msg.headers['Retry-After']}s")
print(f"\n  Redirect details:")
print(f"    Redirect to:   {redirect_body.redirect_to}")
print(f"    Reason:        {redirect_body.reason}")
print(f"    Load level:    {redirect_body.load_level}%")
print(f"    Alternatives:  {redirect_body.alternative_agents}")
print(f"    Retry after:   {redirect_body.retry_after_seconds}s")

# Validate the redirect body
validated_redirect = validate_body("task.redirect", redirect_msg.body)
print(f"\n  Validated:     {type(validated_redirect).__name__}")
print(f"  Task match:    {validated_redirect.task_id == TASK_ID}")

# ---------------------------------------------------------------------------
# Step 3: Agent A follows redirect, sends to Agent C
# ---------------------------------------------------------------------------

print("\n=== Step 3: Agent A -> Agent C (task.create, following redirect) ===\n")

# Rebuild the task.create for Agent C, preserving the original description
redirected_body = TaskCreateBody(
    description=redirect_body.original_description,
    task_id=TASK_ID,
    priority="high",
    tools_required=["data-processing", "analytics"],
    context={"log_source": "nginx-access-2026-04", "window_hours": 24},
    timeout_seconds=120,
)

redirected_msg = AgentMessage(
    sender=AGENT_A,
    recipient=AGENT_C,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.4",
        "Session-Id": SESSION_ID,
        "X-Load-Level": "20",
        "Via": f"{AGENT_B} (redirect: overloaded)",
    },
    body=redirected_body.model_dump(),
)

print(f"  From:         {redirected_msg.sender}")
print(f"  To:           {redirected_msg.recipient}")
print(f"  Body type:    {redirected_msg.body_type}")
print(f"  X-Load-Level: {redirected_msg.headers['X-Load-Level']}")
print(f"  Via:          {redirected_msg.headers['Via']}")

# ---------------------------------------------------------------------------
# Step 4: Agent C completes the task at low load
# ---------------------------------------------------------------------------

print("\n=== Step 4: Agent C -> Agent A (task.complete) ===\n")

complete_body = TaskCompleteBody(
    task_id=TASK_ID,
    result={
        "anomalies_found": 14,
        "severity_high": 3,
        "severity_medium": 7,
        "severity_low": 4,
        "report_url": "https://processor-c.example.com/reports/task-redirect-demo-001",
    },
    duration_seconds=8.3,
    cost_usd=0.015,
)

complete_msg = AgentMessage(
    sender=AGENT_C,
    recipient=AGENT_A,
    body_type="task.complete",
    headers={
        "Protocol-Version": "0.1.4",
        "Session-Id": SESSION_ID,
        "In-Reply-To": redirected_msg.id,
        "X-Load-Level": "30",
    },
    body=complete_body.model_dump(),
)

print(f"  From:         {complete_msg.sender}")
print(f"  To:           {complete_msg.recipient}")
print(f"  Body type:    {complete_msg.body_type}")
print(f"  X-Load-Level: {complete_msg.headers['X-Load-Level']}  (Agent C is lightly loaded)")
print(f"\n  Result:")
print(f"    Task ID:       {complete_body.task_id}")
print(f"    Anomalies:     {complete_body.result['anomalies_found']}")
print(f"    Duration:      {complete_body.duration_seconds}s")
print(f"    Cost:          ${complete_body.cost_usd:.3f}")

# Validate the completion body
validated_complete = validate_body("task.complete", complete_msg.body)
print(f"\n  Validated:     {type(validated_complete).__name__}")
print(f"  Task match:    {validated_complete.task_id == TASK_ID}")

# ---------------------------------------------------------------------------
# Load levels across the flow
# ---------------------------------------------------------------------------

print("\n=== X-Load-Level Summary ===\n")

print(f"  {'Step':5s} {'Direction':45s} {'Load':>6s}")
print(f"  {'----':5s} {'---------':45s} {'----':>6s}")
print(f"  {'1':5s} {'A -> B (task.create)':45s} {'20%':>6s}")
print(f"  {'2':5s} {'B -> A (task.redirect)':45s} {'85%':>6s}")
print(f"  {'3':5s} {'A -> C (task.create, redirected)':45s} {'20%':>6s}")
print(f"  {'4':5s} {'C -> A (task.complete)':45s} {'30%':>6s}")
