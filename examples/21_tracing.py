"""
21 — Distributed Tracing (W3C Trace Context)

Demonstrates a 3-agent delegation chain where each hop creates a child
span under the same trace. The gateway generates the trace_id; the
specialist and worker each link back via parent_span_id.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/21_tracing.py
"""

from ampro import (
    AgentMessage,
    TaskCreateBody,
    TaskCompleteBody,
    TraceContext,
    generate_trace_id,
    generate_span_id,
    inject_trace_headers,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup: Three agents
# ---------------------------------------------------------------------------

GATEWAY = "agent://gateway.example.com"
SPECIALIST = "agent://specialist.example.com"
WORKER = "agent://worker.example.com"
TASK_ID = "task-trace-demo-001"
SESSION_ID = "sess-trace-demo-001"

print("=== Delegation Chain ===\n")
print(f"  {GATEWAY}")
print(f"    -> {SPECIALIST}")
print(f"         -> {WORKER}")

# ---------------------------------------------------------------------------
# Step 1: Gateway creates the root span
# ---------------------------------------------------------------------------

print("\n=== Step 1: Gateway Creates Root Span ===\n")

trace_id = generate_trace_id()
gateway_span_id = generate_span_id()

gateway_ctx = TraceContext(
    trace_id=trace_id,
    span_id=gateway_span_id,
    parent_span_id=None,  # root span — no parent
    trace_flags=1,
)

print(f"  Trace ID:       {gateway_ctx.trace_id}")
print(f"  Span ID:        {gateway_ctx.span_id}")
print(f"  Parent Span ID: {gateway_ctx.parent_span_id}  (root)")
print(f"  Trace Flags:    {gateway_ctx.trace_flags}")

gateway_headers = inject_trace_headers(gateway_ctx)
print(f"\n  Injected headers: {gateway_headers}")

gateway_msg = AgentMessage(
    sender=GATEWAY,
    recipient=SPECIALIST,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        **gateway_headers,
    },
    body=TaskCreateBody(
        description="Summarize recent incident reports",
        task_id=TASK_ID,
        priority="normal",
        timeout_seconds=60,
    ).model_dump(),
)

print(f"\n  Envelope:")
print(f"    From:      {gateway_msg.sender}")
print(f"    To:        {gateway_msg.recipient}")
print(f"    Body type: {gateway_msg.body_type}")
print(f"    Trace-Id:  {gateway_msg.headers['Trace-Id']}")
print(f"    Span-Id:   {gateway_msg.headers['Span-Id']}")

# ---------------------------------------------------------------------------
# Step 2: Specialist creates a child span
# ---------------------------------------------------------------------------

print("\n=== Step 2: Specialist Creates Child Span ===\n")

specialist_span_id = generate_span_id()

specialist_ctx = TraceContext(
    trace_id=trace_id,             # same trace
    span_id=specialist_span_id,    # new span
    parent_span_id=gateway_span_id,  # links to gateway
    trace_flags=1,
)

print(f"  Trace ID:       {specialist_ctx.trace_id}  (same)")
print(f"  Span ID:        {specialist_ctx.span_id}")
print(f"  Parent Span ID: {specialist_ctx.parent_span_id}  (gateway)")
print(f"  Trace Flags:    {specialist_ctx.trace_flags}")

specialist_headers = inject_trace_headers(specialist_ctx)
print(f"\n  Injected headers: {specialist_headers}")

specialist_msg = AgentMessage(
    sender=SPECIALIST,
    recipient=WORKER,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        **specialist_headers,
    },
    body=TaskCreateBody(
        description="Extract severity counts from raw incident data",
        task_id=TASK_ID,
        priority="normal",
        timeout_seconds=30,
    ).model_dump(),
)

print(f"\n  Envelope:")
print(f"    From:      {specialist_msg.sender}")
print(f"    To:        {specialist_msg.recipient}")
print(f"    Body type: {specialist_msg.body_type}")
print(f"    Trace-Id:  {specialist_msg.headers['Trace-Id']}")
print(f"    Span-Id:   {specialist_msg.headers['Span-Id']}")

# ---------------------------------------------------------------------------
# Step 3: Worker creates a leaf span
# ---------------------------------------------------------------------------

print("\n=== Step 3: Worker Creates Leaf Span ===\n")

worker_span_id = generate_span_id()

worker_ctx = TraceContext(
    trace_id=trace_id,                # same trace
    span_id=worker_span_id,           # new span
    parent_span_id=specialist_span_id,  # links to specialist
    trace_flags=1,
)

print(f"  Trace ID:       {worker_ctx.trace_id}  (same)")
print(f"  Span ID:        {worker_ctx.span_id}")
print(f"  Parent Span ID: {worker_ctx.parent_span_id}  (specialist)")
print(f"  Trace Flags:    {worker_ctx.trace_flags}")

worker_headers = inject_trace_headers(worker_ctx)
print(f"\n  Injected headers: {worker_headers}")

# Worker completes the task
complete_body = TaskCompleteBody(
    task_id=TASK_ID,
    result={
        "severity_critical": 2,
        "severity_high": 5,
        "severity_medium": 11,
        "severity_low": 7,
    },
    duration_seconds=1.8,
    cost_usd=0.004,
)

worker_msg = AgentMessage(
    sender=WORKER,
    recipient=SPECIALIST,
    body_type="task.complete",
    headers={
        "Protocol-Version": "0.1.5",
        "Session-Id": SESSION_ID,
        **worker_headers,
    },
    body=complete_body.model_dump(),
)

print(f"\n  Envelope (response):")
print(f"    From:      {worker_msg.sender}")
print(f"    To:        {worker_msg.recipient}")
print(f"    Body type: {worker_msg.body_type}")
print(f"    Trace-Id:  {worker_msg.headers['Trace-Id']}")
print(f"    Span-Id:   {worker_msg.headers['Span-Id']}")

# Validate the completion body
validated = validate_body("task.complete", worker_msg.body)
print(f"\n  Validated:   {type(validated).__name__}")
print(f"  Task match:  {validated.task_id == TASK_ID}")

# ---------------------------------------------------------------------------
# Step 4: Full Trace Tree
# ---------------------------------------------------------------------------

print("\n=== Full Trace Tree ===\n")

print(f"  Trace ID: {trace_id}\n")

spans = [
    ("gateway",    gateway_ctx),
    ("specialist", specialist_ctx),
    ("worker",     worker_ctx),
]

print(f"  {'Hop':12s} {'Span ID':20s} {'Parent Span ID':20s} {'Agent'}")
print(f"  {'---':12s} {'-------':20s} {'--------------':20s} {'-----'}")

agents = [GATEWAY, SPECIALIST, WORKER]
for i, (label, ctx) in enumerate(spans):
    parent = ctx.parent_span_id or "(root)"
    print(f"  {label:12s} {ctx.span_id:20s} {parent:20s} {agents[i]}")

# Show the tree visually
print(f"\n  Tree:")
print(f"    [{gateway_ctx.span_id[:8]}...] {GATEWAY}")
print(f"      [{specialist_ctx.span_id[:8]}...] {SPECIALIST}")
print(f"        [{worker_ctx.span_id[:8]}...] {WORKER}")

# Verify trace_id is the same across all spans
all_same_trace = all(ctx.trace_id == trace_id for _, ctx in spans)
print(f"\n  All spans share trace_id: {all_same_trace}")

# Verify parent chain is correct
chain_valid = (
    gateway_ctx.parent_span_id is None
    and specialist_ctx.parent_span_id == gateway_ctx.span_id
    and worker_ctx.parent_span_id == specialist_ctx.span_id
)
print(f"  Parent chain valid:       {chain_valid}")
