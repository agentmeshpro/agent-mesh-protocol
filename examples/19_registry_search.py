"""
19 — Registry Search (Service Discovery)

Demonstrates the search-select-delegate flow for finding agents by
capability. A client queries a registry for agents that support
"data-processing", ranks them by trust score, selects the best
match, and sends a task.create message.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/19_registry_search.py
"""

from ampro import (
    AgentMessage,
    RegistrySearchMatch,
    RegistrySearchRequest,
    RegistrySearchResult,
    TaskCreateBody,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

CALLER = "agent://orchestrator.example.com"
REGISTRY = "agent://registry.amp-protocol.dev"

print("=== Registry Search: Service Discovery ===\n")

# ---------------------------------------------------------------------------
# Step 1: Build a search request
# ---------------------------------------------------------------------------

print("=== Step 1: Build Search Request ===\n")

search_req = RegistrySearchRequest(
    capability="data-processing",
    min_trust_score=400,
    max_results=5,
    filters={"region": "us-east"},
    include_load_level=True,
)

print(f"  Capability:      {search_req.capability}")
print(f"  Min trust score: {search_req.min_trust_score}")
print(f"  Max results:     {search_req.max_results}")
print(f"  Filters:         {search_req.filters}")
print(f"  Include load:    {search_req.include_load_level}")

# In a real implementation, this would be:
#   GET https://registry.amp-protocol.dev/registry/search?capability=data-processing&min_trust_score=400
print(f"\n  Would query: https://registry.amp-protocol.dev/registry/search"
      f"?capability={search_req.capability}"
      f"&min_trust_score={search_req.min_trust_score}")

# ---------------------------------------------------------------------------
# Step 2: Simulate registry returning 3 matches ranked by trust score
# ---------------------------------------------------------------------------

print("\n=== Step 2: Registry Returns Matches ===\n")

match_alpha = RegistrySearchMatch(
    agent_id="agent://alpha-processor.example.com",
    endpoint="https://alpha-processor.example.com/agent/message",
    capabilities=["data-processing", "analytics", "batch-jobs"],
    trust_score=820,
    trust_tier="verified",
    load_level=45,
    status="active",
    metadata={"version": "3.1.0", "region": "us-east-1"},
)

match_beta = RegistrySearchMatch(
    agent_id="agent://beta-analytics.example.com",
    endpoint="https://beta-analytics.example.com/agent/message",
    capabilities=["data-processing", "analytics"],
    trust_score=650,
    trust_tier="verified",
    load_level=30,
    status="active",
    metadata={"version": "2.4.1", "region": "us-east-2"},
)

match_gamma = RegistrySearchMatch(
    agent_id="agent://gamma-worker.example.com",
    endpoint="https://gamma-worker.example.com/agent/message",
    capabilities=["data-processing"],
    trust_score=480,
    trust_tier="external",
    load_level=72,
    status="active",
    metadata={"version": "1.0.5", "region": "us-east-1"},
)

search_result = RegistrySearchResult(
    matches=[match_alpha, match_beta, match_gamma],
    total_available=3,
    search_time_ms=12.4,
)

print(f"  Total matches:  {search_result.total_available}")
print(f"  Search time:    {search_result.search_time_ms}ms")
print()

print(f"  {'Rank':5s} {'Agent':45s} {'Trust':>6s} {'Tier':10s} {'Load':>5s}")
print(f"  {'----':5s} {'-----':45s} {'-----':>6s} {'----':10s} {'----':>5s}")

for i, match in enumerate(search_result.matches):
    print(f"  {i + 1:<5d} {match.agent_id:45s} {match.trust_score:>6d} {match.trust_tier:10s} {match.load_level:>4d}%")

# ---------------------------------------------------------------------------
# Step 3: Select top match
# ---------------------------------------------------------------------------

print("\n=== Step 3: Select Top Match ===\n")

top_match = search_result.matches[0]

print(f"  Selected:     {top_match.agent_id}")
print(f"  Trust score:  {top_match.trust_score} ({top_match.trust_tier})")
print(f"  Load level:   {top_match.load_level}%")
print(f"  Capabilities: {', '.join(top_match.capabilities)}")
print(f"  Endpoint:     {top_match.endpoint}")

# ---------------------------------------------------------------------------
# Step 4: Build task.create message to the selected agent
# ---------------------------------------------------------------------------

print("\n=== Step 4: Send task.create to Top Match ===\n")

task_body = TaskCreateBody(
    description="Process Q4 transaction log and generate summary statistics",
    task_id="task-registry-demo-001",
    priority="normal",
    tools_required=["data-processing"],
    context={
        "dataset": "transactions-q4-2025",
        "format": "parquet",
        "row_count": 1_200_000,
    },
    timeout_seconds=300,
)

task_msg = AgentMessage(
    sender=CALLER,
    recipient=top_match.agent_id,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.4",
        "Session-Id": "sess-registry-demo-001",
        "Trust-Tier": "verified",
        "Trust-Score": str(top_match.trust_score),
    },
    body=task_body.model_dump(),
)

print("  Envelope:")
print(f"    From:      {task_msg.sender}")
print(f"    To:        {task_msg.recipient}")
print(f"    Body type: {task_msg.body_type}")
print(f"    ID:        {task_msg.id}")

print("\n  Body:")
print(f"    Task ID:     {task_body.task_id}")
print(f"    Description: {task_body.description}")
print(f"    Priority:    {task_body.priority}")
print(f"    Tools:       {task_body.tools_required}")
print(f"    Timeout:     {task_body.timeout_seconds}s")

# Validate the body round-trips correctly
validated = validate_body("task.create", task_msg.body)
print(f"\n  Validated:   {type(validated).__name__}")
print(f"  Task match:  {validated.task_id == task_body.task_id}")

# ---------------------------------------------------------------------------
# Full flow summary
# ---------------------------------------------------------------------------

print("\n=== Search-Select-Delegate Flow ===\n")

print(f"  1. {CALLER}")
print(f"     -> searches {REGISTRY} for capability='{search_req.capability}'")
print(f"  2. Registry returns {search_result.total_available} matches in {search_result.search_time_ms}ms")
print(f"  3. Caller selects {top_match.agent_id} (score={top_match.trust_score}, load={top_match.load_level}%)")
print(f"  4. Caller sends task.create '{task_body.task_id}' to selected agent")
