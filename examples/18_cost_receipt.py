"""
18 — Cost Receipts (Per-Hop Cost Attribution)

Demonstrates end-to-end cost tracking across a three-agent delegation
chain. Each agent attaches a signed cost receipt to its response,
enabling full cost visibility from gateway to leaf.

Since C10, CostReceipt requires a mandatory `nonce` and Ed25519 `signature`.
This example generates ephemeral keypairs for demonstration purposes.
In production, agents use their registered keypairs.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/18_cost_receipt.py
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro import (
    AgentMessage,
    CostReceipt,
    CostReceiptChain,
    TaskCompleteBody,
    validate_body,
)
from ampro.trust.resolver import _PUBLIC_KEY_CACHE

# ---------------------------------------------------------------------------
# Setup: Three-agent delegation chain with Ed25519 keypairs
# ---------------------------------------------------------------------------

GATEWAY = "agent://gateway.example.com"
SPECIALIST = "agent://specialist.example.com"
TOOL_AGENT = "agent://tool-runner.example.com"
TASK_ID = "task-cost-demo-001"

print("=== Delegation Chain ===\n")
print(f"  {GATEWAY}")
print(f"    -> {SPECIALIST}")
print(f"         -> {TOOL_AGENT}")

now = datetime.now(timezone.utc)

# Generate ephemeral keypairs for the demo and seed them in the cache.
# In production, agents register their keys at bootstrap and the resolver
# fetches them from the host platform's key registry.
_keys: dict[str, Ed25519PrivateKey] = {}
for agent_uri in (GATEWAY, SPECIALIST, TOOL_AGENT):
    pk = Ed25519PrivateKey.generate()
    _keys[agent_uri] = pk
    _PUBLIC_KEY_CACHE[agent_uri] = (time.time() + 3600, pk.public_key().public_bytes_raw())


def _sign_receipt(agent_id: str, task_id: str, cost_usd: float,
                  currency: str, issued_at: str, nonce: str) -> str:
    """Sign canonical receipt fields with the agent's ephemeral key."""
    canonical = json.dumps(
        {"agent_id": agent_id, "task_id": task_id, "cost_usd": cost_usd,
         "currency": currency, "issued_at": issued_at, "nonce": nonce},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    sig = _keys[agent_id].sign(canonical)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Step 1: Tool Agent completes work — issues a cost receipt
# ---------------------------------------------------------------------------

print("\n=== Step 1: Tool Agent Completes Work ===\n")

tool_nonce = secrets.token_urlsafe(16)
tool_issued = now.isoformat()
tool_receipt = CostReceipt(
    agent_id=TOOL_AGENT,
    task_id=TASK_ID,
    cost_usd=0.003,
    currency="USD",
    breakdown={
        "llm_inference": 0.001,
        "tool_execution": 0.002,
    },
    token_usage={
        "input": 450,
        "output": 120,
    },
    duration_seconds=1.2,
    nonce=tool_nonce,
    signature=_sign_receipt(TOOL_AGENT, TASK_ID, 0.003, "USD", tool_issued, tool_nonce),
    issued_at=tool_issued,
)

print(f"  Agent:     {tool_receipt.agent_id}")
print(f"  Cost:      ${tool_receipt.cost_usd:.4f}")
print(f"  Breakdown: llm=${tool_receipt.breakdown['llm_inference']:.3f}, "
      f"tool=${tool_receipt.breakdown['tool_execution']:.3f}")
print(f"  Tokens:    {tool_receipt.token_usage['input']}in / {tool_receipt.token_usage['output']}out")
print(f"  Duration:  {tool_receipt.duration_seconds}s")

# ---------------------------------------------------------------------------
# Step 2: Specialist adds its own receipt, builds the chain
# ---------------------------------------------------------------------------

print("\n=== Step 2: Specialist Adds Its Receipt ===\n")

spec_nonce = secrets.token_urlsafe(16)
spec_issued = (now + timedelta(seconds=2)).isoformat()
specialist_receipt = CostReceipt(
    agent_id=SPECIALIST,
    task_id=TASK_ID,
    cost_usd=0.012,
    currency="USD",
    breakdown={
        "llm_inference": 0.010,
        "tool_execution": 0.002,
    },
    token_usage={
        "input": 2100,
        "output": 850,
    },
    duration_seconds=3.8,
    nonce=spec_nonce,
    signature=_sign_receipt(SPECIALIST, TASK_ID, 0.012, "USD", spec_issued, spec_nonce),
    issued_at=spec_issued,
)

chain = CostReceiptChain()
chain.add_receipt(tool_receipt)
chain.add_receipt(specialist_receipt)

print(f"  Agent:     {specialist_receipt.agent_id}")
print(f"  Cost:      ${specialist_receipt.cost_usd:.4f}")
print(f"  Tokens:    {specialist_receipt.token_usage['input']}in / {specialist_receipt.token_usage['output']}out")
print(f"  Duration:  {specialist_receipt.duration_seconds}s")
print("\n  Chain so far:")
print(f"    Receipts: {len(chain.receipts)}")
print(f"    Running total: ${chain.total_cost_usd:.4f}")

# ---------------------------------------------------------------------------
# Step 3: Gateway receives chain, adds its own receipt
# ---------------------------------------------------------------------------

print("\n=== Step 3: Gateway Adds Its Receipt ===\n")

gw_nonce = secrets.token_urlsafe(16)
gw_issued = (now + timedelta(seconds=4)).isoformat()
gateway_receipt = CostReceipt(
    agent_id=GATEWAY,
    task_id=TASK_ID,
    cost_usd=0.005,
    currency="USD",
    breakdown={
        "llm_inference": 0.004,
        "routing_overhead": 0.001,
    },
    token_usage={
        "input": 800,
        "output": 200,
    },
    duration_seconds=0.5,
    nonce=gw_nonce,
    signature=_sign_receipt(GATEWAY, TASK_ID, 0.005, "USD", gw_issued, gw_nonce),
    issued_at=gw_issued,
)

chain.add_receipt(gateway_receipt)

print(f"  Agent:     {gateway_receipt.agent_id}")
print(f"  Cost:      ${gateway_receipt.cost_usd:.4f}")
print(f"  Duration:  {gateway_receipt.duration_seconds}s")

# ---------------------------------------------------------------------------
# Per-hop breakdown and total
# ---------------------------------------------------------------------------

print("\n=== Per-Hop Cost Breakdown ===\n")

print(f"  {'Hop':5s} {'Agent':40s} {'Cost':>10s} {'Duration':>10s}")
print(f"  {'---':5s} {'-----':40s} {'----':>10s} {'--------':>10s}")

for i, receipt in enumerate(chain.receipts):
    print(f"  {i + 1:<5d} {receipt.agent_id:40s} ${receipt.cost_usd:>8.4f} {receipt.duration_seconds:>8.1f}s")

print(f"  {'':5s} {'':40s} {'--------':>10s} {'--------':>10s}")
total_duration = sum(r.duration_seconds for r in chain.receipts if r.duration_seconds)
print(f"  {'':5s} {'TOTAL':40s} ${chain.total_cost_usd:>8.4f} {total_duration:>8.1f}s")

# ---------------------------------------------------------------------------
# Step 4: Wrap in task.complete with cost_receipt field
# ---------------------------------------------------------------------------

print("\n=== Step 4: TaskCompleteBody with Cost Receipt ===\n")

completion = TaskCompleteBody(
    task_id=TASK_ID,
    result={"summary": "Analysis complete", "findings": 3},
    cost_usd=chain.total_cost_usd,
    duration_seconds=total_duration,
    cost_receipt=chain.model_dump(),
    metadata={"hops": len(chain.receipts)},
)

complete_msg = AgentMessage(
    sender=GATEWAY,
    recipient="agent://orchestrator.example.com",
    body_type="task.complete",
    headers={
        "Protocol-Version": "0.1.3",
        "Session-Id": "sess-cost-demo-001",
    },
    body=completion.model_dump(),
)

print(f"  Body type:    {complete_msg.body_type}")
print(f"  Task ID:      {completion.task_id}")
print(f"  Total cost:   ${completion.cost_usd:.4f}")
print(f"  Duration:     {completion.duration_seconds}s")
print(f"  Hops:         {completion.metadata['hops']}")

# Validate the body round-trips correctly
validated = validate_body("task.complete", complete_msg.body)
print(f"\n  Validated:    {type(validated).__name__}")
print(f"  Has receipt:  {validated.cost_receipt is not None}")

# Extract the chain from the validated body
receipt_chain = CostReceiptChain.model_validate(validated.cost_receipt)
print(f"  Chain hops:   {len(receipt_chain.receipts)}")
print(f"  Chain total:  ${receipt_chain.total_cost_usd:.4f}")

# ---------------------------------------------------------------------------
# Token usage summary
# ---------------------------------------------------------------------------

print("\n=== Token Usage Summary ===\n")

total_input = sum(r.token_usage.get("input", 0) for r in chain.receipts if r.token_usage)
total_output = sum(r.token_usage.get("output", 0) for r in chain.receipts if r.token_usage)

for receipt in chain.receipts:
    if receipt.token_usage:
        print(f"  {receipt.agent_id}:")
        print(f"    Input:  {receipt.token_usage['input']:>6d} tokens")
        print(f"    Output: {receipt.token_usage['output']:>6d} tokens")

print(f"\n  Total: {total_input} input + {total_output} output = {total_input + total_output} tokens")
