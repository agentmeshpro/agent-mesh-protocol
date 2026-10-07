"""
40 — Delegation Chain with Cost Receipts

Builds a 3-agent delegation chain with Ed25519 signatures, validates
scope narrowing, tracks per-hop costs via CostReceipt, and demonstrates
Visited-Agents loop detection.

Since C10, CostReceipt requires a mandatory `nonce` and Ed25519 `signature`.
This example reuses the delegation keypairs to sign cost receipts.

Extends example 06 with v0.1.3 cost receipt accumulation.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/40_delegation_chain.py
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro import (
    CostReceipt,
    CostReceiptChain,
    DelegationChain,
    DelegationLink,
    check_visited_agents_limit,
    check_visited_agents_loop,
    parse_chain_budget,
    sign_delegation,
    validate_chain,
    validate_scope_narrowing,
)
from ampro.trust.resolver import _PUBLIC_KEY_CACHE

# ---------------------------------------------------------------------------
# Setup: 3 agents with Ed25519 keypairs
# ---------------------------------------------------------------------------

AGENTS = ["gateway", "planner", "executor"]
keys = {}
pub_keys = {}
_private_keys: dict[str, Ed25519PrivateKey] = {}

for name in AGENTS:
    private = Ed25519PrivateKey.generate()
    uri = f"agent://{name}.example.com"
    keys[name] = private.private_bytes_raw()
    pub_keys[uri] = private.public_key().public_bytes_raw()
    _private_keys[uri] = private
    # Seed public key cache for cost receipt signature verification
    _PUBLIC_KEY_CACHE[uri] = (time.time() + 3600, private.public_key().public_bytes_raw())

now = datetime.now(timezone.utc)
TASK_ID = "task-delegation-demo-001"

print("=== Delegation Chain with Cost Receipts ===\n")
print("  gateway -> planner -> executor")
print(f"  Task: {TASK_ID}")


def _sign_cost_receipt(agent_id: str, task_id: str, cost_usd: float,
                       currency: str, issued_at: str, nonce: str) -> str:
    """Sign canonical receipt fields with the agent's key."""
    canonical = json.dumps(
        {"agent_id": agent_id, "task_id": task_id, "cost_usd": cost_usd,
         "currency": currency, "issued_at": issued_at, "nonce": nonce},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    sig = _private_keys[agent_id].sign(canonical)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Step 1: Build the delegation chain
# ---------------------------------------------------------------------------

print("\n--- Step 1: Build Chain ---\n")

# Link 1: Gateway delegates to Planner
link1_data = {
    "delegator": "agent://gateway.example.com",
    "delegate": "agent://planner.example.com",
    "scopes": ["task:create", "task:delegate", "tool:read", "tool:execute"],
    "max_depth": 4,
    "created_at": now.isoformat(),
    "expires_at": (now + timedelta(hours=2)).isoformat(),
}
link1_sig = sign_delegation(keys["gateway"], link1_data, parent_delegate=None)
link1 = DelegationLink(
    **link1_data,
    signature=link1_sig,
    trust_tier="owner",
    chain_budget="remaining=10.00USD;max=10.00USD",
)
print("  Link 1: gateway -> planner")
print(f"    Scopes: {link1.scopes}")
print(f"    Budget: {link1.chain_budget}")

# Link 2: Planner delegates to Executor (narrowed scope, reduced budget)
link2_data = {
    "delegator": "agent://planner.example.com",
    "delegate": "agent://executor.example.com",
    "scopes": ["tool:read", "tool:execute"],  # Narrowed — no task:*
    "max_depth": 2,
    "created_at": now.isoformat(),
    "expires_at": (now + timedelta(hours=1)).isoformat(),
}
link2_sig = sign_delegation(keys["planner"], link2_data, parent_delegate="agent://planner.example.com")
link2 = DelegationLink(
    **link2_data,
    signature=link2_sig,
    trust_tier="verified",
    chain_budget="remaining=5.00USD;max=10.00USD",
)
print("  Link 2: planner -> executor")
print(f"    Scopes: {link2.scopes}")
print(f"    Budget: {link2.chain_budget}")

# ---------------------------------------------------------------------------
# Step 2: Validate the chain
# ---------------------------------------------------------------------------

print("\n--- Step 2: Validate Chain ---\n")

chain = DelegationChain(links=[link1, link2])
valid, reason = validate_chain(chain, pub_keys)
print(f"  Valid: {valid}")
print(f"  Reason: {reason}")
print(f"  Depth: {chain.depth} hops")

# ---------------------------------------------------------------------------
# Step 3: Scope narrowing analysis
# ---------------------------------------------------------------------------

print("\n--- Step 3: Scope Narrowing ---\n")

print(f"  Gateway scopes:  {link1.scopes}")
print(f"  Planner scopes:  {link2.scopes}")
print(f"  Valid narrowing:  {validate_scope_narrowing(link1.scopes, link2.scopes)}")

# Attempt to widen scope — should fail
print("\n  Widening attempt:")
print(f"    Parent: {link2.scopes}")
print("    Child:  ['tool:read', 'tool:execute', 'tool:admin']")
print(f"    Valid:  {validate_scope_narrowing(link2.scopes, ['tool:read', 'tool:execute', 'tool:admin'])}")

# ---------------------------------------------------------------------------
# Step 4: Cost receipts — each agent reports what it spent (now signed)
# ---------------------------------------------------------------------------

print("\n--- Step 4: Cost Receipt Accumulation ---\n")

cost_chain = CostReceiptChain()

# Executor finishes first (leaf of the chain)
exec_nonce = secrets.token_urlsafe(16)
exec_issued = now.isoformat()
executor_receipt = CostReceipt(
    agent_id="agent://executor.example.com",
    task_id=TASK_ID,
    cost_usd=0.008,
    currency="USD",
    breakdown={"tool_execution": 0.005, "llm_inference": 0.003},
    token_usage={"input": 600, "output": 200},
    duration_seconds=2.1,
    nonce=exec_nonce,
    signature=_sign_cost_receipt(
        "agent://executor.example.com", TASK_ID, 0.008, "USD", exec_issued, exec_nonce,
    ),
    issued_at=exec_issued,
)
cost_chain.add_receipt(executor_receipt)

# Planner adds its own receipt
plan_nonce = secrets.token_urlsafe(16)
plan_issued = (now + timedelta(seconds=3)).isoformat()
planner_receipt = CostReceipt(
    agent_id="agent://planner.example.com",
    task_id=TASK_ID,
    cost_usd=0.015,
    currency="USD",
    breakdown={"llm_inference": 0.012, "planning_overhead": 0.003},
    token_usage={"input": 1800, "output": 900},
    duration_seconds=4.5,
    nonce=plan_nonce,
    signature=_sign_cost_receipt(
        "agent://planner.example.com", TASK_ID, 0.015, "USD", plan_issued, plan_nonce,
    ),
    issued_at=plan_issued,
)
cost_chain.add_receipt(planner_receipt)

# Gateway adds routing overhead
gw_nonce = secrets.token_urlsafe(16)
gw_issued = (now + timedelta(seconds=5)).isoformat()
gateway_receipt = CostReceipt(
    agent_id="agent://gateway.example.com",
    task_id=TASK_ID,
    cost_usd=0.002,
    currency="USD",
    breakdown={"routing_overhead": 0.002},
    token_usage={"input": 200, "output": 50},
    duration_seconds=0.3,
    nonce=gw_nonce,
    signature=_sign_cost_receipt(
        "agent://gateway.example.com", TASK_ID, 0.002, "USD", gw_issued, gw_nonce,
    ),
    issued_at=gw_issued,
)
cost_chain.add_receipt(gateway_receipt)

# Print the per-hop breakdown
print(f"  {'Hop':5s} {'Agent':40s} {'Cost':>10s} {'Tokens':>10s}")
print(f"  {'---':5s} {'-----':40s} {'----':>10s} {'------':>10s}")

for i, receipt in enumerate(cost_chain.receipts):
    tokens = receipt.token_usage or {}
    total_tokens = tokens.get("input", 0) + tokens.get("output", 0)
    print(f"  {i + 1:<5d} {receipt.agent_id:40s} ${receipt.cost_usd:>8.4f} {total_tokens:>10d}")

total_tokens = sum(
    (r.token_usage or {}).get("input", 0) + (r.token_usage or {}).get("output", 0)
    for r in cost_chain.receipts
)
print(f"  {'':5s} {'':40s} {'--------':>10s} {'--------':>10s}")
print(f"  {'':5s} {'TOTAL':40s} ${cost_chain.total_cost_usd:>8.4f} {total_tokens:>10d}")

# ---------------------------------------------------------------------------
# Step 5: Budget tracking across the chain
# ---------------------------------------------------------------------------

print("\n--- Step 5: Budget Tracking ---\n")

remaining, max_budget = parse_chain_budget(link1.chain_budget)
print(f"  Initial budget:   ${max_budget:.2f}")
print(f"  After gateway:    ${remaining:.2f} remaining")

remaining2, _ = parse_chain_budget(link2.chain_budget)
print(f"  After planner:    ${remaining2:.2f} remaining")
print(f"  Actual cost:      ${cost_chain.total_cost_usd:.4f}")
print(f"  Under budget:     {cost_chain.total_cost_usd <= max_budget}")

# ---------------------------------------------------------------------------
# Step 6: Visited-Agents loop detection
# ---------------------------------------------------------------------------

print("\n--- Step 6: Loop Detection ---\n")

visited = "agent://gateway.example.com,agent://planner.example.com"
print(f"  Visited: {visited}")
print(f"  Executor joining: loop? {check_visited_agents_loop(visited, 'agent://executor.example.com')}")
print(f"  Gateway re-joining: loop? {check_visited_agents_loop(visited, 'agent://gateway.example.com')}")

# Add executor and check limit
visited_full = visited + ",agent://executor.example.com"
print(f"  Within 20-agent limit: {check_visited_agents_limit(visited_full)}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n--- Summary ---\n")
print(f"  Chain:    {chain.depth} hops, {len(cost_chain.receipts)} cost receipts")
print(f"  Total:    ${cost_chain.total_cost_usd:.4f} ({total_tokens} tokens)")
print(f"  Valid:    {valid}")
print(f"  Budget:   ${max_budget:.2f} max, ${cost_chain.total_cost_usd:.4f} spent")
