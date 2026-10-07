"""
06 — Delegation Chains with Budget and Trust

Demonstrates signed multi-hop delegation with scope narrowing,
chain budget tracking, and visited-agents loop detection.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/06_delegation_chains.py
"""

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro import (
    DelegationChain,
    DelegationLink,
    check_visited_agents_limit,
    check_visited_agents_loop,
    parse_chain_budget,
    sign_delegation,
    validate_chain,
    validate_scope_narrowing,
)

# --- Generate keypairs for 3 agents ---
keys = {}
pub_keys = {}
for name in ["alice", "bob", "charlie"]:
    private = Ed25519PrivateKey.generate()
    keys[name] = private.private_bytes_raw()
    pub_keys[f"agent://{name}.example.com"] = private.public_key().public_bytes_raw()

now = datetime.now(timezone.utc)

# --- Build delegation chain: Alice → Bob → Charlie ---
print("=== Building Delegation Chain ===\n")

# Link 1: Alice delegates to Bob
link1_data = {
    "delegator": "agent://alice.example.com",
    "delegate": "agent://bob.example.com",
    "scopes": ["tool:read", "tool:execute"],
    "max_depth": 3,
    "created_at": now.isoformat(),
    "expires_at": (now + timedelta(hours=1)).isoformat(),
}
link1_sig = sign_delegation(keys["alice"], link1_data, parent_delegate=None)
link1 = DelegationLink(**link1_data, signature=link1_sig, trust_tier="owner", chain_budget="remaining=5.00USD;max=5.00USD")
print(f"  Link 1: alice → bob (scopes: {link1.scopes})")

# Link 2: Bob delegates to Charlie (narrowed scope)
link2_data = {
    "delegator": "agent://bob.example.com",
    "delegate": "agent://charlie.example.com",
    "scopes": ["tool:read"],  # Narrowed from tool:read + tool:execute
    "max_depth": 2,
    "created_at": now.isoformat(),
    "expires_at": (now + timedelta(minutes=30)).isoformat(),
}
link2_sig = sign_delegation(keys["bob"], link2_data, parent_delegate="agent://bob.example.com")
link2 = DelegationLink(**link2_data, signature=link2_sig, trust_tier="verified", chain_budget="remaining=3.50USD;max=5.00USD")
print(f"  Link 2: bob → charlie (scopes: {link2.scopes})")

# --- Validate chain ---
chain = DelegationChain(links=[link1, link2])
valid, reason = validate_chain(chain, pub_keys)
print(f"\n  Chain valid: {valid}")
print(f"  Reason: {reason}")

# --- Scope narrowing ---
print("\n=== Scope Narrowing ===\n")
print(f"  Parent: {link1.scopes}")
print(f"  Child:  {link2.scopes}")
print(f"  Valid narrowing: {validate_scope_narrowing(link1.scopes, link2.scopes)}")
print(f"  Widening blocked: {validate_scope_narrowing(['tool:read'], ['tool:read', 'tool:admin'])}")

# --- Chain Budget ---
print("\n=== Chain Budget ===\n")
remaining, max_budget = parse_chain_budget("remaining=3.50USD;max=5.00USD")
print(f"  Remaining: ${remaining}")
print(f"  Max: ${max_budget}")
print(f"  Spent: ${max_budget - remaining}")

# --- Visited-Agents Loop Detection ---
print("\n=== Loop Detection ===\n")
visited = "agent://alice.example.com,agent://bob.example.com"
print(f"  Visited: {visited}")
print(f"  Charlie joining: loop? {check_visited_agents_loop(visited, 'agent://charlie.example.com')}")
print(f"  Alice re-joining: loop? {check_visited_agents_loop(visited, 'agent://alice.example.com')}")
print(f"  Within 20 limit: {check_visited_agents_limit(visited)}")
