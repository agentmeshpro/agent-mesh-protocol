"""
11 — Visibility & Contact Policies

Shows how agents control who can see them and who can contact them.
Demonstrates all 4 visibility levels and agent.json filtering.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/11_visibility.py
"""

from ampro import (
    ContactPolicy,
    VisibilityConfig,
    VisibilityLevel,
    check_contact_allowed,
    filter_agent_json,
)

# Sample agent.json
AGENT_JSON = {
    "protocol_version": "1.0.0",
    "identifiers": ["agent://service-provider.example.com"],
    "endpoint": "https://service-provider.example.com/agent/message",
    "visibility": {"level": "authenticated", "contact_policy": "handshake_required"},
    "capabilities": {"groups": ["messaging", "tools"], "level": 3},
    "constraints": {"max_tokens": 4000, "budget_usd": 10.0},
    "security": {"auth_methods": ["jwt", "did:web"]},
    "tools": ["search_catalog", "submit_request", "check_status"],
}

print("=== Visibility Levels ===\n")

for level in VisibilityLevel:
    print(f"--- {level.value.upper()} ---")
    for tier in ["internal", "owner", "verified", "external"]:
        filtered = filter_agent_json(AGENT_JSON, tier, level)
        keys = list(filtered.keys()) if filtered else ["(empty)"]
        print(f"  {tier:12s} sees: {', '.join(keys)}")
    print()


print("=== Contact Policies ===\n")

for policy in ContactPolicy:
    results = []
    for tier in ["internal", "owner", "verified", "external"]:
        allowed = check_contact_allowed(tier, policy)
        results.append(f"{tier}={'yes' if allowed else 'NO'}")
    print(f"  {policy.value:25s} → {', '.join(results)}")


print("\n=== Default Configs by Role ===\n")

configs = {
    "Public API": VisibilityConfig(level=VisibilityLevel.PUBLIC, contact_policy=ContactPolicy.OPEN),
    "Authenticated": VisibilityConfig(level=VisibilityLevel.AUTHENTICATED, contact_policy=ContactPolicy.HANDSHAKE_REQUIRED),
    "Internal Only": VisibilityConfig(level=VisibilityLevel.PRIVATE, contact_policy=ContactPolicy.DELEGATION_ONLY, listed_in_registries=False),
    "Hidden": VisibilityConfig(level=VisibilityLevel.HIDDEN, contact_policy=ContactPolicy.EXPLICIT_INVITE, listed_in_registries=False, searchable=False),
}

for role, cfg in configs.items():
    print(f"  {role:15s}: level={cfg.level.value}, policy={cfg.contact_policy.value}, "
          f"listed={cfg.listed_in_registries}, searchable={cfg.searchable}")
