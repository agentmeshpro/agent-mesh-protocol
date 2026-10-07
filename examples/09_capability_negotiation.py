"""
09 — Capability Negotiation

Demonstrates how two agents with different capability levels
negotiate what they can do together.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/09_capability_negotiation.py
"""

from ampro import (
    CURRENT_VERSION,
    SUPPORTED_VERSIONS,
    CapabilityGroup,
    CapabilityLevel,
    CapabilityNegotiator,
    CapabilitySet,
    NegotiationResult,
    negotiate_version,
)

# --- Capability Levels ---
print("=== Capability Levels ===\n")
print("  Level 0: Static agent.json only (discoverable)")
print("  Level 1: + Messaging")
print("  Level 2: + Tools")
print("  Level 3: + Streaming")
print("  Level 4: + Identity, Session, Delegation, Events")
print("  Level 5: + Presence (all 8 groups)")

# --- Two agents with different capabilities ---
print("\n=== Negotiation Example ===\n")

# Full protocol agent (Level 5 — full protocol)
server = CapabilitySet(groups=set(CapabilityGroup))
print(f"  Server: Level {server.level} ({', '.join(g.value for g in sorted(server.groups, key=lambda g: g.value))})")

# Pi agent (Level 1 — messaging only)
client = CapabilitySet(groups={CapabilityGroup.MESSAGING})
print(f"  Client: Level {client.level} ({', '.join(g.value for g in client.groups)})")

# Negotiate
result = CapabilityNegotiator.full_negotiation(
    server_caps=server,
    client_caps=client,
)
print(f"\n  Negotiated Level: {result.agreed_capabilities.level}")
print(f"  Agreed Groups: {', '.join(g.value for g in result.agreed_capabilities.groups) or '(none)'}")
print(f"  Warnings: {len(result.warnings)}")
for w in result.warnings[:3]:
    print(f"    - {w}")

# --- Better match ---
print("\n=== Better Match ===\n")
client2 = CapabilitySet(groups={
    CapabilityGroup.MESSAGING,
    CapabilityGroup.TOOLS,
    CapabilityGroup.STREAMING,
})
print(f"  Client: Level {client2.level}")
result2 = CapabilityNegotiator.full_negotiation(server_caps=server, client_caps=client2)
print(f"  Negotiated Level: {result2.agreed_capabilities.level}")
print(f"  Warnings: {len(result2.warnings)}")

# --- Version Negotiation ---
print("\n=== Version Negotiation ===\n")
print(f"  Current: {CURRENT_VERSION}")
print(f"  Supported: {SUPPORTED_VERSIONS}")
print(f"  negotiate('2.0.0, 1.0.0'): {negotiate_version('2.0.0, 1.0.0')}")
print(f"  negotiate('0.1.0'): {negotiate_version('0.1.0')}")
try:
    negotiate_version("3.0.0")
except ValueError as e:
    print(f"  negotiate('3.0.0'): ValueError — {e}")
