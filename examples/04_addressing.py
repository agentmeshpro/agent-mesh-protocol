"""
04 — agent:// Addressing

Demonstrates the three addressing forms and resolution rules.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/04_addressing.py
"""

from ampro import (
    AddressType,
    normalize_shorthand,
    parse_agent_uri,
)

# --- Three Address Forms ---
print("=== agent:// Addressing ===\n")

# Form 1: Direct Host
addr = parse_agent_uri("agent://weather-service.example.com")
print(f"Direct Host: {addr.to_uri()}")
print(f"  Type: {addr.address_type.value}")
print(f"  Host: {addr.host}")
print(f"  agent.json URL: {addr.agent_json_url()}")

# Form 2: Registry Slug
addr = parse_agent_uri("agent://data-processor@registry.example.com")
print(f"\nRegistry Slug: {addr.to_uri()}")
print(f"  Type: {addr.address_type.value}")
print(f"  Slug: {addr.slug}")
print(f"  Registry: {addr.registry}")
print(f"  Resolve URL: {addr.registry_resolve_url()}")

# Form 3: DID
addr = parse_agent_uri("agent://did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
print(f"\nDID: {addr.to_uri()}")
print(f"  Type: {addr.address_type.value}")
print(f"  DID: {addr.did}")

# --- Shorthand Normalization ---
print("\n=== Shorthand Normalization ===\n")
shorthands = [
    ("@data-processor", "registry.example.com"),
    ("https://weather-service.example.com", "registry.example.com"),
    ("weather-service.example.com", "registry.example.com"),
    ("agent://already-valid.example.com", "registry.example.com"),
]
for value, registry in shorthands:
    result = normalize_shorthand(value, default_registry=registry)
    print(f"  {value:35s} → {result}")

# --- Resolution Rules ---
print("\n=== Resolution Rules ===\n")
print("  agent://{authority}")
print('  Contains "did:"  → DID resolution')
print('  Contains "@"     → slug@registry resolution')
print("  Otherwise        → direct host resolution")
