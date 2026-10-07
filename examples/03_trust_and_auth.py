"""
03 — Trust Tiers and Authentication

Demonstrates the 4-tier trust system and multi-method auth parsing.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/03_trust_and_auth.py
"""

from ampro import (
    TrustTier,
    TrustConfig,
    AuthMethod,
    parse_authorization,
    CLOCK_SKEW_SECONDS,
)

# --- Trust Tiers ---
print("=== Trust Tiers ===")
for tier in TrustTier:
    config = TrustConfig.from_tier(tier)
    print(f"\n{tier.value}:")
    print(f"  Can delegate:    {tier.can_delegate}")
    print(f"  Requires auth:   {config.check_auth}")
    print(f"  Rate limited:    {config.check_rate_limit}")
    print(f"  Content filter:  {config.check_content_filter}")
    print(f"  Budget check:    {config.check_budget}")
    print(f"  Loop detection:  {config.check_loop_detection}")
    print(f"  Kill switch:     {config.check_kill_switch}")

# --- Multi-Method Auth Parsing ---
print("\n=== Authorization Header Parsing ===")
test_headers = [
    "Bearer eyJhbGciOiJFZERTQSJ9.payload.signature",
    "DID eyJkaWQiOiJkaWQ6a2V5Ono2TWsifQ.sig",
    "ApiKey sk_live_abc123def456",
    None,
    "",
    "Basic dXNlcjpwYXNz",
]

for header in test_headers:
    auth = parse_authorization(header)
    print(f"\n  Header: {header!r}")
    print(f"  Method: {auth.method.value}")
    print(f"  Max tier: {auth.max_trust_tier()}")

# --- Clock Skew ---
print(f"\n=== Clock Skew Tolerance: {CLOCK_SKEW_SECONDS}s ===")
print(f"All timestamp comparisons allow {CLOCK_SKEW_SECONDS} seconds of drift")
print("for cross-platform compatibility (Pi clocks, time zones, etc.)")
