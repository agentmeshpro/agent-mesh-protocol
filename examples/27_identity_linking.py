"""
27 — Identity Linking

Demonstrates proving that two agent:// addresses belong to the same
entity using IdentityLinkProofBody. Creates link proofs with different
proof types, wraps them in AgentMessage, and validates with validate_body.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/27_identity_linking.py
"""

from datetime import UTC, datetime

from ampro import (
    AgentMessage,
    IdentityLinkProofBody,
    validate_body,
)
from ampro.identity.link import DEFAULT_LINK_PROOF_LIFETIME, is_link_proof_valid

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

AGENT_HOST = "agent://assistant.example.com"
AGENT_SLUG = "agent://assistant@hub.example.com"
SESSION_ID = "sess-identity-link-001"

print("=== Identity Linking ===\n")
print(f"  Primary address:   {AGENT_HOST}")
print(f"  Secondary address: {AGENT_SLUG}")

# ---------------------------------------------------------------------------
# Step 1: Create an IdentityLinkProofBody (ed25519_cross_sign)
# ---------------------------------------------------------------------------

print("\n=== Step 1: Create Link Proof (ed25519_cross_sign) ===\n")

link_proof = IdentityLinkProofBody(
    source_id=AGENT_HOST,
    target_id=AGENT_SLUG,
    proof_type="ed25519_cross_sign",
    proof="MEUCIQD2YnoGk5kqLwDhP8N2xJMB1rGpKY8E4vZf1kA9T7vXwAIgEfG3hOd6HjK5nRr8Q2eL1mN4pS7tU0vWxYz3aBcDeF=",
    timestamp="2026-04-09T10:00:00Z",
    # Link proofs MUST carry an expiry strictly after their timestamp.
    expires_at=datetime(2026, 4, 9, 10, 0, tzinfo=UTC) + DEFAULT_LINK_PROOF_LIFETIME,
)

print(f"  source_id:  {link_proof.source_id}")
print(f"  target_id:  {link_proof.target_id}")
print(f"  proof_type: {link_proof.proof_type}")
print(f"  proof:      {link_proof.proof[:50]}...")
print(f"  timestamp:  {link_proof.timestamp}")
print(f"  expires_at: {link_proof.expires_at.isoformat()}")
at = datetime(2026, 6, 1, tzinfo=UTC)
print(f"  valid on {at.date()}: {is_link_proof_valid(link_proof, now=at)}")
later = datetime(2028, 1, 1, tzinfo=UTC)
print(f"  valid on {later.date()}: {is_link_proof_valid(link_proof, now=later)}")

# ---------------------------------------------------------------------------
# Step 2: Wrap in AgentMessage and validate with validate_body
# ---------------------------------------------------------------------------

print("\n=== Step 2: Wrap in AgentMessage ===\n")

link_msg = AgentMessage(
    sender=AGENT_HOST,
    recipient=AGENT_SLUG,
    body_type="identity.link_proof",
    headers={
        "Protocol-Version": "0.1.8",
        "Session-Id": SESSION_ID,
    },
    body=link_proof.model_dump(mode="json"),
)

print(f"  sender:    {link_msg.sender}")
print(f"  recipient: {link_msg.recipient}")
print(f"  body_type: {link_msg.body_type}")
print(f"  id:        {link_msg.id}")

validated = validate_body("identity.link_proof", link_msg.body)
print(f"\n  Validated type: {type(validated).__name__}")

# ---------------------------------------------------------------------------
# Step 3: Show link proof fields
# ---------------------------------------------------------------------------

print("\n=== Step 3: Link Proof Fields ===\n")

dump = link_proof.model_dump()
for key, value in dump.items():
    display = value if len(str(value)) < 60 else str(value)[:57] + "..."
    print(f"  {key:12s} = {display}")

# ---------------------------------------------------------------------------
# Step 4: Second link with different proof_type (dns_txt)
# ---------------------------------------------------------------------------

print("\n=== Step 4: Second Link (dns_txt proof) ===\n")

AGENT_DID = "agent://did:web:example.com"

dns_link = IdentityLinkProofBody(
    source_id=AGENT_HOST,
    target_id=AGENT_DID,
    proof_type="dns_txt",
    proof="amp-verify=abc123def456ghi789jkl012mno345pqr678stu901vwx234",
    timestamp="2026-04-09T10:05:00Z",
    expires_at=datetime(2026, 4, 9, 10, 5, tzinfo=UTC) + DEFAULT_LINK_PROOF_LIFETIME,
)

dns_msg = AgentMessage(
    sender=AGENT_HOST,
    recipient=AGENT_DID,
    body_type="identity.link_proof",
    headers={
        "Protocol-Version": "0.1.8",
        "Session-Id": SESSION_ID,
    },
    body=dns_link.model_dump(mode="json"),
)

print(f"  source_id:  {dns_link.source_id}")
print(f"  target_id:  {dns_link.target_id}")
print(f"  proof_type: {dns_link.proof_type}")
print(f"  proof:      {dns_link.proof}")
print(f"  timestamp:  {dns_link.timestamp}")

validated_dns = validate_body("identity.link_proof", dns_msg.body)
print(f"\n  Validated type: {type(validated_dns).__name__}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== Summary ===\n")

print("  IdentityLinkProofBody proves two agent:// addresses share a")
print("  controlling entity. The proof_type determines how the link is")
print("  verified:")
print()
print(f"    {'Proof Type':22s} {'Verification Method'}")
print(f"    {'----------':22s} {'-------------------'}")
print(f"    {'ed25519_cross_sign':22s} {'Cross-signed by both keys'}")
print(f"    {'dns_txt':22s} {'DNS TXT record at source domain'}")
print(f"    {'registry_attestation':22s} {'Registry vouches for the link'}")
