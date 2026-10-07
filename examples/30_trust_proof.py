"""
30 — Zero-Knowledge Trust Proofs

Demonstrates proving that a trust score meets a threshold without revealing
the exact score. Creates TrustProofBody instances, wraps them in AgentMessage,
validates with validate_body, shows verifier checking, and links to
CertificationLink in agent.json.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/30_trust_proof.py
"""

from ampro import (
    AgentJson,
    AgentMessage,
    CertificationLink,
    TrustProofBody,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

PROVER = "agent://prover.example.com"
VERIFIER = "agent://verifier.example.com"
SESSION_ID = "sess-proof-001"

print("=== Zero-Knowledge Trust Proofs ===\n")
print(f"  Prover:   {PROVER}")
print(f"  Verifier: {VERIFIER}")

# ---------------------------------------------------------------------------
# Step 1: Create TrustProofBody with claim="score_above_500"
# ---------------------------------------------------------------------------

print("\n=== Step 1: Create Trust Proof (score_above_500) ===\n")

proof_500 = TrustProofBody(
    agent_id=PROVER,
    claim="score_above_500",
    proof_type="zkp",
    proof="eyJhbGciOiJ6a3AiLCJ0eXAiOiJ0cnVzdC1wcm9vZiJ9.eyJjbGFpbSI6InNjb3JlX2Fib3ZlXzUwMCIsInRzIjoiMjAyNi0wNC0wOVQxMDowMDowMFoifQ.ZKP_PROOF_BYTES",
    verifier_key_id="key-verifier-2026-04",
)

print(f"  agent_id:        {proof_500.agent_id}")
print(f"  claim:           {proof_500.claim}")
print(f"  proof_type:      {proof_500.proof_type}")
print(f"  proof:           {proof_500.proof[:50]}...")
print(f"  verifier_key_id: {proof_500.verifier_key_id}")

# ---------------------------------------------------------------------------
# Step 2: Wrap in AgentMessage and validate with validate_body
# ---------------------------------------------------------------------------

print("\n=== Step 2: Wrap in AgentMessage ===\n")

proof_msg = AgentMessage(
    sender=PROVER,
    recipient=VERIFIER,
    body_type="trust.proof",
    headers={
        "Protocol-Version": "0.1.9",
        "Session-Id": SESSION_ID,
    },
    body=proof_500.model_dump(),
)

print(f"  sender:    {proof_msg.sender}")
print(f"  recipient: {proof_msg.recipient}")
print(f"  body_type: {proof_msg.body_type}")
print(f"  id:        {proof_msg.id}")

validated = validate_body("trust.proof", proof_msg.body)
print(f"\n  Validated type: {type(validated).__name__}")
print(f"  Validated claim: {validated.claim}")

# ---------------------------------------------------------------------------
# Step 3: Verifier checks the claim string
# ---------------------------------------------------------------------------

print("\n=== Step 3: Verifier Checks Claim ===\n")

THRESHOLD_REQUIRED = 500

claim = validated.claim  # "score_above_500"
parts = claim.split("_")
# Parse threshold from claim: "score_above_<N>"
if len(parts) == 3 and parts[0] == "score" and parts[1] == "above":
    claimed_threshold = int(parts[2])
    meets_requirement = claimed_threshold >= THRESHOLD_REQUIRED
else:
    claimed_threshold = None
    meets_requirement = False

print(f"  Required threshold:  {THRESHOLD_REQUIRED}")
print(f"  Claimed threshold:   {claimed_threshold}")
print(f"  Meets requirement:   {meets_requirement}")
print(f"  Proof type:          {validated.proof_type}")
print()
print("  The verifier confirms the ZKP claim satisfies the minimum")
print("  threshold without learning the prover's actual score.")

# ---------------------------------------------------------------------------
# Step 4: Second proof with claim="score_above_800"
# ---------------------------------------------------------------------------

print("\n=== Step 4: Second Proof (score_above_800) ===\n")

proof_800 = TrustProofBody(
    agent_id=PROVER,
    claim="score_above_800",
    proof_type="zkp",
    proof="eyJhbGciOiJ6a3AiLCJ0eXAiOiJ0cnVzdC1wcm9vZiJ9.eyJjbGFpbSI6InNjb3JlX2Fib3ZlXzgwMCIsInRzIjoiMjAyNi0wNC0wOVQxMDowNTowMFoifQ.ZKP_PROOF_BYTES_800",
    verifier_key_id="key-verifier-2026-04",
)

proof_800_msg = AgentMessage(
    sender=PROVER,
    recipient=VERIFIER,
    body_type="trust.proof",
    headers={
        "Protocol-Version": "0.1.9",
        "Session-Id": SESSION_ID,
    },
    body=proof_800.model_dump(),
)

validated_800 = validate_body("trust.proof", proof_800_msg.body)
print(f"  claim:     {validated_800.claim}")
print(f"  proof:     {validated_800.proof[:50]}...")

parts_800 = validated_800.claim.split("_")
claimed_800 = int(parts_800[2]) if len(parts_800) == 3 else 0
meets_800 = claimed_800 >= 800

print(f"  threshold: {claimed_800}")
print(f"  meets 800: {meets_800}")
print(f"\n  Validated type: {type(validated_800).__name__}")

# ---------------------------------------------------------------------------
# Step 5: Show CertificationLink in agent.json
# ---------------------------------------------------------------------------

print("\n=== Step 5: CertificationLink in agent.json ===\n")

cert_soc2 = CertificationLink(
    standard="SOC2",
    url="https://auditor.example.com/certs/prover-soc2-2026.pdf",
    verified_by="agent://auditor.example.com",
    expires_at="2027-04-09T00:00:00Z",
)

cert_iso = CertificationLink(
    standard="ISO27001",
    url="https://auditor.example.com/certs/prover-iso27001-2026.pdf",
    verified_by="agent://auditor.example.com",
    expires_at="2027-06-01T00:00:00Z",
)

agent_json = AgentJson(
    protocol_version="0.1.9",
    identifiers=[PROVER],
    endpoint="https://prover.example.com/agent/message",
    certifications=[
        cert_soc2.model_dump(),
        cert_iso.model_dump(),
    ],
)

print(f"  protocol_version: {agent_json.protocol_version}")
print(f"  identifiers:      {agent_json.identifiers}")
print("  certifications:")
for cert in agent_json.certifications:
    parsed = CertificationLink.model_validate(cert)
    print(f"    - {parsed.standard}: {parsed.url}")
    print(f"      verified_by: {parsed.verified_by}")
    print(f"      expires_at:  {parsed.expires_at}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== Summary ===\n")

print("  Trust proofs and certifications work together:")
print()
print(f"    {'Primitive':25s} {'Purpose'}")
print(f"    {'---------':25s} {'-------'}")
print(f"    {'TrustProofBody':25s} {'ZK proof that trust >= threshold'}")
print(f"    {'CertificationLink':25s} {'External compliance attestation'}")
print(f"    {'agent.json certs':25s} {'Advertise certifications to callers'}")
