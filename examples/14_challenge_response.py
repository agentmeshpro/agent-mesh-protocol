"""
14 — Challenge-Response (Anti-Abuse)

Demonstrates a public-facing agent issuing a proof-of-work challenge
to a new sender, and the sender solving it. Shows the full message
flow with AgentMessage envelopes.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git
    python examples/14_challenge_response.py
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from ampro import (
    AgentMessage,
    ChallengeReason,
    TaskChallengeBody,
    TaskChallengeResponseBody,
    validate_body,
)

print("=== Challenge Reasons ===\n")

for reason in ChallengeReason:
    print(f"  {reason.value}")

# ---------------------------------------------------------------------------
# Step 1: New sender tries to create a task
# ---------------------------------------------------------------------------

print("\n=== Step 1: Sender Sends Initial Request ===\n")

initial_request = AgentMessage(
    sender="agent://new-client.example.com",
    recipient="agent://public-api.example.com",
    body_type="task.create",
    body={
        "description": "Aggregate last 24h of system metrics",
        "priority": "normal",
    },
)

print(f"  From: {initial_request.sender}")
print(f"  To:   {initial_request.recipient}")
print(f"  Type: {initial_request.body_type}")
print(f"  Msg:  {initial_request.id[:8]}...")

# ---------------------------------------------------------------------------
# Step 2: Receiver issues a challenge (first_contact)
# ---------------------------------------------------------------------------

print("\n=== Step 2: Receiver Issues Challenge ===\n")

challenge_nonce = secrets.token_hex(16)
difficulty = 4  # Number of leading zero hex chars required
expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

challenge = TaskChallengeBody(
    challenge_id=f"ch-{secrets.token_hex(8)}",
    challenge_type="proof_of_work",
    parameters={
        "algorithm": "sha256",
        "nonce": challenge_nonce,
        "difficulty": difficulty,
        "target_prefix": "0" * difficulty,
    },
    expires_at=expires,
    reason=ChallengeReason.FIRST_CONTACT.value,
)

challenge_msg = AgentMessage(
    sender="agent://public-api.example.com",
    recipient="agent://new-client.example.com",
    body_type="task.challenge",
    headers={"In-Reply-To": initial_request.id},
    body=challenge.model_dump(),
)

print(f"  Challenge ID:   {challenge.challenge_id}")
print(f"  Type:           {challenge.challenge_type}")
print(f"  Difficulty:     {difficulty} leading zeros")
print(f"  Nonce:          {challenge_nonce[:16]}...")
print(f"  Expires:        {challenge.expires_at}")
print(f"  Reason:         {challenge.reason}")

# ---------------------------------------------------------------------------
# Step 3: Sender solves the challenge
# ---------------------------------------------------------------------------

print("\n=== Step 3: Sender Solves Challenge ===\n")

# Brute-force the proof of work
target_prefix = "0" * difficulty
attempt = 0
while True:
    candidate = f"{challenge_nonce}:{attempt}"
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    if digest.startswith(target_prefix):
        break
    attempt += 1

print(f"  Solved in {attempt + 1} attempts")
print(f"  Solution:       {attempt}")
print(f"  Hash:           {digest[:32]}...")
print(f"  Starts with:    {digest[:difficulty]} (matches '{target_prefix}')")

# ---------------------------------------------------------------------------
# Step 4: Sender sends the solution
# ---------------------------------------------------------------------------

print("\n=== Step 4: Sender Submits Solution ===\n")

response = TaskChallengeResponseBody(
    challenge_id=challenge.challenge_id,
    solution=str(attempt),
)

response_msg = AgentMessage(
    sender="agent://new-client.example.com",
    recipient="agent://public-api.example.com",
    body_type="task.challenge_response",
    headers={"In-Reply-To": challenge_msg.id},
    body=response.model_dump(),
)

print(f"  Challenge ID:   {response.challenge_id}")
print(f"  Solution:       {response.solution}")
print(f"  Message ID:     {response_msg.id[:8]}...")

# ---------------------------------------------------------------------------
# Step 5: Receiver verifies the solution
# ---------------------------------------------------------------------------

print("\n=== Step 5: Receiver Verifies ===\n")

# Validate the incoming body
verified_body = validate_body("task.challenge_response", response_msg.body)
print(f"  Validated type: {type(verified_body).__name__}")

# Check the proof of work
check_candidate = f"{challenge_nonce}:{verified_body.solution}"
check_digest = hashlib.sha256(check_candidate.encode()).hexdigest()
valid = check_digest.startswith(target_prefix)

print(f"  Recomputed:     {check_digest[:32]}...")
print(f"  Valid:           {valid}")

if valid:
    print("  Result:         PASS — original task.create will now be processed")
else:
    print("  Result:         FAIL — sender is rejected")

# ---------------------------------------------------------------------------
# Other challenge reasons
# ---------------------------------------------------------------------------

print("\n=== Other Challenge Reasons ===\n")

for reason in [ChallengeReason.SUSPICIOUS_BEHAVIOR, ChallengeReason.RATE_LIMIT_EXCEEDED, ChallengeReason.TRUST_UPGRADE]:
    c = TaskChallengeBody(
        challenge_id=f"ch-{secrets.token_hex(4)}",
        challenge_type="proof_of_work",
        parameters={"algorithm": "sha256", "nonce": secrets.token_hex(8), "difficulty": 3},
        expires_at=expires,
        reason=reason.value,
    )
    print(f"  {reason.value:25s} → challenge {c.challenge_id}")
