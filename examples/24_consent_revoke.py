"""
24 — Consent Revocation and Erasure Propagation

Demonstrates partial and full consent revocation, immediate vs scheduled
revocation, and tracking erasure propagation status across multiple agents.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/24_consent_revoke.py
"""

from ampro import (
    AgentMessage,
    DataConsentRevokeBody,
    ErasurePropagationStatus,
    ErasurePropagationStatusBody,
    DataResidency,
    validate_residency_region,
    check_residency_violation,
    validate_body,
)

# ---------------------------------------------------------------------------
# Setup: Agents
# ---------------------------------------------------------------------------

REQUESTER = "agent://requester.example.com"
TARGET = "agent://target.example.com"
DOWNSTREAM_A = "agent://downstream-a.example.com"
DOWNSTREAM_B = "agent://downstream-b.example.com"
DOWNSTREAM_C = "agent://downstream-c.example.com"
SESSION_ID = "sess-consent-revoke-demo-001"

print("=== Agent Topology ===\n")
print(f"  {REQUESTER}")
print(f"    -> {TARGET}")
print(f"         -> {DOWNSTREAM_A}")
print(f"         -> {DOWNSTREAM_B}")
print(f"         -> {DOWNSTREAM_C}")

# ---------------------------------------------------------------------------
# Step 1: Partial scope revocation
# ---------------------------------------------------------------------------

print("\n=== Step 1: Partial Scope Revocation ===\n")

partial_revoke = DataConsentRevokeBody(
    grant_id="grant-abc-001",
    requester=REQUESTER,
    target=TARGET,
    scopes=["read:analytics", "read:logs"],
    reason="Analytics access no longer required after project completion",
    effective_at=None,  # immediate
)

partial_msg = AgentMessage(
    sender=REQUESTER,
    recipient=TARGET,
    body_type="data.consent_revoke",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=partial_revoke.model_dump(),
)

print(f"  From:         {partial_msg.sender}")
print(f"  To:           {partial_msg.recipient}")
print(f"  Body type:    {partial_msg.body_type}")
print(f"  Grant ID:     {partial_revoke.grant_id}")
print(f"  Scopes:       {partial_revoke.scopes}  (partial — only these scopes)")
print(f"  Reason:       {partial_revoke.reason}")
print(f"  Effective at: {partial_revoke.effective_at}  (None = immediate)")

validated = validate_body("data.consent_revoke", partial_msg.body)
print(f"\n  Validated:    {type(validated).__name__}")

# ---------------------------------------------------------------------------
# Step 2: Full revocation (empty scopes = revoke all)
# ---------------------------------------------------------------------------

print("\n=== Step 2: Full Revocation ===\n")

full_revoke = DataConsentRevokeBody(
    grant_id="grant-abc-002",
    requester=REQUESTER,
    target=TARGET,
    scopes=[],  # empty = revoke all scopes
    reason="Agent decommissioned, revoking all data access",
    effective_at=None,
)

full_msg = AgentMessage(
    sender=REQUESTER,
    recipient=TARGET,
    body_type="data.consent_revoke",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=full_revoke.model_dump(),
)

print(f"  Grant ID:     {full_revoke.grant_id}")
print(f"  Scopes:       {full_revoke.scopes}  (empty = revoke ALL scopes)")
print(f"  Reason:       {full_revoke.reason}")
print(f"  Effective at: {full_revoke.effective_at}  (immediate)")

validated2 = validate_body("data.consent_revoke", full_msg.body)
print(f"\n  Validated:    {type(validated2).__name__}")

# ---------------------------------------------------------------------------
# Step 3: Scheduled revocation (future effective_at)
# ---------------------------------------------------------------------------

print("\n=== Step 3: Scheduled Revocation ===\n")

scheduled_revoke = DataConsentRevokeBody(
    grant_id="grant-abc-003",
    requester=REQUESTER,
    target=TARGET,
    scopes=["write:config"],
    reason="Contract ends on 2026-05-01, revoking write access",
    effective_at="2026-05-01T00:00:00Z",
)

scheduled_msg = AgentMessage(
    sender=REQUESTER,
    recipient=TARGET,
    body_type="data.consent_revoke",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=scheduled_revoke.model_dump(),
)

print(f"  Grant ID:     {scheduled_revoke.grant_id}")
print(f"  Scopes:       {scheduled_revoke.scopes}")
print(f"  Reason:       {scheduled_revoke.reason}")
print(f"  Effective at: {scheduled_revoke.effective_at}  (scheduled)")
print(f"  Status:       Revocation will take effect at the specified time")

validated3 = validate_body("data.consent_revoke", scheduled_msg.body)
print(f"\n  Validated:    {type(validated3).__name__}")

# ---------------------------------------------------------------------------
# Step 4: Erasure propagation status tracking across 3 downstream agents
# ---------------------------------------------------------------------------

print("\n=== Step 4: Erasure Propagation Tracking ===\n")

ERASURE_ID = "erasure-req-001"

print(f"  Erasure ID: {ERASURE_ID}")
print(f"  Tracking propagation across 3 downstream agents...\n")

# Downstream A: completed
status_a = ErasurePropagationStatusBody(
    erasure_id=ERASURE_ID,
    agent_id=DOWNSTREAM_A,
    status=ErasurePropagationStatus.PENDING.value,
    records_affected=0,
    timestamp="2026-04-09T10:00:00Z",
    downstream_agents=[],
)

print(f"  T+0s  {DOWNSTREAM_A}")
print(f"         Status:  {status_a.status}")
print(f"         Records: {status_a.records_affected}")

# Simulate transition to completed
status_a_done = ErasurePropagationStatusBody(
    erasure_id=ERASURE_ID,
    agent_id=DOWNSTREAM_A,
    status=ErasurePropagationStatus.COMPLETED.value,
    records_affected=42,
    timestamp="2026-04-09T10:00:05Z",
    downstream_agents=[],
)

msg_a = AgentMessage(
    sender=DOWNSTREAM_A,
    recipient=TARGET,
    body_type="erasure.propagation_status",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=status_a_done.model_dump(),
)

print(f"  T+5s  {DOWNSTREAM_A}")
print(f"         Status:  {status_a_done.status}")
print(f"         Records: {status_a_done.records_affected}")

validated_a = validate_body("erasure.propagation_status", msg_a.body)
print(f"         Validated: {type(validated_a).__name__}")

# Downstream B: completed
status_b = ErasurePropagationStatusBody(
    erasure_id=ERASURE_ID,
    agent_id=DOWNSTREAM_B,
    status=ErasurePropagationStatus.COMPLETED.value,
    records_affected=17,
    timestamp="2026-04-09T10:00:08Z",
    downstream_agents=[],
)

msg_b = AgentMessage(
    sender=DOWNSTREAM_B,
    recipient=TARGET,
    body_type="erasure.propagation_status",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=status_b.model_dump(),
)

print(f"\n  T+8s  {DOWNSTREAM_B}")
print(f"         Status:  {status_b.status}")
print(f"         Records: {status_b.records_affected}")

# Downstream C: failed
status_c = ErasurePropagationStatusBody(
    erasure_id=ERASURE_ID,
    agent_id=DOWNSTREAM_C,
    status=ErasurePropagationStatus.FAILED.value,
    records_affected=0,
    timestamp="2026-04-09T10:00:12Z",
    detail="Storage backend unreachable after 3 retries",
    downstream_agents=[],
)

msg_c = AgentMessage(
    sender=DOWNSTREAM_C,
    recipient=TARGET,
    body_type="erasure.propagation_status",
    headers={
        "Protocol-Version": "0.1.6",
        "Session-Id": SESSION_ID,
    },
    body=status_c.model_dump(),
)

print(f"\n  T+12s {DOWNSTREAM_C}")
print(f"         Status:  {status_c.status}")
print(f"         Records: {status_c.records_affected}")
print(f"         Detail:  {status_c.detail}")

# ---------------------------------------------------------------------------
# Step 5: Erasure propagation with downstream chain
# ---------------------------------------------------------------------------

print("\n=== Step 5: Downstream Agent Reports Its Own Propagation ===\n")

status_chain = ErasurePropagationStatusBody(
    erasure_id=ERASURE_ID,
    agent_id=DOWNSTREAM_A,
    status=ErasurePropagationStatus.COMPLETED.value,
    records_affected=42,
    timestamp="2026-04-09T10:00:15Z",
    downstream_agents=[
        "agent://sub-agent-x.example.com",
        "agent://sub-agent-y.example.com",
    ],
)

print(f"  Agent:            {status_chain.agent_id}")
print(f"  Status:           {status_chain.status}")
print(f"  Records:          {status_chain.records_affected}")
print(f"  Downstream:       {status_chain.downstream_agents}")
print(f"  Note:             Agent A propagated erasure to 2 sub-agents")

# ---------------------------------------------------------------------------
# Step 6: Data residency check
# ---------------------------------------------------------------------------

print("\n=== Step 6: Data Residency Checks ===\n")

message_residency = DataResidency(
    region="eu-west-1",
    strict=True,
    allowed_regions=[],
)

agent_eu = DataResidency(
    region="eu-west-1",
    strict=True,
    allowed_regions=[],
)

agent_us = DataResidency(
    region="us-east-1",
    strict=True,
    allowed_regions=[],
)

# Check eu-west-1 agent handling eu-west-1 data
violation_eu, detail_eu = check_residency_violation(message_residency, agent_eu)
print(f"  Message region: {message_residency.region} (strict={message_residency.strict})")
print(f"  Agent region:   {agent_eu.region}")
print(f"  Violation:      {violation_eu}")
print(f"  Detail:         {detail_eu}")

# Check us-east-1 agent handling eu-west-1 strict data
print()
violation_us, detail_us = check_residency_violation(message_residency, agent_us)
print(f"  Message region: {message_residency.region} (strict={message_residency.strict})")
print(f"  Agent region:   {agent_us.region}")
print(f"  Violation:      {violation_us}")
print(f"  Detail:         {detail_us}")

# Non-strict with allowed regions
print()
message_flex = DataResidency(
    region="eu-west-1",
    strict=False,
    allowed_regions=["eu-central-1", "eu-north-1"],
)

agent_central = DataResidency(region="eu-central-1", strict=True)
agent_apac = DataResidency(region="ap-southeast-1", strict=True)

violation_central, detail_central = check_residency_violation(message_flex, agent_central)
print(f"  Message region: {message_flex.region} (strict=False, allowed={message_flex.allowed_regions})")
print(f"  Agent region:   {agent_central.region}")
print(f"  Violation:      {violation_central}  (in allowed_regions)")

print()
violation_apac, detail_apac = check_residency_violation(message_flex, agent_apac)
print(f"  Agent region:   {agent_apac.region}")
print(f"  Violation:      {violation_apac}")
print(f"  Detail:         {detail_apac}")

# ---------------------------------------------------------------------------
# Step 7: Validate residency region identifiers
# ---------------------------------------------------------------------------

print("\n=== Step 7: Validate Residency Regions ===\n")

test_regions = [
    ("eu-west-1", True),
    ("us-east-1", True),
    ("ap-southeast-1", True),
    ("eu-central-1", True),
    ("abc", True),          # 3 chars, valid
    ("-invalid", False),    # starts with hyphen
    ("AB", False),          # too short (2 chars), uppercase
    ("", False),            # empty
    ("a", False),           # single character — too short
]

print(f"  {'Region':20s} {'Expected':10s} {'Result':10s} {'Match'}")
print(f"  {'------':20s} {'--------':10s} {'------':10s} {'-----'}")

for region, expected in test_regions:
    result = validate_residency_region(region)
    match = result == expected
    print(f"  {repr(region):20s} {str(expected):10s} {str(result):10s} {match}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== Summary ===\n")

print(f"  Consent Revocation:")
print(f"    Partial:   Revoke specific scopes (scopes=['read:analytics', ...])")
print(f"    Full:      Revoke all scopes (scopes=[])")
print(f"    Immediate: effective_at=None")
print(f"    Scheduled: effective_at='2026-05-01T00:00:00Z'")
print(f"")
print(f"  Erasure Propagation:")
print(f"    pending   -> Agent acknowledged the request")
print(f"    completed -> Records erased successfully")
print(f"    failed    -> Erasure could not be completed")
print(f"")
print(f"  Data Residency:")
print(f"    strict=True  -> Data MUST stay in declared region")
print(f"    strict=False -> Data may go to allowed_regions")
