"""
08 — GDPR Compliance (PII Classification, Audit Logging, Erasure)

Demonstrates content classification, hash-chain audit logs,
and cross-platform data erasure.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/08_compliance.py
"""

import asyncio
from ampro import (
    AgentMessage,
    ContentClassification,
    ErasureRequest,
    AuditLogger,
    AuditEntry,
    ErasureProcessor,
    check_content_classification,
    requires_audit,
)

# --- Content Classification ---
print("=== Content Classification ===\n")
for cls in ContentClassification:
    print(f"  {cls.value:15s}")

# --- PII Rejection ---
print("\n=== PII Rejection (accepts_pii=False) ===\n")
pii_msg = AgentMessage(
    sender="agent://sender.example.com",
    recipient="agent://receiver.example.com",
    body_type="message",
    body={"text": "Here is the user's SSN: 123-45-6789"},
    headers={"Content-Classification": "pii"},
)
result = check_content_classification(pii_msg, accepts_pii=False)
print(f"  PII message to non-PII agent:")
print(f"    Allowed: {result.allowed}")
print(f"    Reason: {result.reason}")
print(f"    Detail: {result.detail}")

result2 = check_content_classification(pii_msg, accepts_pii=True)
print(f"\n  PII message to PII-accepting agent:")
print(f"    Allowed: {result2.allowed}")

# --- Audit Requires Check ---
print("\n=== Audit Requirements ===\n")
for cls_value in ["public", "internal", "pii", "sensitive-pii", "confidential"]:
    msg = AgentMessage(
        sender="a", recipient="b", body_type="message",
        headers={"Content-Classification": cls_value},
    )
    print(f"  {cls_value:15s} → requires_audit: {requires_audit(msg)}")

# --- Hash-Chain Audit Logger ---
print("\n=== Audit Logger (Hash Chain) ===\n")
logger = AuditLogger()

for i in range(3):
    entry = logger.log(AuditEntry(
        message_id=f"msg-{i}",
        sender="agent://alice.example.com",
        recipient="agent://bob.example.com",
        body_type="task.create",
        content_classification="pii",
        trust_tier="verified",
        action_taken="processed",
    ))
    print(f"  Entry {i}: hash={entry.hash[:16]}... prev={entry.previous_hash[:16]}...")

print(f"\n  Chain integrity valid: {logger.verify_chain()}")
print(f"  Total entries: {logger.count}")

# Tamper detection
logger._entries[1].action_taken = "TAMPERED"
print(f"  After tampering: valid={logger.verify_chain()}")

# --- Erasure Processing ---
print("\n=== GDPR Erasure ===\n")

async def demo_erasure():
    processor = ErasureProcessor()
    
    req = ErasureRequest(
        subject_id="user-42",
        subject_proof="ed25519-signed-proof",
        scope="all",
        reason="user_request",
        deadline="2026-05-09T00:00:00Z",
    )
    
    resp = await processor.process(req)
    print(f"  Subject: {resp.subject_id}")
    print(f"  Status: {resp.status}")
    print(f"  Records deleted: {resp.records_deleted}")
    print(f"  Completed at: {resp.completed_at}")
    print(f"  Status check: {processor.get_status('user-42')}")

asyncio.run(demo_erasure())
