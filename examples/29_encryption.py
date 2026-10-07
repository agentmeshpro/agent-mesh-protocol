"""
29 — End-to-End Encryption

Demonstrates encrypted message envelopes: building an AgentMessage with the
Content-Encryption header, wrapping an EncryptedBody with ciphertext/iv/tag,
then "decrypting" by replacing the body with a plaintext TaskCreateBody.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/29_encryption.py
"""

from ampro import (
    AgentMessage,
    EncryptedBody,
    TaskCreateBody,
    validate_body,
    CONTENT_ENCRYPTION_HEADER,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

SENDER = "agent://requester.example.com"
RECIPIENT = "agent://executor.example.com"
SESSION_ID = "sess-enc-001"

print("=== End-to-End Encryption ===\n")
print(f"  Sender:    {SENDER}")
print(f"  Recipient: {RECIPIENT}")
print(f"  Header constant: {CONTENT_ENCRYPTION_HEADER}")

# ---------------------------------------------------------------------------
# Step 1: Build AgentMessage with Content-Encryption header
# ---------------------------------------------------------------------------

print("\n=== Step 1: Build Encrypted Envelope ===\n")

encrypted_body = EncryptedBody(
    ciphertext="dGhpcyBpcyBhIHNpbXVsYXRlZCBjaXBoZXJ0ZXh0IGJsb2I=",
    iv="AAAAAAAAAAAAAAAAAAAAAA==",
    tag="kMbTHlCzQ3GP9v7NrF2xYQ==",
    algorithm="A256GCM",
    recipient_key_id="key-executor-2026-04",
)

encrypted_msg = AgentMessage(
    sender=SENDER,
    recipient=RECIPIENT,
    body_type="message",
    headers={
        "Protocol-Version": "0.1.9",
        "Session-Id": SESSION_ID,
        CONTENT_ENCRYPTION_HEADER: "A256GCM",
    },
    body=encrypted_body.model_dump(),
)

print(f"  sender:    {encrypted_msg.sender}")
print(f"  recipient: {encrypted_msg.recipient}")
print(f"  body_type: {encrypted_msg.body_type}")
print(f"  id:        {encrypted_msg.id}")
print(f"  headers:")
for k, v in encrypted_msg.headers.items():
    print(f"    {k}: {v}")

print(f"\n  Encrypted body fields:")
print(f"    ciphertext:       {encrypted_body.ciphertext[:40]}...")
print(f"    iv:               {encrypted_body.iv}")
print(f"    tag:              {encrypted_body.tag}")
print(f"    algorithm:        {encrypted_body.algorithm}")
print(f"    recipient_key_id: {encrypted_body.recipient_key_id}")

# ---------------------------------------------------------------------------
# Step 2: Check for Content-Encryption header
# ---------------------------------------------------------------------------

print("\n=== Step 2: Detect Encryption ===\n")

is_encrypted = CONTENT_ENCRYPTION_HEADER in encrypted_msg.headers
print(f"  Has {CONTENT_ENCRYPTION_HEADER} header: {is_encrypted}")
print(f"  Algorithm: {encrypted_msg.headers.get(CONTENT_ENCRYPTION_HEADER)}")

if is_encrypted:
    # Parse the encrypted body to validate its structure
    enc = EncryptedBody.model_validate(encrypted_msg.body)
    print(f"  EncryptedBody parsed — key: {enc.recipient_key_id}")

# ---------------------------------------------------------------------------
# Step 3: "Decrypt" — replace body with plaintext TaskCreateBody
# ---------------------------------------------------------------------------

print("\n=== Step 3: Decrypted Envelope ===\n")

plaintext_body = TaskCreateBody(
    description="Find the nearest available courier",
    priority="high",
    tools_required=["routing", "dispatch"],
    timeout_seconds=120,
)

decrypted_msg = AgentMessage(
    sender=encrypted_msg.sender,
    recipient=encrypted_msg.recipient,
    id=encrypted_msg.id,
    body_type="task.create",
    headers={
        "Protocol-Version": "0.1.9",
        "Session-Id": SESSION_ID,
    },
    body=plaintext_body.model_dump(),
)

print(f"  sender:    {decrypted_msg.sender}")
print(f"  recipient: {decrypted_msg.recipient}")
print(f"  body_type: {decrypted_msg.body_type}")
print(f"  id:        {decrypted_msg.id}")
print(f"  headers:   (no {CONTENT_ENCRYPTION_HEADER})")

validated = validate_body("task.create", decrypted_msg.body)
print(f"\n  Validated type: {type(validated).__name__}")
print(f"    description:     {validated.description}")
print(f"    priority:        {validated.priority}")
print(f"    tools_required:  {validated.tools_required}")
print(f"    timeout_seconds: {validated.timeout_seconds}")

# ---------------------------------------------------------------------------
# Step 4: Print both envelopes side by side
# ---------------------------------------------------------------------------

print("\n=== Step 4: Encrypted vs Decrypted ===\n")

print("  ENCRYPTED envelope:")
enc_dump = encrypted_msg.model_dump()
print(f"    body_type: {enc_dump['body_type']}")
print(f"    headers:   ...{CONTENT_ENCRYPTION_HEADER}: A256GCM")
print(f"    body:      ciphertext={enc_dump['body']['ciphertext'][:30]}...")

print()

print("  DECRYPTED envelope:")
dec_dump = decrypted_msg.model_dump()
print(f"    body_type: {dec_dump['body_type']}")
print(f"    headers:   (no encryption header)")
print(f"    body:      description={dec_dump['body']['description']}")

# ---------------------------------------------------------------------------
# Step 5: Show CONTENT_ENCRYPTION_HEADER constant
# ---------------------------------------------------------------------------

print("\n=== Step 5: Protocol Constant ===\n")

print(f"  CONTENT_ENCRYPTION_HEADER = {CONTENT_ENCRYPTION_HEADER!r}")
print()
print("  When this header is present in an AgentMessage, the body field")
print("  contains an EncryptedBody. Receivers must decrypt before")
print("  processing the inner body_type payload.")
