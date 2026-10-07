"""
05 — Body Type Schemas (23 typed message bodies)

Demonstrates typed validation for all protocol body types.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/05_body_schemas.py
"""

from ampro import validate_body
from pydantic import ValidationError

# --- Valid body types ---
print("=== Valid Body Types ===\n")

bodies = [
    ("message", {"text": "Hello, world!"}),
    ("task.create", {"description": "Find me a hotel in Paris", "priority": "high"}),
    ("task.quote", {"task_id": "t-1", "estimated_cost_usd": 0.50, "expires_at": "2026-04-09T12:00:00Z"}),
    ("task.escalate", {"task_id": "t-1", "escalate_to": "sender_human", "reason": "Need human approval"}),
    ("task.complete", {"task_id": "t-1", "result": {"hotel": "Grand Hotel", "price": 250}}),
    ("task.error", {"reason": "processing_error", "retry_eligible": True, "retry_after_seconds": 30}),
    ("task.reject", {"task_id": "t-1", "reason": "insufficient_trust", "detail": "EXTERNAL tier cannot delegate"}),
    ("data.erasure_request", {"subject_id": "user-123", "subject_proof": "signed", "scope": "all", "reason": "user_request", "deadline": "2026-05-09T00:00:00Z"}),
]

for body_type, body in bodies:
    result = validate_body(body_type, body)
    name = type(result).__name__
    print(f"  {body_type:25s} → {name}")

# --- Invalid body (caught by schema) ---
print("\n=== Invalid Body (ValidationError) ===\n")
try:
    validate_body("task.create", {})  # Missing required 'description'
except ValidationError as e:
    print(f"  task.create with empty body: {e.error_count()} validation error(s)")
    for err in e.errors():
        print(f"    - {err['loc']}: {err['msg']}")

# --- Unknown body type (passthrough) ---
print("\n=== Extension Body Type (Passthrough) ===\n")
result = validate_body("com.mycorp.custom_action", {"anything": "goes"})
print(f"  com.mycorp.custom_action → {type(result).__name__}: {result}")

# --- Escalation targets ---
print("\n=== Escalation Targets ===\n")
for target in ["sender_human", "local_human", "specific"]:
    body = validate_body("task.escalate", {
        "task_id": "t-1",
        "escalate_to": target,
        "target": "agent://manager@corp.example.com" if target == "specific" else None,
        "reason": "Need help",
    })
    print(f"  escalate_to: {body.escalate_to}")
