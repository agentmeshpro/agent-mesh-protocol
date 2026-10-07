"""
33 — AMP Server with Authorization

Demonstrates trust-aware message handling. The server inspects the
Authorization header to determine the caller's auth method, maps it
to a trust tier, and returns different responses depending on trust.

Key point: trust resolution is YOUR handler's job, not the server's.
The server routes messages; your handler decides what trust means.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git fastapi uvicorn
    python examples/33_server_with_auth.py

Test (no auth — external tier):
    curl -X POST http://localhost:8003/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://anon","recipient":"agent://secure.example.com","body_type":"message","body":{"text":"hello"}}'

Test (Bearer token — verified tier):
    curl -X POST http://localhost:8003/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://trusted","recipient":"agent://secure.example.com","body_type":"message","body":{"text":"hello"},"headers":{"Authorization":"Bearer eyJ0b2tlbiI6ImRlbW8ifQ"}}'

Test (API key — verified tier):
    curl -X POST http://localhost:8003/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://partner","recipient":"agent://secure.example.com","body_type":"message","body":{"text":"hello"},"headers":{"Authorization":"ApiKey sk_live_demo123"}}'
"""

from ampro.server import AgentServer
from ampro import AgentMessage
from ampro.identity.auth_methods import parse_authorization

server = AgentServer(
    agent_id="agent://secure.example.com",
    endpoint="http://localhost:8003",
)

# ── Trust tier mapping ──────────────────────────────────────────────

# ParsedAuth.max_trust_tier() returns the ceiling for each method:
#   JWT    → "owner"
#   DID    → "verified"
#   API_KEY → "verified"
#   mTLS   → "verified"
#   none   → "external"

# Full data — only available to verified or higher trust callers.
FULL_RESPONSE = {
    "status": "operational",
    "cpu_percent": 42.3,
    "memory_mb": 1024,
    "active_tasks": 7,
    "queue_depth": 23,
}

# Restricted data — safe to share with external callers.
RESTRICTED_RESPONSE = {
    "status": "operational",
    "note": "Authenticate for full metrics. Supported: Bearer, ApiKey, DID.",
}


@server.on("message")
def handle_message(msg: AgentMessage) -> dict:
    """Return full or restricted data based on the caller's trust tier."""
    # Step 1: Extract the Authorization header from the message.
    auth_header = msg.headers.get("Authorization")

    # Step 2: Parse it into method + token.
    auth = parse_authorization(auth_header)
    tier = auth.max_trust_tier()

    # Step 3: Gate the response on trust tier.
    if tier in ("owner", "verified"):
        data = FULL_RESPONSE
    else:
        data = RESTRICTED_RESPONSE

    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "message",
        "body": {
            "text": f"Trust tier: {tier} (auth method: {auth.method.value})",
            "data": data,
        },
        "headers": {
            "In-Reply-To": msg.id,
            "Trust-Tier": tier,
        },
    }


if __name__ == "__main__":
    print("=== AMP Server with Authorization ===\n")
    print(f"Agent: {server.agent_id}")
    print(f"Auth methods supported: Bearer (JWT), ApiKey, DID\n")
    print("Trust tier mapping:")
    print("  Bearer token → owner  (full access)")
    print("  ApiKey        → verified (full access)")
    print("  DID proof     → verified (full access)")
    print("  No auth       → external (restricted)\n")
    print("Try without auth (external):\n")
    print("  curl -X POST http://localhost:8003/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://anon\",\"recipient\":\"agent://secure.example.com\",\"body_type\":\"message\",\"body\":{\"text\":\"hello\"}}'")
    print()
    print("Try with Bearer (owner):\n")
    print("  curl -X POST http://localhost:8003/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://trusted\",\"recipient\":\"agent://secure.example.com\",\"body_type\":\"message\",\"body\":{\"text\":\"hello\"},\"headers\":{\"Authorization\":\"Bearer eyJ0b2tlbiI6ImRlbW8ifQ\"}}'")
    print()
    server.run(port=8003)
