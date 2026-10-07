"""
01 — Minimum Viable Agent (Level 1: Messaging)

The simplest possible protocol-compliant agent.
30 lines. No framework dependency beyond Flask.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git flask
    python examples/01_minimum_viable_agent.py

Test:
    curl http://localhost:8000/.well-known/agent.json
    curl -X POST http://localhost:8000/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://tester.local","recipient":"agent://my-pi.local","body_type":"message","body":{"text":"hello"},"headers":{"Protocol-Version":"1.0.0"}}'
"""

from flask import Flask, request, jsonify
from uuid import uuid4

app = Flask(__name__)


@app.route("/.well-known/agent.json")
def agent_json():
    return jsonify({
        "protocol_version": "1.0.0",
        "identifiers": ["agent://my-pi.local"],
        "endpoint": "http://localhost:8000/agent/message",
        "capabilities": {"groups": ["messaging"], "level": 1},
        "constraints": {"max_concurrent_tasks": 1, "max_message_size_bytes": 65536},
        "security": {"auth_methods": [], "api_key_allowed": True},
        "ttl_seconds": 3600,
    })


@app.route("/agent/health")
def health():
    return jsonify({"status": "healthy", "protocol_version": "1.0.0"})


@app.route("/agent/message", methods=["POST"])
def message():
    msg = request.json
    return jsonify({
        "sender": "agent://my-pi.local",
        "recipient": msg["sender"],
        "id": str(uuid4()),
        "body_type": "task.response",
        "headers": {"Protocol-Version": "1.0.0", "In-Reply-To": msg["id"]},
        "body": {"text": f"Hello! You said: {msg.get('body', {}).get('text', '?')}"},
    })


if __name__ == "__main__":
    app.run(port=8000)
