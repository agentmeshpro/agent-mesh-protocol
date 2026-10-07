"""
31 — Simple AMP Agent Server

The minimum viable AMP agent. Receives messages, responds.
Like Python's http.server — just enough to speak the protocol.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git fastapi uvicorn
    python examples/31_simple_server.py

Then in another terminal:
    curl http://localhost:8001/.well-known/agent.json
    curl http://localhost:8001/agent/health
    curl -X POST http://localhost:8001/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://client.example.com","recipient":"agent://simple.example.com","body_type":"message","body":{"text":"hello"}}'
"""

import os
from ampro.server import AgentServer
from ampro import AgentMessage

server = AgentServer(
    agent_id="agent://simple.example.com",
    endpoint="http://localhost:8001",
)


@server.on("message")
def handle_message(msg: AgentMessage) -> dict:
    """Echo the message text back to the sender."""
    text = ""
    if isinstance(msg.body, dict):
        text = msg.body.get("text", "")
    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "message",
        "body": {"text": f"Echo: {text}"},
        "headers": {"In-Reply-To": msg.id},
    }


@server.default
def fallback(msg: AgentMessage) -> dict:
    """Reject any body type we don't explicitly handle."""
    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "task.reject",
        "body": {
            "task_id": msg.id,
            "reason": "unprocessable",
            "detail": f"Unsupported body_type: {msg.body_type}",
        },
        "headers": {"In-Reply-To": msg.id},
    }


if __name__ == "__main__":
    print("=== Simple AMP Agent Server ===\n")
    print(f"Agent:    {server.agent_id}")
    print(f"Endpoint: {server.endpoint}\n")
    print("Try these in another terminal:\n")
    print("  curl http://localhost:8001/.well-known/agent.json")
    print("  curl http://localhost:8001/agent/health")
    print("  curl -X POST http://localhost:8001/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://client.example.com\",\"recipient\":\"agent://simple.example.com\",\"body_type\":\"message\",\"body\":{\"text\":\"hello\"}}'")
    print()
    if os.environ.get("AMPRO_EXAMPLE_NO_SERVE"):
        # Smoke-test mode (tests/test_examples_run.py): everything above ran,
        # but don't block on a long-running server.
        print("AMPRO_EXAMPLE_NO_SERVE is set; not starting the server.")
    else:
        server.run(port=8001)
