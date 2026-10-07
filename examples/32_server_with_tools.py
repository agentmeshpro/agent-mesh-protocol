"""
32 — AMP Server with Tools

An agent that exposes tools via the protocol. Clients send task.create
messages with a tool_name in the context, and the server dispatches
to the matching tool function.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git fastapi uvicorn
    python examples/32_server_with_tools.py

Test:
    curl -X POST http://localhost:8002/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://caller","recipient":"agent://tools.example.com","body_type":"task.create","body":{"description":"multiply","context":{"tool_name":"multiply","a":6,"b":7}}}'
"""

import os

from ampro import AgentMessage
from ampro.server import AgentServer

server = AgentServer(
    agent_id="agent://tools.example.com",
    endpoint="http://localhost:8002",
)

# ── Tool registry ───────────────────────────────────────────────────

TOOLS: dict[str, dict] = {
    "multiply": {
        "description": "Multiply two numbers",
        "parameters": {"a": "number", "b": "number"},
    },
    "reverse_text": {
        "description": "Reverse a string",
        "parameters": {"text": "string"},
    },
}


def _run_multiply(ctx: dict) -> dict:
    a = ctx.get("a", 0)
    b = ctx.get("b", 0)
    return {"product": a * b}


def _run_reverse_text(ctx: dict) -> dict:
    text = ctx.get("text", "")
    return {"reversed": text[::-1]}


_DISPATCH = {
    "multiply": _run_multiply,
    "reverse_text": _run_reverse_text,
}

# ── Handlers ────────────────────────────────────────────────────────


@server.on("task.create")
def handle_task(msg: AgentMessage) -> dict:
    """Dispatch to the requested tool and return task.complete."""
    context = {}
    if isinstance(msg.body, dict):
        context = msg.body.get("context", {}) or {}

    tool_name = context.get("tool_name", "")
    fn = _DISPATCH.get(tool_name)

    if fn is None:
        return {
            "sender": server.agent_id,
            "recipient": msg.sender,
            "body_type": "task.error",
            "body": {
                "reason": "unprocessable",
                "detail": f"Unknown tool: {tool_name!r}. Available: {list(TOOLS)}",
                "retry_eligible": False,
            },
            "headers": {"In-Reply-To": msg.id},
        }

    result = fn(context)
    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "task.complete",
        "body": {"task_id": msg.id, "result": result},
        "headers": {"In-Reply-To": msg.id},
    }


if __name__ == "__main__":
    print("=== AMP Server with Tools ===\n")
    print(f"Agent: {server.agent_id}")
    print("Tools:")
    for name, spec in TOOLS.items():
        print(f"  - {name}: {spec['description']}")
    print("\nTry:\n")
    print("  curl -X POST http://localhost:8002/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://caller\",\"recipient\":\"agent://tools.example.com\",\"body_type\":\"task.create\",\"body\":{\"description\":\"multiply\",\"context\":{\"tool_name\":\"multiply\",\"a\":6,\"b\":7}}}'")
    print()
    if os.environ.get("AMPRO_EXAMPLE_NO_SERVE"):
        # Smoke-test mode (tests/test_examples_run.py): everything above ran,
        # but don't block on a long-running server.
        print("AMPRO_EXAMPLE_NO_SERVE is set; not starting the server.")
    else:
        server.run(port=8002)
