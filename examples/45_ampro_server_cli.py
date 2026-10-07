"""
45 — Running an AMPI agent via the `ampro-server` CLI

`ampro-server` is the reference CLI entry point. It takes a
``module:attribute`` string, imports the module, and serves the
`AgentApp` it finds.

Run:
    ampro-server examples.45_ampro_server_cli:agent --port 8000

Probe:
    curl http://localhost:8000/.well-known/agent.json
    curl -X POST http://localhost:8000/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://caller.example.com",
           "recipient":"agent://cli-demo.example.com",
           "body_type":"task.create",
           "body":{"name":"world"},
           "headers":{"Protocol-Version":"1.0.0"}}'

This file has no ``if __name__ == "__main__"`` block. The CLI is
responsible for lifecycle — the module only exposes ``agent``.
"""
from __future__ import annotations

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage

agent = AgentApp(
    agent_id="agent://cli-demo.example.com",
    endpoint="http://localhost:8000/agent/message",
)


@agent.on("task.create")
async def greet(msg: AgentMessage, ctx: AMPContext) -> dict:
    name = (msg.body or {}).get("name", "world")
    return {"greeting": f"hello, {name}"}
