"""
43 — AMPI: unit-testing handlers with TestServer

`TestServer` is the unit-test path for AMPI. No HTTP, no network —
just: build a synthetic AgentMessage, hand it to `server.send()`,
and assert on the handler's return value.

Because TestServer skips transport entirely, the same test works
against any AMPI implementation that honours the handler contract.

Run:
    python examples/43_ampi_testing.py
"""
from __future__ import annotations

import asyncio

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage
from ampro.server.test import TestServer

agent = AgentApp(
    agent_id="agent://tested-bot.example.com",
    endpoint="http://localhost:8000/agent/message",
)


@agent.on("task.create")
async def handle(msg: AgentMessage, ctx: AMPContext) -> dict:
    return {"ok": True, "echo": msg.body, "sender": ctx.sender_address}


async def run_test() -> bool:
    server = TestServer(agent)
    msg = AgentMessage(
        sender="agent://caller.example.com",
        recipient="agent://tested-bot.example.com",
        body_type="task.create",
        body={"question": "what is 2+2?"},
    )
    reply = await server.send(msg)
    assert reply["ok"] is True
    assert reply["echo"] == {"question": "what is 2+2?"}
    assert reply["sender"] == "agent://caller.example.com"
    return True


if __name__ == "__main__":
    try:
        asyncio.run(run_test())
        print("PASS")
    except AssertionError as exc:
        print(f"FAIL: {exc}")
