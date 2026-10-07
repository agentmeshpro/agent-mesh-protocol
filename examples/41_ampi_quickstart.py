"""
41 — AMPI Quickstart (the one-liner demo)

The smallest possible AMPI agent. `AgentApp` is a declarative registry:
register handlers with `@agent.on(body_type)`, hand the app to a server,
done.

See also:
  - 42_ampi_with_tools.py      — tools, middleware, session-start hooks
  - 43_ampi_testing.py         — unit-testing handlers without HTTP
  - 44_ampi_ctx_methods.py     — AMPContext (send/emit/discover/delegate)
  - 45_ampro_server_cli.py     — running an agent via `ampro-server`

Run:
    ampro-server examples.41_ampi_quickstart:agent --port 8000
"""
from __future__ import annotations

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage

agent = AgentApp(
    agent_id="agent://quickstart-bot.example.com",
    endpoint="http://localhost:8000/agent/message",
)


@agent.on("task.create")
async def echo(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Echo the incoming body back to the sender."""
    return {"echo": msg.body, "from": ctx.agent_address}
