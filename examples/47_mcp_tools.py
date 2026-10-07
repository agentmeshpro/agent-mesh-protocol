"""
47 — MCP: expose an AMP agent's tools to Claude, Cursor and other MCP hosts

An AMPI agent's @agent.tool functions become Model Context Protocol tools,
and its task.create handler becomes one extra tool, `amp_task`.  The same
process keeps serving AMP on /agent/message; MCP lives on /mcp.

  @agent.tool(name, *, description=None, input_schema=None, scopes=())
      The input JSON Schema is derived from the type hints; `ctx` is
      skipped and receives the AMPContext (ctx.protocol == "mcp").

This script runs entirely in-process (no sockets): it mounts the MCP
adapter, talks to it with ampro's own MCP client over an ASGI transport,
then registers the remote tools into a second agent — the "consume" side.

Serve it for real (loopback only by default):

    ampro-server examples.47_mcp_tools:agent --protocols amp,mcp --port 8000

and point an MCP host at http://127.0.0.1:8000/mcp, e.g. Claude Code:

    claude mcp add --transport http travel http://127.0.0.1:8000/mcp

Run this demo:
    python examples/47_mcp_tools.py
"""
from __future__ import annotations

import asyncio

import httpx

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage
from ampro.interop.mcp import MCPAdapter, MCPToolSource
from ampro.server.core import AgentServer

agent = AgentApp(
    agent_id="agent://travel.example.com",
    endpoint="http://127.0.0.1:8000/agent/message",
    capabilities=["messaging", "tools"],
)

FARES = {("LIS", "OPO"): 49, ("LIS", "MAD"): 89, ("OPO", "MAD"): 99}


@agent.tool("fare_quote")
async def fare_quote(origin: str, destination: str, passengers: int = 1, ctx: AMPContext | None = None) -> dict:
    """Quote an economy fare in EUR between two IATA airport codes."""
    base = FARES.get((origin.upper(), destination.upper())) or FARES.get(
        (destination.upper(), origin.upper())
    )
    if base is None:
        return {"available": False}
    return {"available": True, "total_eur": base * passengers, "via": getattr(ctx, "protocol", "amp")}


@agent.tool(
    "convert_currency",
    description="Convert an amount between EUR and USD.",
    input_schema={
        "type": "object",
        "properties": {
            "amount": {"type": "number", "minimum": 0},
            "to": {"type": "string", "enum": ["EUR", "USD"]},
        },
        "required": ["amount", "to"],
        "additionalProperties": False,
    },
)
def convert_currency(amount: float, to: str) -> dict:
    rate = 1.08 if to == "USD" else 1 / 1.08
    return {"amount": round(amount * rate, 2), "currency": to}


@agent.tool("cancel_booking", scopes=["bookings:write"])
async def cancel_booking(reference: str) -> str:
    """Cancel a booking (requires the bookings:write scope)."""
    return f"cancelled {reference}"


@agent.on("task.create")
async def plan_trip(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Plan a short trip from a natural-language request."""
    return {"plan": f"Itinerary for: {msg.body['description']}", "requested_via": ctx.headers.get("Protocol")}


def build_server() -> AgentServer:
    server = AgentServer.from_app(agent)
    # No authenticator: fine on loopback.  Before exposing beyond
    # 127.0.0.1, pass authenticators=[...] and require_auth=True (or give the
    # server a SecurityPolicy.production(...); for_server inherits it).
    server.mount(MCPAdapter.for_server(server))
    return server


async def main() -> None:
    server = build_server()
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()))

    async with http, MCPToolSource("http://127.0.0.1:8000/mcp", http_client=http) as mcp:
        print(f"negotiated MCP {mcp.protocol_version} with {mcp.server_info['name']}")
        for tool in await mcp.list_tools():
            print(f"  tool {tool['name']:<17} {tool.get('description', '').splitlines()[0][:60]}")
        # cancel_booking is not listed: the anonymous caller lacks its scope.

        quote = await mcp.call_tool("fare_quote", {"origin": "LIS", "destination": "OPO", "passengers": 2})
        print("fare_quote       ->", quote["structuredContent"])

        bad = await mcp.call_tool("fare_quote", {"origin": "LIS"})
        print("missing argument ->", bad["content"][0]["text"])

        task = await mcp.call_tool("amp_task", {"description": "two days in Porto"})
        print("amp_task         ->", task["structuredContent"])

        # Consume: register the remote tools into another agent.
        concierge = AgentApp("agent://concierge.example.com", "http://127.0.0.1:9000/agent/message")
        names = await mcp.register_into(concierge, prefix="travel.")
        print("registered       ->", names)
        usd = await concierge.tools["travel.convert_currency"](amount=100, to="USD")
        print("proxy call       ->", usd)


if __name__ == "__main__":
    asyncio.run(main())
