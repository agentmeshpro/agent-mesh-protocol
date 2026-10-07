"""
46 — Serve an AMP agent over Google A2A 1.0

One AgentApp, two wire protocols: native AMP (POST /agent/message) and
A2A 1.0 (HTTP+JSON under /a2a, JSON-RPC at POST /a2a, card at
/.well-known/agent-card.json).  Handlers are written once against AMP;
the adapter translates A2A messages to ``task.create`` / ``task.response``
and maps results back to A2A Messages and Tasks.

This script talks to the agent in-process (httpx ASGI transport), so it
needs no network:

  1. fetch the A2A agent card;
  2. send a message, get a Message back;
  3. start a task that needs input (INPUT_REQUIRED), answer it, get COMPLETED;
  4. trigger AUTH_REQUIRED from a handler with ``raise AuthRequired(...)``;
  5. send AMP metadata through the AMP extension.

Serve it for real with:
    ampro-server examples.46_a2a_agent:agent --protocols amp,a2a --port 8000
(the CLI mounts a default adapter; build the server as below to pass options)
"""
from __future__ import annotations

import asyncio

import httpx

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage
from ampro.interop.a2a import (
    AMP_EXTENSION_URI,
    A2AAdapter,
    A2AClient,
    AuthRequired,
    Principal,
    Task,
    TaskState,
)
from ampro.server import AgentServer
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

agent = AgentApp(agent_id="@travel", endpoint="https://travel.example")


@agent.on("task.create")
async def plan(msg: AgentMessage, ctx: AMPContext):
    """Plan trips and answer travel questions."""
    text = msg.body["text"]
    if text.startswith("book"):
        return {"body_type": "task.input_required",
                "body": {"task_id": msg.body["task_id"], "reason": "destination",
                         "prompt": "Where would you like to go?"}}
    if text.startswith("refund"):
        if "bookings:refund" not in ctx.scopes:
            raise AuthRequired(["bookings:refund"], "https://travel.example/consent",
                               message="I need permission to issue refunds.")
        return "Refund issued."
    where = ctx.jurisdiction or "anywhere"
    return f"[{ctx.protocol} from {ctx.sender_address}, jurisdiction {where}] You said: {text}"


@agent.on("task.response")
async def answer(msg: AgentMessage, ctx: AMPContext):
    return {"body_type": "task.complete",
            "body": {"task_id": msg.body["task_id"],
                     "result": {"booked": msg.body["text"]}}}


class DemoBearer:
    """Toy authenticator: ``Authorization: Bearer demo-<name>``."""

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        header = request.header("authorization") or ""
        if not header.startswith("Bearer demo-"):
            return None
        name = header.removeprefix("Bearer demo-")
        return Principal(id=f"user://{name}", trust_tier=TrustTier.VERIFIED,
                         scopes=frozenset(), auth_method="demo")


server = AgentServer.from_app(agent)
server.mount(A2AAdapter.for_server(server, authenticators=[DemoBearer()],
                                   description="Books trips (demo)"))
asgi = server.asgi()


async def main() -> None:
    transport = httpx.ASGITransport(app=asgi)
    async with httpx.AsyncClient(transport=transport, base_url="https://travel.example") as http:
        client = A2AClient("https://travel.example", http_client=http, auth="demo-alice")

        card = await client.fetch_card()
        print("card:", card.name, [i.protocol_binding for i in card.supported_interfaces])

        reply = await client.send_message("hello")
        print("message:", reply.parts[0].text)

        task = await client.send_message("book a trip")
        assert isinstance(task, Task) and task.status.state == TaskState.INPUT_REQUIRED
        print("task needs input:", task.status.message.parts[0].text)
        done = await client.send_message("Lisbon", task_id=task.id, context_id=task.context_id)
        print("task:", done.status.state.value, done.artifacts[0].parts[0].data)

        auth = await client.send_message("refund my booking")
        print("auth:", auth.status.state.value, auth.metadata)

        reply = await client.send_message("hi again", amp={"jurisdiction": "EU"})
        print("amp ext:", reply.parts[0].text, "| activated:", sorted(client.activated_extensions))
        print("reply trace id:", reply.metadata[AMP_EXTENSION_URI]["traceId"])


if __name__ == "__main__":
    asyncio.run(main())
