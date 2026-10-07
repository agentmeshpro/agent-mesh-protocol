"""
39 — Two Agents Talking

This one ACTUALLY WORKS. Starts an AgentServer, sends it a message
via httpx, and prints the full request/response cycle. No external
dependencies beyond ampro + fastapi + uvicorn.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git fastapi uvicorn
    python examples/39_two_agents_talking.py
"""

# requires: fastapi, uvicorn  (tests/test_examples_run.py skips this example if missing)
import asyncio
import json
import threading
import time

import httpx

from ampro import AgentMessage
from ampro.server import AgentServer


# ---------------------------------------------------------------------------
def _free_port() -> int:
    """Pick an unused loopback port so the example never collides."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


PORT = _free_port()
BASE_URL = f"http://127.0.0.1:{PORT}"

# Agent A: "Echo" server — listens on a free loopback port
# ---------------------------------------------------------------------------

echo_server = AgentServer(
    agent_id="agent://echo.example.com",
    endpoint=f"{BASE_URL}/agent/message",
)


@echo_server.on("message")
def handle_message(msg: AgentMessage) -> dict:
    """Echo the message back with a greeting."""
    text = ""
    if isinstance(msg.body, dict):
        text = msg.body.get("text", "")
    return {
        "sender": echo_server.agent_id,
        "recipient": msg.sender,
        "body_type": "message",
        "body": {"text": f"Hello! You said: {text}"},
        "headers": {"In-Reply-To": msg.id},
    }


@echo_server.on("task.create")
def handle_task(msg: AgentMessage) -> dict:
    """Accept a task and return a result immediately."""
    description = ""
    if isinstance(msg.body, dict):
        description = msg.body.get("description", "")
    return {
        "sender": echo_server.agent_id,
        "recipient": msg.sender,
        "body_type": "task.complete",
        "body": {
            "task_id": msg.id,
            "result": {"answer": f"Completed: {description}"},
        },
        "headers": {"In-Reply-To": msg.id},
    }


# ---------------------------------------------------------------------------
# Agent B: "Client" — sends messages via httpx
# ---------------------------------------------------------------------------

CLIENT_ID = "agent://client.example.com"


def wait_for_health(url: str, retries: int = 60, delay: float = 0.25) -> bool:
    """Poll the health endpoint until the server is ready."""
    for _ in range(retries):
        try:
            resp = httpx.get(f"{url}/agent/health", timeout=2.0)
            if resp.status_code == 200:
                return True
        except httpx.ConnectError:
            pass
        time.sleep(delay)
    return False


async def run_client() -> None:
    """Send messages to the echo server and print results."""

    # ── 1. Discover the agent ───────────────────────────────────────
    print("\n--- Step 1: Discover agent.json ---\n")

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/.well-known/agent.json")
        agent_json = resp.json()

    print(f"  Protocol:    {agent_json.get('protocol_version')}")
    print(f"  Identifiers: {agent_json.get('identifiers')}")
    print(f"  Endpoint:    {agent_json.get('endpoint')}")

    # ── 2. Check health ─────────────────────────────────────────────
    print("\n--- Step 2: Health check ---\n")

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/agent/health")
        health = resp.json()

    print(f"  Status:   {health.get('status')}")
    print(f"  Version:  {health.get('protocol_version')}")
    print(f"  Uptime:   {health.get('uptime_seconds')}s")

    # ── 3. Send a message ───────────────────────────────────────────
    print("\n--- Step 3: Send a message ---\n")

    msg = AgentMessage(
        sender=CLIENT_ID,
        recipient=echo_server.agent_id,
        body_type="message",
        body={"text": "What is the weather like?"},
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/agent/message",
            json=msg.model_dump(mode="json"),
            headers={"Content-Type": "application/json"},
        )
        reply_data = resp.json()

    reply = AgentMessage.model_validate(reply_data)
    print(f"  Sent:     {msg.body}")
    print(f"  Received: {reply.body}")
    print(f"  From:     {reply_data.get('sender')}")
    print(f"  Reply-To: {reply_data.get('headers', {}).get('In-Reply-To')}")

    # ── 4. Send a task ──────────────────────────────────────────────
    print("\n--- Step 4: Send a task ---\n")

    task_msg = AgentMessage(
        sender=CLIENT_ID,
        recipient=echo_server.agent_id,
        body_type="task.create",
        body={"description": "Analyze quarterly report"},
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/agent/message",
            json=task_msg.model_dump(mode="json"),
            headers={"Content-Type": "application/json"},
        )
        task_reply = resp.json()

    print(f"  Task:     {task_msg.body}")
    print(f"  Reply:    {task_reply.get('body_type')}")
    print(f"  Result:   {task_reply.get('body', {}).get('result')}")

    # ── 5. Invalid body type ────────────────────────────────────────
    print("\n--- Step 5: Unhandled body type ---\n")

    bad_msg = AgentMessage(
        sender=CLIENT_ID,
        recipient=echo_server.agent_id,
        body_type="unknown.type",
        body={"data": "test"},
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/agent/message",
            json=bad_msg.model_dump(mode="json"),
            headers={"Content-Type": "application/json"},
        )

    print(f"  Status:   {resp.status_code}")
    print(f"  Error:    {resp.json().get('title', resp.json())}")


def main() -> None:
    print("=== Two Agents Talking ===")
    print(f"\n  Server: {echo_server.agent_id}")
    print(f"  Client: {CLIENT_ID}")

    # Start the server in a background thread
    server_thread = threading.Thread(
        target=echo_server.run,
        kwargs={"port": PORT},
        daemon=True,
    )
    server_thread.start()

    # Wait for the server to be ready
    if not wait_for_health(BASE_URL):
        print("\n  ERROR: Server did not start in time.")
        raise SystemExit(1)

    print(f"\n  Server ready at {BASE_URL}")

    # Run the client
    asyncio.run(run_client())

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
