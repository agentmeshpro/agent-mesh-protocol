"""
36 — Send a Message to an AMP Agent

The simplest client interaction — send one message, get one response.
Like httpx.post() but speaks the AMP envelope protocol.

Run:
    python examples/36_client_send_message.py
    (Requires a running AMP agent — see example 31)
"""

import asyncio

from ampro import AgentMessage
from ampro.client import AmpProtocolError, send

TARGET = "agent://weather.example.com"
SENDER = "agent://my-assistant.example.com"


async def main() -> None:
    print("=== Client: Send a Message ===\n")

    # ── 1. Simple send() ────────────────────────────────────────────
    # send() builds an AMP envelope, POSTs to /agent/message, returns
    # the response as an AgentMessage.
    print("1. Using ampro.client.send()\n")
    print(f"   Target: {TARGET}")
    print(f"   Sender: {SENDER}")

    try:
        reply: AgentMessage = await send(
            TARGET,
            body={"text": "What is the forecast for tomorrow?"},
            body_type="message",
            sender=SENDER,
            headers={"Priority": "normal", "Protocol-Version": "1.0.0"},
            timeout=10.0,
        )
        # If a server were running, we'd see the reply:
        print(f"   Reply body_type: {reply.body_type}")
        print(f"   Reply body: {reply.body}")

    except AmpProtocolError as exc:
        # RFC 7807 error — server returned a structured problem
        print("   Protocol error (expected — no server running):")
        print(f"     Status:  {exc.status_code}")
        print(f"     Type:    {exc.error_type}")
        if exc.retry_after:
            print(f"     Retry:   {exc.retry_after}s")

    except Exception as exc:
        # Connection refused, DNS failure, etc.
        print("   Connection error (expected — no server running):")
        print(f"     {type(exc).__name__}: {exc}")

    # ── 2. What send() does under the hood ──────────────────────────
    print("\n2. Equivalent raw httpx call\n")
    print("   import httpx")
    print("   from ampro import AgentMessage")
    print()
    print("   msg = AgentMessage(")
    print(f'       sender="{SENDER}",')
    print(f'       recipient="{TARGET}",')
    print('       body_type="message",')
    print('       body={"text": "What is the forecast?"},')
    print("   )")
    print()
    print("   async with httpx.AsyncClient() as client:")
    print("       resp = await client.post(")
    print('           "https://weather.example.com/agent/message",')
    print("           json=msg.model_dump(mode='json'),")
    print('           headers={"Content-Type": "application/json"},')
    print("       )")
    print("       reply = AgentMessage.model_validate(resp.json())")

    # ── 3. Error handling patterns ──────────────────────────────────
    print("\n3. Error handling patterns\n")
    print("   AmpProtocolError wraps RFC 7807 ProblemDetail:")
    print("     exc.status_code  → HTTP status (429, 503, ...)")
    print("     exc.error_type   → URN like 'urn:amp:error:rate-limited'")
    print("     exc.retry_after  → seconds to wait (or None)")
    print("     exc.problem      → full ProblemDetail model")


if __name__ == "__main__":
    asyncio.run(main())
