"""
37 — Client Session with 3-Phase Handshake

Demonstrates the full session lifecycle via the client SDK:
  1. connect() sends session.init with client_nonce
  2. Server replies session.established with binding_token
  3. Client sends session.confirm with binding_proof
  4. session.send() auto-attaches Session-Id and HMAC binding
  5. session.close() sends session.close

Run:
    python examples/37_client_with_handshake.py
    (Requires a running AMP agent — see example 31)
"""

import asyncio

from ampro.client import AmpProtocolError, connect, send
from ampro.client.session import Session

TARGET = "agent://planner.example.com"
SENDER = "agent://my-assistant.example.com"


async def main() -> None:
    print("=== Client: Session with Handshake ===\n")

    # ── 1. Using async with (recommended) ──────────────────────────
    print("1. Session via async with (auto-close)\n")
    print(f"   Target: {TARGET}")
    print(f"   Sender: {SENDER}\n")

    try:
        async with await connect(TARGET, sender=SENDER) as session:
            print(f"   Session ID:  {session.session_id}")

            # session.send() auto-attaches Session-Id + binding HMAC
            reply = await session.send(
                body={"text": "Plan a 3-day trip to Tokyo"},
                body_type="task.create",
            )
            print(f"   Reply type:  {reply.body_type}")
            print(f"   Reply body:  {reply.body}")

            # Send a follow-up within the same session
            reply2 = await session.send(
                body={"text": "Add budget constraints under $2000"},
                body_type="message",
                headers={"Priority": "high"},
            )
            print(f"   Follow-up:   {reply2.body}")

            # close() is called automatically by async with

    except AmpProtocolError as exc:
        print("   Protocol error (expected — no server running):")
        print(f"     {exc.status_code}: {exc}")

    except Exception as exc:
        print("   Connection error (expected — no server running):")
        print(f"     {type(exc).__name__}: {exc}")

    # ── 2. Manual session management ────────────────────────────────
    print("\n2. Manual session lifecycle\n")
    print("   # Establish the session")
    print("   session = await connect('agent://target.example.com',")
    print("                           sender='agent://me.example.com')")
    print()
    print("   # Send messages with automatic binding")
    print("   reply = await session.send({'q': 'hello'}, body_type='message')")
    print()
    print("   # Session properties")
    print("   print(session.session_id)   # 'sess-...'")
    print()
    print("   # Explicit close (sends session.close body type)")
    print("   await session.close()")

    # ── 3. What connect() does internally ───────────────────────────
    print("\n3. 3-phase handshake internals\n")
    print("   Phase 1 — session.init:")
    print("     Client generates client_nonce (64 hex chars)")
    print("     Sends body_type='session.init' with proposed capabilities")
    print()
    print("   Phase 2 — session.established:")
    print("     Server returns session_id, server_nonce, binding_token")
    print("     Client computes binding_proof = HMAC-SHA256(")
    print("       key=binding_token, msg=client_nonce + '\\x00' + server_nonce)")
    print()
    print("   Phase 3 — session.confirm:")
    print("     Client sends binding_proof back to server")
    print("     Server verifies proof → session is ACTIVE")

    # ── 4. Per-message binding ──────────────────────────────────────
    print("\n4. Per-message binding\n")
    print("   Every session.send() call automatically:")
    print("     - Adds 'Session-Id' header to the envelope")
    print("     - Computes HMAC(session_id + msg_id, binding_token)")
    print("     - Attaches 'Session-Binding' HTTP header")
    print("   This prevents session hijacking and replay attacks.")


if __name__ == "__main__":
    asyncio.run(main())
