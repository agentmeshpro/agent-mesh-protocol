"""
38 — Client Streaming (SSE)

Stream Server-Sent Events from an AMP agent task. The stream()
function handles reconnection with exponential backoff and
Last-Event-ID resumption automatically.

Run:
    python examples/38_client_streaming.py
    (Requires a running AMP agent with streaming — see example 31)
"""

import asyncio

from ampro.client import AmpProtocolError, stream
from ampro.streaming.events import StreamingEventType

TARGET = "agent://analyst.example.com"
TASK_ID = "task-analysis-001"


async def main() -> None:
    print("=== Client: Streaming Events ===\n")

    # ── 1. Basic streaming ──────────────────────────────────────────
    print("1. Streaming events from a task\n")
    print(f"   Target:  {TARGET}")
    print(f"   Task ID: {TASK_ID}\n")

    try:
        async for event in stream(TARGET, task_id=TASK_ID, timeout=10.0):
            # Match on event type to handle each kind of update
            if event.type == StreamingEventType.THINKING:
                print(f"   [thinking] {event.data.get('text', '...')}")

            elif event.type == StreamingEventType.TEXT_DELTA:
                # Partial text — append to output
                print(f"   [delta] {event.data.get('text', '')}", end="")

            elif event.type == StreamingEventType.TOOL_CALL:
                tool = event.data.get("tool_name", "?")
                print(f"   [tool_call] {tool}({event.data.get('args', {})})")

            elif event.type == StreamingEventType.TOOL_RESULT:
                print(f"   [tool_result] {event.data.get('result', '')}")

            elif event.type == StreamingEventType.STATE_CHANGE:
                print(f"   [state] {event.data.get('from', '?')} -> {event.data.get('to', '?')}")

            elif event.type == StreamingEventType.ERROR:
                print(f"   [error] {event.data.get('message', 'unknown')}")

            elif event.type == StreamingEventType.DONE:
                print("   [done] Stream complete.")
                break

            elif event.type == StreamingEventType.HEARTBEAT:
                pass  # Keepalive — ignore silently

    except AmpProtocolError as exc:
        print("   Protocol error (expected — no server running):")
        print(f"     {exc.status_code}: {exc}")

    except Exception as exc:
        print("   Connection error (expected — no server running):")
        print(f"     {type(exc).__name__}: {exc}")

    # ── 2. Reconnection with Last-Event-ID ──────────────────────────
    print("\n2. Resuming a stream after disconnect\n")
    print("   # If the connection drops mid-stream, pass last_event_id")
    print("   # to resume from where you left off:")
    print()
    print("   async for event in stream(")
    print(f'       "{TARGET}",')
    print(f'       task_id="{TASK_ID}",')
    print('       last_event_id="evt-42",  # resume after event 42')
    print("   ):")
    print("       process(event)")
    print()
    print("   # stream() also retries automatically on connection drops")
    print("   # (up to 3 times with exponential backoff: 1s, 2s, 4s)")

    # ── 3. Event type reference ─────────────────────────────────────
    print("\n3. All 17 streaming event types\n")
    for et in StreamingEventType:
        print(f"   {et.value:25s} — {_event_description(et)}")


def _event_description(et: StreamingEventType) -> str:
    """One-line description of each event type."""
    descriptions = {
        StreamingEventType.THINKING: "Agent is reasoning",
        StreamingEventType.TOOL_CALL: "Agent is calling a tool",
        StreamingEventType.TOOL_RESULT: "Tool returned a result",
        StreamingEventType.TEXT_DELTA: "Partial text output",
        StreamingEventType.STATE_CHANGE: "Task status changed",
        StreamingEventType.AGENT_CALL: "Delegating to another agent",
        StreamingEventType.AGENT_RESULT: "Delegated agent returned",
        StreamingEventType.ERROR: "Something went wrong",
        StreamingEventType.HEARTBEAT: "Keepalive ping",
        StreamingEventType.DONE: "Stream complete",
        StreamingEventType.STREAM_ACK: "Client acknowledges events",
        StreamingEventType.STREAM_PAUSE: "Server pauses the stream",
        StreamingEventType.STREAM_RESUME: "Client is ready for more",
        StreamingEventType.STREAM_CHANNEL_OPEN: "Open a logical channel",
        StreamingEventType.STREAM_CHANNEL_CLOSE: "Close a logical channel",
        StreamingEventType.STREAM_CHECKPOINT: "State snapshot for recovery",
        StreamingEventType.STREAM_AUTH_REFRESH: "Mid-stream token renewal",
    }
    return descriptions.get(et, "")


if __name__ == "__main__":
    asyncio.run(main())
