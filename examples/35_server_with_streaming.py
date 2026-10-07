"""
35 — AMP Server with Streaming

Demonstrates streaming event patterns for long-running tasks. When a
task.create arrives, the handler emits a sequence of streaming events
(thinking, tool_call, tool_result, text_delta, done) through a StreamBus,
then returns a task.acknowledge response.

Note: Actual SSE delivery requires the framework adapter (FastAPI/Flask)
to iterate over the StreamBus and push events to the HTTP response.
This example shows the event emission pattern and prints the SSE output
that would be sent over the wire.

Run:
    pip install git+https://github.com/vesakri/agent-mesh-protocol.git fastapi uvicorn
    python examples/35_server_with_streaming.py

Test:
    curl -X POST http://localhost:8005/agent/message \
      -H "Content-Type: application/json" \
      -d '{"sender":"agent://caller","recipient":"agent://stream.example.com","body_type":"task.create","body":{"description":"analyze server logs"}}'
"""

import os
import asyncio
import uuid

from ampro.server import AgentServer
from ampro import AgentMessage
from ampro.streaming.events import StreamingEvent, StreamingEventType
from ampro.streaming.bus import StreamBus


server = AgentServer(
    agent_id="agent://stream.example.com",
    endpoint="http://localhost:8005",
)


def _build_event_sequence(task_id: str) -> list[StreamingEvent]:
    """Build a realistic sequence of streaming events for a task."""
    return [
        StreamingEvent(
            type=StreamingEventType.THINKING,
            data={"content": "Analyzing the request..."},
        ),
        StreamingEvent(
            type=StreamingEventType.TOOL_CALL,
            data={
                "tool_name": "log_parser",
                "arguments": {"source": "syslog", "lines": 500},
            },
        ),
        StreamingEvent(
            type=StreamingEventType.TOOL_RESULT,
            data={
                "tool_name": "log_parser",
                "result": {"error_count": 12, "warning_count": 47},
            },
        ),
        StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"content": "Found 12 errors and "},
        ),
        StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"content": "47 warnings in the last 500 log lines."},
        ),
        StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"content": " Most errors are connection timeouts."},
        ),
        StreamingEvent(
            type=StreamingEventType.STATE_CHANGE,
            data={"from": "working", "to": "completed"},
        ),
    ]


@server.on("task.create")
async def handle_task(msg: AgentMessage) -> dict:
    """Process a task by emitting streaming events, then return acknowledge."""
    task_id = f"task-{uuid.uuid4().hex[:12]}"

    # Create a StreamBus for this task and subscribe the server itself.
    bus = StreamBus(task_id)
    bus.subscribe("server")

    print(f"  [task] {task_id} — emitting streaming events\n")

    # Emit the event sequence.
    events = _build_event_sequence(task_id)
    for event in events:
        bus.emit(event)

    # Close the bus — this emits a DONE event automatically.
    bus.close()

    # Print what the SSE output would look like over the wire.
    print("  SSE output (what the client would receive):")
    print("  " + "-" * 50)
    for event in bus.replay_from(0, subscriber_id="server"):
        sse_text = event.to_sse()
        for line in sse_text.strip().split("\n"):
            print(f"  {line}")
        print()
    print("  " + "-" * 50)
    print(f"  Total events: {bus.last_event_id}")
    print()

    # Return a task.acknowledge — the client should connect to
    # GET /agent/stream?task_id=<id> for the real-time event feed.
    return {
        "sender": server.agent_id,
        "recipient": msg.sender,
        "body_type": "task.acknowledge",
        "body": {
            "task_id": task_id,
            "status": "streaming",
            "stream_url": f"{server.endpoint}/agent/stream?task_id={task_id}",
            "total_events": bus.last_event_id,
        },
        "headers": {"In-Reply-To": msg.id},
    }


if __name__ == "__main__":
    print("=== AMP Server with Streaming ===\n")
    print(f"Agent: {server.agent_id}")
    print(f"Streaming event types used:")
    print(f"  1. thinking     — agent reasoning")
    print(f"  2. tool_call    — invoking a tool")
    print(f"  3. tool_result  — tool returned data")
    print(f"  4. text_delta   — partial text output")
    print(f"  5. state_change — task status transition")
    print(f"  6. done         — stream complete (auto-emitted on close)\n")
    print("Try:\n")
    print("  curl -X POST http://localhost:8005/agent/message \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"sender\":\"agent://caller\",\"recipient\":\"agent://stream.example.com\",\"body_type\":\"task.create\",\"body\":{\"description\":\"analyze server logs\"}}'")
    print()
    if os.environ.get("AMPRO_EXAMPLE_NO_SERVE"):
        # Smoke-test mode (tests/test_examples_run.py): everything above ran,
        # but don't block on a long-running server.
        print("AMPRO_EXAMPLE_NO_SERVE is set; not starting the server.")
    else:
        server.run(port=8005)
