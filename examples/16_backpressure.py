"""
16 — Streaming Backpressure

Demonstrates flow control for SSE streams. A server emits events,
the client ACKs processed batches, the server pauses when the client
falls behind, and the client signals it is ready to resume.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/16_backpressure.py
"""

from datetime import datetime, timezone

from ampro import (
    StreamingEvent,
    StreamingEventType,
    StreamAckEvent,
    StreamPauseEvent,
    StreamResumeEvent,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLIENT_BUFFER_CAPACITY = 5   # Client can buffer 5 events before falling behind
SERVER_PAUSE_THRESHOLD = 3   # Server pauses if client is 3+ events behind

print("=== Streaming Event Types ===\n")

print("  Data events:")
for t in [StreamingEventType.THINKING, StreamingEventType.TOOL_CALL,
          StreamingEventType.TOOL_RESULT, StreamingEventType.TEXT_DELTA]:
    print(f"    {t.value}")

print("  Flow control:")
for t in [StreamingEventType.STREAM_ACK, StreamingEventType.STREAM_PAUSE,
          StreamingEventType.STREAM_RESUME]:
    print(f"    {t.value}")

print("  Lifecycle:")
for t in [StreamingEventType.HEARTBEAT, StreamingEventType.DONE]:
    print(f"    {t.value}")

# ---------------------------------------------------------------------------
# Simulate: Server emits events, client processes them
# ---------------------------------------------------------------------------

print(f"\n=== Stream Simulation (buffer={CLIENT_BUFFER_CAPACITY}, pause_threshold={SERVER_PAUSE_THRESHOLD}) ===\n")

# Server state
server_seq = 0
server_paused = False
last_acked_seq = 0

# Simulated event plan: (event_type, description)
event_plan = [
    (StreamingEventType.THINKING, "Analyzing request..."),
    (StreamingEventType.TOOL_CALL, "Calling metric_collector"),
    (StreamingEventType.TOOL_RESULT, "Received 1,200 data points"),
    (StreamingEventType.TEXT_DELTA, "Processing batch 1/3"),
    (StreamingEventType.TEXT_DELTA, "Processing batch 2/3"),
    # Client ACKs here
    (StreamingEventType.TEXT_DELTA, "Processing batch 3/3"),
    (StreamingEventType.TOOL_CALL, "Calling aggregator"),
    (StreamingEventType.TOOL_RESULT, "Aggregation complete"),
    (StreamingEventType.TEXT_DELTA, "Formatting results"),
    (StreamingEventType.TEXT_DELTA, "Adding summary table"),
    # Client falls behind here — server pauses
    (StreamingEventType.TEXT_DELTA, "Final paragraph"),
    (StreamingEventType.DONE, "Stream complete"),
]


def emit_event(event_type: StreamingEventType, description: str) -> StreamingEvent:
    """Server emits a streaming event."""
    global server_seq
    server_seq += 1
    event = StreamingEvent(
        type=event_type,
        data={"description": description},
        seq=server_seq,
    )
    return event


def client_ack(up_to_seq: int) -> StreamAckEvent:
    """Client acknowledges processed events."""
    return StreamAckEvent(
        last_seq=up_to_seq,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# Run the simulation
client_processed = 0

for i, (etype, desc) in enumerate(event_plan):
    # Check if server should pause
    gap = server_seq - last_acked_seq
    if gap >= SERVER_PAUSE_THRESHOLD and not server_paused and server_seq > 0:
        pause = StreamPauseEvent(
            reason="client_behind",
            resume_after_ack=server_seq,
        )
        pause_event = StreamingEvent(
            type=StreamingEventType.STREAM_PAUSE,
            data=pause.model_dump(),
            seq=server_seq,  # Reuse current seq — pause is control, not data
        )
        server_paused = True
        print(f"  [SERVER] PAUSE — client is {gap} events behind (need ACK for seq {pause.resume_after_ack})")
        print(f"           SSE: {pause_event.to_sse().strip()[:80]}...")

        # Client catches up and sends ACK + resume
        last_acked_seq = server_seq
        client_processed = server_seq
        ack = client_ack(last_acked_seq)
        print(f"  [CLIENT] ACK seq={ack.last_seq}")

        resume = StreamResumeEvent(
            from_seq=last_acked_seq + 1,
            buffer_capacity=CLIENT_BUFFER_CAPACITY,
        )
        resume_event = StreamingEvent(
            type=StreamingEventType.STREAM_RESUME,
            data=resume.model_dump(),
            seq=0,  # Client-sent events use seq=0
        )
        server_paused = False
        print(f"  [CLIENT] RESUME from seq={resume.from_seq} (buffer={resume.buffer_capacity})")
        print()

    # Emit the event
    event = emit_event(etype, desc)
    sse_preview = event.to_sse().strip().replace("\n", " | ")
    if len(sse_preview) > 80:
        sse_preview = sse_preview[:77] + "..."
    print(f"  [SERVER] seq={event.seq:2d} {event.type.value:15s} {desc}")

    # Client ACKs every 5 events
    if event.seq % CLIENT_BUFFER_CAPACITY == 0 and event.seq > 0:
        last_acked_seq = event.seq
        client_processed = event.seq
        ack = client_ack(last_acked_seq)
        print(f"  [CLIENT] ACK seq={ack.last_seq}")
        print()

# Final ACK
if last_acked_seq < server_seq:
    ack = client_ack(server_seq)
    print(f"  [CLIENT] ACK seq={ack.last_seq} (final)")

# ---------------------------------------------------------------------------
# SSE format examples
# ---------------------------------------------------------------------------

print(f"\n=== SSE Wire Format Examples ===\n")

examples = [
    StreamingEvent(
        type=StreamingEventType.TEXT_DELTA,
        data={"description": "Hello, world"},
        id="evt-001",
        seq=1,
    ),
    StreamingEvent(
        type=StreamingEventType.STREAM_PAUSE,
        data=StreamPauseEvent(reason="buffer_full", resume_after_ack=10).model_dump(),
        seq=10,
    ),
    StreamingEvent(
        type=StreamingEventType.STREAM_RESUME,
        data=StreamResumeEvent(from_seq=11, buffer_capacity=20).model_dump(),
        seq=0,
    ),
    StreamingEvent(
        type=StreamingEventType.DONE,
        data={},
        seq=12,
    ),
]

for ex in examples:
    print(f"--- {ex.type.value} (seq={ex.seq}) ---")
    for line in ex.to_sse().strip().split("\n"):
        print(f"  {line}")
    print()
