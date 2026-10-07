"""
25 — Stream Multiplexing

Demonstrates opening two logical channels (ch-monitoring, ch-processing)
on a single SSE connection, sending events with different Stream-Channel
headers, and closing each channel independently.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/25_stream_multiplexing.py
"""

from datetime import datetime, timezone

from ampro import (
    AgentMessage,
    StreamingEvent,
    StreamingEventType,
    StreamChannelOpenEvent,
    StreamChannelCloseEvent,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SENDER = "agent://processor.example.com"
RECIPIENT = "agent://orchestrator.example.com"
SESSION_ID = "sess-mux-demo-001"

CHANNEL_MON = "ch-monitoring"
CHANNEL_PROC = "ch-processing"

now = datetime.now(timezone.utc).isoformat()

# ---------------------------------------------------------------------------
# Step 1: Open two channels on one connection
# ---------------------------------------------------------------------------

print("=== Step 1: Open Two Channels ===\n")

open_mon = StreamChannelOpenEvent(
    channel_id=CHANNEL_MON,
    task_id="task-health-check",
    created_at=now,
)

open_proc = StreamChannelOpenEvent(
    channel_id=CHANNEL_PROC,
    task_id="task-data-pipeline",
    created_at=now,
)

for ch_open in [open_mon, open_proc]:
    event = StreamingEvent(
        type=StreamingEventType.STREAM_CHANNEL_OPEN,
        data=ch_open.model_dump(),
        id=f"evt-open-{ch_open.channel_id}",
        seq=0,
    )
    print(f"  Channel: {ch_open.channel_id}")
    print(f"  Task:    {ch_open.task_id}")
    print(f"  SSE:")
    for line in event.to_sse().strip().split("\n"):
        print(f"    {line}")
    print()

# ---------------------------------------------------------------------------
# Step 2: Send events with Stream-Channel headers
# ---------------------------------------------------------------------------

print("=== Step 2: Events on Different Channels ===\n")

# Interleaved events on both channels
channel_events = [
    (CHANNEL_MON, StreamingEventType.TEXT_DELTA, {"text": "CPU usage: 42%"}, 1),
    (CHANNEL_PROC, StreamingEventType.THINKING, {"thought": "Analyzing dataset"}, 2),
    (CHANNEL_MON, StreamingEventType.TEXT_DELTA, {"text": "Memory: 3.2 GB / 8 GB"}, 3),
    (CHANNEL_PROC, StreamingEventType.TOOL_CALL, {"tool": "csv_parser", "args": {"path": "/data/input.csv"}}, 4),
    (CHANNEL_MON, StreamingEventType.TEXT_DELTA, {"text": "Disk I/O: 120 MB/s"}, 5),
    (CHANNEL_PROC, StreamingEventType.TOOL_RESULT, {"rows_parsed": 15000, "errors": 0}, 6),
    (CHANNEL_PROC, StreamingEventType.TEXT_DELTA, {"text": "Pipeline stage 1 complete"}, 7),
]

for channel_id, etype, data, seq in channel_events:
    # Build envelope with Stream-Channel header
    msg = AgentMessage(
        sender=SENDER,
        recipient=RECIPIENT,
        body_type="message",
        headers={
            "Protocol-Version": "0.1.7",
            "Session-Id": SESSION_ID,
            "Stream-Channel": channel_id,
        },
        body=data,
    )

    event = StreamingEvent(
        type=etype,
        data=data,
        id=f"evt-{seq:03d}",
        seq=seq,
    )

    tag = "MON " if channel_id == CHANNEL_MON else "PROC"
    print(f"  [{tag}] seq={event.seq} {event.type.value:15s} Stream-Channel: {channel_id}")

print()

# Show one full SSE frame with Stream-Channel in the envelope
print("  --- Full envelope example (seq=4, ch-processing) ---\n")

example_msg = AgentMessage(
    sender=SENDER,
    recipient=RECIPIENT,
    body_type="message",
    headers={
        "Protocol-Version": "0.1.7",
        "Session-Id": SESSION_ID,
        "Stream-Channel": CHANNEL_PROC,
    },
    body={"tool": "csv_parser", "args": {"path": "/data/input.csv"}},
)

example_event = StreamingEvent(
    type=StreamingEventType.TOOL_CALL,
    data={"tool": "csv_parser", "args": {"path": "/data/input.csv"}},
    id="evt-004",
    seq=4,
)

print(f"  Envelope headers:")
for k, v in example_msg.headers.items():
    print(f"    {k}: {v}")

print(f"\n  SSE frame:")
for line in example_event.to_sse().strip().split("\n"):
    print(f"    {line}")

# ---------------------------------------------------------------------------
# Step 3: Close each channel independently
# ---------------------------------------------------------------------------

print(f"\n=== Step 3: Close Channels Independently ===\n")

# Close monitoring channel first (normal completion)
close_mon = StreamChannelCloseEvent(
    channel_id=CHANNEL_MON,
    reason="complete",
)

close_mon_event = StreamingEvent(
    type=StreamingEventType.STREAM_CHANNEL_CLOSE,
    data=close_mon.model_dump(),
    id=f"evt-close-{CHANNEL_MON}",
    seq=8,
)

print(f"  Close {CHANNEL_MON}:")
print(f"    Reason: {close_mon.reason}")
print(f"    SSE:")
for line in close_mon_event.to_sse().strip().split("\n"):
    print(f"      {line}")

# Send one more event on the processing channel (monitoring is closed)
print(f"\n  (ch-monitoring is closed; ch-processing still active)")
print(f"  [PROC] seq=9  text_delta       Pipeline stage 2 complete")

# Close processing channel with error
close_proc = StreamChannelCloseEvent(
    channel_id=CHANNEL_PROC,
    reason="error",
)

close_proc_event = StreamingEvent(
    type=StreamingEventType.STREAM_CHANNEL_CLOSE,
    data=close_proc.model_dump(),
    id=f"evt-close-{CHANNEL_PROC}",
    seq=10,
)

print(f"\n  Close {CHANNEL_PROC}:")
print(f"    Reason: {close_proc.reason}")
print(f"    SSE:")
for line in close_proc_event.to_sse().strip().split("\n"):
    print(f"      {line}")

# ---------------------------------------------------------------------------
# Step 4: SSE wire format output for each event type
# ---------------------------------------------------------------------------

print(f"\n=== Step 4: SSE Wire Format Reference ===\n")

wire_examples = [
    (
        "Channel Open",
        StreamingEvent(
            type=StreamingEventType.STREAM_CHANNEL_OPEN,
            data=StreamChannelOpenEvent(
                channel_id="ch-analytics",
                task_id="task-report-gen",
                created_at="2026-04-09T12:00:00Z",
            ).model_dump(),
            id="evt-open-ch-analytics",
            seq=0,
        ),
    ),
    (
        "Data Event (on channel)",
        StreamingEvent(
            type=StreamingEventType.TEXT_DELTA,
            data={"text": "Processing row 500/1000"},
            id="evt-050",
            seq=50,
        ),
    ),
    (
        "Channel Close (complete)",
        StreamingEvent(
            type=StreamingEventType.STREAM_CHANNEL_CLOSE,
            data=StreamChannelCloseEvent(
                channel_id="ch-analytics",
                reason="complete",
            ).model_dump(),
            id="evt-close-ch-analytics",
            seq=51,
        ),
    ),
    (
        "Channel Close (error)",
        StreamingEvent(
            type=StreamingEventType.STREAM_CHANNEL_CLOSE,
            data=StreamChannelCloseEvent(
                channel_id="ch-ingest",
                reason="error",
            ).model_dump(),
            id="evt-close-ch-ingest",
            seq=99,
        ),
    ),
]

for label, evt in wire_examples:
    print(f"  --- {label} ---")
    for line in evt.to_sse().strip().split("\n"):
        print(f"  {line}")
    print()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("=== Summary ===\n")
print("  Stream multiplexing allows multiple logical channels on one SSE connection.")
print("  Each channel:")
print("    - Has a unique channel_id")
print("    - Can be associated with a task_id")
print("    - Uses the Stream-Channel header in message envelopes")
print("    - Is opened and closed independently")
print("    - Close reasons: complete, error, timeout")
