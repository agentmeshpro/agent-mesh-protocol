"""
26 — Stream Checkpoints and Reconnection

Demonstrates periodic state snapshots for SSE reconnection. Emits events
with checkpoints at seq 5 and seq 15, simulates a disconnect at seq 18,
and shows how to resume from the last checkpoint. Also demonstrates
mid-stream auth token refresh.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/26_stream_checkpoint.py
"""

from datetime import datetime, timezone

from ampro import (
    StreamingEvent,
    StreamingEventType,
    StreamCheckpointEvent,
    StreamAuthRefreshEvent,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts(offset_seconds: int = 0) -> str:
    """Generate an ISO-8601 timestamp with an optional offset."""
    from datetime import timedelta
    return (datetime(2026, 4, 9, 12, 0, 0, tzinfo=timezone.utc)
            + timedelta(seconds=offset_seconds)).isoformat()


def emit(seq: int, etype: StreamingEventType, data: dict) -> StreamingEvent:
    """Create a streaming event with the given sequence number."""
    return StreamingEvent(
        type=etype,
        data=data,
        id=f"evt-{seq:03d}",
        seq=seq,
    )

# ---------------------------------------------------------------------------
# Step 1: Emit 10 events, checkpoint at seq 5
# ---------------------------------------------------------------------------

print("=== Step 1: First Batch (seq 1-10, checkpoint at seq 5) ===\n")

events_batch_1 = [
    (1, StreamingEventType.THINKING, {"thought": "Analyzing input parameters"}),
    (2, StreamingEventType.TOOL_CALL, {"tool": "data_loader", "args": {"source": "db"}}),
    (3, StreamingEventType.TOOL_RESULT, {"rows": 500, "columns": 12}),
    (4, StreamingEventType.TEXT_DELTA, {"text": "Loaded 500 rows from database"}),
    (5, StreamingEventType.TEXT_DELTA, {"text": "Starting aggregation phase"}),
]

for seq, etype, data in events_batch_1:
    event = emit(seq, etype, data)
    print(f"  seq={event.seq:2d}  {event.type.value:15s}")

# Checkpoint at seq 5
checkpoint_1 = StreamCheckpointEvent(
    checkpoint_id="chk-001",
    seq=5,
    state_snapshot={
        "rows_loaded": 500,
        "phase": "aggregation",
        "cursor": "batch-1-complete",
    },
    timestamp=ts(5),
)

checkpoint_1_event = StreamingEvent(
    type=StreamingEventType.STREAM_CHECKPOINT,
    data=checkpoint_1.model_dump(),
    id="evt-chk-001",
    seq=5,
)

print(f"\n  >>> CHECKPOINT at seq={checkpoint_1.seq}")
print(f"      checkpoint_id: {checkpoint_1.checkpoint_id}")
print(f"      state_snapshot: {checkpoint_1.state_snapshot}")
print(f"      SSE:")
for line in checkpoint_1_event.to_sse().strip().split("\n"):
    print(f"        {line}")

# Continue with events 6-10
events_6_10 = [
    (6, StreamingEventType.THINKING, {"thought": "Computing averages"}),
    (7, StreamingEventType.TOOL_CALL, {"tool": "aggregator", "args": {"op": "mean"}}),
    (8, StreamingEventType.TOOL_RESULT, {"mean_value": 42.7, "std_dev": 3.1}),
    (9, StreamingEventType.TEXT_DELTA, {"text": "Average computed: 42.7"}),
    (10, StreamingEventType.TEXT_DELTA, {"text": "Standard deviation: 3.1"}),
]

print()
for seq, etype, data in events_6_10:
    event = emit(seq, etype, data)
    print(f"  seq={event.seq:2d}  {event.type.value:15s}")

# ---------------------------------------------------------------------------
# Step 2: Emit 10 more events, checkpoint at seq 15
# ---------------------------------------------------------------------------

print(f"\n=== Step 2: Second Batch (seq 11-20, checkpoint at seq 15) ===\n")

events_batch_2a = [
    (11, StreamingEventType.THINKING, {"thought": "Generating visualization"}),
    (12, StreamingEventType.TOOL_CALL, {"tool": "chart_builder", "args": {"type": "bar"}}),
    (13, StreamingEventType.TOOL_RESULT, {"chart_url": "/charts/abc123.png"}),
    (14, StreamingEventType.TEXT_DELTA, {"text": "Chart generated successfully"}),
    (15, StreamingEventType.TEXT_DELTA, {"text": "Preparing final summary"}),
]

for seq, etype, data in events_batch_2a:
    event = emit(seq, etype, data)
    print(f"  seq={event.seq:2d}  {event.type.value:15s}")

# Checkpoint at seq 15
checkpoint_2 = StreamCheckpointEvent(
    checkpoint_id="chk-002",
    seq=15,
    state_snapshot={
        "rows_loaded": 500,
        "phase": "summary",
        "cursor": "batch-2-complete",
        "aggregation": {"mean": 42.7, "std_dev": 3.1},
        "chart_url": "/charts/abc123.png",
    },
    timestamp=ts(15),
)

checkpoint_2_event = StreamingEvent(
    type=StreamingEventType.STREAM_CHECKPOINT,
    data=checkpoint_2.model_dump(),
    id="evt-chk-002",
    seq=15,
)

print(f"\n  >>> CHECKPOINT at seq={checkpoint_2.seq}")
print(f"      checkpoint_id: {checkpoint_2.checkpoint_id}")
print(f"      state_snapshot: {checkpoint_2.state_snapshot}")

# Continue with events 16-18 (disconnect at 18)
events_16_18 = [
    (16, StreamingEventType.TEXT_DELTA, {"text": "Summary section 1 of 3"}),
    (17, StreamingEventType.TEXT_DELTA, {"text": "Summary section 2 of 3"}),
    (18, StreamingEventType.TEXT_DELTA, {"text": "Summary section 3 of 3"}),
]

print()
for seq, etype, data in events_16_18:
    event = emit(seq, etype, data)
    print(f"  seq={event.seq:2d}  {event.type.value:15s}")

# ---------------------------------------------------------------------------
# Step 3: Simulate disconnect at seq 18
# ---------------------------------------------------------------------------

print(f"\n=== Step 3: Disconnect at seq 18 ===\n")

print(f"  Client received up to seq=18")
print(f"  Connection lost!")
print(f"")
print(f"  Last checkpoint: chk-002 at seq=15")
print(f"  Events lost:     seq 16, 17, 18 (3 events)")
print(f"  Recovery:        Resume from checkpoint chk-002 (seq 15)")

# ---------------------------------------------------------------------------
# Step 4: Resume from checkpoint at seq 15
# ---------------------------------------------------------------------------

print(f"\n=== Step 4: Resume from Checkpoint (seq 15) ===\n")

print(f"  Client reconnects with Last-Event-ID: evt-chk-002")
print(f"  Server restores state from checkpoint chk-002:")
print(f"")
for key, value in checkpoint_2.state_snapshot.items():
    print(f"    {key}: {value}")

print(f"\n  Server replays events from seq 16:")
print()

for seq, etype, data in events_16_18:
    event = emit(seq, etype, data)
    print(f"  [REPLAY] seq={event.seq:2d}  {event.type.value:15s}")

# Continue with remaining events
events_remaining = [
    (19, StreamingEventType.TEXT_DELTA, {"text": "Conclusion drafted"}),
    (20, StreamingEventType.DONE, {}),
]

print()
for seq, etype, data in events_remaining:
    event = emit(seq, etype, data)
    print(f"  [NEW]    seq={event.seq:2d}  {event.type.value:15s}")

# ---------------------------------------------------------------------------
# Step 5: Mid-stream auth token refresh
# ---------------------------------------------------------------------------

print(f"\n=== Step 5: Mid-Stream Auth Token Refresh ===\n")

auth_refresh = StreamAuthRefreshEvent(
    method="jwt",
    token="eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZ2VudDovL3Byb2Nlc3Nvci5leGFtcGxlLmNvbSIsImV4cCI6MTc0NDI0MDAwMH0.SIGNATURE",
    expires_at="2026-04-09T14:00:00Z",
)

auth_event = StreamingEvent(
    type=StreamingEventType.STREAM_AUTH_REFRESH,
    data=auth_refresh.model_dump(),
    id="evt-auth-refresh-001",
    seq=12,  # Can arrive between any data events
)

print(f"  Auth refresh injected at seq=12 (between data events):")
print(f"    Method:     {auth_refresh.method}")
print(f"    Token:      {auth_refresh.token[:40]}...")
print(f"    Expires at: {auth_refresh.expires_at}")
print(f"\n  SSE frame:")
for line in auth_event.to_sse().strip().split("\n"):
    print(f"    {line}")

# ---------------------------------------------------------------------------
# SSE wire format: checkpoint event
# ---------------------------------------------------------------------------

print(f"\n=== SSE Wire Format: Checkpoint ===\n")

for label, chk_event in [("Checkpoint 1 (seq 5)", checkpoint_1_event),
                          ("Checkpoint 2 (seq 15)", checkpoint_2_event)]:
    print(f"  --- {label} ---")
    for line in chk_event.to_sse().strip().split("\n"):
        print(f"  {line}")
    print()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("=== Summary ===\n")
print("  Checkpoints provide periodic state snapshots on SSE streams.")
print("  On disconnect, clients resume from the last checkpoint:")
print(f"    1. Client reconnects with Last-Event-ID of the checkpoint")
print(f"    2. Server restores state_snapshot from that checkpoint")
print(f"    3. Server replays events from checkpoint seq + 1")
print(f"")
print(f"  StreamAuthRefreshEvent allows mid-stream token renewal")
print(f"  without breaking the connection.")
