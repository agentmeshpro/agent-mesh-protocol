"""
Agent Protocol — StreamBus.

Per-task event bus backed by asyncio.Queue with ring-buffer replay
for SSE reconnection support.  Each task_id gets its own StreamBus
registered in a global ``_active_streams`` dict.

Public API
----------
- ``get_or_create_stream(task_id)`` → ``StreamBus``
- ``cleanup_stream(task_id)``
- ``StreamBus.subscribe(subscriber_id)``
- ``StreamBus.emit(event)``
- ``StreamBus.events(subscriber_id)``  (async iterator, auth-gated)
- ``StreamBus.replay_from(last_event_id, subscriber_id=...)``  (auth-gated)
- ``StreamBus.close()``
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator

from ampro.streaming.events import StreamingEvent, StreamingEventType

# ---------------------------------------------------------------------------
# Ring buffer capacity — keeps the latest N events for replay
# ---------------------------------------------------------------------------
_RING_BUFFER_CAPACITY = 100

# Maximum number of active streams in the global registry.
# Prevents unbounded memory growth from leaked or abandoned streams.
MAX_ACTIVE_STREAMS = 10_000

# How long a stream may sit idle (no events emitted, no consumers) before
# the global registry is permitted to evict it under memory pressure. An
# idle stream past this cutoff is dropped to make room for a new one.
IDLE_STREAM_TTL_SECONDS = 300.0

# Sentinel used to signal the consumer that the stream is finished.
_SENTINEL = object()


class StreamBus:
    """Per-task event bus with async queue + ring-buffer replay."""

    def __init__(self, task_id: str, *, creator_id: str | None = None) -> None:
        self.task_id = task_id
        self._queue: asyncio.Queue[StreamingEvent | object] = asyncio.Queue(maxsize=1000)
        self._ring: deque[StreamingEvent] = deque(maxlen=_RING_BUFFER_CAPACITY)
        self._seq: int = 0  # monotonically increasing event id
        self._closed: bool = False
        self._dropped_count: int = 0
        self._authorized_subscribers: set[str] = set()
        # First caller to ``get_or_create_stream`` owns the task_id. Future
        # callers with a different creator_id get a different stream (the
        # registry rejects the lookup) so an attacker who pre-creates with
        # a guessable task_id cannot intercept events meant for someone else.
        self._creator_id: str | None = creator_id
        self._last_activity: float = time.monotonic()

    # ----- subscription -----

    def subscribe(self, subscriber_id: str) -> None:
        """Authorize *subscriber_id* to consume events from this bus.

        Must be called before ``events()`` or ``replay_from()`` to
        grant read access.
        """
        if not subscriber_id:
            raise ValueError("subscriber_id must be a non-empty string")
        self._authorized_subscribers.add(subscriber_id)

    def _check_authorized(self, subscriber_id: str) -> None:
        """Raise ``PermissionError`` if *subscriber_id* is not subscribed."""
        if subscriber_id not in self._authorized_subscribers:
            raise PermissionError(
                f"subscriber '{subscriber_id}' is not authorized on stream "
                f"'{self.task_id}'"
            )

    # ----- writing side -----

    def emit(self, event: StreamingEvent) -> None:
        """Assign a sequential ID, store in ring buffer, and enqueue."""
        if self._closed:
            return
        self._seq += 1
        # Stamp the event with an integer id (as string for SSE spec)
        event = event.model_copy(update={"id": str(self._seq), "seq": self._seq})
        self._ring.append(event)
        self._last_activity = time.monotonic()
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped_count += 1  # Track drops so consumers can detect gaps

    @property
    def creator_id(self) -> str | None:
        return self._creator_id

    @property
    def last_activity(self) -> float:
        return self._last_activity

    def close(self) -> None:
        """Emit a DONE event (if not already closed) and signal end of stream."""
        if self._closed:
            return
        self._closed = True
        # Emit a terminal DONE event
        done_event = StreamingEvent(
            type=StreamingEventType.DONE,
            data={"finish_reason": "stream_closed"},
        )
        self._seq += 1
        done_event = done_event.model_copy(update={"id": str(self._seq), "seq": self._seq})
        self._ring.append(done_event)
        self._queue.put_nowait(done_event)
        # Put sentinel so the async iterator exits
        self._queue.put_nowait(_SENTINEL)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def last_event_id(self) -> int:
        return self._seq

    @property
    def dropped_count(self) -> int:
        """Number of events dropped because the consumer queue was full."""
        return self._dropped_count

    # ----- reading side -----

    async def events(self, subscriber_id: str) -> AsyncIterator[StreamingEvent]:
        """Yield events as they arrive.  Stops when the bus is closed.

        Raises ``PermissionError`` if *subscriber_id* has not been
        registered via ``subscribe()``.
        """
        self._check_authorized(subscriber_id)
        while True:
            item = await self._queue.get()
            if item is _SENTINEL:
                return
            # item is a StreamingEvent at this point
            yield item  # type: ignore[misc]

    def replay_from(
        self, last_event_id: int, *, subscriber_id: str
    ) -> list[StreamingEvent]:
        """Return buffered events with id > ``last_event_id``.

        Used for SSE reconnection: the client sends ``Last-Event-ID``
        and the server replays everything that was emitted after that id.

        Raises ``PermissionError`` if *subscriber_id* has not been
        registered via ``subscribe()``.
        """
        self._check_authorized(subscriber_id)
        result: list[StreamingEvent] = []
        for ev in self._ring:
            ev_id = int(ev.id) if ev.id else 0
            if ev_id > last_event_id:
                result.append(ev)
        return result


# ---------------------------------------------------------------------------
# Global stream registry
# ---------------------------------------------------------------------------
_active_streams: dict[str, StreamBus] = {}


def _evict_idle_streams() -> int:
    """Drop streams that have been idle past ``IDLE_STREAM_TTL_SECONDS``.

    Returns the number of streams evicted. Closed streams are always
    evicted; live-but-idle streams only when they exceed the TTL.
    """
    now = time.monotonic()
    drop: list[str] = []
    for tid, bus in _active_streams.items():
        if bus.closed:
            drop.append(tid)
        elif now - bus.last_activity > IDLE_STREAM_TTL_SECONDS:
            drop.append(tid)
    for tid in drop:
        bus = _active_streams.pop(tid, None)
        if bus and not bus.closed:
            bus.close()
    return len(drop)


_REQUIRE_CREATOR_ID = False  # opt-in strict mode for production deployments


def set_require_creator_id(required: bool) -> None:
    """Toggle strict creator binding for the global stream registry.

    When True, every ``get_or_create_stream`` call MUST pass a non-empty
    ``creator_id``. Anonymous streams are rejected. Production deployments
    SHOULD enable this on startup; the default is False for backwards
    compatibility with fixtures and local-only callers.
    """
    global _REQUIRE_CREATOR_ID
    _REQUIRE_CREATOR_ID = required


def get_or_create_stream(task_id: str, *, creator_id: str | None = None) -> StreamBus:
    """Return the existing StreamBus for *task_id*, or create a new one.

    Security:
      * The first caller's ``creator_id`` is recorded on the bus. Subsequent
        ``get_or_create_stream`` calls for the same task_id from a DIFFERENT
        ``creator_id`` raise :class:`PermissionError`. This blocks the
        "task-id squat" attack where an attacker pre-creates a bus for a
        guessable task_id and then receives events from a legitimate creator.
      * If ``creator_id`` is None on either side the binding check is
        skipped (legacy path; emit a deprecation warning in callers).

    Memory:
      * When the registry is at ``MAX_ACTIVE_STREAMS`` an eviction sweep
        drops idle/closed streams first. If no room can be made, raises
        :class:`RuntimeError`.
    """
    if _REQUIRE_CREATOR_ID and not creator_id:
        raise PermissionError(
            "creator_id is required (strict mode enabled via set_require_creator_id)"
        )

    if task_id in _active_streams:
        bus = _active_streams[task_id]
        # Strict creator binding: any mismatch — including the case where
        # the original creator was anonymous (None) but a later caller
        # presents an identity, or vice-versa — is rejected. The squat
        # attack relied on the asymmetry where the attacker pre-created
        # anonymously and the legitimate caller later joined.
        if creator_id != bus.creator_id:
            raise PermissionError(
                f"task_id '{task_id}' is bound to a different creator"
            )
        return bus

    if len(_active_streams) >= MAX_ACTIVE_STREAMS:
        _evict_idle_streams()
        if len(_active_streams) >= MAX_ACTIVE_STREAMS:
            raise RuntimeError(
                f"Maximum active streams ({MAX_ACTIVE_STREAMS}) reached "
                f"and no idle streams to evict."
            )
    _active_streams[task_id] = StreamBus(task_id, creator_id=creator_id)
    return _active_streams[task_id]


def cleanup_stream(task_id: str) -> None:
    """Remove the StreamBus for *task_id* from the global registry."""
    bus = _active_streams.pop(task_id, None)
    if bus and not bus.closed:
        bus.close()
