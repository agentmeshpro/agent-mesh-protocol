"""
Agent Protocol — Stream Channels.

Multiplexing multiple logical streams on a single SSE connection.
Each channel is identified by a channel_id and can be independently
opened, used, and closed.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

# Per-session cap on simultaneously open stream channels. Keeps a single
# client from exhausting server memory / file-descriptor budgets by
# opening unbounded multiplexed streams.
MAX_CHANNELS_PER_SESSION = 16


class ChannelQuotaExceededError(Exception):
    """Raised when opening a channel would exceed the per-session limit."""

    def __init__(self, session_id: str, limit: int):
        self.session_id = session_id
        self.limit = limit
        super().__init__(
            f"Session {session_id} already has {limit} channels open; "
            f"MAX_CHANNELS_PER_SESSION={MAX_CHANNELS_PER_SESSION}"
        )


@runtime_checkable
class ChannelRegistryBackend(Protocol):
    """Open-channel accounting per session (quota enforcement).

    :class:`ChannelRegistry` is per-process; a session whose SSE
    connections land on several workers needs a shared implementation
    (e.g. :class:`ampro.stores.redis.RedisChannelRegistry`) for the cap to
    hold globally.
    """

    def register_channel(self, session_id: str, channel_id: str) -> None: ...

    def release_channel(self, session_id: str, channel_id: str) -> None: ...

    def count(self, session_id: str) -> int: ...


class ChannelRegistry:
    """Tracks open channels per session and enforces the per-session cap.

    Thread-safe — all mutations are serialised on an internal lock.
    """

    def __init__(self, max_per_session: int = MAX_CHANNELS_PER_SESSION):
        self._max_per_session = max_per_session
        self._channels: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def register_channel(self, session_id: str, channel_id: str) -> None:
        """Record that *channel_id* is open on *session_id*.

        Raises:
            ChannelQuotaExceededError: If the session is already at the limit.
        """
        with self._lock:
            open_set = self._channels.setdefault(session_id, set())
            if channel_id in open_set:
                return
            if len(open_set) >= self._max_per_session:
                raise ChannelQuotaExceededError(session_id, self._max_per_session)
            open_set.add(channel_id)

    def release_channel(self, session_id: str, channel_id: str) -> None:
        """Mark *channel_id* closed on *session_id* (idempotent)."""
        with self._lock:
            open_set = self._channels.get(session_id)
            if not open_set:
                return
            open_set.discard(channel_id)
            if not open_set:
                self._channels.pop(session_id, None)

    def count(self, session_id: str) -> int:
        """Return the number of open channels for *session_id*."""
        with self._lock:
            return len(self._channels.get(session_id, ()))


class StreamChannel(BaseModel):
    """A single logical stream multiplexed on one SSE connection."""

    channel_id: str = Field(description="Unique channel identifier")
    task_id: str | None = Field(
        default=None,
        description="Task this channel is associated with",
    )
    created_at: str = Field(description="ISO-8601 timestamp when channel was opened")

    model_config = {"extra": "ignore"}


class StreamChannelOpenEvent(BaseModel):
    """Event emitted when a new stream channel is opened."""

    channel_id: str = Field(description="Channel being opened")
    task_id: str | None = Field(
        default=None,
        description="Task this channel serves",
    )
    created_at: str = Field(description="ISO-8601 timestamp")

    model_config = {"extra": "ignore"}


class StreamChannelCloseEvent(BaseModel):
    """Event emitted when a stream channel is closed."""

    channel_id: str = Field(description="Channel being closed")
    reason: str = Field(
        default="complete",
        description="Reason for closing (complete, error, timeout)",
    )

    model_config = {"extra": "ignore"}
