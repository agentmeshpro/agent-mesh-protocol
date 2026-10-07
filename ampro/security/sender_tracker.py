"""
Agent Protocol — Sender Tracker (Poison Message Protection).

Tracks processing failures per sender. After 3 failures in 5 minutes,
sender is throttled (1 req/min for 15 min). Continued failures → blocked 1 hour.

Spec ref: Sections 3.10, 7.8

All timing uses ``time.monotonic()`` to prevent clock manipulation attacks.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Protocol, runtime_checkable


class SenderState(str, Enum):
    NORMAL = "normal"
    THROTTLED = "throttled"
    BLOCKED = "blocked"


@runtime_checkable
class SenderTrackerBackend(Protocol):
    """Poison-message escalation state per sender.

    :class:`SenderTracker` is the per-process default;
    :class:`ampro.stores.redis.RedisSenderTracker` shares it so a sender
    cannot spread failures over several workers to stay unthrottled.
    """

    def get_state(self, sender: str) -> SenderState: ...

    def record_failure(self, sender: str) -> SenderState: ...

    def record_success(self, sender: str) -> None: ...

    def is_allowed(self, sender: str) -> bool: ...


class SenderTracker:
    """Track sender failures and apply escalating restrictions."""

    def __init__(
        self,
        failure_threshold: int = 3,
        failure_window: int = 300,
        throttle_duration: int = 900,
        block_duration: int = 3600,
        max_senders: int = 100_000,
    ):
        self._threshold = failure_threshold
        self._window = failure_window
        self._throttle_dur = throttle_duration
        self._block_dur = block_duration
        self._max_senders = max_senders
        self._failures: dict[str, list[float]] = {}
        self._state: dict[str, tuple[SenderState, float]] = {}
        self._lock = threading.Lock()

    def _get_state_unlocked(self, sender: str) -> SenderState:
        """Get current state for a sender (no lock — internal use only)."""
        entry = self._state.get(sender)
        if entry is None:
            return SenderState.NORMAL
        state, expires_at = entry
        if time.monotonic() > expires_at:
            del self._state[sender]
            self._failures.pop(sender, None)
            return SenderState.NORMAL
        return state

    def get_state(self, sender: str) -> SenderState:
        """Get current state for a sender."""
        with self._lock:
            return self._get_state_unlocked(sender)

    def record_failure(self, sender: str) -> SenderState:
        """Record a processing failure. Returns new state."""
        with self._lock:
            now = time.monotonic()
            current = self._get_state_unlocked(sender)

            if current == SenderState.BLOCKED:
                return SenderState.BLOCKED

            if current == SenderState.THROTTLED:
                self._state[sender] = (SenderState.BLOCKED, now + self._block_dur)
                return SenderState.BLOCKED

            failures = self._failures.setdefault(sender, [])
            failures[:] = [t for t in failures if now - t < self._window]
            failures.append(now)

            if len(failures) >= self._threshold:
                self._state[sender] = (SenderState.THROTTLED, now + self._throttle_dur)
                return SenderState.THROTTLED

            self._evict_oldest_senders()
            return SenderState.NORMAL

    def _evict_oldest_senders(self) -> None:
        """Evict oldest failure entries when over max_senders limit."""
        if len(self._failures) <= self._max_senders:
            return
        # Find senders with the oldest last-failure timestamp and evict them
        senders_by_age = sorted(
            self._failures.items(),
            key=lambda item: item[1][-1] if item[1] else 0,
        )
        evict_count = len(self._failures) - int(self._max_senders * 0.9)
        for sender, _ in senders_by_age[:evict_count]:
            del self._failures[sender]
            self._state.pop(sender, None)

    def record_success(self, sender: str) -> None:
        """Record successful processing — decays failures, never resets.

        Each success drops the OLDEST recorded failure. An attacker that
        alternates 2 failures + 1 success previously stayed NORMAL forever
        because any success wiped the failure list. Now successes only chip
        away at the count, so a sustained poison pattern still escalates.
        """
        with self._lock:
            failures = self._failures.get(sender)
            if not failures:
                return
            failures.pop(0)
            if not failures:
                self._failures.pop(sender, None)

    def is_allowed(self, sender: str) -> bool:
        """Check if sender is allowed to send messages."""
        with self._lock:
            state = self._get_state_unlocked(sender)
            return state == SenderState.NORMAL
