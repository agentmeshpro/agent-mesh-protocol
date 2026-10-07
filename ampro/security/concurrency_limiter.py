"""
Agent Protocol — Per-Sender Concurrency Limiter.

Tracks active tasks per sender. Single sender cannot consume
more than 50% of max_concurrent_tasks per spec Section 3.13.1.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class ConcurrencyBackend(Protocol):
    """Leased concurrency slots per sender plus a global cap.

    :class:`ConcurrencyLimiter` is the per-process default;
    :class:`ampro.stores.redis.RedisConcurrencyLimiter` enforces the caps
    across every worker.
    """

    def acquire(self, sender: str) -> bool: ...

    def release(self, sender: str) -> None: ...

    def can_accept(self, sender: str) -> bool: ...

    def sender_active(self, sender: str) -> int: ...


class ConcurrencyLimiter:
    """Per-sender concurrent task limiter with leased slots.

    Each :meth:`acquire` returns a lease that auto-expires after
    ``slot_ttl_seconds`` so a caller that forgets to ``release`` (or
    crashes) does not permanently hold a slot. Every :meth:`acquire`
    sweeps expired leases first, so the limiter is self-healing under
    normal traffic without a separate reaper thread.
    """

    def __init__(
        self,
        max_total: int = 50,
        per_sender_pct: float = 0.5,
        slot_ttl_seconds: float = 600.0,
    ):
        if max_total <= 0:
            raise ValueError("max_total must be > 0")
        if not (0.0 < per_sender_pct <= 1.0):
            raise ValueError("per_sender_pct must be in (0, 1]")
        self._max_total = max_total
        self._per_sender_max = max(1, int(max_total * per_sender_pct))
        self._slot_ttl = float(slot_ttl_seconds)
        # Active leases: {sender: [acquired_monotonic_ts, ...]}.
        # The list length is the active count; values are used for TTL.
        self._active: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sweep_unlocked(self) -> None:
        """Drop expired leases. Called under the lock."""
        if self._slot_ttl <= 0:
            return
        now = time.monotonic()
        cutoff = now - self._slot_ttl
        empty: list[str] = []
        for sender, leases in self._active.items():
            leases[:] = [t for t in leases if t >= cutoff]
            if not leases:
                empty.append(sender)
        for sender in empty:
            del self._active[sender]

    def _total_unlocked(self) -> int:
        return sum(len(v) for v in self._active.values())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def total_active(self) -> int:
        with self._lock:
            self._sweep_unlocked()
            return self._total_unlocked()

    def can_accept(self, sender: str) -> bool:
        with self._lock:
            self._sweep_unlocked()
            if self._total_unlocked() >= self._max_total:
                return False
            sender_count = len(self._active.get(sender, []))
            return sender_count < self._per_sender_max

    def acquire(self, sender: str) -> bool:
        with self._lock:
            self._sweep_unlocked()
            if self._total_unlocked() >= self._max_total:
                return False
            leases = self._active.setdefault(sender, [])
            if len(leases) >= self._per_sender_max:
                return False
            leases.append(time.monotonic())
            return True

    def release(self, sender: str) -> None:
        with self._lock:
            leases = self._active.get(sender)
            if not leases:
                return
            leases.pop()
            if not leases:
                self._active.pop(sender, None)

    def sender_active(self, sender: str) -> int:
        with self._lock:
            self._sweep_unlocked()
            return len(self._active.get(sender, []))
