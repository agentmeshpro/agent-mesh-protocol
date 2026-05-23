"""
Agent Protocol — Nonce Tracker.

Tracks seen nonces to prevent replay attacks on sensitive operations.
In-memory with 1-hour sliding window per spec Section 3.4.

All timing uses ``time.monotonic()`` to prevent clock manipulation attacks.
"""

from __future__ import annotations

import threading
import time


class NonceTracker:
    """Track seen nonces with sliding window expiry."""

    def __init__(self, window_seconds: int = 3600, max_size: int = 100_000):
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be > 0 — a non-positive window disables "
                "replay protection because every nonce expires immediately."
            )
        if max_size <= 0:
            raise ValueError("max_size must be > 0")
        self._window = window_seconds
        self._max_size = max_size
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cleanup(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._seen.items() if now - v > self._window]
        for k in expired:
            del self._seen[k]

    def _make_room(self) -> bool:
        """Make room for one new entry without evicting still-fresh nonces.

        Returns True if there is now space (or already was), False if the
        cache is full of still-in-window entries and accepting the new
        nonce would require dropping one that is still within its replay
        protection window — which would reopen the replay window.

        Drops only expired entries. If after expiring there is still no
        room, returns False so the caller fails closed.
        """
        if len(self._seen) < self._max_size:
            return True
        now = time.monotonic()
        expired = [k for k, v in self._seen.items() if now - v > self._window]
        for k in expired:
            del self._seen[k]
        return len(self._seen) < self._max_size

    def is_replay(self, nonce: str) -> bool:
        """Check if nonce was already seen. Returns True if replay detected.

        When the tracker is full of still-in-window entries (an attacker
        flooded with unique nonces), this method REJECTS the new nonce as
        if it were a replay. That is fail-closed: we'd rather refuse a
        legitimate request than silently shrink the replay window by
        evicting a previously-recorded nonce.
        """
        with self._lock:
            self._cleanup()
            if nonce in self._seen:
                return True
            if not self._make_room():
                # Cache full of unexpired nonces. Fail-closed: treat the
                # incoming nonce as a replay rather than evict a real one.
                return True
            self._seen[nonce] = time.monotonic()
            return False

    def seen_count(self) -> int:
        """Number of nonces currently tracked."""
        with self._lock:
            self._cleanup()
            return len(self._seen)
