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

    def _make_room(self) -> None:
        """Make room for one new entry.

        Expired entries are dropped first. If the cache is still full of
        in-window entries, the OLDEST entry is evicted (dicts preserve
        insertion order). Denying every new nonce when full — the previous
        behaviour — let anyone who could get ~``max_size`` nonces recorded
        lock out all legitimate traffic. Callers such as
        :func:`ampro.security.rfc9421.verify_request` only record a nonce
        after the signature has verified and the request is inside its
        (much shorter) freshness window, so an attacker must hold a valid
        key to evict entries, and evicted nonces belong to signatures that
        the freshness check rejects anyway once ``max_size`` is sized for
        the request rate.
        """
        if len(self._seen) < self._max_size:
            return
        self._cleanup()
        while len(self._seen) >= self._max_size:
            oldest = next(iter(self._seen))
            del self._seen[oldest]

    def is_replay(self, nonce: str) -> bool:
        """Check if nonce was already seen. Returns True if replay detected.

        The nonce is recorded atomically when it is new. When the tracker
        is full, expired entries are dropped first and then the oldest
        entry is evicted, so a flood of unique nonces can never make the
        tracker reject every request.
        """
        with self._lock:
            self._cleanup()
            if nonce in self._seen:
                return True
            self._make_room()
            self._seen[nonce] = time.monotonic()
            return False

    def seen_count(self) -> int:
        """Number of nonces currently tracked."""
        with self._lock:
            self._cleanup()
            return len(self._seen)
