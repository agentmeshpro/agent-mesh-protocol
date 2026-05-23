"""
Agent Protocol — Message Deduplication Store.

In-memory dedup with TTL-based expiry. A persistent-store-backed version
can be swapped in via the DedupStore protocol.

All timing uses ``time.monotonic()`` to prevent clock manipulation attacks.
"""

from __future__ import annotations

import asyncio
import time
from typing import Protocol


class DedupStore(Protocol):
    async def is_duplicate(self, message_id: str) -> bool: ...
    async def mark_seen(self, message_id: str) -> None: ...


class InMemoryDedupStore:
    def __init__(self, window_seconds: int = 300, max_size: int = 100_000):
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be > 0 — non-positive window disables dedup."
            )
        if max_size <= 0:
            raise ValueError("max_size must be > 0")
        self._window = window_seconds
        self._max_size = max_size
        self._seen: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _cleanup(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._seen.items() if now - v > self._window]
        for k in expired:
            del self._seen[k]

    def _make_room(self) -> bool:
        """Drop only expired entries; return True if space exists for one more."""
        if len(self._seen) < self._max_size:
            return True
        now = time.monotonic()
        expired = [k for k, v in self._seen.items() if now - v > self._window]
        for k in expired:
            del self._seen[k]
        return len(self._seen) < self._max_size

    async def is_duplicate(self, message_id: str) -> bool:
        """Return True if message_id was already seen.

        Fail-closed when the cache is full of still-in-window IDs: returns
        True (treats as duplicate) rather than evicting a valid entry that
        would reopen the dedup window. An attacker that floods unique IDs
        cannot use that flood to clear someone else's dedup record.
        """
        async with self._lock:
            self._cleanup()
            if message_id in self._seen:
                return True
            if not self._make_room():
                return True
            self._seen[message_id] = time.monotonic()
            return False

    async def mark_seen(self, message_id: str) -> None:
        async with self._lock:
            self._seen[message_id] = time.monotonic()
