"""
Agent Protocol — Per-Sender Rate Limiter.

In-memory sliding window rate limiter per spec Sections 3.13.1, 4.4.
Returns rate limit info for X-RateLimit-* response headers.

All internal timing uses ``time.monotonic()`` to prevent clock manipulation
attacks (NTP adjustments, DST changes, manual clock setting). The only
exception is ``RateLimitInfo.reset`` which uses ``time.time()`` because it
is a Unix epoch timestamp exposed via HTTP ``X-RateLimit-Reset`` headers.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

from ampro.security.rate_limit import RateLimitInfo


@runtime_checkable
class RateLimiterBackend(Protocol):
    """Per-key request budget.

    :class:`RateLimiter` is the per-process default; behind a load
    balancer use a shared implementation such as
    :class:`ampro.stores.redis.RedisRateLimiter`, otherwise every worker
    grants its own full budget.
    """

    def check(self, sender: str) -> tuple[bool, RateLimitInfo]:
        """Count one request for *sender*; ``(allowed, info)``."""
        ...


class RateLimiter:
    """Per-sender sliding window rate limiter."""

    def __init__(self, rpm: int = 60, window_seconds: int = 60, max_senders: int = 100_000):
        if rpm <= 0:
            raise ValueError("rpm must be > 0")
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be > 0 — a non-positive window disables "
                "rate limiting because every prior request is immediately stale."
            )
        if max_senders <= 0:
            raise ValueError("max_senders must be > 0")
        self._rpm = rpm
        self._window = window_seconds
        self._max_senders = max_senders
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, sender: str) -> tuple[bool, RateLimitInfo]:
        """
        Check if sender is within rate limit.
        Returns (allowed, info). If not allowed, caller should return 429.

        Fail-closed when the sender table is full of still-in-window
        entries: the new sender is denied rather than displacing existing
        quota state. This prevents attackers from flooding throwaway
        sender IDs to clear legitimate senders' counters.
        """
        with self._lock:
            now = time.monotonic()
            # reset_at is a Unix epoch timestamp for the X-RateLimit-Reset HTTP
            # header, so it intentionally uses time.time() (wall-clock).
            # All other timing in this method uses time.monotonic().
            reset_at = int(time.time()) + self._window

            # Make room for a new sender only by dropping fully-stale entries.
            # If every slot is still in-window, REFUSE the new sender — never
            # silently displace another sender's accounting.
            if sender not in self._requests and len(self._requests) >= self._max_senders:
                self._evict_stale_senders()
                if len(self._requests) >= self._max_senders:
                    return False, RateLimitInfo(
                        limit=self._rpm, remaining=0, reset=reset_at,
                    )

            requests = self._requests.setdefault(sender, [])
            # Prune old requests
            requests[:] = [t for t in requests if now - t < self._window]
            # Hard cap per-sender list to bound memory: we never need more
            # than rpm entries within the window (anything beyond that is
            # already over-limit).
            if len(requests) > self._rpm:
                del requests[: len(requests) - self._rpm]

            remaining = max(0, self._rpm - len(requests))
            info = RateLimitInfo(limit=self._rpm, remaining=remaining, reset=reset_at)

            if len(requests) >= self._rpm:
                return False, info

            requests.append(now)
            info.remaining = max(0, self._rpm - len(requests))
            return True, info

    def _evict_stale_senders(self) -> None:
        """Evict stale senders and enforce *max_senders* bound.

        Two-phase eviction:
        1. Remove every sender whose **entire** request list is older than
           the current window (they will never count toward any future check).
        2. If the dict is *still* over ``max_senders``, evict the oldest
           senders (by most-recent-request timestamp) until we are at the
           limit.  This is deterministic (stalest-first) so an attacker
           cannot survive eviction by luck.
        """
        now = time.monotonic()

        # --- Phase 1: evict fully-stale senders ---
        stale_keys = [
            sender
            for sender, timestamps in self._requests.items()
            if not timestamps or (now - max(timestamps)) >= self._window
        ]
        for key in stale_keys:
            del self._requests[key]

        # --- Phase 2: hard-cap enforcement ---
        if len(self._requests) <= self._max_senders:
            return

        import heapq

        evict_count = len(self._requests) - self._max_senders
        # nsmallest by newest-request time → stalest senders first
        stalest = heapq.nsmallest(
            evict_count,
            self._requests.items(),
            key=lambda item: max(item[1]) if item[1] else 0.0,
        )
        for sender, _ in stalest:
            del self._requests[sender]

    def sender_count(self) -> int:
        """Number of senders currently tracked."""
        with self._lock:
            return len(self._requests)
