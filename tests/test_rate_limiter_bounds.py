"""Tests for RateLimiter memory bounds.

NOTE — behaviour changed in the v0.3.4 security patches: when the sender
table is full of still-in-window entries, the limiter now REFUSES new
senders rather than evicting an active one. The previous "evict oldest
active sender to make room" semantics let an attacker flood throwaway
sender IDs to clear legitimate senders' quotas. The current contract is
fail-closed under contention.
"""

from __future__ import annotations

import time

from ampro.security.rate_limiter import RateLimiter


class TestSenderTableBounds:
    """Verify the new fail-closed sender-table semantics."""

    def test_new_sender_rejected_when_table_full_of_active(self):
        """When max_senders is reached and every slot is still in-window,
        a new sender is denied (rather than displacing an existing one)."""
        max_s = 5
        limiter = RateLimiter(rpm=100, window_seconds=60, max_senders=max_s)

        # Fill exactly max_senders, all freshly active.
        for i in range(max_s):
            allowed, _ = limiter.check(f"sender-{i}")
            assert allowed

        # The (max_s+1)th sender must be denied — table is full of fresh entries.
        allowed, info = limiter.check("newcomer")
        assert allowed is False
        assert info.remaining == 0
        # Existing senders remain in the table.
        for i in range(max_s):
            assert f"sender-{i}" in limiter._requests
        assert "newcomer" not in limiter._requests

    def test_stale_senders_cleaned_up_to_make_room(self):
        """A sender whose entire request list has aged out of the window
        is evicted to make room for a new sender — but only stale entries
        are dropped, never in-window ones."""
        window = 2  # seconds
        max_s = 2
        limiter = RateLimiter(rpm=100, window_seconds=window, max_senders=max_s)

        # Inject a stale sender directly (timestamps older than window)
        ancient = time.monotonic() - window - 10
        limiter._requests["stale-sender"] = [ancient]
        # And one currently-active sender
        limiter.check("active-sender")

        # Now a new sender shows up. max_senders is reached, but one slot
        # holds a stale entry — that slot SHOULD be reclaimed.
        allowed, _ = limiter.check("newcomer")
        assert allowed
        assert "stale-sender" not in limiter._requests
        assert "active-sender" in limiter._requests
        assert "newcomer" in limiter._requests

    def test_active_senders_never_displaced(self):
        """Active senders are never evicted to make room for a new sender.
        Prevents the throwaway-flood attack on rate-limit quotas."""
        max_s = 3
        limiter = RateLimiter(rpm=100, window_seconds=60, max_senders=max_s)

        # Fill with active senders.
        for i in range(max_s):
            limiter.check(f"active-{i}")
        assert limiter.sender_count() == max_s

        # Many newcomers all rejected.
        for i in range(10):
            allowed, _ = limiter.check(f"newcomer-{i}")
            assert allowed is False

        # Original active senders intact.
        for i in range(max_s):
            assert f"active-{i}" in limiter._requests
        # No newcomer slipped in.
        for i in range(10):
            assert f"newcomer-{i}" not in limiter._requests

    def test_memory_stays_bounded_under_flood(self):
        """len(_requests) never exceeds max_senders under attacker flood."""
        max_s = 10
        limiter = RateLimiter(rpm=1000, window_seconds=60, max_senders=max_s)

        # Hammer with unique sender IDs.
        for i in range(max_s * 5):
            limiter.check(f"flood-{i}")
            assert limiter.sender_count() <= max_s, (
                f"sender_count {limiter.sender_count()} exceeded max_senders {max_s}"
            )

    def test_per_sender_list_bounded_by_rpm(self):
        """A single sender's timestamp list does not grow without bound —
        we cap at rpm entries since anything beyond is already over-limit."""
        rpm = 5
        limiter = RateLimiter(rpm=rpm, window_seconds=60, max_senders=100)
        # Make 100 attempts (all denied after the 5th).
        for _ in range(100):
            limiter.check("loud")
        # The list of recorded timestamps is bounded.
        assert len(limiter._requests["loud"]) <= rpm
