"""
07 — Security Modules (Dedup, Rate Limiting, Nonce, Concurrency)

Demonstrates the built-in security primitives.

Run:
    pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git
    python examples/07_security.py
"""

import asyncio

from ampro import (
    ConcurrencyLimiter,
    InMemoryDedupStore,
    NonceTracker,
    RateLimiter,
    SenderState,
    SenderTracker,
    format_rate_limit_headers,
)


async def demo_dedup():
    print("=== Message Deduplication ===\n")
    store = InMemoryDedupStore(window_seconds=300)

    msg_id = "msg-uuid-123"
    print(f"  First time '{msg_id}': duplicate={await store.is_duplicate(msg_id)}")
    print(f"  Second time '{msg_id}': duplicate={await store.is_duplicate(msg_id)}")
    print(f"  Different msg 'msg-456': duplicate={await store.is_duplicate('msg-456')}")


def demo_nonce():
    print("\n=== Nonce Replay Prevention ===\n")
    tracker = NonceTracker(window_seconds=3600)

    print(f"  First use 'nonce-abc': replay={tracker.is_replay('nonce-abc')}")
    print(f"  Reuse 'nonce-abc':     replay={tracker.is_replay('nonce-abc')}")
    print(f"  New 'nonce-def':       replay={tracker.is_replay('nonce-def')}")
    print(f"  Tracked nonces: {tracker.seen_count()}")


def demo_rate_limit():
    print("\n=== Per-Sender Rate Limiting ===\n")
    limiter = RateLimiter(rpm=3)  # 3 requests per minute for demo

    for i in range(5):
        allowed, info = limiter.check("agent://spammer.example.com")
        headers = format_rate_limit_headers(info)
        print(f"  Request {i+1}: allowed={allowed}, remaining={info.remaining}")
        if not allowed:
            print("    → 429 Too Many Requests")
            print(f"    → Headers: {headers}")


def demo_concurrency():
    print("\n=== Concurrency Limiter ===\n")
    limiter = ConcurrencyLimiter(max_total=4, per_sender_pct=0.5)

    print("  Max total: 4, per-sender cap: 50% = 2")
    for i in range(3):
        acquired = limiter.acquire("agent://busy-sender.example.com")
        print(f"  Task {i+1}: acquired={acquired}, active={limiter.sender_active('agent://busy-sender.example.com')}")

    limiter.release("agent://busy-sender.example.com")
    print(f"  After release: acquired={limiter.acquire('agent://busy-sender.example.com')}")


def demo_sender_tracking():
    print("\n=== Poison Message Protection ===\n")
    tracker = SenderTracker(failure_threshold=3, throttle_duration=900)

    sender = "agent://bad-actor.example.com"
    for i in range(4):
        state = tracker.record_failure(sender)
        print(f"  Failure {i+1}: state={state.value}")

    print(f"  Is allowed: {tracker.is_allowed(sender)}")

    tracker.record_success(sender)
    # Note: success only resets failure count, not existing throttle/block state


asyncio.run(demo_dedup())
demo_nonce()
demo_rate_limit()
demo_concurrency()
demo_sender_tracking()
