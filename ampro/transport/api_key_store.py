"""
Agent Protocol — API Key Store.

In-memory API key allowlist with brute force protection.

Spec ref: Sections 2.3, 3.6
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
#
# Production deployments SHOULD replace this in-memory store with a
# persistent implementation backed by your framework's session/KV
# store, preserving the same interface.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class ApiKeyFailureTracker(Protocol):
    """Brute-force protection for API-key auth, keyed by client address.

    :class:`ApiKeyStore` is the per-process default; register a shared one
    (e.g. :class:`ampro.stores.redis.RedisApiKeyFailureTracker`) with
    :func:`ampro.trust.resolver.set_api_key_failure_tracker` so a guesser
    cannot multiply its budget by the number of workers.
    """

    def is_blocked(self, ip: str) -> bool: ...

    def record_failure(self, ip: str) -> None: ...

    def reset_failures(self, ip: str) -> None: ...


class ApiKeyStore:
    """In-memory API key allowlist with brute force protection.

    Uses SHA-256 hash-based lookup for O(1) key validation, followed by
    a constant-time comparison to prevent timing side-channels.
    """

    def __init__(self, max_failures: int = 10, block_seconds: int = 900):
        self._keys: dict[str, str] = {}  # key → agent_id
        self._key_hashes: dict[str, str] = {}  # sha256(key) → key
        self._failures: dict[str, list[float]] = {}
        self._blocked: dict[str, float] = {}
        self._max_failures = max_failures
        self._block_seconds = block_seconds
        self._lock = threading.Lock()

    def add_key(self, key: str, agent_id: str) -> None:
        self._keys[key] = agent_id
        self._key_hashes[hashlib.sha256(key.encode()).hexdigest()] = key

    def remove_key(self, key: str) -> None:
        self._keys.pop(key, None)
        self._key_hashes.pop(hashlib.sha256(key.encode()).hexdigest(), None)

    def validate(self, key: str) -> str | None:
        """Validate an API key using O(1) hash lookup + constant-time comparison.

        First narrows via SHA-256 hash (O(1) dict lookup), then confirms
        with hmac.compare_digest to prevent timing side-channels.
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        stored_key = self._key_hashes.get(key_hash)
        if stored_key is not None and hmac.compare_digest(stored_key, key):
            return self._keys.get(stored_key)
        return None

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            blocked_until = self._blocked.get(ip)
            if blocked_until is None:
                return False
            if time.monotonic() > blocked_until:
                self._blocked.pop(ip, None)
                self._failures.pop(ip, None)
                return False
            return True

    def record_failure(self, ip: str) -> None:
        with self._lock:
            now = time.monotonic()
            failures = self._failures.setdefault(ip, [])
            failures[:] = [t for t in failures if now - t < 60]
            failures.append(now)
            if len(failures) >= self._max_failures:
                self._blocked[ip] = now + self._block_seconds

    def reset_failures(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
            self._blocked.pop(ip, None)
