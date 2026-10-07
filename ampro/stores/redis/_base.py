"""Key naming, JSON encoding and small helpers shared by the Redis stores.

Keys are ``{prefix}:{namespace}:{part}...``.  A part that is not a short
plain token (``[A-Za-z0-9._@-]{1,128}``) is replaced by ``~`` plus a
SHA-256 prefix, so caller-controlled ids can neither collide with one
another (no ``:`` injection) nor make keys unbounded.  Values are JSON
only (never pickle) and size-checked before they are written.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_SAFE_PART = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
_SAFE_PREFIX = re.compile(r"^[A-Za-z0-9._{}-]{1,64}$")

#: Default upper bound on one stored JSON value.
DEFAULT_MAX_VALUE_BYTES = 1_048_576


def key_part(value: Any) -> str:
    text = str(value)
    if _SAFE_PART.match(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return "~" + digest[:40]


class Keyspace:
    """Builds namespaced keys under one configurable prefix."""

    def __init__(self, prefix: str = "ampro") -> None:
        prefix = prefix.rstrip(":")
        if not _SAFE_PREFIX.match(prefix):
            raise ValueError("prefix must be 1-64 characters of [A-Za-z0-9._{}-]")
        self.prefix = prefix

    def key(self, *parts: Any) -> str:
        return ":".join([self.prefix, *(key_part(p) for p in parts)])


def dumps(value: Any, *, limit: int = DEFAULT_MAX_VALUE_BYTES) -> str:
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode("utf-8")) > limit:
        raise ValueError(f"value exceeds the {limit}-byte store limit")
    return text


def text(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8")
    return str(raw)


def loads(raw: Any) -> Any:
    value = text(raw)
    return None if value is None else json.loads(value)


def pairs(flat: Any) -> dict[str, str]:
    """``HGETALL`` result (dict, or a flat list from a Lua script) -> dict."""
    if not flat:
        return {}
    if isinstance(flat, dict):
        return {text(k): text(v) for k, v in flat.items()}  # type: ignore[misc]
    items = list(flat)
    return {text(items[i]): text(items[i + 1]) for i in range(0, len(items), 2)}  # type: ignore[misc]


def ms(seconds: float) -> int:
    """Seconds -> whole milliseconds, at least 1."""
    return max(1, int(seconds * 1000))


def require_redis() -> Any:
    try:
        import redis
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise RuntimeError(
            "The Redis backend needs the 'redis' package: pip install 'ampro[redis]'"
        ) from exc
    return redis


#: Lua helper: current server time in milliseconds (one clock for all workers).
LUA_NOW_MS = (
    "local __t = redis.call('TIME') "
    "local now = tonumber(__t[1]) * 1000 + math.floor(tonumber(__t[2]) / 1000) "
)
