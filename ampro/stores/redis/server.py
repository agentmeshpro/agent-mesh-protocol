"""Redis stores for the native AMP route: response cache and dedup."""
from __future__ import annotations

import base64
from typing import Any

from ampro.server.security import CachedResponse
from ampro.stores.redis._base import (
    DEFAULT_MAX_VALUE_BYTES,
    Keyspace,
    dumps,
    loads,
    ms,
)

# Reservation: a completed reply wins; otherwise claim the in-flight mark.
#   {1, reply} completed duplicate / {0} claimed (process it) / {2} in flight
_RESERVE = """
local r = redis.call('GET', KEYS[1])
if r then return {1, r} end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) then return {0} end
return {2}
"""


class RedisResponseCache:
    """Shared :class:`~ampro.server.security.ResponseCache` (AMP dedup).

    A message id reserved on one worker is "in flight" for every worker,
    and the stored reply is replayed by whichever worker the duplicate
    reaches.  The in-flight mark expires after *pending_ttl_seconds* so a
    crashed worker cannot wedge a message id forever.
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", ttl_seconds: float = 300.0,
                 pending_ttl_seconds: float | None = None,
                 max_response_bytes: int = DEFAULT_MAX_VALUE_BYTES) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self.client = client
        self.keys = Keyspace(prefix)
        self.ttl_seconds = ttl_seconds
        self.pending_ttl_seconds = pending_ttl_seconds or ttl_seconds
        self.max_response_bytes = max_response_bytes
        self._reserve = client.register_script(_RESERVE)

    def _k(self, key: str) -> list[str]:
        return [self.keys.key("dedup", "done", key), self.keys.key("dedup", "pend", key)]

    async def reserve(self, key: str) -> CachedResponse | bool:
        result = await self._reserve(keys=self._k(key), args=[ms(self.pending_ttl_seconds)])
        code = int(result[0])
        if code == 0:
            return True
        if code == 2:
            return False
        data = loads(result[1])
        return CachedResponse(int(data["s"]), dict(data["h"]), base64.b64decode(data["b"]))

    async def complete(self, key: str, response: CachedResponse) -> None:
        done, pend = self._k(key)
        try:
            value = dumps({"s": response.status, "h": response.headers,
                           "b": base64.b64encode(response.body).decode("ascii")},
                          limit=self.max_response_bytes)
        except ValueError:
            # Too large to cache: forget the reservation; a retry re-runs.
            await self.client.delete(pend)
            return
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.set(done, value, px=ms(self.ttl_seconds))
            pipe.delete(pend)
            await pipe.execute()

    async def release(self, key: str) -> None:
        await self.client.delete(self._k(key)[1])


class RedisDedupStore:
    """Shared :class:`~ampro.security.dedup.DedupStore` (``SET NX PX``)."""

    def __init__(self, client: Any, *, prefix: str = "ampro", window_seconds: float = 300) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.client = client
        self.keys = Keyspace(prefix)
        self.window_seconds = window_seconds

    async def is_duplicate(self, message_id: str) -> bool:
        created = await self.client.set(self.keys.key("seen", message_id), b"1", nx=True,
                                        px=ms(self.window_seconds))
        return not created

    async def mark_seen(self, message_id: str) -> None:
        await self.client.set(self.keys.key("seen", message_id), b"1",
                              px=ms(self.window_seconds))


__all__ = ["RedisDedupStore", "RedisResponseCache"]
