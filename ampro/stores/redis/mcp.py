"""Redis session store for the MCP adapter (Streamable HTTP sessions)."""
from __future__ import annotations

import secrets
import time
from typing import Any

from ampro.interop.mcp.server import MCPSession
from ampro.stores.redis._base import Keyspace, dumps, loads, ms

# KEYS: quota zset, global zset, new session key
# ARGV: now_ms, idle_ms, per_owner, max_sessions, sid, json, session key prefix
_CREATE = """
local now, idle = tonumber(ARGV[1]), tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - idle)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - idle)
while redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) do
  local m = redis.call('ZPOPMIN', KEYS[1])
  if not m[1] then break end
  redis.call('ZREM', KEYS[2], m[1])
  redis.call('DEL', ARGV[7] .. m[1])
end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return 0 end
redis.call('SET', KEYS[3], ARGV[6], 'PX', idle)
redis.call('ZADD', KEYS[1], now, ARGV[5])
redis.call('PEXPIRE', KEYS[1], idle)
redis.call('ZADD', KEYS[2], now, ARGV[5])
redis.call('PEXPIRE', KEYS[2], idle)
return 1
"""


class RedisSessionStore:
    """Shared :class:`~ampro.interop.mcp.server.SessionStore`.

    A session created on one worker is valid on every worker.  Same
    bounds as the in-memory store: idle expiry (``PX``, refreshed on use),
    an absolute lifetime, a per-caller cap that evicts that caller's least
    recently used session, and a global cap that refuses new sessions.
    Session ids are 256-bit random tokens; a session owned by another
    principal reads exactly like an unknown one.
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "mcp",
                 max_sessions: int = 100_000, idle_timeout: float = 3600.0,
                 max_lifetime: float = 86400.0, max_sessions_per_owner: int = 8,
                 max_client_info_bytes: int = 16_384) -> None:
        if max_sessions < 1 or max_sessions_per_owner < 1:
            raise ValueError("max_sessions and max_sessions_per_owner must be >= 1")
        self.client = client
        self.keys = Keyspace(prefix)
        self.namespace = namespace
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self.max_lifetime = max_lifetime
        self.max_sessions_per_owner = max_sessions_per_owner
        self.max_client_info_bytes = max_client_info_bytes
        self._create = client.register_script(_CREATE)

    def _skey(self, sid: str) -> str:
        return self.keys.key(self.namespace, "s", sid)

    def _quota(self, quota_key: str | None) -> str:
        return self.keys.key(self.namespace, "q", quota_key if quota_key is not None else "\x00")

    def _all(self) -> str:
        return self.keys.key(self.namespace, "all")

    @staticmethod
    def _encode(s: MCPSession) -> dict[str, Any]:
        return {"id": s.id, "v": s.protocol_version, "o": s.owner, "ci": s.client_info,
                "init": s.initialized, "c": s.created_at, "l": s.last_seen, "q": s.quota_key}

    @staticmethod
    def _decode(d: dict[str, Any]) -> MCPSession:
        return MCPSession(id=d["id"], protocol_version=d["v"], owner=d["o"],
                          client_info=d.get("ci") or {}, initialized=bool(d.get("init")),
                          created_at=float(d["c"]), last_seen=float(d["l"]), quota_key=d.get("q"))

    async def create(self, protocol_version: str, owner: str | None,
                     client_info: dict[str, Any] | None = None, *,
                     quota_key: str | None = None) -> MCPSession | None:
        if quota_key is None:
            quota_key = owner
        info = dict(client_info or {})
        try:
            dumps(info, limit=self.max_client_info_bytes)
        except (ValueError, TypeError):
            info = {}
        now = time.time()
        session = MCPSession(id=secrets.token_hex(32), protocol_version=protocol_version,
                             owner=owner, client_info=info, created_at=now, last_seen=now,
                             quota_key=quota_key)
        ok = await self._create(
            keys=[self._quota(quota_key), self._all(), self._skey(session.id)],
            args=[round(now * 1000, 3), ms(self.idle_timeout), self.max_sessions_per_owner,
                  self.max_sessions, session.id, dumps(self._encode(session)),
                  self.keys.key(self.namespace, "s") + ":"],
        )
        return session if int(ok) else None

    async def _forget(self, session: MCPSession) -> None:
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.delete(self._skey(session.id))
            pipe.zrem(self._quota(session.quota_key), session.id)
            pipe.zrem(self._all(), session.id)
            await pipe.execute()

    async def get(self, session_id: str, owner: str | None) -> MCPSession | None:
        if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
            return None
        raw = await self.client.get(self._skey(session_id))
        if raw is None:
            return None
        session = self._decode(loads(raw))
        now = time.time()
        if now - session.created_at > self.max_lifetime:
            await self._forget(session)
            return None
        if session.owner != owner:
            return None
        session.last_seen = now
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.set(self._skey(session.id), dumps(self._encode(session)), xx=True,
                     px=ms(self.idle_timeout))
            pipe.zadd(self._quota(session.quota_key), {session.id: round(now * 1000, 3)}, xx=True)
            pipe.zadd(self._all(), {session.id: round(now * 1000, 3)}, xx=True)
            await pipe.execute()
        return session

    async def save(self, session: MCPSession) -> None:
        await self.client.set(self._skey(session.id), dumps(self._encode(session)), xx=True,
                              keepttl=True)

    async def delete(self, session_id: str, owner: str | None) -> bool:
        session = await self.get(session_id, owner)
        if session is None:
            return False
        await self._forget(session)
        return True


__all__ = ["RedisSessionStore"]
