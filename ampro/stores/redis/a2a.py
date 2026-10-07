"""Redis stores for the A2A adapter (tasks, contexts, replies, live tasks)."""
from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from ampro.interop.a2a.store import CANCEL, PENDING, TIMEOUT, _Pending, _Timeout
from ampro.interop.a2a.types import Task, TaskState, dump
from ampro.stores.redis._base import Keyspace, dumps, loads, ms, text

_SAVE_TASK = """
local o = redis.call('HGET', KEYS[1], 'o')
if o and o ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'o', ARGV[1], 'd', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[4], ARGV[6])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
local n = redis.call('ZCARD', KEYS[2])
local cap = tonumber(ARGV[5])
if n > cap then redis.call('ZREMRANGEBYRANK', KEYS[2], 0, n - cap - 1) end
return 1
"""


class _AsyncStore:
    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "a2a") -> None:
        self.client = client
        self.keys = Keyspace(prefix)
        self.namespace = namespace

    def _key(self, *parts: Any) -> str:
        return self.keys.key(self.namespace, *parts)


class RedisTaskStore(_AsyncStore):
    """Shared :class:`~ampro.interop.a2a.store.TaskStore`.

    One hash per task (owner + JSON) with a TTL, and a per-owner sorted
    set (by update time, capped at *max_tasks_per_owner*) for listing.
    Saving a task id that another owner holds is refused atomically.
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "a2a",
                 ttl_seconds: float = 24 * 3600, max_tasks_per_owner: int = 10_000,
                 max_task_bytes: int = 4 * 1_048_576) -> None:
        super().__init__(client, prefix=prefix, namespace=namespace)
        self.ttl_seconds = ttl_seconds
        self.max_tasks_per_owner = max_tasks_per_owner
        self.max_task_bytes = max_task_bytes
        self._save = client.register_script(_SAVE_TASK)

    async def get_task(self, task_id: str, owner: str) -> Task | None:
        o, d = await self.client.hmget(self._key("task", task_id), ["o", "d"])
        if o is None or d is None or text(o) != owner:
            return None
        return Task.model_validate(loads(d))

    async def save_task(self, task: Task, owner: str) -> None:
        ok = await self._save(
            keys=[self._key("task", task.id), self._key("owner", owner)],
            args=[owner, dumps(dump(task), limit=self.max_task_bytes), ms(self.ttl_seconds),
                  time.time(), self.max_tasks_per_owner, task.id],
        )
        if not int(ok):
            raise PermissionError("task id belongs to another owner")

    async def list_tasks(self, owner: str, *, context_id: str | None = None,
                         state: TaskState | None = None) -> list[Task]:
        ids = await self.client.zrevrange(self._key("owner", owner), 0, -1)
        if not ids:
            return []
        async with self.client.pipeline(transaction=False) as pipe:
            for tid in ids:
                pipe.hmget(self._key("task", text(tid)), ["o", "d"])
            rows = await pipe.execute()
        out = []
        for o, d in rows:
            if o is None or d is None or text(o) != owner:
                continue
            task = Task.model_validate(loads(d))
            if context_id and task.context_id != context_id:
                continue
            if state is not None and task.status.state != state:
                continue
            out.append(task)
        return out


_CLAIM_CONTEXT = """
local cur = redis.call('GET', KEYS[1])
if cur then
  if cur == ARGV[1] then return 1 end
  return 0
end
if ARGV[2] == '1' then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
  return 1
end
return 0
"""


class RedisContextStore(_AsyncStore):
    """Shared :class:`~ampro.interop.a2a.store.ContextStore` (atomic claim)."""

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "a2a",
                 ttl_seconds: float = 24 * 3600) -> None:
        super().__init__(client, prefix=prefix, namespace=namespace)
        self.ttl_seconds = ttl_seconds
        self._claim = client.register_script(_CLAIM_CONTEXT)

    async def claim_context(self, context_id: str, owner: str, *, create: bool = True) -> bool:
        return bool(int(await self._claim(
            keys=[self._key("ctx", context_id)],
            args=[owner, "1" if create else "0", ms(self.ttl_seconds)],
        )))

    async def close_context(self, context_id: str) -> None:
        await self.client.set(self._key("ctxclosed", context_id), b"1", px=ms(self.ttl_seconds))

    async def is_context_closed(self, context_id: str) -> bool:
        return bool(await self.client.exists(self._key("ctxclosed", context_id)))


_BEGIN = """
local r = redis.call('GET', KEYS[1])
if r then return {1, r} end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) then return {0} end
return {2}
"""


class RedisIdempotencyStore(_AsyncStore):
    """Shared :class:`~ampro.interop.a2a.store.IdempotencyStore`.

    ``begin_message`` is one atomic step: a stored reply wins, otherwise
    exactly one worker claims the in-flight mark (``SET NX PX``).
    """

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "a2a",
                 ttl_seconds: float = 24 * 3600, pending_ttl_seconds: float = 300,
                 max_reply_bytes: int = 4 * 1_048_576) -> None:
        super().__init__(client, prefix=prefix, namespace=namespace)
        self.ttl_seconds = ttl_seconds
        self.pending_ttl_seconds = pending_ttl_seconds
        self.max_reply_bytes = max_reply_bytes
        self._begin = client.register_script(_BEGIN)

    def _keys(self, context_id: str, message_id: str) -> list[str]:
        return [self._key("reply", context_id, message_id),
                self._key("replypend", context_id, message_id)]

    async def begin_message(self, context_id: str,
                            message_id: str) -> dict[str, Any] | _Pending | None:
        result = await self._begin(keys=self._keys(context_id, message_id),
                                   args=[ms(self.pending_ttl_seconds)])
        code = int(result[0])
        if code == 0:
            return None
        if code == 2:
            return PENDING
        return loads(result[1])

    async def finish_message(self, context_id: str, message_id: str,
                             reply: dict[str, Any] | None) -> None:
        done, pend = self._keys(context_id, message_id)
        if reply is None:
            await self.client.delete(pend)
            return
        try:
            value = dumps(reply, limit=self.max_reply_bytes)
        except ValueError:
            await self.client.delete(pend)
            return
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.set(done, value, px=ms(self.ttl_seconds))
            pipe.delete(pend)
            await pipe.execute()


class _Subscription:
    def __init__(self, pubsub: Any, preloaded: list[Any]) -> None:
        self._pubsub = pubsub
        self._ready: deque[Any] = deque(preloaded)

    async def get(self, timeout: float) -> dict[str, Any] | None | _Timeout:
        if self._ready:
            return self._ready.popleft()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return TIMEOUT
            msg = await self._pubsub.get_message(ignore_subscribe_messages=True,
                                                 timeout=min(remaining, 1.0))
            if msg is None or msg.get("type") != "message":
                continue
            try:
                payload = loads(msg["data"])
            except ValueError:
                continue
            if isinstance(payload, dict) and "i" in payload:
                return payload["i"]


class RedisTaskBroker(_AsyncStore):
    """Distributed :class:`~ampro.interop.a2a.store.TaskBroker` (Redis pub/sub).

    * events: ``PUBLISH`` on a per-task channel; each ``SubscribeToTask``
      stream (and each running task's cancel watcher) holds one
      subscription for its lifetime;
    * cancel: a flag key (seen by a watcher that subscribes late) plus a
      control message;
    * liveness: a key with a TTL, refreshed on every event, so a worker
      that dies mid-task stops counting as "running" after *live_ttl_seconds*;
    * busy lock: ``SET NX PX``.

    Pub/sub is fire-and-forget: a subscriber only receives events published
    after it subscribed (the adapter subscribes before reading the task, so
    nothing between the read and the stream is lost).
    """

    distributed = True

    def __init__(self, client: Any, *, prefix: str = "ampro", namespace: str = "a2a",
                 live_ttl_seconds: float = 3600, lock_ttl_seconds: float = 600,
                 cancel_ttl_seconds: float = 600, max_event_bytes: int = 1_048_576) -> None:
        super().__init__(client, prefix=prefix, namespace=namespace)
        self.live_ttl_seconds = live_ttl_seconds
        self.lock_ttl_seconds = lock_ttl_seconds
        self.cancel_ttl_seconds = cancel_ttl_seconds
        self.max_event_bytes = max_event_bytes

    def _channel(self, task_id: str) -> str:
        return self._key("ev", task_id)

    async def publish(self, task_id: str, item: dict[str, Any] | None) -> None:
        payload = dumps({"i": item}, limit=self.max_event_bytes)
        async with self.client.pipeline(transaction=False) as pipe:
            pipe.publish(self._channel(task_id), payload)
            if item is not None:
                pipe.pexpire(self._key("live", task_id), ms(self.live_ttl_seconds))
            await pipe.execute()

    @asynccontextmanager
    async def subscribe(self, task_id: str) -> AsyncIterator[_Subscription]:
        pubsub = self.client.pubsub()
        try:
            await pubsub.subscribe(self._channel(task_id))
            # Wait for the confirmation so the subscription is active on the
            # server before the caller reads any state.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5.0
            while loop.time() < deadline:
                msg = await pubsub.get_message(timeout=0.5)
                if msg is not None and msg.get("type") == "subscribe":
                    break
            preloaded: list[Any] = []
            if await self.client.exists(self._key("cancel", task_id)):
                preloaded.append(dict(CANCEL))
            yield _Subscription(pubsub, preloaded)
        finally:
            try:
                await pubsub.unsubscribe()
            finally:
                close = getattr(pubsub, "aclose", None) or pubsub.close
                await close()

    async def set_live(self, task_id: str) -> None:
        await self.client.set(self._key("live", task_id), b"1", px=ms(self.live_ttl_seconds))

    async def clear_live(self, task_id: str) -> None:
        await self.client.delete(self._key("live", task_id))

    async def is_live(self, task_id: str) -> bool:
        return bool(await self.client.exists(self._key("live", task_id)))

    async def request_cancel(self, task_id: str) -> None:
        await self.client.set(self._key("cancel", task_id), b"1", px=ms(self.cancel_ttl_seconds))
        await self.client.publish(self._channel(task_id), dumps({"i": CANCEL}))

    async def try_lock(self, task_id: str) -> bool:
        return bool(await self.client.set(self._key("busy", task_id), b"1", nx=True,
                                          px=ms(self.lock_ttl_seconds)))

    async def unlock(self, task_id: str) -> None:
        await self.client.delete(self._key("busy", task_id))

    async def aclose(self) -> None:
        return None


__all__ = ["RedisContextStore", "RedisIdempotencyStore", "RedisTaskBroker", "RedisTaskStore"]
