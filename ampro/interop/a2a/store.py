"""State for the A2A adapter: tasks, conversation contexts, idempotent replies.

Each concern is a small :class:`typing.Protocol` so operators can back it
with Redis or a database:

* :class:`TaskStore` — A2A tasks, scoped to the owning principal;
* :class:`ContextStore` — which principal owns a ``contextId``, and whether
  the conversation was closed;
* :class:`IdempotencyStore` — stored replies keyed by
  ``(contextId, messageId)`` so retries never re-run the agent;
* :class:`TaskBroker` — cross-worker coordination of *running* tasks:
  event fan-out to ``SubscribeToTask`` streams on other workers,
  cancellation requests, liveness and the "task is busy" lock.

The ``InMemory*`` defaults are bounded (LRU capacity + TTL) and suitable
for a single process.  All methods are ``async``.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol, runtime_checkable

from ampro.interop.a2a.types import Task, TaskState


class _Pending:
    """Marker: a reply for this ``(contextId, messageId)`` is being produced."""

    def __repr__(self) -> str:
        return "PENDING"


PENDING = _Pending()


@runtime_checkable
class TaskStore(Protocol):
    """Persistence for A2A tasks.  Every read is scoped to ``owner``."""

    async def get_task(self, task_id: str, owner: str) -> Task | None:
        """The task, or ``None`` if unknown *or owned by someone else*."""

    async def save_task(self, task: Task, owner: str) -> None:
        """Insert or replace *task* for *owner*."""

    async def list_tasks(
        self,
        owner: str,
        *,
        context_id: str | None = None,
        state: TaskState | None = None,
    ) -> list[Task]:
        """*owner*'s tasks, most recently updated first."""


@runtime_checkable
class ContextStore(Protocol):
    """Ownership and lifecycle of conversation contexts (``contextId``)."""

    async def claim_context(self, context_id: str, owner: str, *, create: bool = True) -> bool:
        """``True`` if *context_id* belongs to *owner*.

        An unknown context is bound to *owner* when *create* is true and
        rejected otherwise.  A context held by another owner is always
        ``False`` (callers must not reveal which case applied).
        """

    async def close_context(self, context_id: str) -> None:
        """Mark a context closed; further messages get ``UNSUPPORTED_OPERATION``."""

    async def is_context_closed(self, context_id: str) -> bool:
        """Whether :meth:`close_context` was called for *context_id*."""


@runtime_checkable
class IdempotencyStore(Protocol):
    """Replies already sent, for safe retries of the same ``messageId``."""

    async def begin_message(
        self, context_id: str, message_id: str
    ) -> dict[str, Any] | _Pending | None:
        """Start processing a message.

        Returns ``None`` (new — now marked in flight), :data:`PENDING` (a
        duplicate still in flight), or the stored reply of a completed one.
        """

    async def finish_message(
        self, context_id: str, message_id: str, reply: dict[str, Any] | None
    ) -> None:
        """Store the reply for a message (``None`` releases the in-flight mark)."""


class BoundedTTLMap:
    """An LRU map with a capacity and an idle TTL (seconds, ``None`` = no TTL)."""

    def __init__(self, max_items: int, ttl: float | None) -> None:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        self.max_items = max_items
        self.ttl = ttl
        self._data: OrderedDict[Any, tuple[float, Any]] = OrderedDict()

    def get(self, key: Any) -> Any:
        item = self._data.get(key)
        if item is None:
            return None
        stamp, value = item
        if self.ttl is not None and time.monotonic() - stamp > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: Any, value: Any) -> None:
        self._data[key] = (time.monotonic(), value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)

    def pop(self, key: Any) -> None:
        self._data.pop(key, None)

    def values(self) -> list[Any]:
        if self.ttl is not None:
            now = time.monotonic()
            for k in [k for k, (stamp, _) in self._data.items() if now - stamp > self.ttl]:
                del self._data[k]
        return [v for _, v in self._data.values()]

    def __len__(self) -> int:
        return len(self._data)


class InMemoryTaskStore:
    """Bounded in-memory :class:`TaskStore`."""

    def __init__(self, *, max_tasks: int = 10_000, ttl_seconds: float | None = 24 * 3600) -> None:
        self._tasks = BoundedTTLMap(max_tasks, ttl_seconds)

    async def get_task(self, task_id: str, owner: str) -> Task | None:
        rec = self._tasks.get(task_id)
        if rec is None or rec[0] != owner:
            return None
        return rec[1].model_copy(deep=True)

    async def save_task(self, task: Task, owner: str) -> None:
        current = self._tasks.get(task.id)
        if current is not None and current[0] != owner:
            raise PermissionError("task id belongs to another owner")
        self._tasks.set(task.id, (owner, task.model_copy(deep=True), time.time()))

    async def list_tasks(
        self,
        owner: str,
        *,
        context_id: str | None = None,
        state: TaskState | None = None,
    ) -> list[Task]:
        out = []
        for rec_owner, task, stamp in self._tasks.values():
            if rec_owner != owner:
                continue
            if context_id and task.context_id != context_id:
                continue
            if state is not None and task.status.state != state:
                continue
            out.append((stamp, task.model_copy(deep=True)))
        out.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in out]


class InMemoryContextStore:
    """Bounded in-memory :class:`ContextStore`."""

    def __init__(self, *, max_contexts: int = 10_000,
                 ttl_seconds: float | None = 24 * 3600) -> None:
        self._owners = BoundedTTLMap(max_contexts, ttl_seconds)
        self._closed = BoundedTTLMap(max_contexts, ttl_seconds)
        self._lock = asyncio.Lock()

    async def claim_context(self, context_id: str, owner: str, *, create: bool = True) -> bool:
        async with self._lock:
            current = self._owners.get(context_id)
            if current is None:
                if not create:
                    return False
                self._owners.set(context_id, owner)
                return True
            return current == owner

    async def close_context(self, context_id: str) -> None:
        self._closed.set(context_id, True)

    async def is_context_closed(self, context_id: str) -> bool:
        return bool(self._closed.get(context_id))


class InMemoryIdempotencyStore:
    """Bounded in-memory :class:`IdempotencyStore`.

    ``pending_ttl_seconds`` bounds how long an in-flight mark survives a
    crashed handler before the message may be processed again.
    """

    def __init__(self, *, max_replies: int = 10_000, ttl_seconds: float | None = 24 * 3600,
                 pending_ttl_seconds: float = 300) -> None:
        self._replies = BoundedTTLMap(max_replies, ttl_seconds)
        self._pending_ttl = pending_ttl_seconds
        self._lock = asyncio.Lock()

    async def begin_message(
        self, context_id: str, message_id: str
    ) -> dict[str, Any] | _Pending | None:
        key = (context_id, message_id)
        async with self._lock:
            entry = self._replies.get(key)
            if entry is not None:
                stamp, reply = entry
                if reply is not PENDING:
                    return reply
                if time.monotonic() - stamp < self._pending_ttl:
                    return PENDING
            self._replies.set(key, (time.monotonic(), PENDING))
            return None

    async def finish_message(
        self, context_id: str, message_id: str, reply: dict[str, Any] | None
    ) -> None:
        key = (context_id, message_id)
        if reply is None:
            self._replies.pop(key)
        else:
            self._replies.set(key, (time.monotonic(), reply))


class _Timeout:
    def __repr__(self) -> str:
        return "TIMEOUT"


#: Returned by :meth:`TaskSubscription.get` when nothing arrived in time.
TIMEOUT = _Timeout()

#: Control item asking the worker that runs a task to cancel it.
CANCEL = {"__amp_control__": "cancel"}


@runtime_checkable
class TaskSubscription(Protocol):
    async def get(self, timeout: float) -> dict[str, Any] | None | _Timeout:
        """Next published item, ``None`` (end of stream) or :data:`TIMEOUT`."""


@runtime_checkable
class TaskBroker(Protocol):
    """Coordination of running A2A tasks between workers.

    A task's handler runs on the worker that received the request; this
    seam lets the *other* workers see it.  :class:`InMemoryTaskBroker`
    (``distributed = False``) is the single-process default: the adapter
    then uses its local fan-out only.  A distributed broker (e.g.
    :class:`ampro.stores.redis.RedisTaskBroker`) carries events, cancel
    requests, liveness and the per-task busy lock across processes.
    """

    #: ``True`` when events / cancels must cross process boundaries.
    distributed: bool

    async def publish(self, task_id: str, item: dict[str, Any] | None) -> None:
        """Deliver *item* (``None`` = end of stream) to every subscriber."""

    def subscribe(self, task_id: str) -> Any:
        """Async context manager yielding a :class:`TaskSubscription`.

        The subscription is active when the context is entered, so an
        event published afterwards is never missed.
        """

    async def set_live(self, task_id: str) -> None:
        """Mark *task_id* as running somewhere (expires on its own)."""

    async def clear_live(self, task_id: str) -> None: ...

    async def is_live(self, task_id: str) -> bool: ...

    async def request_cancel(self, task_id: str) -> None:
        """Ask whichever worker runs *task_id* to cancel it."""

    async def try_lock(self, task_id: str) -> bool:
        """Take the per-task busy lock (one input turn at a time)."""

    async def unlock(self, task_id: str) -> None: ...

    async def aclose(self) -> None: ...


class _NoSubscription:
    async def get(self, timeout: float) -> dict[str, Any] | None | _Timeout:
        return None


class InMemoryTaskBroker:
    """Single-process :class:`TaskBroker`: only the busy lock is real."""

    distributed = False

    def __init__(self) -> None:
        self._busy: set[str] = set()

    async def publish(self, task_id: str, item: dict[str, Any] | None) -> None:
        return None

    @asynccontextmanager
    async def subscribe(self, task_id: str) -> AsyncIterator[_NoSubscription]:
        yield _NoSubscription()

    async def set_live(self, task_id: str) -> None:
        return None

    async def clear_live(self, task_id: str) -> None:
        return None

    async def is_live(self, task_id: str) -> bool:
        return False

    async def request_cancel(self, task_id: str) -> None:
        return None

    async def try_lock(self, task_id: str) -> bool:
        if task_id in self._busy:
            return False
        self._busy.add(task_id)
        return True

    async def unlock(self, task_id: str) -> None:
        self._busy.discard(task_id)

    async def aclose(self) -> None:
        return None


__all__ = [
    "CANCEL",
    "InMemoryTaskBroker",
    "TIMEOUT",
    "TaskBroker",
    "TaskSubscription",
    "BoundedTTLMap",
    "ContextStore",
    "IdempotencyStore",
    "InMemoryContextStore",
    "InMemoryIdempotencyStore",
    "InMemoryTaskStore",
    "PENDING",
    "TaskStore",
]
