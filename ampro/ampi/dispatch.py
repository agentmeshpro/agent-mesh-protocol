"""Shared AMPI dispatch — the one code path every server uses.

``TestServer``, ``AgentServer`` and the interop adapters (A2A, MCP) all
call :func:`dispatch` so a handler behaves identically no matter which
transport or wire protocol delivered the message.
"""
from __future__ import annotations

import inspect
import uuid
from collections.abc import Callable
from typing import Any

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.ampi.errors import AMPError
from ampro.core.envelope import AgentMessage
from ampro.delegation.tracing import generate_span_id, generate_trace_id
from ampro.trust.tiers import TrustTier


def build_context(
    agent_id: str,
    message: AgentMessage,
    *,
    trust_tier: TrustTier = TrustTier.EXTERNAL,
    **overrides: Any,
) -> AMPContext:
    """Build the :class:`AMPContext` a handler sees for *message*.

    *trust_tier* defaults to ``EXTERNAL`` — the least-privileged tier.
    Callers that have authenticated the sender pass the resolved tier.
    """
    ctx = AMPContext(
        agent_address=agent_id,
        sender_address=message.sender or "agent://unknown",
        request_id=message.id or str(uuid.uuid4()),
        trust_tier=trust_tier,
        trace_id=generate_trace_id(),
        span_id=generate_span_id(),
        headers=dict(message.headers) if message.headers else {},
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def dispatch(
    app: AgentApp,
    message: AgentMessage,
    ctx: AMPContext,
    *,
    handlers: dict[str, Callable] | None = None,
) -> Any:
    """Run *message* through *app*'s middleware chain and handler.

    Raises :class:`AMPError` (code ``no_handler``) when no handler is
    registered for ``message.body_type``.  Exceptions raised by the
    handler are passed to the app's ``@on_error`` hook, called as
    ``(exc, msg, ctx)``, when one is registered; otherwise they propagate.
    """
    registry = handlers if handlers is not None else app.handlers
    handler = registry.get(message.body_type)
    if handler is None:
        raise AMPError(
            "no_handler",
            f"No handler for body_type '{message.body_type}'",
        )

    async def call_handler(msg: AgentMessage, c: AMPContext) -> Any:
        return await _maybe_await(handler(msg, c))

    # Build the middleware chain inside-out so the first-registered
    # middleware runs first (outermost wrapper).
    chain = call_handler
    for mw in reversed(app.middleware_chain):
        prev = chain

        def _wrap(m: Any = mw, nxt: Any = prev) -> Any:
            async def wrapped(msg: AgentMessage, c: AMPContext) -> Any:
                return await _maybe_await(m(msg, c, nxt))
            return wrapped

        chain = _wrap()

    try:
        return await chain(message, ctx)
    except Exception as exc:
        if app.error_handler is None:
            raise
        return await _maybe_await(app.error_handler(exc, message, ctx))


async def run_hooks(hooks: list[Callable]) -> None:
    """Run lifecycle hooks (startup/shutdown) in registration order."""
    for hook in hooks:
        await _maybe_await(hook())
