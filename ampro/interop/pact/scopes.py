"""Handler-side PACT API: who is calling, which scopes, what was done.

While the PACT provider runs a Brand handler it publishes the turn in a
:class:`contextvars.ContextVar`, so ordinary AMPI handlers can use::

    from ampro.interop.pact import requires_scopes, record_action, current_delegation

    @app.on("task.create")
    @requires_scopes("orders:read")
    async def lookup(msg, ctx):
        user = current_delegation().sub          # the Brand's own user id
        record_action("lookup_orders")
        ...

* :func:`requires_scopes` / :func:`ensure_scopes` — if the delegation
  token lacks a scope (or there is none), raise ``AuthRequired`` with the
  missing ids and a fresh login link: the provider answers with a task in
  ``TASK_STATE_AUTH_REQUIRED`` (§5.5 step-up).  Granted scopes are recorded
  as ``scopesUsed`` on the receipt.
* :func:`record_action` — add ``{tool, argsHash?}`` to the receipt (§5.6).
* :func:`close_conversation` — close this ``contextId`` (§4.2).
"""
from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from ampro.interop.a2a import AuthRequired
from ampro.interop.pact._jwt import sha256_b64url

MAX_ACTIONS = 64


@dataclass(frozen=True)
class Delegation:
    """A verified ``X-A2A-User-Delegation`` token (§5.4)."""

    sub: str  # the User's id at the Brand
    scopes: frozenset[str]
    grant_id: str
    client_id: str  # the personal agent's issuer
    token: str = field(repr=False, default="")
    exp: int = 0


@dataclass
class Turn:
    """State of one ``message:send`` as seen by the Brand's handler."""

    brand_id: str
    interface_url: str
    issuer: str
    pa_sub: str
    context_id: str | None
    delegation: Delegation | None = None
    actions: list[dict[str, str]] = field(default_factory=list)
    scopes_used: list[str] = field(default_factory=list)
    close_requested: bool = False
    step_up: Callable[[list[str]], Awaitable[str | None]] | None = field(default=None, repr=False)


_turn: ContextVar[Turn | None] = ContextVar("pact_turn", default=None)


def current_turn() -> Turn | None:
    return _turn.get()


def current_delegation() -> Delegation | None:
    turn = _turn.get()
    return turn.delegation if turn else None


def use_scopes(*scopes: str) -> None:
    """Record scopes as used on this turn's receipt."""
    turn = _turn.get()
    if turn is None:
        return
    for s in scopes:
        if s not in turn.scopes_used:
            turn.scopes_used.append(s)


def args_hash(args: Any) -> str:
    """SHA-256 (base64url) of the canonical JSON of *args*."""
    return sha256_b64url(json.dumps(args, sort_keys=True, separators=(",", ":"), default=str))


def record_action(tool: str, args: Any = None) -> None:
    """Record an action for the receipt; *args* are hashed, never stored."""
    turn = _turn.get()
    if turn is None or not isinstance(tool, str) or not tool:
        return
    if len(turn.actions) >= MAX_ACTIONS:
        return
    action = {"tool": tool[:128]}
    if args is not None:
        action["argsHash"] = args_hash(args)
    turn.actions.append(action)


def close_conversation() -> None:
    """Close this conversation after the reply; later messages get ``UNSUPPORTED_OPERATION``."""
    turn = _turn.get()
    if turn is not None:
        turn.close_requested = True


async def ensure_scopes(*scopes: str, message: str | None = None, ctx: Any = None) -> Delegation:
    """Require *scopes* on the current delegation, else step up (raise ``AuthRequired``)."""
    turn = _turn.get()
    if turn is not None:
        granted = turn.delegation.scopes if turn.delegation else frozenset()
    else:
        granted = frozenset(getattr(ctx, "scopes", None) or ())
    missing = [s for s in dict.fromkeys(scopes) if s not in granted]
    if missing or (turn is not None and turn.delegation is None):
        missing = missing or list(dict.fromkeys(scopes))
        uri = None
        if turn is not None and turn.step_up is not None:
            uri = await turn.step_up(missing)
        meta: dict[str, Any] = {"pact.missingScopes": list(missing)}
        if uri:
            meta["pact.verificationUriComplete"] = uri
        raise AuthRequired(
            missing, uri,
            message=message or "I need your permission to do that.",
            metadata=meta,
        )
    use_scopes(*scopes)
    assert turn is None or turn.delegation is not None
    return turn.delegation if turn is not None else Delegation(
        sub="", scopes=granted, grant_id="", client_id="")


def requires_scopes(*scopes: str, message: str | None = None) -> Callable[[Callable], Callable]:
    """Decorator for AMPI handlers ``(msg, ctx)``: :func:`ensure_scopes` first."""
    if not scopes:
        raise ValueError("requires_scopes needs at least one scope")

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(msg: Any, ctx: Any, *args: Any, **kwargs: Any) -> Any:
            await ensure_scopes(*scopes, message=message, ctx=ctx)
            result = fn(msg, ctx, *args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
            return result

        wrapper.__pact_scopes__ = tuple(scopes)  # type: ignore[attr-defined]
        return wrapper

    return decorator


__all__ = [
    "Delegation",
    "Turn",
    "args_hash",
    "close_conversation",
    "current_delegation",
    "current_turn",
    "ensure_scopes",
    "record_action",
    "requires_scopes",
    "use_scopes",
]
