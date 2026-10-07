"""
AMP Client SDK — send().

Fire-and-forget message sending to an AMP agent.  Like ``httpx.post()``
but speaks the AMP envelope protocol.

Usage::

    from ampro.client import send

    reply = await send(
        "agent://weather.example.com",
        body={"q": "forecast for tomorrow"},
        body_type="task.create",
        sender="agent://my-agent.example.com",
    )
    print(reply.body)
"""

from __future__ import annotations

from typing import Any

from ampro.client.core import _post_message, _resolve_endpoint
from ampro.core.envelope import AgentMessage


async def send(
    to: str,
    body: dict[str, Any],
    body_type: str = "message",
    sender: str | None = None,
    headers: dict[str, Any] | None = None,
    timeout: float = 30.0,
    *,
    allow_private: bool = False,
) -> AgentMessage:
    """Send a message to an AMP agent and return the response.

    This is the simplest way to communicate with an AMP agent: build an
    envelope, POST it to ``/agent/message``, and return the reply.

    Args:
        to: Agent URI of the recipient (e.g. ``agent://weather.example.com``).
        body: Message body (dict).  Interpreted according to *body_type*.
        body_type: AMP body type (default ``"message"``).  Use canonical
            types like ``"task.create"``, ``"task.complete"``, etc.
        sender: Agent URI of the sender.  Optional for unauthenticated
            messages, but required for session-bound communication.
        headers: Additional AMP headers (e.g. ``{"Priority": "high"}``).
        timeout: HTTP timeout in seconds (default 30).
        allow_private: Allow the target to resolve to a loopback, private
            or otherwise internal address.  Off by default (SSRF
            protection); set ``True`` only for local development, e.g.
            ``send("agent://localhost:8443", ..., allow_private=True)``.

    Returns:
        The response ``AgentMessage`` from the target agent.

    Raises:
        AmpProtocolError: If the server returns a non-2xx response.
        ValueError: If the URI cannot be resolved.
        SSRFError: (subclass of ``ValueError``) if the target is internal
            and ``allow_private`` is False.
    """
    endpoint = await _resolve_endpoint(to)

    msg = AgentMessage(
        sender=sender or "anonymous",
        recipient=to,
        body_type=body_type,
        headers=headers or {},
        body=body,
    )

    return await _post_message(
        endpoint, msg, timeout=timeout, allow_private=allow_private,
    )
