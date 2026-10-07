"""Minimal ASGI binding for :class:`~ampro.server.core.AgentServer`.

No web framework required — any ASGI server (uvicorn, hypercorn, ...)
can run the result, and it can be mounted inside FastAPI/Starlette::

    from ampro.server import AgentServer
    server = AgentServer.from_app(agent)
    asgi_app = server.asgi()            # uvicorn module:asgi_app

PURE — zero platform-specific imports.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from ampro.ampi.dispatch import run_hooks
from ampro.server.http import HTTPRequest, HTTPResponse

if TYPE_CHECKING:
    from ampro.server.core import AgentServer

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    """Read the request body; ``None`` if it exceeds *limit* bytes."""
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _send_response(send: Send, response: HTTPResponse) -> None:
    headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers.items()]
    await send({"type": "http.response.start", "status": response.status, "headers": headers})
    if response.is_streaming:
        async for chunk in response.body:  # type: ignore[union-attr]
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    else:
        await send({"type": "http.response.body", "body": response.body})


def make_asgi_app(server: AgentServer) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """Wrap *server* as an ASGI 3 application."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            hooks = server.app
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if hooks is not None:
                        await run_hooks(hooks.startup_hooks)
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    if hooks is not None:
                        await run_hooks(hooks.shutdown_hooks)
                    await send({"type": "lifespan.shutdown.complete"})
                    return

        if scope["type"] != "http":
            return

        limit = server.config.max_message_bytes
        body = await _read_body(receive, limit)
        if body is None:
            await _send_response(send, server.too_large_response())
            return

        # Routes are relative to the mount point when embedded in another
        # ASGI app (Starlette/FastAPI ``Mount`` keep the prefix in root_path).
        path = scope["path"]
        root_path = scope.get("root_path", "")
        if root_path and path.startswith(root_path):
            path = path[len(root_path):] or "/"
        query = dict(parse_qsl(scope.get("query_string", b"").decode("latin-1")))
        request = HTTPRequest(
            method=scope["method"],
            path=path,
            headers={k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]},
            query=query,
            body=body,
            client=(scope.get("client") or (None,))[0],
        )
        response = await server.handle(request)
        await _send_response(send, response)

    return app
