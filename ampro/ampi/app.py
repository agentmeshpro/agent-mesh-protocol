"""AgentApp — the optional convenience wrapper for AMPI.

A registry for handlers, middleware, tools, and lifecycle hooks.
~150 lines. Not a framework.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from ampro.agent.schema import AgentJson
from ampro.core.versioning import CURRENT_VERSION


class AgentApp:
    """Minimal AMPI application — a registry, not a framework."""

    def __init__(
        self,
        agent_id: str,
        endpoint: str,
        capabilities: list[str] | None = None,
        agent_json: AgentJson | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.endpoint = endpoint
        self.capabilities_list = capabilities or ["messaging"]

        if agent_json is not None:
            self.agent_json = agent_json
        else:
            self.agent_json = AgentJson(
                protocol_version=CURRENT_VERSION,
                identifiers=[agent_id],
                endpoint=endpoint,
            )

        self.handlers: dict[str, Callable] = {}
        self.streaming_handlers: set[str] = set()
        self.tools: dict[str, Callable] = {}
        self.tool_meta: dict[str, dict[str, Any]] = {}
        self.middleware_chain: list[Callable] = []
        self.startup_hooks: list[Callable] = []
        self.shutdown_hooks: list[Callable] = []
        self.session_start_hooks: list[Callable] = []
        self.error_handler: Callable | None = None
        self.state: dict[str, Any] = {}

    def on(self, body_type: str, *, streaming: bool = False) -> Callable:
        """Register a handler for a body type (e.g. ``task.create``)."""
        def decorator(fn: Callable) -> Callable:
            self.handlers[body_type] = fn
            if streaming:
                self.streaming_handlers.add(body_type)
            return fn
        return decorator

    def middleware(self, fn: Callable) -> Callable:
        """Register a middleware function."""
        self.middleware_chain.append(fn)
        return fn

    def tool(
        self,
        name: str,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        scopes: Iterable[str] = (),
    ) -> Callable:
        """Register a tool by name.

        The optional metadata is kept in ``self.tool_meta[name]`` and used
        by protocol adapters (e.g. MCP) that advertise tools to callers:

        * *description* — shown to the caller (defaults to the docstring).
        * *input_schema* — explicit JSON Schema for the arguments
          (defaults to one derived from the function signature).
        * *scopes* — scopes a caller's principal must hold to see or call it.
        """
        def decorator(fn: Callable) -> Callable:
            self.tools[name] = fn
            meta: dict[str, Any] = {}
            if description is not None:
                meta["description"] = description
            if input_schema is not None:
                meta["input_schema"] = dict(input_schema)
            scope_list = [scopes] if isinstance(scopes, str) else list(scopes)
            if scope_list:
                meta["scopes"] = scope_list
            if meta:
                self.tool_meta[name] = meta
            else:
                self.tool_meta.pop(name, None)
            return fn
        return decorator

    def on_startup(self, fn: Callable) -> Callable:
        """Register a startup hook."""
        self.startup_hooks.append(fn)
        return fn

    def on_shutdown(self, fn: Callable) -> Callable:
        """Register a shutdown hook."""
        self.shutdown_hooks.append(fn)
        return fn

    def on_session_start(self, fn: Callable) -> Callable:
        """Register a session-start hook."""
        self.session_start_hooks.append(fn)
        return fn

    def on_error(self, fn: Callable) -> Callable:
        """Register a global error handler."""
        self.error_handler = fn
        return fn

    def to_dict(self) -> dict[str, Any]:
        """Serialize the app's registry for introspection."""
        return {
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
            "handlers": dict(self.handlers),
            "tools": dict(self.tools),
            "middleware": list(self.middleware_chain),
            "error_handler": self.error_handler,
            "startup": list(self.startup_hooks),
            "shutdown": list(self.shutdown_hooks),
        }
