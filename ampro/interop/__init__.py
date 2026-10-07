"""Interop — serve and call AMP agents over other agent protocols.

Each sub-package is a :class:`~ampro.server.http.ProtocolAdapter` that
translates a foreign wire protocol to and from AMP's ``AgentMessage`` and
dispatches through the same AMPI handlers:

* ``ampro.interop.a2a``  — Google A2A 1.0 (HTTP+JSON and JSON-RPC bindings)
* ``ampro.interop.pact`` — PACT personal-agent identity and delegated authority on A2A
* ``ampro.interop.mcp``  — Model Context Protocol (expose ``@tool``s)

Optional dependencies are imported lazily so ``import ampro`` stays light.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ampro.server.core import AgentServer
    from ampro.server.http import ProtocolAdapter

_ADAPTERS = {
    "a2a": "ampro.interop.a2a:A2AAdapter",
    "mcp": "ampro.interop.mcp:MCPAdapter",
}


def load_adapter(name: str, server: AgentServer) -> ProtocolAdapter:
    """Instantiate the adapter registered under *name* for *server*."""
    import importlib

    try:
        target = _ADAPTERS[name]
    except KeyError:
        raise ValueError(
            f"Unknown protocol '{name}'. Available: amp, {', '.join(sorted(_ADAPTERS))}"
        ) from None
    module_name, attr = target.split(":")
    cls = getattr(importlib.import_module(module_name), attr)
    return cls.for_server(server)


__all__ = ["load_adapter"]
