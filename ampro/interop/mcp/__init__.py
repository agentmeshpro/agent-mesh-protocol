"""Model Context Protocol (MCP) interop for AMP agents.

* :class:`MCPAdapter` — serve an AMPI agent's ``@app.tool`` functions (and a
  ``task.create`` bridge tool, ``amp_task``) as an MCP server over
  Streamable HTTP, so MCP hosts such as Claude Desktop, Claude Code or
  Cursor can call it.
* :class:`MCPToolSource` — consume a remote MCP server and register its
  tools into an :class:`~ampro.ampi.app.AgentApp`.

Implemented natively — the official ``mcp`` SDK is not a runtime
dependency.  See ``docs/INTEROP-MCP.md``.
"""
from __future__ import annotations

from ampro.interop.mcp.client import MCPClientError, MCPToolError, MCPToolSource
from ampro.interop.mcp.protocol import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
    LATEST_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from ampro.interop.mcp.server import (
    TASK_TOOL_NAME,
    InMemorySessionStore,
    MCPAdapter,
    MCPSession,
    SessionStore,
)

__all__ = [
    "HANDSHAKE_PROTOCOL_VERSIONS",
    "InMemorySessionStore",
    "MCPSession",
    "LATEST_HANDSHAKE_VERSION",
    "LATEST_PROTOCOL_VERSION",
    "MCPAdapter",
    "MCPClientError",
    "MCPToolError",
    "MCPToolSource",
    "MODERN_PROTOCOL_VERSIONS",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "SessionStore",
    "TASK_TOOL_NAME",
]
