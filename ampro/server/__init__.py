"""
Minimal AMP Reference Server.

Usage::

    from ampro.server import AgentServer

    server = AgentServer(agent_id="@my-agent", endpoint="https://example.com")

    @server.on("task.create")
    async def handle_create(msg):
        return {"status": "accepted"}

    server.run(port=8000)
"""

from __future__ import annotations

from ampro.server.core import AgentServer
from ampro.server.http import HTTPRequest, HTTPResponse, ProtocolAdapter
from ampro.server.test import TestServer

__all__ = ["AgentServer", "HTTPRequest", "HTTPResponse", "ProtocolAdapter", "TestServer"]
