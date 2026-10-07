"""Google A2A 1.0 interop for AMP agents.

Serve an AMP agent over A2A (HTTP+JSON and JSON-RPC bindings)::

    from ampro.interop.a2a import A2AAdapter
    server = AgentServer.from_app(app)
    server.mount(A2AAdapter.for_server(server, public_url="https://agent.example"))

Call an A2A agent::

    from ampro.interop.a2a import A2AClient
    async with A2AClient("https://other.example/.well-known/agent-card.json") as client:
        reply = await client.send_message("hello")

See ``docs/INTEROP-A2A.md`` for the mapping tables, routes, auth hook and
the AMP extension.  The official ``a2a-sdk`` is *not* required.
"""
from __future__ import annotations

from ampro.interop.a2a.adapter import DEFAULT_INPUT_MODES, TEXT_MODES, A2AAdapter
from ampro.interop.a2a.auth import (
    ANONYMOUS,
    ANONYMOUS_ID,
    PACT_AUTH_KEYS,
    Authenticator,
    AuthRequired,
    AuthRequiredKeys,
    InvalidToken,
    Principal,
    Unauthorized,
)
from ampro.interop.a2a.card import AMP_EXTENSION_URI, bearer_scheme, build_agent_card
from ampro.interop.a2a.client import A2AClient, A2AClientError, discover_protocol
from ampro.interop.a2a.errors import A2AError
from ampro.interop.a2a.store import (
    ContextStore,
    IdempotencyStore,
    InMemoryContextStore,
    InMemoryIdempotencyStore,
    InMemoryTaskStore,
    TaskStore,
)
from ampro.interop.a2a.types import (
    AgentCard,
    AgentSkill,
    Artifact,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
)

__all__ = [
    "A2AAdapter",
    "A2AClient",
    "A2AClientError",
    "A2AError",
    "AMP_EXTENSION_URI",
    "ANONYMOUS",
    "ANONYMOUS_ID",
    "AgentCard",
    "AgentSkill",
    "Artifact",
    "AuthRequired",
    "AuthRequiredKeys",
    "Authenticator",
    "ContextStore",
    "DEFAULT_INPUT_MODES",
    "IdempotencyStore",
    "InMemoryContextStore",
    "InMemoryIdempotencyStore",
    "InMemoryTaskStore",
    "InvalidToken",
    "Message",
    "PACT_AUTH_KEYS",
    "Part",
    "Principal",
    "Role",
    "TEXT_MODES",
    "Task",
    "TaskState",
    "TaskStatus",
    "TaskStore",
    "Unauthorized",
    "bearer_scheme",
    "build_agent_card",
    "discover_protocol",
]
