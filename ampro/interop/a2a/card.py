"""Build an A2A 1.0 Agent Card for an AMP agent.

The card advertises:

* ``supportedInterfaces`` — HTTP+JSON and JSON-RPC, both ``protocolVersion
  "1.0"``, at ``{public_url}{base_path}``;
* ``skills`` — one per registered ``@on`` body type and ``@tool`` (or an
  explicit list);
* ``capabilities.extensions`` — the AMP extension
  (:data:`AMP_EXTENSION_URI`, ``required: false``) whose params tell an
  AMP-aware client where the native AMP endpoint lives.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from ampro.core.versioning import CURRENT_VERSION
from ampro.interop.a2a.types import (
    A2A_PROTOCOL_VERSION,
    BINDING_HTTP_JSON,
    BINDING_JSONRPC,
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    SecurityRequirement,
)

if TYPE_CHECKING:
    from ampro.ampi.app import AgentApp
    from ampro.server.core import AgentServer

AMP_EXTENSION_URI = "https://github.com/CatlystAI/agent-mesh-protocol/ext/amp/v1"

# Body types that are protocol plumbing rather than user-facing skills.
_NON_SKILL_BODY_TYPES = frozenset({
    "task.response", "task.acknowledge", "task.progress", "task.complete",
    "task.error", "task.reject", "task.input_required", "task.quote",
})


def bearer_scheme(bearer_format: str = "JWT", description: str | None = None) -> dict[str, Any]:
    """An ``httpAuthSecurityScheme`` with ``scheme: "Bearer"`` (proto JSON shape)."""
    scheme: dict[str, Any] = {"scheme": "Bearer", "bearerFormat": bearer_format}
    if description:
        scheme["description"] = description
    return {"httpAuthSecurityScheme": scheme}


def _doc_summary(fn: Callable[..., Any] | None) -> str:
    doc = inspect.getdoc(fn) if fn is not None else None
    return doc.strip().splitlines()[0] if doc else ""


def derive_skills(
    handlers: dict[str, Callable[..., Any]],
    tools: dict[str, Callable[..., Any]] | None = None,
) -> list[AgentSkill]:
    """One skill per user-facing handler body type and per tool."""
    skills: list[AgentSkill] = []
    for body_type, fn in handlers.items():
        if body_type in _NON_SKILL_BODY_TYPES:
            continue
        skills.append(AgentSkill(
            id=body_type,
            name=body_type,
            description=_doc_summary(fn) or f"Handles AMP '{body_type}' messages",
            tags=["amp", body_type.split(".")[0]],
        ))
    for name, fn in (tools or {}).items():
        skills.append(AgentSkill(
            id=f"tool:{name}",
            name=name,
            description=_doc_summary(fn) or f"Tool '{name}'",
            tags=["tool"],
        ))
    return skills


def build_agent_card(
    server: AgentServer | AgentApp,
    *,
    public_url: str | None = None,
    base_path: str = "/a2a",
    name: str | None = None,
    description: str | None = None,
    version: str = "1.0.0",
    skills: Iterable[AgentSkill | dict[str, Any]] | None = None,
    streaming: bool = True,
    provider: AgentProvider | dict[str, Any] | None = None,
    security_schemes: dict[str, dict[str, Any]] | None = None,
    security_requirements: Iterable[SecurityRequirement | dict[str, Any]] | None = None,
    extensions: Iterable[AgentExtension | dict[str, Any]] = (),
    include_amp_extension: bool = True,
    documentation_url: str | None = None,
) -> AgentCard:
    """Build the :class:`AgentCard` for *server* (an ``AgentServer`` or ``AgentApp``).

    ``public_url`` defaults to the agent's AMP ``endpoint``.
    """
    agent_id: str = server.agent_id
    endpoint: str = server.endpoint
    root = (public_url or endpoint).rstrip("/")
    interface_url = root + ("/" + base_path.strip("/") if base_path.strip("/") else "")

    if hasattr(server, "tools"):  # AgentApp
        app: Any = server
        handlers: dict[str, Callable[..., Any]] = dict(server.handlers)
    else:  # AgentServer — shares the app's registry when built with from_app
        app = server.app
        handlers = dict(server._handlers)
    tools: dict[str, Callable[..., Any]] = dict(getattr(app, "tools", None) or {})

    if skills is None:
        skill_list = derive_skills(handlers, tools)
    else:
        skill_list = [s if isinstance(s, AgentSkill) else AgentSkill.model_validate(s)
                      for s in skills]

    ext_list: list[AgentExtension] = []
    if include_amp_extension:
        ext_list.append(AgentExtension(
            uri=AMP_EXTENSION_URI,
            description="Agent Mesh Protocol: native AMP endpoint, delegation chain, "
                        "jurisdiction, tracing and cost receipts via message metadata.",
            required=False,
            params={
                "agent_id": agent_id,
                "amp_endpoint": endpoint,
                "protocol_version": CURRENT_VERSION,
            },
        ))
    ext_list.extend(e if isinstance(e, AgentExtension) else AgentExtension.model_validate(e)
                    for e in extensions)

    reqs = None
    if security_requirements is not None:
        reqs = [r if isinstance(r, SecurityRequirement) else SecurityRequirement.model_validate(r)
                for r in security_requirements]

    prov = None
    if provider is not None:
        prov = provider if isinstance(provider, AgentProvider) else AgentProvider.model_validate(provider)

    return AgentCard(
        name=name or agent_id,
        description=description or f"AMP agent {agent_id}",
        supported_interfaces=[
            AgentInterface(url=interface_url, protocol_binding=BINDING_HTTP_JSON,
                           protocol_version=A2A_PROTOCOL_VERSION),
            AgentInterface(url=interface_url, protocol_binding=BINDING_JSONRPC,
                           protocol_version=A2A_PROTOCOL_VERSION),
        ],
        provider=prov,
        version=version,
        documentation_url=documentation_url,
        capabilities=AgentCapabilities(
            streaming=streaming,
            push_notifications=False,
            extended_agent_card=False,
            extensions=ext_list or None,
        ),
        security_schemes=security_schemes,
        security_requirements=reqs,
        skills=skill_list,
    )


__all__ = ["AMP_EXTENSION_URI", "bearer_scheme", "build_agent_card", "derive_skills"]
