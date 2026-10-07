"""
44 — AMPI: AMPContext methods

AMPContext is the single object every handler reads from. It carries
identity, trust, session, delegation, compliance, and tracing state,
plus a set of server-provided async methods:

  ctx.send(to, body, body_type)     — forward a message to another agent
  ctx.emit_event(topic, data)       — publish an event (audit/metrics)
  ctx.emit_audit(action, desc, ...) — append a compliance audit record
  ctx.discover(uri)                 — fetch another agent's agent.json
  ctx.delegate(to, body, scopes)    — delegate a subtask with scopes/budget
  ctx.search_registry(capability)   — look up agents by capability
  ctx.check_consent(grant, scope)   — verify a tool-consent grant

Handlers SHOULD gate sensitive actions on `ctx.trust_tier`.

Run:
    ampro-server examples.44_ampi_ctx_methods:agent --port 8000
"""
from __future__ import annotations

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage
from ampro.trust.tiers import TrustTier

agent = AgentApp(
    agent_id="agent://ctx-demo.example.com",
    endpoint="http://localhost:8000/agent/message",
)


@agent.on("task.forward")
async def forward(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Send the body on to another agent."""
    target = (msg.body or {}).get("target", "agent://peer.example.com")
    reply = await ctx.send(to=target, body=msg.body, body_type="task.create")
    return {"forwarded_to": target, "reply_id": getattr(reply, "id", None)}


@agent.on("task.audit")
async def audit(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Record an audit event for compliance."""
    await ctx.emit_audit(
        action="task.audit",
        description="caller requested an audited action",
        details={"sender": ctx.sender_address},
    )
    await ctx.emit_event("metrics", {"kind": "audit_written"})
    return {"audited": True}


@agent.on("task.discover")
async def discover(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Look up another agent's capabilities."""
    uri = (msg.body or {}).get("uri", "agent://peer.example.com")
    agent_json = await ctx.discover(uri)
    return {"endpoint": agent_json.endpoint, "identifiers": agent_json.identifiers}


@agent.on("task.delegate")
async def delegate(msg: AgentMessage, ctx: AMPContext) -> dict:
    """Delegate a subtask — trust-gated."""
    # Only VERIFIED and above may delegate.
    if ctx.trust_tier < TrustTier.VERIFIED:
        return {"delegated": False, "reason": "trust_tier_too_low"}

    sub = (msg.body or {}).get("subagent", "agent://worker.example.com")
    reply = await ctx.delegate(
        to=sub,
        body={"work": "do the thing"},
        scopes=["task.create"],
        budget="1.00USD",
    )
    return {"delegated": True, "reply_id": getattr(reply, "id", None)}
