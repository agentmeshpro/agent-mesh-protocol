"""A2A <-> AMP translation.

Inbound (A2A Message -> AMP ``AgentMessage``)
---------------------------------------------
* new message (no ``taskId``)             -> ``task.create``
  ``{"description": <text, <=8192 chars>, "text": <full text>, "task_id": <minted>,
  "data": {...}?, "attachments": [...]?}``
* message continuing an ``INPUT_REQUIRED`` / ``AUTH_REQUIRED`` task -> ``task.response``
  ``{"task_id", "text", "data"?, "attachments"?}``
* ``data`` parts: a single object part becomes ``body["data"]`` as-is; anything
  else is ``{"parts": [<values>]}``.  ``url`` / ``raw`` parts become
  ``body["attachments"]`` entries ``{"url"|"raw", "filename"?, "media_type"?}``.

Outbound (handler result -> A2A)
--------------------------------
=====================================  =====================================
handler returns                        A2A reply
=====================================  =====================================
``str`` / ``dict`` / ``BaseModel``     ``Message`` (role agent; text / data part)
``task.complete``                      ``Task`` COMPLETED + artifact
``task.input_required``                ``Task`` INPUT_REQUIRED (status msg = prompt)
``task.error``                         ``Task`` FAILED
``task.reject``                        ``Task`` REJECTED
``task.acknowledge`` / ``task.progress`` ``Task`` WORKING (client polls)
``task.response`` / ``message``        ``Message``
``raise AuthRequired(...)``            ``Task`` AUTH_REQUIRED (+ metadata)
=====================================  =====================================

A result is "AMP-shaped" when it is an ``AgentMessage`` or a ``dict`` with a
``body_type`` key (its ``body`` key, or the remaining keys, is the body).
When the inbound message continued a task, plain results complete that task.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

from ampro.core.envelope import AgentMessage
from ampro.interop.a2a.auth import AuthRequired, AuthRequiredKeys
from ampro.interop.a2a.errors import A2AError
from ampro.interop.a2a.types import (
    Artifact,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
    now_timestamp,
)

DESCRIPTION_LIMIT = 8192

_STATE_FOR_BODY_TYPE = {
    "task.complete": TaskState.COMPLETED,
    "task.input_required": TaskState.INPUT_REQUIRED,
    "task.error": TaskState.FAILED,
    "task.reject": TaskState.REJECTED,
    "task.acknowledge": TaskState.WORKING,
    "task.progress": TaskState.WORKING,
}


def new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Parts
# ---------------------------------------------------------------------------


def split_parts(parts: list[Part]) -> tuple[str, dict[str, Any] | None, list[dict[str, Any]]]:
    """``(joined text, data, attachments)`` for a list of A2A parts."""
    texts = [p.text for p in parts if p.text is not None]
    datas = [p.data for p in parts if p.data is not None]
    attachments: list[dict[str, Any]] = []
    for p in parts:
        if p.url is None and p.raw is None:
            continue
        att: dict[str, Any] = {"url": p.url} if p.url is not None else {"raw": p.raw}
        if p.filename:
            att["filename"] = p.filename
        if p.media_type:
            att["media_type"] = p.media_type
        attachments.append(att)
    data: dict[str, Any] | None = None
    if len(datas) == 1 and isinstance(datas[0], dict):
        data = datas[0]
    elif datas:
        data = {"parts": datas}
    return "\n".join(texts), data, attachments


def attachment_to_part(att: Any) -> Part:
    if not isinstance(att, dict):
        return Part(data=att)
    filename = att.get("filename") or att.get("name")
    media_type = att.get("media_type") or att.get("mime_type") or att.get("content_type")
    url = att.get("url") or att.get("uri")
    raw = att.get("raw") or att.get("bytes")
    if isinstance(url, str):
        return Part(url=url, filename=filename, media_type=media_type)
    if isinstance(raw, str):
        try:
            return Part(raw=raw, filename=filename, media_type=media_type)
        except ValidationError:
            pass
    return Part(data=att)


def value_to_parts(value: Any) -> list[Part]:
    """str -> text part; dict/list/model -> data part; None -> []."""
    if value is None:
        return []
    if isinstance(value, Part):
        return [value]
    if isinstance(value, str):
        return [Part(text=value)]
    if isinstance(value, BaseModel):
        return [Part(data=value.model_dump(mode="json"))]
    if isinstance(value, (dict, list, bool, int, float)):
        return [Part(data=value)]
    return [Part(text=str(value))]


# ---------------------------------------------------------------------------
# Inbound
# ---------------------------------------------------------------------------


def a2a_to_amp(
    message: Message,
    *,
    agent_id: str,
    sender: str,
    context_id: str,
    task_id: str,
    continuing: Task | None = None,
    body_type: str | None = None,
) -> AgentMessage:
    """Translate an inbound A2A message into an AMP ``AgentMessage``.

    *task_id* is the A2A task id this exchange will use if it produces a
    task (pre-minted for new messages, the existing id for continuations).
    """
    text, data, attachments = split_parts(message.parts)
    if continuing is not None:
        bt = body_type or "task.response"
        body: dict[str, Any] = {"task_id": task_id, "text": text}
    else:
        bt = body_type or "task.create"
        if bt == "message":
            body = {"text": text}
        else:
            body = {"description": text[:DESCRIPTION_LIMIT], "text": text, "task_id": task_id}
    if data is not None:
        body["data"] = data
    if attachments:
        body["attachments"] = attachments
    return AgentMessage(
        id=message.message_id,
        sender=sender,
        recipient=agent_id,
        body_type=bt,
        body=body,
        headers={"Session-Id": context_id},
    )


# ---------------------------------------------------------------------------
# Outbound
# ---------------------------------------------------------------------------


@dataclass
class Reply:
    """What a handler result maps to: exactly one of ``message`` / ``task``."""

    message: Message | None = None
    task: Task | None = None
    # AMP-only fields surfaced through the AMP extension (e.g. cost receipt).
    amp: dict[str, Any] = field(default_factory=dict)

    @property
    def is_task(self) -> bool:
        return self.task is not None


def amp_shape(result: Any) -> tuple[str, Any] | None:
    """``(body_type, body)`` if *result* is AMP-shaped, else ``None``."""
    if isinstance(result, AgentMessage):
        return result.body_type, result.body
    if isinstance(result, dict) and isinstance(result.get("body_type"), str):
        if "body" in result:
            return result["body_type"], result["body"]
        return result["body_type"], {k: v for k, v in result.items() if k != "body_type"}
    return None


def agent_message(parts: list[Part], *, context_id: str, task_id: str | None = None,
                  metadata: dict[str, Any] | None = None) -> Message:
    return Message(
        message_id=new_id(),
        context_id=context_id,
        task_id=task_id,
        role=Role.AGENT,
        parts=parts or [Part(text="")],
        metadata=metadata or None,
    )


def _task(
    *,
    task_id: str,
    context_id: str,
    state: TaskState,
    status_parts: list[Part] | None,
    history: list[Message],
    artifacts: list[Artifact] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Task:
    status_msg = None
    if status_parts:
        status_msg = agent_message(status_parts, context_id=context_id, task_id=task_id)
    return Task(
        id=task_id,
        context_id=context_id,
        status=TaskStatus(state=state, message=status_msg, timestamp=now_timestamp()),
        artifacts=artifacts or None,
        history=history or None,
        metadata=metadata or None,
    )


def _text(body: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = body.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def result_to_reply(
    result: Any,
    *,
    context_id: str,
    task_id: str,
    user_message: Message,
    continuing: Task | None = None,
) -> Reply:
    """Map a handler result to an A2A reply (see the module table)."""
    history = list(continuing.history or []) if continuing else []
    history.append(user_message.model_copy(update={"task_id": task_id, "context_id": context_id}))
    base_meta = dict(continuing.metadata or {}) if continuing else {}
    prior_artifacts = list(continuing.artifacts or []) if continuing else []

    shaped = amp_shape(result)
    if shaped is None:
        parts = value_to_parts(result)
        if continuing is None and parts:
            return Reply(message=agent_message(parts, context_id=context_id))
        artifacts = prior_artifacts + (
            [Artifact(artifact_id=new_id(), name="result", parts=parts)] if parts else []
        )
        return Reply(task=_task(task_id=task_id, context_id=context_id,
                                state=TaskState.COMPLETED, status_parts=None,
                                history=history, artifacts=artifacts, metadata=base_meta))

    body_type, body = shaped
    if not isinstance(body, dict):
        body = {"result": body} if body_type == "task.complete" else {"text": body}
    state = _STATE_FOR_BODY_TYPE.get(body_type)

    if state is None:
        # task.response / message / any other body type -> a plain Message
        parts = []
        text = _text(body, "text", "message")
        if text is not None:
            parts.append(Part(text=text))
        if body.get("data") is not None:
            parts.extend(value_to_parts(body["data"]))
        parts.extend(attachment_to_part(a) for a in body.get("attachments") or [])
        meta = None
        if not parts:
            parts = value_to_parts(body) or [Part(text="")]
            meta = {"amp.bodyType": body_type}
        if continuing is not None:
            artifacts = prior_artifacts + [Artifact(artifact_id=new_id(), name="result", parts=parts)]
            return Reply(task=_task(task_id=task_id, context_id=context_id,
                                    state=TaskState.COMPLETED, status_parts=None,
                                    history=history, artifacts=artifacts, metadata=base_meta))
        return Reply(message=agent_message(parts, context_id=context_id, metadata=meta))

    amp_extra: dict[str, Any] = {}
    artifacts = prior_artifacts
    status_parts: list[Part] = []
    meta = base_meta
    if body_type == "task.complete":
        parts = value_to_parts(body.get("result"))
        parts.extend(attachment_to_part(a) for a in body.get("attachments") or [])
        if parts:
            artifacts = artifacts + [Artifact(artifact_id=new_id(), name="result", parts=parts,
                                              metadata=body.get("metadata") or None)]
        for k_src, k_dst in (("cost_receipt", "costReceipt"), ("cost_usd", "costUsd"),
                             ("duration_seconds", "durationSeconds")):
            if body.get(k_src) is not None:
                amp_extra[k_dst] = body[k_src]
    elif body_type == "task.input_required":
        status_parts.append(Part(text=_text(body, "prompt", "reason") or "Input required."))
        if body.get("options"):
            status_parts.append(Part(data={"options": list(body["options"])}))
        if body.get("consent_url"):
            meta = {**meta, "amp.consentUrl": body["consent_url"]}
    elif body_type == "task.error":
        status_parts.append(Part(text=_text(body, "detail", "reason") or "Task failed."))
        meta = {**meta, "amp.errorReason": str(body.get("reason") or "error")}
        if body.get("retry_eligible"):
            meta["amp.retryEligible"] = True
    elif body_type == "task.reject":
        status_parts.append(Part(text=_text(body, "reason", "detail") or "Task rejected."))
    else:  # acknowledge / progress
        text = _text(body, "message")
        if text:
            status_parts.append(Part(text=text))
        if body.get("percentage") is not None:
            meta = {**meta, "amp.progress": body["percentage"]}

    return Reply(
        task=_task(task_id=task_id, context_id=context_id, state=state,
                   status_parts=status_parts, history=history, artifacts=artifacts,
                   metadata=meta),
        amp=amp_extra,
    )


def auth_required_reply(
    exc: AuthRequired,
    *,
    context_id: str,
    task_id: str,
    user_message: Message,
    keys: AuthRequiredKeys,
    continuing: Task | None = None,
) -> Reply:
    history = list(continuing.history or []) if continuing else []
    history.append(user_message.model_copy(update={"task_id": task_id, "context_id": context_id}))
    meta: dict[str, Any] = dict(exc.metadata)
    meta[keys.missing_scopes] = list(exc.missing_scopes)
    if exc.verification_uri:
        meta[keys.verification_uri] = exc.verification_uri
    return Reply(task=_task(task_id=task_id, context_id=context_id,
                            state=TaskState.AUTH_REQUIRED, status_parts=[Part(text=exc.message)],
                            history=history, metadata=meta))


# ---------------------------------------------------------------------------
# AMP extension metadata
# ---------------------------------------------------------------------------

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_SHORT_STR = 256


def read_amp_metadata(*metadatas: dict[str, Any] | None, keys: tuple[str, ...]) -> dict[str, Any]:
    """Merge the AMP extension objects found under any of *keys* (later wins)."""
    merged: dict[str, Any] = {}
    for meta in metadatas:
        if not meta:
            continue
        for k in keys:
            v = meta.get(k)
            if isinstance(v, dict):
                merged.update(v)
    return merged


def _get(amp: dict[str, Any], camel: str, snake: str) -> Any:
    return amp.get(camel, amp.get(snake))


def apply_amp_metadata(ctx: Any, amp: dict[str, Any]) -> None:
    """Copy AMP extension fields into an ``AMPContext``.

    Identity is never taken from metadata: a claimed ``sender`` is kept in
    ``ctx.metadata["amp.claimedSender"]`` only.  The delegation chain is
    parsed, not verified — verify it in a handler or middleware with
    ``ampro.delegation.chain.validate_chain`` before relying on it.
    Raises ``A2AError(INVALID_PARAMS)`` for malformed values.
    """
    from ampro.delegation.chain import DelegationChain

    chain = _get(amp, "delegationChain", "delegation_chain")
    if chain is not None:
        try:
            ctx.delegation_chain = DelegationChain.model_validate(
                {"links": chain} if isinstance(chain, list) else chain
            )
        except ValidationError:
            raise A2AError("INVALID_PARAMS", "Invalid AMP delegation chain") from None
    for camel, snake, attr in (
        ("jurisdiction", "jurisdiction", "jurisdiction"),
        ("dataResidency", "data_residency", "data_residency"),
        ("transactionId", "transaction_id", "transaction_id"),
        ("correlationGroup", "correlation_group", "correlation_group"),
        ("priority", "priority", "priority"),
        ("remainingBudget", "remaining_budget", "remaining_budget"),
    ):
        v = _get(amp, camel, snake)
        if v is None:
            continue
        if not isinstance(v, str) or len(v) > _SHORT_STR:
            raise A2AError("INVALID_PARAMS", f"Invalid AMP field '{camel}'")
        setattr(ctx, attr, v)
    for camel, snake, attr in (("traceId", "trace_id", "trace_id"),
                               ("spanId", "span_id", "parent_span_id")):
        v = _get(amp, camel, snake)
        if v is None:
            continue
        if not isinstance(v, str) or not _SAFE_ID.match(v):
            raise A2AError("INVALID_PARAMS", f"Invalid AMP field '{camel}'")
        if attr == "trace_id":
            ctx.trace_id = v
        else:
            ctx.metadata["amp.parentSpanId"] = v
    visited = _get(amp, "visitedAgents", "visited_agents")
    if visited is not None:
        if not isinstance(visited, list) or len(visited) > 50 or not all(
            isinstance(a, str) and len(a) <= 512 for a in visited
        ):
            raise A2AError("INVALID_PARAMS", "Invalid AMP field 'visitedAgents'")
        ctx.visited_agents = list(visited)
    sender = amp.get("sender")
    if isinstance(sender, str):
        ctx.metadata["amp.claimedSender"] = sender[:512]
    ctx.metadata["amp.extension"] = amp


def amp_reply_metadata(ctx: Any, agent_id: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """The AMP extension object attached to replies when the extension is active."""
    from ampro.core.versioning import CURRENT_VERSION

    out: dict[str, Any] = {
        "agentId": agent_id,
        "protocolVersion": CURRENT_VERSION,
        "traceId": ctx.trace_id,
        "spanId": ctx.span_id,
    }
    if ctx.jurisdiction:
        out["jurisdiction"] = ctx.jurisdiction
    out.update(extra or {})
    return out


__all__ = [
    "DESCRIPTION_LIMIT",
    "Reply",
    "a2a_to_amp",
    "agent_message",
    "amp_reply_metadata",
    "amp_shape",
    "apply_amp_metadata",
    "attachment_to_part",
    "auth_required_reply",
    "new_id",
    "read_amp_metadata",
    "result_to_reply",
    "split_parts",
    "value_to_parts",
]
