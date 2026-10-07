"""
AMP Wire Binding -- JSON Schema (2020-12) documents for the wire format.

Builds the language-neutral JSON Schemas published under ``spec/schemas/``
from the reference Pydantic models, so that the schemas and the reference
implementation cannot drift: ``scripts/generate_spec.py --check`` fails CI
when a model changes without the published schemas being regenerated.

Every document has a stable ``$id`` under :data:`SCHEMA_BASE`.  Documents
reference each other with relative ``$ref`` values (``body/task.create.json``
from ``envelope.json``), which resolve against those ``$id`` values.

Usage::

    from ampro.wire.schemas import build_schemas

    docs = build_schemas()            # {"envelope.json": {...}, ...}
    docs["body/task.create.json"]["$id"]

PURE -- zero platform-specific imports.  Only pydantic and stdlib.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

#: Base URL of the machine-readable specification.
SPEC_BASE = "https://github.com/agentmeshpro/agent-mesh-protocol/spec/"
#: Base URL every schema ``$id`` lives under.
SCHEMA_BASE = SPEC_BASE + "schemas/"
#: JSON Schema dialect used by every document.
DIALECT = "https://json-schema.org/draft/2020-12/schema"

#: Cross-field rules that JSON Schema cannot express.  They are published
#: in each schema as ``x-amp-constraints`` so that implementers see them;
#: validators MUST enforce them in code.
SEMANTIC_CONSTRAINTS: dict[str, list[str]] = {
    "identity.link_proof": [
        "expires_at MUST be strictly after timestamp",
        "proof MUST verify per WIRE-BINDING section 16.1.9",
    ],
    "key.revocation": [
        "signature MUST verify over the canonical form (tests/vectors/key_revocation.json)",
        "revoked_at and compromised_at MUST be valid calendar instants",
        "replacement_key_id MUST differ from revoked_key_id",
        "compromised_at is only allowed with reason key_compromise and MUST NOT be after revoked_at",
        "key_compromise / agent_decommissioned invalidate every signature by the key "
        "regardless of its timestamp; key_rotation invalidates only signatures made at "
        "or after revoked_at (WIRE-BINDING section 12.12.1)",
    ],
    "registry.federation_request": [
        "trust proof MUST verify per WIRE-BINDING section 12.16.1",
    ],
    "registry.federation_revoke": [
        "signature MUST verify per WIRE-BINDING section 12.16.2",
    ],
}


def schema_id(path: str) -> str:
    """The canonical ``$id`` for a schema published at ``spec/schemas/<path>``."""
    return SCHEMA_BASE + path


def body_schema_path(body_type: str) -> str:
    """Relative path (under ``spec/schemas/``) of a body type's schema."""
    return f"body/{body_type}.json"


def stream_schema_path(event_type: str) -> str:
    """Relative path (under ``spec/schemas/``) of a streaming event's data schema."""
    return f"stream/{event_type}.json"


def _wrap(path: str, schema: dict[str, Any], *, title: str | None = None,
          description: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Put ``$schema`` / ``$id`` / title / description first, then the body."""
    doc: dict[str, Any] = {"$schema": DIALECT, "$id": schema_id(path)}
    if title or "title" in schema:
        doc["title"] = title or schema["title"]
    if description or "description" in schema:
        doc["description"] = description or schema["description"]
    for key, value in schema.items():
        if key not in ("title", "description"):
            doc[key] = value
    if extra:
        doc.update(extra)
    return doc


def _model(model: type[BaseModel]) -> dict[str, Any]:
    return model.model_json_schema(mode="validation")


# ---------------------------------------------------------------------------
# Body types
# ---------------------------------------------------------------------------


def _body_registry() -> dict[str, type[BaseModel]]:
    from ampro.core.body_schemas import _BODY_TYPE_REGISTRY

    return dict(sorted(_BODY_TYPE_REGISTRY.items()))


def body_schemas() -> dict[str, dict[str, Any]]:
    """One schema per registered body type, keyed by relative path."""
    out: dict[str, dict[str, Any]] = {}
    for body_type, model in _body_registry().items():
        path = body_schema_path(body_type)
        extra: dict[str, Any] = {"x-amp-body-type": body_type}
        if body_type in SEMANTIC_CONSTRAINTS:
            extra["x-amp-constraints"] = SEMANTIC_CONSTRAINTS[body_type]
        out[path] = _wrap(
            path,
            _model(model),
            title=f"AMP body: {body_type}",
            extra=extra,
        )
    return out


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def envelope_schema() -> dict[str, Any]:
    """``AgentMessage`` envelope, dispatching ``body`` to its body-type schema.

    The schema is the *receiver acceptance* contract (what a receiver MUST
    accept).  Senders MUST additionally include ``id`` and ``body_type``
    (WIRE-BINDING section 5.1.1); receivers that get an envelope without
    them apply the defaults (a fresh id, ``"message"``).

    Body validation mirrors the reference server: an object body is
    validated against its registered body type; an envelope carrying the
    ``Content-Encryption`` header carries an ``EncryptedBody`` instead;
    unknown body types pass through unvalidated (section 5.1.4).
    """
    from ampro.core.envelope import AgentMessage

    base = _model(AgentMessage)
    branches: list[dict[str, Any]] = []
    for body_type in _body_registry():
        branches.append({
            "if": {
                "properties": {
                    "body_type": {"const": body_type},
                    "body": {"type": "object"},
                },
                "required": ["body_type", "body"],
            },
            "then": {"properties": {"body": {"$ref": body_schema_path(body_type)}}},
        })
    # A missing body_type defaults to "message".
    branches.append({
        "if": {
            "properties": {"body": {"type": "object"}},
            "required": ["body"],
            "not": {"required": ["body_type"]},
        },
        "then": {"properties": {"body": {"$ref": body_schema_path("message")}}},
    })
    dispatch = {
        "if": {
            "properties": {"headers": {"required": ["Content-Encryption"]}},
            "required": ["headers"],
        },
        "then": {
            "properties": {
                "body": {
                    "if": {"type": "object"},
                    "then": {"$ref": "encrypted-body.json"},
                },
            },
        },
        "else": {"allOf": branches},
    }
    base["allOf"] = [dispatch]
    return _wrap(
        "envelope.json",
        base,
        title="AgentMessage",
        description=(
            "AMP message envelope (WIRE-BINDING section 5.1). Receiver acceptance "
            "schema: senders MUST also include `id` and `body_type`. Unknown "
            "top-level fields and headers MUST be ignored."
        ),
        extra={"x-amp-sender-required": ["sender", "recipient", "id", "body_type"]},
    )


# ---------------------------------------------------------------------------
# Discovery, health, errors, encryption
# ---------------------------------------------------------------------------


def agent_json_schema() -> dict[str, Any]:
    from ampro.agent.schema import AgentJson

    return _wrap(
        "agent-json.json",
        _model(AgentJson),
        title="AgentJson",
        description=(
            "Agent identity document served at GET /.well-known/agent.json "
            "(WIRE-BINDING section 4.1). Unknown fields MUST be ignored."
        ),
    )


def health_schema() -> dict[str, Any]:
    from ampro.agent.health import HealthResponse

    schema = _model(HealthResponse)
    schema["properties"]["status"]["enum"] = ["healthy", "unhealthy"]
    return _wrap(
        "health-response.json",
        schema,
        title="HealthResponse",
        description="Response of GET /agent/health (WIRE-BINDING section 4.2).",
    )


def problem_schema() -> dict[str, Any]:
    from ampro.wire.errors import ProblemDetail

    schema = _model(ProblemDetail)
    schema["properties"]["type"]["pattern"] = r"^urn:"
    return _wrap(
        "problem-details.json",
        schema,
        title="ProblemDetails",
        description=(
            "RFC 7807 problem details, served as application/problem+json "
            "(WIRE-BINDING section 7). Extension members are allowed and MUST "
            "be ignored when not understood. Standard `type` URNs are listed "
            "in spec/registry/errors.json."
        ),
    )


def encrypted_body_schema() -> dict[str, Any]:
    from ampro.security.encryption import EncryptedBody

    return _wrap(
        "encrypted-body.json",
        _model(EncryptedBody),
        title="EncryptedBody",
        description=(
            "Body of an envelope that carries the Content-Encryption header "
            "(WIRE-BINDING section 12.11)."
        ),
    )


def delegation_link_v2_schema() -> dict[str, Any]:
    from ampro.delegation.v2 import DelegationLinkV2

    return _wrap(
        "delegation-link-v2.json",
        _model(DelegationLinkV2),
        title="DelegationLinkV2",
        description=(
            "One link of a v2 delegation chain (WIRE-BINDING section 11.11.2). "
            "Structure only: string formats, narrowing and signature rules are "
            "normative in the specification text."
        ),
    )


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def stream_event_models() -> dict[str, type[BaseModel]]:
    """Streaming event types whose ``data`` payload has a defined schema."""
    from ampro.streaming.auth import StreamAuthRefreshEvent
    from ampro.streaming.backpressure import (
        StreamAckEvent,
        StreamPauseEvent,
        StreamResumeEvent,
    )
    from ampro.streaming.channel import StreamChannelCloseEvent, StreamChannelOpenEvent
    from ampro.streaming.checkpoint import StreamCheckpointEvent

    return {
        "stream.ack": StreamAckEvent,
        "stream.auth_refresh": StreamAuthRefreshEvent,
        "stream.channel_close": StreamChannelCloseEvent,
        "stream.channel_open": StreamChannelOpenEvent,
        "stream.checkpoint": StreamCheckpointEvent,
        "stream.pause": StreamPauseEvent,
        "stream.resume": StreamResumeEvent,
    }


def stream_schemas() -> dict[str, dict[str, Any]]:
    from ampro.streaming.events import StreamingEventType

    out: dict[str, dict[str, Any]] = {}
    models = stream_event_models()
    for event_type, model in models.items():
        path = stream_schema_path(event_type)
        out[path] = _wrap(
            path,
            _model(model),
            title=f"AMP stream event data: {event_type}",
            extra={"x-amp-event-type": event_type},
        )

    branches = [
        {
            "if": {"properties": {"event": {"const": et}}, "required": ["event"]},
            "then": {"properties": {"data": {"$ref": f"{et}.json"}}},  # sibling of event.json
        }
        for et in models
    ]
    out["stream/event.json"] = {
        "$schema": DIALECT,
        "$id": schema_id("stream/event.json"),
        "title": "StreamEvent",
        "description": (
            "One Server-Sent Event on GET /agent/stream, as parsed from the "
            "`id:`, `event:` and `data:` lines (WIRE-BINDING section 8.3). "
            "`data` is the JSON-decoded payload. Receivers MUST ignore event "
            "types they do not understand."
        ),
        "type": "object",
        "required": ["event", "data"],
        "properties": {
            "id": {"type": "string", "description": "Event id for Last-Event-ID reconnection"},
            "event": {
                "type": "string",
                "description": "Event type; see spec/registry/stream-events.json",
                "examples": [e.value for e in StreamingEventType],
            },
            "data": {
                "type": "object",
                "description": "Event payload. Server-emitted events carry a monotonically increasing integer `seq`.",
                "properties": {"seq": {"type": "integer", "minimum": 0}},
            },
        },
        "allOf": branches,
    }
    return out


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def build_schemas() -> dict[str, dict[str, Any]]:
    """Every published schema, keyed by its path under ``spec/schemas/``."""
    docs: dict[str, dict[str, Any]] = {
        "envelope.json": envelope_schema(),
        "agent-json.json": agent_json_schema(),
        "health-response.json": health_schema(),
        "problem-details.json": problem_schema(),
        "encrypted-body.json": encrypted_body_schema(),
        "delegation-link-v2.json": delegation_link_v2_schema(),
    }
    docs.update(body_schemas())
    docs.update(stream_schemas())
    return dict(sorted(docs.items()))


def schema_registry(docs: dict[str, dict[str, Any]] | None = None) -> Any:
    """A ``referencing.Registry`` holding every schema (needs ``jsonschema``).

    Raises ``ImportError`` when the optional ``jsonschema`` package is absent.
    """
    from referencing import Registry, Resource

    docs = docs if docs is not None else build_schemas()
    return Registry().with_resources(
        (doc["$id"], Resource.from_contents(doc)) for doc in docs.values()
    )


def validator_for(path: str, docs: dict[str, dict[str, Any]] | None = None) -> Any:
    """A Draft 2020-12 validator for ``spec/schemas/<path>`` (needs ``jsonschema``)."""
    from jsonschema import Draft202012Validator

    docs = docs if docs is not None else build_schemas()
    return Draft202012Validator(docs[path], registry=schema_registry(docs))
