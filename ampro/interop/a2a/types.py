"""Lean pydantic models for the A2A 1.0 wire format (HTTP+JSON / JSON-RPC).

The shapes follow the protobuf JSON mapping of ``a2a.proto`` 1.0 — the
format the official SDK emits and parses: camelCase field names, enums as
their proto names (``TASK_STATE_COMPLETED``, ``ROLE_USER``), ``Part`` as a
oneof of ``text`` / ``raw`` / ``url`` / ``data``.

Input is lenient (unknown fields are ignored, enum ints and short names are
accepted).  Output is strict: :func:`dump` emits only fields defined by
the 1.0 schema, because the SDK client parses responses without
``ignore_unknown_fields``.

PURE — pydantic and stdlib only.  The A2A SDK is *not* a dependency.
"""
from __future__ import annotations

import base64
import builtins
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

A2A_PROTOCOL_VERSION = "1.0"
A2A_JSON_MEDIA_TYPE = "application/a2a+json"
VERSION_HEADER = "A2A-Version"
EXTENSIONS_HEADER = "A2A-Extensions"
AGENT_CARD_PATH = "/.well-known/agent-card.json"

BINDING_HTTP_JSON = "HTTP+JSON"
BINDING_JSONRPC = "JSONRPC"
BINDING_GRPC = "GRPC"


class _Model(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="ignore",
    )

    def to_json_dict(self) -> dict[str, Any]:
        """Serialise to the A2A JSON shape (camelCase, no unset/None fields)."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def now_timestamp() -> str:
    """RFC 3339 UTC timestamp with millisecond precision (protobuf Timestamp JSON)."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TaskState(str, Enum):
    UNSPECIFIED = "TASK_STATE_UNSPECIFIED"
    SUBMITTED = "TASK_STATE_SUBMITTED"
    WORKING = "TASK_STATE_WORKING"
    COMPLETED = "TASK_STATE_COMPLETED"
    FAILED = "TASK_STATE_FAILED"
    CANCELED = "TASK_STATE_CANCELED"
    INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    REJECTED = "TASK_STATE_REJECTED"
    AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL

    @property
    def is_interrupted(self) -> bool:
        return self in (TaskState.INPUT_REQUIRED, TaskState.AUTH_REQUIRED)

    @classmethod
    def parse(cls, value: Any) -> TaskState:
        """Accept proto names, enum numbers and v0.3 short names (``completed``)."""
        if isinstance(value, TaskState):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return _TASK_STATE_ORDER[value]
            except IndexError:
                raise ValueError(f"unknown task state {value}") from None
        if isinstance(value, str):
            v = value.strip()
            if v.isdigit():
                return cls.parse(int(v))
            upper = v.upper().replace("-", "_")
            if not upper.startswith("TASK_STATE_"):
                upper = "TASK_STATE_" + upper
            if upper == "TASK_STATE_CANCELLED":
                upper = "TASK_STATE_CANCELED"
            return cls(upper)
        raise ValueError(f"invalid task state {value!r}")


_TASK_STATE_ORDER = [
    TaskState.UNSPECIFIED,
    TaskState.SUBMITTED,
    TaskState.WORKING,
    TaskState.COMPLETED,
    TaskState.FAILED,
    TaskState.CANCELED,
    TaskState.INPUT_REQUIRED,
    TaskState.REJECTED,
    TaskState.AUTH_REQUIRED,
]
_TERMINAL = frozenset(
    {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELED, TaskState.REJECTED}
)


class Role(str, Enum):
    UNSPECIFIED = "ROLE_UNSPECIFIED"
    USER = "ROLE_USER"
    AGENT = "ROLE_AGENT"

    @classmethod
    def parse(cls, value: Any) -> Role:
        if isinstance(value, Role):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return [Role.UNSPECIFIED, Role.USER, Role.AGENT][value]
        if isinstance(value, str):
            upper = value.strip().upper()
            if not upper.startswith("ROLE_"):
                upper = "ROLE_" + upper
            return cls(upper)
        raise ValueError(f"invalid role {value!r}")


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


class Part(_Model):
    """One content part.  Exactly one of ``text``, ``raw``, ``url``, ``data``.

    ``raw`` is base64 in JSON (protobuf ``bytes``).
    """

    text: str | None = None
    raw: str | None = None
    url: str | None = None
    data: Any = None
    metadata: dict[str, Any] | None = None
    filename: str | None = None
    media_type: str | None = None

    @model_validator(mode="after")
    def _exactly_one_content(self) -> Part:
        present = [
            name
            for name in ("text", "raw", "url")
            if getattr(self, name) is not None
        ]
        if self.data is not None:
            present.append("data")
        if len(present) != 1:
            raise ValueError("a Part must carry exactly one of text, raw, url, data")
        if self.raw is not None:
            try:
                base64.b64decode(self.raw, validate=True)
            except (ValueError, TypeError):
                raise ValueError("Part.raw must be base64") from None
        return self

    @property
    def kind(self) -> str:
        if self.text is not None:
            return "text"
        if self.data is not None:
            return "data"
        return "file"

    @classmethod
    def from_text(cls, text: str, **kw: Any) -> Part:
        return cls(text=text, **kw)

    @classmethod
    def from_data(cls, data: Any, **kw: Any) -> Part:
        return cls(data=data, **kw)

    @classmethod
    def from_bytes(cls, raw: bytes, *, media_type: str | None = None,
                   filename: str | None = None) -> Part:
        return cls(raw=base64.b64encode(raw).decode("ascii"),
                   media_type=media_type, filename=filename)


class Message(_Model):
    message_id: str = Field(min_length=1, max_length=256)
    context_id: str | None = Field(default=None, max_length=256)
    task_id: str | None = Field(default=None, max_length=256)
    role: Role = Role.UNSPECIFIED
    parts: list[Part] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    extensions: list[str] | None = None
    reference_task_ids: list[str] | None = None

    @field_validator("role", mode="before")
    @classmethod
    def _role(cls, v: Any) -> Role:
        return Role.parse(v)

    @field_validator("context_id", "task_id", mode="before")
    @classmethod
    def _empty_is_none(cls, v: Any) -> Any:
        return v or None

    def text(self) -> str:
        """All text parts joined with newlines."""
        return "\n".join(p.text for p in self.parts if p.text is not None)


class TaskStatus(_Model):
    state: TaskState
    message: Message | None = None
    timestamp: str | None = None

    @field_validator("state", mode="before")
    @classmethod
    def _state(cls, v: Any) -> TaskState:
        return TaskState.parse(v)


class Artifact(_Model):
    artifact_id: str
    name: str | None = None
    description: str | None = None
    parts: list[Part] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    extensions: list[str] | None = None


class Task(_Model):
    id: str
    context_id: str | None = None
    status: TaskStatus
    artifacts: list[Artifact] | None = None
    history: list[Message] | None = None
    metadata: dict[str, Any] | None = None


class TaskStatusUpdateEvent(_Model):
    task_id: str
    context_id: str | None = None
    status: TaskStatus
    metadata: dict[str, Any] | None = None


class TaskArtifactUpdateEvent(_Model):
    task_id: str
    context_id: str | None = None
    artifact: Artifact
    append: bool | None = None
    last_chunk: bool | None = None
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Requests / responses
# ---------------------------------------------------------------------------


class SendMessageConfiguration(_Model):
    accepted_output_modes: list[str] | None = None
    task_push_notification_config: dict[str, Any] | None = None
    history_length: int | None = None
    return_immediately: bool | None = None


class SendMessageRequest(_Model):
    tenant: str | None = None
    message: Message
    configuration: SendMessageConfiguration | None = None
    metadata: dict[str, Any] | None = None


class SendMessageResponse(_Model):
    task: Task | None = None
    message: Message | None = None

    @model_validator(mode="after")
    def _one_of(self) -> SendMessageResponse:
        if (self.task is None) == (self.message is None):
            raise ValueError("SendMessageResponse carries exactly one of task, message")
        return self


class StreamResponse(_Model):
    task: Task | None = None
    message: Message | None = None
    status_update: TaskStatusUpdateEvent | None = None
    artifact_update: TaskArtifactUpdateEvent | None = None

    @property
    def payload(self) -> Task | Message | TaskStatusUpdateEvent | TaskArtifactUpdateEvent | None:
        return self.task or self.message or self.status_update or self.artifact_update


class ListTasksResponse(_Model):
    tasks: list[Task] = Field(default_factory=list)
    next_page_token: str = ""
    page_size: int = 0
    total_size: int = 0


# ---------------------------------------------------------------------------
# Agent card
# ---------------------------------------------------------------------------


class AgentInterface(_Model):
    url: str
    protocol_binding: str
    tenant: str | None = None
    protocol_version: str | None = None


class AgentProvider(_Model):
    url: str | None = None
    organization: str | None = None


class AgentExtension(_Model):
    uri: str
    description: str | None = None
    required: bool | None = None
    params: dict[str, Any] | None = None


class AgentCapabilities(_Model):
    streaming: bool | None = None
    push_notifications: bool | None = None
    extensions: list[AgentExtension] | None = None
    extended_agent_card: bool | None = None


class StringList(_Model):
    """Proto ``StringList`` — JSON ``{"list": [...]}``."""

    items: builtins.list[str] = Field(default_factory=builtins.list, alias="list")


class SecurityRequirement(_Model):
    """``{"schemes": {"<scheme name>": {"list": [<scopes>]}}}``."""

    schemes: dict[str, StringList] = Field(default_factory=dict)

    @classmethod
    def of(cls, scheme: str, scopes: list[str] | None = None) -> SecurityRequirement:
        return cls(schemes={scheme: StringList(items=list(scopes or []))})


class AgentSkill(_Model):
    id: str
    name: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    examples: list[str] | None = None
    input_modes: list[str] | None = None
    output_modes: list[str] | None = None
    security_requirements: list[SecurityRequirement] | None = None


class AgentCard(_Model):
    """A2A 1.0 Agent Card.

    ``security_schemes`` values are kept as plain dicts in the proto JSON
    shape (e.g. ``{"httpAuthSecurityScheme": {"scheme": "Bearer"}}``) — see
    :func:`ampro.interop.a2a.card.bearer_scheme`.
    """

    name: str
    description: str = ""
    supported_interfaces: list[AgentInterface] = Field(default_factory=list)
    provider: AgentProvider | None = None
    version: str = "0.0.0"
    documentation_url: str | None = None
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    security_schemes: dict[str, dict[str, Any]] | None = None
    security_requirements: list[SecurityRequirement] | None = None
    default_input_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    default_output_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    skills: list[AgentSkill] = Field(default_factory=list)
    icon_url: str | None = None

    def interface(self, binding: str, major: int = 1) -> AgentInterface | None:
        """Pick an interface by binding and protocol major version (not position).

        An exact ``1.0`` match wins; otherwise any ``1.x``; an interface with
        no ``protocolVersion`` is accepted last.
        """
        candidates = [i for i in self.supported_interfaces if i.protocol_binding == binding]
        for i in candidates:
            if i.protocol_version == f"{major}.0":
                return i
        for i in candidates:
            if i.protocol_version and i.protocol_version.split(".")[0] == str(major):
                return i
        for i in candidates:
            if not i.protocol_version:
                return i
        return None

    def extension(self, uri: str) -> AgentExtension | None:
        for ext in self.capabilities.extensions or []:
            if ext.uri == uri:
                return ext
        return None


__all__ = [
    "A2A_JSON_MEDIA_TYPE",
    "A2A_PROTOCOL_VERSION",
    "AGENT_CARD_PATH",
    "AgentCapabilities",
    "AgentCard",
    "AgentExtension",
    "AgentInterface",
    "AgentProvider",
    "AgentSkill",
    "Artifact",
    "BINDING_GRPC",
    "BINDING_HTTP_JSON",
    "BINDING_JSONRPC",
    "EXTENSIONS_HEADER",
    "ListTasksResponse",
    "Message",
    "Part",
    "Role",
    "SecurityRequirement",
    "SendMessageConfiguration",
    "SendMessageRequest",
    "SendMessageResponse",
    "StreamResponse",
    "StringList",
    "Task",
    "TaskArtifactUpdateEvent",
    "TaskState",
    "TaskStatus",
    "TaskStatusUpdateEvent",
    "VERSION_HEADER",
    "dump",
    "now_timestamp",
]
