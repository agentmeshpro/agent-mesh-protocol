"""Turn AMPI ``@app.tool`` callables into MCP tool definitions.

* The input JSON Schema is derived from the function signature and type
  hints with pydantic; a parameter named ``ctx`` (or annotated as
  :class:`~ampro.ampi.context.AMPContext`) is skipped and receives the
  handler context instead.  An explicit ``input_schema`` in
  ``app.tool_meta[name]`` wins for advertising.
* Arguments are validated against the same pydantic model before the
  function runs, so a tool never sees ill-typed input.
* Return values become MCP ``content`` blocks (plus ``structuredContent``
  for dict / model results).
"""
from __future__ import annotations

import inspect
import json
import typing
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model
from pydantic.fields import FieldInfo

CTX_PARAM = "ctx"
MAX_TOOL_NAME_LENGTH = 128


class ArgumentValidationError(Exception):
    """Tool arguments failed validation.  ``fields`` names the bad paths only."""

    def __init__(self, fields: list[str]) -> None:
        self.fields = fields
        super().__init__("Invalid arguments" + (f" for: {', '.join(fields)}" if fields else ""))


def _is_ctx_annotation(annotation: Any) -> bool:
    if annotation is inspect.Parameter.empty:
        return False
    if isinstance(annotation, str):
        return annotation.split(".")[-1] == "AMPContext"
    try:
        from ampro.ampi.context import AMPContext
    except ImportError:  # pragma: no cover
        return False
    return isinstance(annotation, type) and issubclass(annotation, AMPContext)


@dataclass
class ToolSpec:
    """Everything the adapter needs to advertise and call one tool."""

    name: str
    fn: Callable[..., Any]
    description: str
    input_schema: dict[str, Any]
    scopes: tuple[str, ...] = ()
    ctx_param: str | None = None
    args_model: type[BaseModel] | None = None
    # field name in args_model -> (parameter name, positional-only?)
    param_map: dict[str, tuple[str, bool]] = field(default_factory=dict)
    accepts_extra: bool = False
    title: str | None = None

    def to_mcp(self) -> dict[str, Any]:
        tool: dict[str, Any] = {"name": self.name, "inputSchema": self.input_schema}
        if self.title:
            tool["title"] = self.title
        if self.description:
            tool["description"] = self.description
        return tool

    def bind(self, arguments: Mapping[str, Any] | None) -> tuple[list[Any], dict[str, Any]]:
        """Validate *arguments*; return ``(args, kwargs)`` for the call (ctx excluded)."""
        arguments = dict(arguments or {})
        bad: set[str] = set()
        required = self.input_schema.get("required")
        if isinstance(required, list):
            bad.update(str(k) for k in required if k not in arguments)
        if self.args_model is None:
            if bad:
                raise ArgumentValidationError(sorted(bad))
            return [], arguments
        try:
            # Strict JSON-mode validation: no silent coercion ("1" is not an
            # int, 1.5 is not truncated), while JSON-native encodings of
            # dates, UUIDs and enums are still accepted.
            model = self.args_model.model_validate_json(json.dumps(arguments), strict=True)
        except ValidationError as exc:
            bad.update(
                ".".join(str(p) for p in err.get("loc", ())) or "<root>" for err in exc.errors()
            )
            raise ArgumentValidationError(sorted(bad)) from None
        if bad:
            raise ArgumentValidationError(sorted(bad))
        args: list[Any] = []
        kwargs: dict[str, Any] = {}
        for field_name, (param, positional) in self.param_map.items():
            if field_name not in model.model_fields_set and param not in arguments:
                # Let the function apply its own default.
                continue
            value = getattr(model, field_name)
            if positional:
                args.append(value)
            else:
                kwargs[param] = value
        if self.accepts_extra and model.model_extra:
            kwargs.update(model.model_extra)
        return args, kwargs


def _clean_schema(schema: dict[str, Any]) -> dict[str, Any]:
    schema.pop("title", None)
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if isinstance(sub, dict) and sub.get("title") == name.replace("_", " ").title():
                sub.pop("title", None)
    schema["type"] = "object"
    schema.setdefault("properties", {})
    return schema


def build_tool_spec(name: str, fn: Callable[..., Any], meta: Mapping[str, Any] | None = None) -> ToolSpec:
    """Build a :class:`ToolSpec` for *fn* registered under *name*."""
    meta = dict(meta or {})
    description = meta.get("description")
    if description is None:
        description = inspect.getdoc(fn) or ""

    target = fn
    try:
        sig = inspect.signature(target)
    except (TypeError, ValueError):
        sig = None
    try:
        hints = typing.get_type_hints(target, include_extras=True)
    except Exception:
        hints = {}

    ctx_param: str | None = None
    accepts_extra = False
    fields: dict[str, Any] = {}
    param_map: dict[str, tuple[str, bool]] = {}
    if sig is not None:
        index = 0
        for pname, param in sig.parameters.items():
            if param.kind is inspect.Parameter.VAR_POSITIONAL:
                continue
            if param.kind is inspect.Parameter.VAR_KEYWORD:
                accepts_extra = True
                continue
            annotation = hints.get(pname, param.annotation)
            if pname == CTX_PARAM or _is_ctx_annotation(annotation):
                ctx_param = pname
                continue
            if annotation is inspect.Parameter.empty:
                annotation = Any
            # Field names are synthetic and the parameter name is the alias,
            # so parameters like ``schema`` or ``json`` cannot shadow
            # BaseModel attributes.
            field_name = f"p{index}"
            index += 1
            default = param.default
            if isinstance(default, FieldInfo):
                # ``x: int = Field(5, ge=0)`` — keep its constraints; the
                # later alias-only FieldInfo is merged on top by pydantic.
                fields[field_name] = Annotated[annotation, default, Field(alias=pname)]
            elif default is inspect.Parameter.empty:
                fields[field_name] = Annotated[annotation, Field(alias=pname)]
            else:
                fields[field_name] = Annotated[annotation, Field(default=default, alias=pname)]
            param_map[field_name] = (pname, param.kind is inspect.Parameter.POSITIONAL_ONLY)

    args_model: type[BaseModel] | None = None
    derived: dict[str, Any] = {"type": "object", "properties": {}}
    if sig is not None:
        args_model = create_model(  # type: ignore[call-overload]
            f"{_model_name(name)}Arguments",
            __config__=ConfigDict(
                extra="allow" if accepts_extra else "forbid",
                arbitrary_types_allowed=True,
                populate_by_name=False,
            ),
            **fields,
        )
        try:
            derived = _clean_schema(args_model.model_json_schema(by_alias=True))
        except Exception:
            # Arbitrary (non-JSON-schema-able) types: advertise a permissive
            # object; pydantic still validates on call.
            derived = {"type": "object", "properties": {}}

    explicit = meta.get("input_schema")
    if isinstance(explicit, Mapping):
        input_schema = dict(explicit)
        input_schema.setdefault("type", "object")
    else:
        input_schema = derived

    scopes = meta.get("scopes") or ()
    if isinstance(scopes, str):
        scopes = (scopes,)
    return ToolSpec(
        name=name,
        fn=fn,
        description=description,
        input_schema=input_schema,
        scopes=tuple(scopes),
        ctx_param=ctx_param,
        args_model=args_model,
        param_map=param_map,
        accepts_extra=accepts_extra,
        title=meta.get("title"),
    )


def _model_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in name)
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Tool"


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def to_call_result(value: Any) -> dict[str, Any]:
    """Convert a tool's return value into an MCP ``CallToolResult`` dict."""
    value = _jsonable(value)
    if value is None:
        return {"content": [], "isError": False}
    if isinstance(value, str):
        return {"content": [{"type": "text", "text": value}], "isError": False}
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", errors="replace")
        return {"content": [{"type": "text", "text": text}], "isError": False}
    text = json.dumps(value, default=str, ensure_ascii=False)
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": False}
    if isinstance(value, dict):
        # Round-trip through JSON so structuredContent is plain JSON too.
        result["structuredContent"] = json.loads(text)
    return result


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def scopes_satisfied(required: Iterable[str], held: Iterable[str]) -> bool:
    held_set = set(held)
    return all(scope in held_set for scope in required)


__all__ = [
    "ArgumentValidationError",
    "ToolSpec",
    "build_tool_spec",
    "error_result",
    "scopes_satisfied",
    "to_call_result",
]
