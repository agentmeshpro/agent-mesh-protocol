"""Trace and hop-count propagation across protocol boundaries.

AMP's own loop detection (the ``Visited-Agents`` header) and trace ids
live inside the AMP envelope, so a cycle such as AMP -> A2A -> MCP -> AMP
would lose them at the first foreign hop.  This module carries two
protocol-neutral signals through every adapter and client:

* **W3C Trace Context** — ``traceparent`` (parsed strictly, see
  :func:`ampro.delegation.tracing.parse_traceparent`) and ``tracestate``
  (validated and passed through, bounded to the W3C limits);
* **hop count** — the number of agent-to-agent hops the request has taken,
  in the ``AMP-Hop-Count`` HTTP header and, on A2A, the ``amp.hopCount``
  message-metadata field.  Every outbound call sends ``current + 1``;
  every inbound request whose hop count exceeds the configured maximum
  (default :data:`DEFAULT_MAX_HOPS`, the same limit as
  ``SecurityPolicy.max_visited_agents``) is rejected.

Inbound, the adapters call :func:`read_inbound` and :func:`begin_span`,
copy the result onto the handler's ``AMPContext`` with
:func:`apply_to_context`, and run the handler inside
:func:`use_propagation`.  Outbound, the clients (A2A, MCP, PACT and the
native AMP client) call :func:`outbound_headers`, which reads the
propagation of the handler they are running in (a ``ContextVar``) — or
starts a new trace at hop 1 when called outside any handler.

Hop counts are only ever combined with ``max()``: a value that is lower
than another one seen for the same request never lowers the count.

Pure: stdlib + :mod:`ampro.delegation.tracing` only.
"""
from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from ampro.delegation.tracing import (
    TRACEPARENT_HEADER,
    TRACESTATE_HEADER,
    TraceContextError,
    TraceParent,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    parse_traceparent,
    parse_tracestate,
)

HOP_COUNT_HEADER = "AMP-Hop-Count"
HOP_COUNT_METADATA_KEY = "amp.hopCount"
#: Message-metadata keys (A2A) that may carry W3C trace context.
TRACEPARENT_METADATA_KEY = TRACEPARENT_HEADER
TRACESTATE_METADATA_KEY = TRACESTATE_HEADER
#: Default maximum hop count — mirrors ``SecurityPolicy.max_visited_agents``
#: and ``check_visited_agents_limit``.
DEFAULT_MAX_HOPS = 20
#: Upper bound for any configured ``max_hops``.
MAX_HOPS_CEILING = 1000
#: Longest accepted hop-count header value (``"9999"``).
MAX_HOP_COUNT_DIGITS = 4

_HOP_RE = re.compile(r"[0-9]{1,%d}" % MAX_HOP_COUNT_DIGITS)
_OWS = " \t"


class TracePropagationError(ValueError):
    """Inbound trace / hop-count data is malformed or contradictory.

    ``str(exc)`` is a short, generic message that is safe to return to the
    caller; it never echoes the offending value.
    """


class HopLimitExceeded(TracePropagationError):
    """The hop count exceeds the configured maximum (inbound or outbound)."""


def check_max_hops(max_hops: int) -> int:
    """Validate a configured hop limit (``1..MAX_HOPS_CEILING``)."""
    if (not isinstance(max_hops, int) or isinstance(max_hops, bool)
            or not 1 <= max_hops <= MAX_HOPS_CEILING):
        raise ValueError(f"max_hops must be an integer in 1..{MAX_HOPS_CEILING}")
    return max_hops


def hop_limit_from_policy(policy: Any) -> int:
    """The hop limit implied by a ``SecurityPolicy`` (``max_visited_agents``).

    Clamped to ``1..MAX_HOPS_CEILING``; :data:`DEFAULT_MAX_HOPS` without a
    policy.
    """
    value = getattr(policy, "max_visited_agents", DEFAULT_MAX_HOPS)
    try:
        limit = int(value)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_HOPS
    return max(1, min(MAX_HOPS_CEILING, limit))


def parse_hop_count(value: Any) -> int:
    """Parse a hop count from a header (decimal string) or metadata (int).

    Strings must be 1-4 ASCII digits (HTTP optional whitespace aside);
    integers must be non-negative and at most 9999.  Booleans, floats,
    signs, and anything else are rejected.
    """
    if isinstance(value, bool):
        raise TracePropagationError("Invalid hop count")
    if isinstance(value, int):
        if not 0 <= value < 10 ** MAX_HOP_COUNT_DIGITS:
            raise TracePropagationError("Invalid hop count")
        return value
    if isinstance(value, str) and len(value) <= 64:
        stripped = value.strip(_OWS)
        if _HOP_RE.fullmatch(stripped):
            return int(stripped)
    raise TracePropagationError("Invalid hop count")


@dataclass(frozen=True)
class InboundTrace:
    """What an inbound request carried (already validated)."""

    traceparent: TraceParent | None = None
    tracestate: str | None = None
    hop_count: int = 0


@dataclass(frozen=True)
class Propagation:
    """The trace position and hop count of the request being handled."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    trace_flags: int = 1
    tracestate: str | None = None
    hop_count: int = 0
    max_hops: int = DEFAULT_MAX_HOPS

    def next_hop(self, max_hops: int | None = None) -> int:
        """The hop count to send on an outbound call; refuses past the limit."""
        limit = self.max_hops if max_hops is None else min(self.max_hops, max_hops)
        nxt = self.hop_count + 1
        if nxt > limit:
            raise HopLimitExceeded("Hop limit exceeded")
        return nxt

    def outbound_headers(self, max_hops: int | None = None) -> dict[str, str]:
        headers = {
            TRACEPARENT_HEADER: format_traceparent(self.trace_id, self.span_id, self.trace_flags),
            HOP_COUNT_HEADER: str(self.next_hop(max_hops)),
        }
        if self.tracestate:
            headers[TRACESTATE_HEADER] = self.tracestate
        return headers


_current: ContextVar[Propagation | None] = ContextVar("ampro_propagation", default=None)


def current_propagation() -> Propagation | None:
    """The propagation of the handler currently running, if any."""
    return _current.get()


@contextmanager
def use_propagation(prop: Propagation | None) -> Iterator[Propagation | None]:
    """Make *prop* the current propagation for the enclosed block."""
    token = _current.set(prop)
    try:
        yield prop
    finally:
        _current.reset(token)


def _header(headers: Mapping[str, str] | None, name: str) -> str | None:
    if not headers:
        return None
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    if value is None:
        lname = name.lower()
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == lname:
                return v
    return value


def read_inbound(
    headers: Mapping[str, str] | None = None,
    *,
    metadata: Sequence[Mapping[str, Any] | None] = (),
    max_hops: int = DEFAULT_MAX_HOPS,
    hop_floor: int = 0,
) -> InboundTrace:
    """Validate the trace context and hop count an inbound request carries.

    *headers* are the HTTP request headers; *metadata* are protocol
    metadata objects (e.g. A2A request and message metadata) that may
    carry ``traceparent`` / ``tracestate`` / ``amp.hopCount``.
    *hop_floor* is a hop count known from elsewhere (e.g. the length of
    AMP's ``Visited-Agents``).

    * Every ``traceparent`` present must parse; if several sources carry
      one they must agree exactly.
    * ``tracestate`` is only read when a ``traceparent`` is present (W3C);
      it must be well-formed and, if repeated, agree.
    * The hop count is the maximum of every source and *hop_floor*; above
      *max_hops* raises :class:`HopLimitExceeded`.

    Raises :class:`TracePropagationError` (generic message) on malformed
    or contradictory input.
    """
    check_max_hops(max_hops)
    parents: list[str] = []
    states: list[str] = []
    hops: list[Any] = []
    for source in (headers, *metadata):
        if not source:
            continue
        is_headers = source is headers
        tp = _header(source, TRACEPARENT_HEADER) if is_headers else source.get(
            TRACEPARENT_METADATA_KEY)
        ts = _header(source, TRACESTATE_HEADER) if is_headers else source.get(
            TRACESTATE_METADATA_KEY)
        hc = _header(source, HOP_COUNT_HEADER) if is_headers else source.get(
            HOP_COUNT_METADATA_KEY)
        if tp is not None:
            if not isinstance(tp, str):
                raise TracePropagationError("Invalid traceparent")
            parents.append(tp)
        if ts is not None:
            if not isinstance(ts, str):
                raise TracePropagationError("Invalid tracestate")
            states.append(ts)
        if hc is not None:
            hops.append(hc)

    hop_count = max([hop_floor, *(parse_hop_count(h) for h in hops)])
    if hop_count > max_hops:
        raise HopLimitExceeded("Hop limit exceeded")

    traceparent: TraceParent | None = None
    for raw in parents:
        try:
            parsed = parse_traceparent(raw)
        except TraceContextError:
            raise TracePropagationError("Invalid traceparent") from None
        if traceparent is None:
            traceparent = parsed
        elif (parsed.trace_id, parsed.parent_id) != (traceparent.trace_id, traceparent.parent_id):
            raise TracePropagationError("Conflicting traceparent values")

    tracestate: str | None = None
    if traceparent is not None:
        canon: list[str | None] = []
        for raw in states:
            try:
                canon.append(parse_tracestate(raw))
            except TraceContextError:
                raise TracePropagationError("Invalid tracestate") from None
        if len(set(canon)) > 1:
            raise TracePropagationError("Conflicting tracestate values")
        tracestate = canon[0] if canon else None
    return InboundTrace(traceparent=traceparent, tracestate=tracestate, hop_count=hop_count)


def begin_span(
    inbound: InboundTrace | None,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    trace_id: str | None = None,
    span_id: str | None = None,
) -> Propagation:
    """Open this hop's span: continue *inbound*'s trace, or start one.

    *trace_id* / *span_id* are used when given and valid (e.g. the ids
    already on an ``AMPContext``), otherwise fresh ones are generated.
    An inbound ``traceparent`` always wins for the trace id.
    """
    check_max_hops(max_hops)
    inbound = inbound or InboundTrace()
    tp = inbound.traceparent
    if tp is not None:
        tid = tp.trace_id
    elif trace_id is not None and _is_hex_id(trace_id, 32):
        tid = trace_id
    else:
        tid = generate_trace_id()
    sid = span_id if span_id is not None and _is_hex_id(span_id, 16) else generate_span_id()
    return Propagation(
        trace_id=tid,
        span_id=sid,
        parent_span_id=tp.parent_id if tp is not None else None,
        trace_flags=(tp.trace_flags & 0x01) if tp is not None else 1,
        tracestate=inbound.tracestate,
        hop_count=inbound.hop_count,
        max_hops=max_hops,
    )


def _is_hex_id(value: Any, length: int) -> bool:
    return (isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdef" for c in value) and set(value) != {"0"})


def apply_to_context(ctx: Any, prop: Propagation) -> None:
    """Copy *prop* onto an ``AMPContext`` (trace ids, tracestate, hop count)."""
    ctx.trace_id = prop.trace_id
    ctx.span_id = prop.span_id
    ctx.parent_span_id = prop.parent_span_id
    ctx.trace_state = prop.tracestate
    ctx.hop_count = prop.hop_count
    if prop.parent_span_id is not None:
        ctx.metadata["amp.parentSpanId"] = prop.parent_span_id


def propagation_from_context(ctx: Any, *, max_hops: int = DEFAULT_MAX_HOPS) -> Propagation:
    """The :class:`Propagation` an ``AMPContext`` describes.

    A trace id that is not W3C-shaped (an AMP extension may carry any safe
    id) cannot be sent as a ``traceparent``; a fresh one is used for
    outbound calls in that case.
    """
    tid = getattr(ctx, "trace_id", None)
    sid = getattr(ctx, "span_id", None)
    parent = getattr(ctx, "parent_span_id", None)
    return Propagation(
        trace_id=str(tid) if _is_hex_id(tid, 32) else generate_trace_id(),
        span_id=str(sid) if _is_hex_id(sid, 16) else generate_span_id(),
        parent_span_id=parent if _is_hex_id(parent, 16) else None,
        tracestate=getattr(ctx, "trace_state", None),
        hop_count=max(int(getattr(ctx, "hop_count", 0) or 0),
                      len(getattr(ctx, "visited_agents", None) or ())),
        max_hops=max_hops,
    )


def outbound_propagation(max_hops: int = DEFAULT_MAX_HOPS) -> Propagation:
    """The current propagation, or a new root trace at hop 0."""
    prop = current_propagation()
    if prop is None:
        prop = Propagation(trace_id=generate_trace_id(), span_id=generate_span_id(),
                           max_hops=check_max_hops(max_hops))
    return prop


def outbound_headers(max_hops: int = DEFAULT_MAX_HOPS) -> dict[str, str]:
    """``traceparent`` / ``tracestate`` / ``AMP-Hop-Count`` for an outbound call.

    Uses the propagation of the handler currently running; outside any
    handler a new trace is started at hop 1.  Raises
    :class:`HopLimitExceeded` instead of sending a request whose hop count
    would exceed ``min(max_hops, <inbound limit>)``.
    """
    check_max_hops(max_hops)
    return outbound_propagation(max_hops).outbound_headers(max_hops)


def outbound_hop_count(max_hops: int = DEFAULT_MAX_HOPS) -> int:
    """The hop count an outbound call carries (see :func:`outbound_headers`)."""
    check_max_hops(max_hops)
    return outbound_propagation(max_hops).next_hop(max_hops)


__all__ = [
    "DEFAULT_MAX_HOPS",
    "HOP_COUNT_HEADER",
    "HOP_COUNT_METADATA_KEY",
    "HopLimitExceeded",
    "InboundTrace",
    "MAX_HOPS_CEILING",
    "Propagation",
    "TRACEPARENT_METADATA_KEY",
    "TRACESTATE_METADATA_KEY",
    "TracePropagationError",
    "apply_to_context",
    "begin_span",
    "check_max_hops",
    "current_propagation",
    "hop_limit_from_policy",
    "outbound_headers",
    "outbound_hop_count",
    "outbound_propagation",
    "parse_hop_count",
    "propagation_from_context",
    "read_inbound",
    "use_propagation",
]
