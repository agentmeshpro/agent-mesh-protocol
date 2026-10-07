"""W3C Trace Context parsing (``traceparent`` / ``tracestate``) — strict."""
from __future__ import annotations

import pytest

from ampro.delegation.tracing import (
    MAX_TRACEPARENT_LENGTH,
    MAX_TRACESTATE_INPUT_LENGTH,
    MAX_TRACESTATE_LENGTH,
    MAX_TRACESTATE_MEMBERS,
    TraceContextError,
    TraceParent,
    format_traceparent,
    parse_traceparent,
    parse_tracestate,
)

TID = "4bf92f3577b34da6a3ce929d0e0e4736"
PID = "00f067aa0ba902b7"
VALID = f"00-{TID}-{PID}-01"


def test_parse_valid_version_00():
    tp = parse_traceparent(VALID)
    assert tp == TraceParent(trace_id=TID, parent_id=PID, trace_flags=1, version=0)
    assert tp.sampled and tp.to_header() == VALID


def test_parse_unsampled_and_ows():
    tp = parse_traceparent(f" \t00-{TID}-{PID}-00\t ")
    assert not tp.sampled and tp.trace_flags == 0


def test_unknown_flags_are_cleared_on_output():
    tp = parse_traceparent(f"00-{TID}-{PID}-ff")
    assert tp.trace_flags == 0xFF
    assert tp.to_header().endswith("-01")
    assert format_traceparent(TID, PID, 0x02).endswith("-00")


@pytest.mark.parametrize("value", [
    "",
    "garbage",
    VALID.upper(),                                  # uppercase hex
    f"00-{TID.upper()}-{PID}-01",
    f"00-{TID}-{PID.upper()}-01",
    f"00-{'0' * 32}-{PID}-01",                      # all-zero trace-id
    f"00-{TID}-{'0' * 16}-01",                      # all-zero parent-id
    f"ff-{TID}-{PID}-01",                           # version ff is invalid
    f"00-{TID}-{PID}-01-extra",                     # v00 must be exactly 55 chars
    f"00-{TID}-{PID}-1",                            # short flags
    f"00-{TID[:-1]}-{PID}-01",                      # short trace-id
    f"00-{TID}-{PID[:-1]}-01",                      # short parent-id
    f"00-{TID}x-{PID}-01",
    f"00_{TID}_{PID}_01",                           # wrong separators
    f"0-{TID}-{PID}-01",
    f"00-{TID}-{PID}-0g",                           # non-hex
    f"cc-{TID}-{PID}-01x",                          # future version, bad continuation
    f"00-{TID}-{PID}-01\n",                         # not OWS
    "x" * (MAX_TRACEPARENT_LENGTH + 1),             # bounded input
])
def test_parse_rejects_malformed(value):
    with pytest.raises(TraceContextError):
        parse_traceparent(value)


def test_parse_rejects_non_string():
    with pytest.raises(TraceContextError):
        parse_traceparent(None)  # type: ignore[arg-type]
    with pytest.raises(TraceContextError):
        parse_traceparent(b"00")  # type: ignore[arg-type]


def test_future_version_forward_compat():
    # Spec: parse the first 55 chars as v00; anything after must start with '-'.
    tp = parse_traceparent(f"cc-{TID}-{PID}-01-what-the-future-holds")
    assert tp.version == 0xCC and tp.trace_id == TID and tp.parent_id == PID
    assert tp.to_header() == VALID  # we always speak v00
    assert parse_traceparent(f"01-{TID}-{PID}-01").version == 1


def test_traceparent_dataclass_validates():
    with pytest.raises(ValueError):
        TraceParent(trace_id="A" * 32, parent_id=PID)
    with pytest.raises(ValueError):
        TraceParent(trace_id=TID, parent_id=PID, trace_flags=256)
    with pytest.raises(ValueError):
        TraceParent(trace_id=TID, parent_id=PID, version=0xFF)
    with pytest.raises(ValueError):
        format_traceparent(TID, "0" * 16)


# ---------------------------------------------------------------------------
# tracestate
# ---------------------------------------------------------------------------


def test_tracestate_valid_and_canonical():
    assert parse_tracestate("rojo=00f067aa0ba902b7,congo=t61rcWkgMzE") == \
        "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"
    assert parse_tracestate(" a=1 ,\t, b=2 ") == "a=1,b=2"   # OWS + empty members
    assert parse_tracestate("tenant@vendor=x y") == "tenant@vendor=x y"
    assert parse_tracestate("") is None
    assert parse_tracestate(" , ") is None


@pytest.mark.parametrize("value", [
    "noequals",
    "Upper=1",                       # keys are lowercase
    "1abc=1",                        # simple key starts with a letter
    "a=",                            # empty value
    "a=x ",                          # value must not end in a space... after OWS strip it's fine
    "a=b=c",                         # '=' not allowed in value
    "a=1,a=2",                       # duplicate keys
    "a" * 257 + "=1",                # key too long
    "a=" + "v" * 257,                # value too long
    "t" * 242 + "@v=1",              # tenant id too long
    "t@" + "v" * 15 + "=1",          # system id too long
    "a=\x7f",                        # non-printable
    "a=café",                   # non-ASCII
])
def test_tracestate_rejects_malformed(value):
    if value == "a=x ":
        # Trailing OWS is stripped from the member; the value itself is fine.
        assert parse_tracestate(value) == "a=x"
        return
    with pytest.raises(TraceContextError):
        parse_tracestate(value)


def test_tracestate_member_limit():
    ok = ",".join(f"k{i}=v" for i in range(MAX_TRACESTATE_MEMBERS))
    assert parse_tracestate(ok) == ok
    with pytest.raises(TraceContextError):
        parse_tracestate(ok + ",extra=v")


def test_tracestate_input_bound():
    with pytest.raises(TraceContextError):
        parse_tracestate("a=1" + " " * MAX_TRACESTATE_INPUT_LENGTH)
    with pytest.raises(TraceContextError):
        parse_tracestate(None)  # type: ignore[arg-type]


def test_tracestate_truncation_drops_long_members_first_then_from_end():
    big = "big=" + "x" * 200          # > 128 chars: dropped first
    small = [f"k{i}=" + "v" * 40 for i in range(15)]
    value = ",".join([small[0], big, *small[1:]])
    out = parse_tracestate(value)
    assert out is not None and len(out) <= MAX_TRACESTATE_LENGTH
    assert "big=" not in out
    members = out.split(",")
    assert members == small[: len(members)]  # dropped from the end
