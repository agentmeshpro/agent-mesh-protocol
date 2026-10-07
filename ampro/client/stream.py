"""
AMP Client SDK — stream().

Stream Server-Sent Events (SSE) from an AMP agent task.  Handles
connection drops with exponential backoff and automatic reconnection.

Usage::

    from ampro.client import stream

    async for event in stream("agent://weather.example.com", task_id="t-42"):
        if event.type == StreamingEventType.TEXT_DELTA:
            print(event.data.get("text", ""), end="")
        elif event.type == StreamingEventType.DONE:
            break
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator

import httpx

from ampro.client.core import (
    _USER_AGENT,
    _guarded_client,
    _raise_for_problem,
    _resolve_endpoint,
)
from ampro.streaming.events import MAX_SSE_EVENT_BYTES, StreamingEvent, StreamingEventType
from ampro.transport.limits import (
    ResponseTooLarge,
    StreamDeadlineExceeded,
    iter_sse_lines,
    read_capped,
)
from ampro.wire.config import DEFAULTS

logger = logging.getLogger("ampro.client.stream")

_MAX_RETRIES = 3
_BASE_BACKOFF = 1.0  # seconds


def _parse_sse_line(
    line: str,
    current_event: dict[str, str | None],
) -> StreamingEvent | None:
    """Parse a single SSE line into the accumulator, yielding an event when complete.

    Returns a StreamingEvent when a blank line terminates an event block,
    or None if the line is part of an in-progress event.
    """
    if line.startswith(":"):
        # SSE comment — ignore
        return None

    if line == "":
        # Blank line = event boundary
        if current_event.get("data") is not None:
            event_type_str = current_event.get("event") or "heartbeat"
            try:
                event_type = StreamingEventType(event_type_str)
            except ValueError:
                # Unknown event type — skip
                logger.debug("Unknown SSE event type: %s", event_type_str)
                current_event.clear()
                return None

            try:
                data = json.loads(current_event["data"]) if current_event["data"] else {}
            except json.JSONDecodeError:
                data = {"raw": current_event["data"]}

            event = StreamingEvent(
                type=event_type,
                data=data if isinstance(data, dict) else {"value": data},
                id=current_event.get("id"),
            )
            current_event.clear()
            return event
        current_event.clear()
        return None

    if ":" in line:
        field, _, value = line.partition(":")
        value = value.lstrip(" ")  # SSE spec: strip single leading space
    else:
        field = line
        value = ""

    if field == "event":
        current_event["event"] = value
    elif field == "data":
        # SSE spec: multiple data lines are joined with newlines
        existing = current_event.get("data")
        if existing is not None:
            if len(existing) + len(value) > MAX_SSE_EVENT_BYTES:
                raise ResponseTooLarge(f"SSE event exceeds {MAX_SSE_EVENT_BYTES} bytes")
            current_event["data"] = existing + "\n" + value
        else:
            current_event["data"] = value
    elif field == "id":
        current_event["id"] = value
    # "retry" field is ignored for now

    return None


async def stream(
    to: str,
    task_id: str,
    timeout: float = 300.0,
    last_event_id: str | None = None,
    *,
    allow_private: bool = False,
) -> AsyncIterator[StreamingEvent]:
    """Stream SSE events from an AMP agent task.

    Connects to ``GET /agent/stream?task_id=<task_id>`` and yields
    ``StreamingEvent`` objects as they arrive.  On connection drops,
    retries up to 3 times with exponential backoff.

    Args:
        to: Agent URI of the target (e.g. ``agent://weather.example.com``).
        task_id: The task ID to stream events for.
        timeout: Overall stream timeout in seconds (default 300).
        last_event_id: Resume from this event ID on reconnection.
        allow_private: Allow the target to resolve to a loopback, private
            or otherwise internal address.  Off by default (SSRF
            protection); set ``True`` only for local development.

    Yields:
        ``StreamingEvent`` instances.

    Raises:
        AmpProtocolError: If the server returns a non-2xx response.
        ConnectionError: If all retry attempts are exhausted.
        SSRFError: (subclass of ``ValueError``) if the target is internal
            and ``allow_private`` is False.
        ResponseTooLarge: (a ``ValueError``) if a line or event exceeds
            ``MAX_SSE_EVENT_BYTES`` or an error body ``max_response_bytes``.
        StreamDeadlineExceeded: (a ``TimeoutError``) once *timeout* has
            elapsed in total, reconnects included.
    """
    endpoint = await _resolve_endpoint(to)
    url = f"{endpoint}/agent/stream"
    # Overall deadline across reconnects; lines are capped so a server that
    # never terminates a line cannot grow client memory.
    deadline = time.monotonic() + timeout
    retries = 0
    current_last_id = last_event_id

    while retries <= _MAX_RETRIES:
        headers: dict[str, str] = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "User-Agent": _USER_AGENT,
        }
        if current_last_id:
            headers["Last-Event-ID"] = current_last_id

        params = {"task_id": task_id}

        try:
            # Re-validated (and re-pinned) on every reconnect.
            async with await _guarded_client(url, allow_private=allow_private) as client:
                async with client.stream(
                    "GET",
                    url,
                    headers=headers,
                    params=params,
                    timeout=httpx.Timeout(timeout, connect=10.0),
                ) as response:
                    if response.status_code >= 400:
                        await read_capped(response, DEFAULTS.max_response_bytes)
                        _raise_for_problem(response)

                    # Reset retry counter on successful connection
                    retries = 0
                    current_event: dict[str, str | None] = {}

                    if time.monotonic() > deadline:
                        raise StreamDeadlineExceeded("stream deadline exceeded")
                    async for raw_line in iter_sse_lines(
                        response, max_line_bytes=MAX_SSE_EVENT_BYTES, deadline=deadline,
                    ):
                        event = _parse_sse_line(raw_line, current_event)
                        if event is not None:
                            if event.id:
                                current_last_id = event.id
                            yield event
                            if event.type == StreamingEventType.DONE:
                                return

        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ReadTimeout) as exc:
            retries += 1
            if retries > _MAX_RETRIES:
                raise ConnectionError(
                    f"Stream connection lost after {_MAX_RETRIES} retries: {exc}"
                ) from exc
            backoff = _BASE_BACKOFF * (2 ** (retries - 1))
            logger.warning(
                "Stream connection lost (attempt %d/%d), retrying in %.1fs: %s",
                retries, _MAX_RETRIES, backoff, exc,
            )
            await asyncio.sleep(backoff)
