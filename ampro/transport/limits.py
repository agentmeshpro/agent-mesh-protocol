"""Bounded reads of outbound HTTP responses.

Every client in ampro that reads a peer's response goes through these
helpers so a hostile or broken server cannot exhaust memory or hold a
connection open forever:

* :func:`read_capped` — read a (streamed) ``httpx.Response`` body, aborting
  as soon as it exceeds ``max_bytes`` (``Content-Length`` is checked first).
* :func:`iter_sse_lines` — split a Server-Sent Events body into lines from
  raw bytes with a cap on the buffered (unterminated) line and an overall
  deadline.  ``httpx.Response.aiter_lines`` has neither: a server that
  never sends a newline makes it buffer without bound.

PURE — httpx only.
"""
from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any


class ResponseTooLarge(ValueError):
    """A response (or one SSE line / event) exceeded its size cap."""


class StreamDeadlineExceeded(TimeoutError):
    """A streamed response ran past its overall deadline."""


async def read_capped(response: Any, max_bytes: int) -> bytes:
    """Read *response* (opened with ``stream=True``) up to *max_bytes*.

    The body is also stored on the response so ``response.json()`` /
    ``response.text`` work afterwards.  Raises :class:`ResponseTooLarge`
    without reading further once the cap is exceeded.
    """
    declared = response.headers.get("content-length")
    if declared and declared.strip().isdigit() and int(declared) > max_bytes:
        raise ResponseTooLarge(f"response declares {declared} bytes (cap {max_bytes})")
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise ResponseTooLarge(f"response exceeds {max_bytes} bytes")
        chunks.append(chunk)
    body = b"".join(chunks)
    response._content = body  # make .json()/.text usable on a streamed response
    return body


async def iter_sse_lines(
    response: Any,
    *,
    max_line_bytes: int,
    deadline: float | None = None,
) -> AsyncIterator[str]:
    """Yield decoded SSE lines (without terminators) from *response*.

    Lines end with ``\\n`` (an optional preceding ``\\r`` is stripped).
    Raises :class:`ResponseTooLarge` when an unterminated line grows past
    *max_line_bytes* — comment lines included — and
    :class:`StreamDeadlineExceeded` once ``time.monotonic()`` passes
    *deadline*.  Idle connections are bounded by the client's read timeout.
    """
    buffer = bytearray()
    async for chunk in response.aiter_bytes():
        if deadline is not None and time.monotonic() > deadline:
            raise StreamDeadlineExceeded("stream deadline exceeded")
        buffer.extend(chunk)
        while True:
            idx = buffer.find(b"\n")
            if idx < 0:
                break
            line = bytes(buffer[:idx])
            del buffer[: idx + 1]
            if len(line) > max_line_bytes:
                raise ResponseTooLarge(f"SSE line exceeds {max_line_bytes} bytes")
            if line.endswith(b"\r"):
                line = line[:-1]
            yield line.decode("utf-8", errors="replace")
        if len(buffer) > max_line_bytes:
            raise ResponseTooLarge(f"SSE line exceeds {max_line_bytes} bytes")
    if buffer:
        line = bytes(buffer).rstrip(b"\r")
        yield line.decode("utf-8", errors="replace")


__all__ = ["ResponseTooLarge", "StreamDeadlineExceeded", "iter_sse_lines", "read_capped"]
