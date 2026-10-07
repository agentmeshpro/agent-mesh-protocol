"""Outbound response bounds: capped bodies, bounded SSE lines, stream deadlines.

Regression tests for unbounded reads in the AMP client (``_post_message``,
``_get_json``, ``stream``) and callback delivery.  No network: transports
are ``httpx.MockTransport`` whose bodies count how much was produced.
"""
from __future__ import annotations

import time

import httpx
import pytest

from ampro.security.ssrf import ValidatedURL
from ampro.transport.limits import (
    ResponseTooLarge,
    StreamDeadlineExceeded,
    iter_sse_lines,
    read_capped,
)

CHUNK = b"A" * 65536


class Producer:
    """An async body that yields *total* bytes in chunks and counts them."""

    def __init__(self, total: int, chunk: bytes = CHUNK, prefix: bytes = b"") -> None:
        self.total = total
        self.chunk = chunk
        self.prefix = prefix
        self.produced = 0

    async def __aiter__(self):
        if self.prefix:
            yield self.prefix
        while self.produced < self.total:
            self.produced += len(self.chunk)
            yield self.chunk


def mock_client(producer: Producer, *, headers=None, status=200) -> httpx.AsyncClient:
    def handler(request):
        return httpx.Response(status, headers=headers or {}, content=producer)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def test_read_capped_aborts_early():
    producer = Producer(50 * 1024 * 1024)
    async with mock_client(producer) as client:
        async with client.stream("GET", "https://x.example/") as resp:
            with pytest.raises(ResponseTooLarge):
                await read_capped(resp, 1024 * 1024)
    assert producer.produced < 2 * 1024 * 1024


async def test_read_capped_content_length_and_ok():
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"x" * 2000))) as client:
        async with client.stream("GET", "https://x.example/") as resp:
            with pytest.raises(ResponseTooLarge):
                await read_capped(resp, 1000)
        async with client.stream("GET", "https://x.example/") as resp:
            assert await read_capped(resp, 4000) == b"x" * 2000
            assert resp.text == "x" * 2000


async def test_sse_unterminated_line_is_bounded():
    producer = Producer(100 * 1024 * 1024, prefix=b":")  # one comment line, never ends
    async with mock_client(producer) as client:
        async with client.stream("GET", "https://x.example/") as resp:
            with pytest.raises(ResponseTooLarge):
                async for _ in iter_sse_lines(resp, max_line_bytes=1024 * 1024):
                    pass
    assert producer.produced < 2 * 1024 * 1024


async def test_sse_lines_and_deadline():
    body = b"event: a\r\ndata: 1\n\n: comment\ndata: 2"
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=body))) as client:
        async with client.stream("GET", "https://x.example/") as resp:
            lines = [line async for line in iter_sse_lines(resp, max_line_bytes=100)]
    assert lines == ["event: a", "data: 1", "", ": comment", "data: 2"]

    producer = Producer(10 * 1024 * 1024, chunk=b"data: x\n\n")
    async with mock_client(producer) as client:
        async with client.stream("GET", "https://x.example/") as resp:
            with pytest.raises(StreamDeadlineExceeded):
                async for _ in iter_sse_lines(resp, max_line_bytes=100,
                                              deadline=time.monotonic() - 1):
                    pass


# ---------------------------------------------------------------------------
# AMP client
# ---------------------------------------------------------------------------


def _patch_guard(monkeypatch, module, producer: Producer, *, headers=None):
    async def fake_validate(url, **kw):
        return ValidatedURL(url=url, scheme="https", hostname="peer.example", port=443,
                            addresses=("93.184.216.34",))

    def fake_transport(validated, **kw):
        return httpx.MockTransport(
            lambda r: httpx.Response(200, headers=headers or {}, content=producer))

    monkeypatch.setattr(module, "validate_url_async", fake_validate)
    monkeypatch.setattr(module, "pinned_async_transport", fake_transport)


async def test_get_json_and_post_message_are_capped(monkeypatch):
    import ampro.client.core as core
    from ampro.core.envelope import AgentMessage

    producer = Producer(50 * 1024 * 1024, prefix=b'{"a": "')
    _patch_guard(monkeypatch, core, producer)
    with pytest.raises(ResponseTooLarge):
        await core._get_json("https://peer.example/x", max_response_bytes=1024 * 1024)
    assert producer.produced < 2 * 1024 * 1024

    producer.produced = 0
    msg = AgentMessage(sender="@a", recipient="@b", body={"x": 1})
    with pytest.raises(ResponseTooLarge):
        await core._post_message("https://peer.example", msg)  # default WireConfig cap
    assert producer.produced < 7 * 1024 * 1024


async def test_get_json_small_body_still_works(monkeypatch):
    import ampro.client.core as core

    async def fake_validate(url, **kw):
        return ValidatedURL(url=url, scheme="https", hostname="peer.example", port=443,
                            addresses=("93.184.216.34",))

    monkeypatch.setattr(core, "validate_url_async", fake_validate)
    monkeypatch.setattr(core, "pinned_async_transport", lambda v, **kw: httpx.MockTransport(
        lambda r: httpx.Response(200, json={"ok": True})))
    assert await core._get_json("https://peer.example/x") == {"ok": True}


async def test_stream_unterminated_line_is_bounded(monkeypatch):
    import ampro.client.core as core
    from ampro.client.stream import stream as stream_fn

    producer = Producer(100 * 1024 * 1024, prefix=b":")
    _patch_guard(monkeypatch, core, producer, headers={"content-type": "text/event-stream"})
    with pytest.raises(ResponseTooLarge):
        async for _ in stream_fn("agent://peer.example", task_id="t"):
            pass
    assert producer.produced < 2 * 1024 * 1024


async def test_stream_overall_deadline(monkeypatch):
    import ampro.client.core as core
    from ampro.client.stream import stream as stream_fn

    producer = Producer(10 * 1024 * 1024, chunk=b": keepalive\n")
    _patch_guard(monkeypatch, core, producer, headers={"content-type": "text/event-stream"})
    with pytest.raises(StreamDeadlineExceeded):
        async for _ in stream_fn("agent://peer.example", task_id="t", timeout=0.05):
            pass


# ---------------------------------------------------------------------------
# Callback delivery
# ---------------------------------------------------------------------------


async def test_callback_does_not_buffer_response_body(monkeypatch):
    import ampro.transport.callback as callback

    producer = Producer(100 * 1024 * 1024)
    _patch_guard(monkeypatch, callback, producer)
    ok = await callback.deliver_callback("https://peer.example/hook", {"x": 1}, max_retries=1)
    assert ok is True
    assert producer.produced < 2 * 1024 * 1024
