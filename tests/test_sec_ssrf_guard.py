"""Tests for the shared SSRF guard (ampro.security.ssrf) and its callers.

No test touches real DNS or the network: resolution is stubbed and the
only sockets opened are to a throwaway server on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import httpcore
import httpx
import pytest

from ampro.security.ssrf import (
    SSRFError,
    ValidatedURL,
    is_blocked_ip,
    is_url_safe_static,
    pinned_async_transport,
    validate_url,
    validate_url_async,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _gai(*ips: str):
    def resolver(host, port, *args, **kwargs):
        out = []
        for ip in ips:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (ip, port)))
        return out
    return resolver


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

BLOCKED_URLS = [
    # schemes / userinfo / malformed
    "http://example.com/",
    "ftp://example.com/",
    "file:///etc/passwd",
    "gopher://example.com/",
    "https://user:pw@example.com/",
    "https://example.com@127.0.0.1/",
    "https:///path",
    "",
    # internal hostnames + trailing-dot variants
    "https://localhost/",
    "https://localhost./",
    "https://LOCALHOST/",
    "https://foo.localhost/",
    "https://foo.localhost./",
    "https://localhost.localdomain/",
    "https://metadata.google.internal/computeMetadata/v1/",
    "https://metadata.google.internal./",
    "https://db.corp.internal/",
    "https://printer.local/",
    "https://router.home.arpa/",
    # IPv4 literals, every inet_aton spelling
    "https://127.0.0.1/",
    "https://127.0.0.1./",
    "https://127.1/",
    "https://0x7f.1/",
    "https://0x7f.0x0.0x0.0x1/",
    "https://0x7f000001/",
    "https://2130706433/",
    "https://0177.0.0.1/",
    "https://012.0.0.1/",
    "https://0/",
    "https://0.0.0.0/",
    "https://10.0.0.1/",
    "https://172.16.0.1/",
    "https://192.168.1.1/",
    "https://169.254.169.254/latest/meta-data/",
    "https://100.64.0.1/",
    "https://100.127.255.254/",
    "https://224.0.0.1/",
    "https://240.0.0.1/",
    "https://255.255.255.255/",
    "https://198.18.0.1/",
    "https://127%2e0%2e0%2e1/",
    # malformed numeric hosts
    "https://1.2.3.4.5/",
    "https://256.0.0.1/",
    "https://08.0.0.1/",
    "https://foo.123/",
    # IPv6
    "https://[::1]/",
    "https://[::]/",
    "https://[fe80::1]/",
    "https://[fe80::1%25eth0]/",
    "https://[fc00::1]/",
    "https://[fec0::1]/",
    "https://[ff02::1]/",
    "https://[::ffff:127.0.0.1]/",
    "https://[::ffff:10.0.0.1]/",
    "https://[::ffff:7f00:1]/",
    "https://[::127.0.0.1]/",          # IPv4-compatible
    "https://[::8.8.8.8]/",            # IPv4-compatible (deprecated)
    "https://[2002:7f00:1::]/",        # 6to4 → 127.0.0.1
    "https://[2002:808:808::]/",       # 6to4 tunnel at all
    "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",  # Teredo
    "https://[64:ff9b::7f00:1]/",      # NAT64 → 127.0.0.1
    "https://[64:ff9b::a9fe:a9fe]/",   # NAT64 → 169.254.169.254
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_static_blocked(url):
    assert is_url_safe_static(url) is False
    with pytest.raises(SSRFError):
        validate_url(url, resolver=_gai(PUBLIC_V4))


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://example.com./x",
        "https://api.example.com:8443/path?q=1",
        "https://8.8.8.8/",
        "https://172.15.0.1/",
        "https://[2606:4700::1111]/",
        "https://[::ffff:8.8.8.8]/",
        "https://bücher.de/",
    ],
)
def test_static_allowed(url):
    assert is_url_safe_static(url) is True


def test_http_allowed_only_with_flag():
    assert is_url_safe_static("http://example.com/") is False
    assert is_url_safe_static("http://example.com/", allow_http=True) is True


def test_allow_private_opt_out():
    assert is_url_safe_static("https://localhost:8443/", allow_private=True)
    assert is_url_safe_static("https://127.0.0.1/", allow_private=True)
    v = validate_url("https://localhost/", allow_private=True, resolver=_gai("127.0.0.1"))
    assert v.addresses == ("127.0.0.1",)
    # allow_private never relaxes scheme or userinfo checks.
    assert not is_url_safe_static("ftp://localhost/", allow_private=True)
    assert not is_url_safe_static("https://a:b@localhost/", allow_private=True)


@pytest.mark.parametrize(
    "ip,blocked",
    [
        ("8.8.8.8", False),
        (PUBLIC_V6, False),
        ("100.64.0.1", True),
        ("127.0.0.1", True),
        ("::ffff:169.254.169.254", True),
        ("64:ff9b::808:808", True),
        ("not-an-ip", True),
    ],
)
def test_is_blocked_ip(ip, blocked):
    assert is_blocked_ip(ip) is blocked


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def test_resolution_returns_pinned_addresses():
    v = validate_url("https://Example.com:8443/x", resolver=_gai(PUBLIC_V4, PUBLIC_V6, PUBLIC_V4))
    assert isinstance(v, ValidatedURL)
    assert v.hostname == "example.com"
    assert v.port == 8443
    assert v.addresses == (PUBLIC_V4, PUBLIC_V6)


@pytest.mark.parametrize(
    "ips",
    [
        ("127.0.0.1",),
        ("10.1.2.3",),
        ("100.64.0.1",),
        ("169.254.169.254",),
        ("::1",),
        ("::ffff:127.0.0.1",),
        ("fe80::1%eth0",),
        (PUBLIC_V4, "127.0.0.1"),  # one bad record poisons the lot
    ],
)
def test_public_name_resolving_internal_rejected(ips):
    with pytest.raises(SSRFError, match="non-public"):
        validate_url("https://evil.example.com/", resolver=_gai(*ips))


def test_resolution_failure_rejected():
    def boom(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, "nope")

    with pytest.raises(SSRFError, match="DNS resolution failed"):
        validate_url("https://nx.example.com/", resolver=boom)
    with pytest.raises(SSRFError, match="did not resolve"):
        validate_url("https://empty.example.com/", resolver=lambda *a, **k: [])


def test_literal_ip_not_resolved():
    def boom(*a, **k):
        raise AssertionError("must not resolve a literal")

    assert validate_url("https://8.8.8.8/", resolver=boom).addresses == ("8.8.8.8",)


@pytest.fixture
def fake_loop_dns(monkeypatch):
    """Stub loop.getaddrinfo; returns the call log. Set .answers to change."""
    calls: list[str] = []
    state = {"answers": [(PUBLIC_V4,)]}

    async def fake(self, host, port, *args, **kwargs):
        calls.append(host)
        answers = state["answers"]
        ips = answers[min(len(calls) - 1, len(answers) - 1)]
        return _gai(*ips)(host, port)

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake)
    calls_obj = type("Calls", (), {})()
    calls_obj.calls = calls
    calls_obj.state = state
    return calls_obj


async def test_async_variant(fake_loop_dns):
    v = await validate_url_async("https://example.com/")
    assert v.addresses == (PUBLIC_V4,)
    fake_loop_dns.state["answers"] = [("10.0.0.1",)]
    with pytest.raises(SSRFError):
        await validate_url_async("https://example.com/")
    with pytest.raises(SSRFError):
        await validate_url_async("https://localhost./")


# ---------------------------------------------------------------------------
# Pinned transport
# ---------------------------------------------------------------------------

async def _start_http_server():
    seen: list[bytes] = []

    async def handle(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        seen.append(data)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, seen


async def test_pinned_transport_dials_pin_and_keeps_host_header():
    server, port, seen = await _start_http_server()
    try:
        pins = ValidatedURL(
            url=f"http://pinned.test:{port}/", scheme="http",
            hostname="pinned.test", port=port, addresses=("127.0.0.1",),
        )
        async with httpx.AsyncClient(
            transport=pinned_async_transport(pins), trust_env=False,
        ) as client:
            resp = await client.get(f"http://pinned.test:{port}/hello")
            assert resp.status_code == 200
            assert resp.text == "ok"
            # A host that was not validated is never dialled.
            with pytest.raises(httpx.ConnectError, match="unpinned"):
                await client.get(f"http://other.test:{port}/")
    finally:
        server.close()
        await server.wait_closed()
    assert len(seen) == 1
    assert b"GET /hello" in seen[0]
    assert f"host: pinned.test:{port}".encode() in seen[0].lower()


class _RecordingStream(httpcore.AsyncNetworkStream):
    def __init__(self, log):
        self.log = log

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.log.append(("tls", server_hostname))
        raise httpcore.ConnectError("stop here")

    async def read(self, max_bytes, timeout=None):  # pragma: no cover
        return b""

    async def write(self, buffer, timeout=None):  # pragma: no cover
        return None

    async def aclose(self):
        return None


@pytest.fixture
def record_dials(monkeypatch):
    log: list[tuple[str, str | None]] = []

    async def fake_connect(self, host, port, timeout=None, local_address=None,
                           socket_options=None):
        log.append(("dial", host))
        return _RecordingStream(log)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", fake_connect)
    return log


# ---------------------------------------------------------------------------
# transport/callback.py — DNS rebinding
# ---------------------------------------------------------------------------

async def test_callback_resolves_once_and_dials_pinned_ip(fake_loop_dns, record_dials):
    from ampro.transport.callback import deliver_callback

    # First answer public, every later answer loopback (rebinding attack).
    fake_loop_dns.state["answers"] = [(PUBLIC_V4,), ("127.0.0.1",)]
    ok = await deliver_callback("https://cb.example.com/hook", {"x": 1}, max_retries=1)
    assert ok is False  # our fake stream aborts the TLS handshake
    assert fake_loop_dns.calls == ["cb.example.com"]
    assert ("dial", PUBLIC_V4) in record_dials
    assert all(entry != ("dial", "127.0.0.1") for entry in record_dials)
    assert all(entry != ("dial", "cb.example.com") for entry in record_dials)
    # TLS SNI / certificate verification still target the real hostname.
    assert ("tls", "cb.example.com") in record_dials


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost./hook",
        "https://0x7f.1/hook",
        "https://100.64.0.1/hook",
        "https://metadata.google.internal/hook",
        "http://cb.example.com/hook",
    ],
)
async def test_callback_rejects_static(url, fake_loop_dns, record_dials):
    from ampro.transport.callback import deliver_callback, validate_callback_url

    assert validate_callback_url(url) is False
    assert await deliver_callback(url, {}, max_retries=1) is False
    assert record_dials == []


async def test_callback_rejects_name_resolving_internal(fake_loop_dns, record_dials):
    from ampro.transport.callback import deliver_callback

    fake_loop_dns.state["answers"] = [("169.254.169.254",)]
    assert await deliver_callback("https://cb.example.com/", {}, max_retries=1) is False
    assert record_dials == []


# ---------------------------------------------------------------------------
# transport/attachment.py
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://localhost./x",
        "https://0x7f.1/x",
        "https://100.64.0.1/x",
        "https://metadata.google.internal/x",
        "https://metadata.google.internal./x",
    ],
)
def test_attachment_url_bypasses_closed(url):
    from ampro.transport.attachment import validate_attachment_url

    assert validate_attachment_url(url) is False


# ---------------------------------------------------------------------------
# client — send / discover / stream
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "uri",
    [
        "agent://127.0.0.1",
        "agent://localhost",
        "agent://10.0.0.5",
        "agent://metadata.google.internal",
    ],
)
async def test_client_send_blocks_internal(uri, fake_loop_dns, record_dials):
    from ampro.client import send

    try:
        await send(uri, body={"q": 1})
    except SSRFError:
        pass
    except ValueError:
        # Some forms are rejected by the agent:// parser itself — also fine.
        pass
    else:  # pragma: no cover
        pytest.fail("send() reached an internal target")
    assert record_dials == []


async def test_client_send_blocks_rebinding_name(fake_loop_dns, record_dials):
    from ampro.client import discover, send, stream

    fake_loop_dns.state["answers"] = [("127.0.0.1",)]
    with pytest.raises(SSRFError):
        await send("agent://evil.example.com", body={})
    with pytest.raises(SSRFError):
        await discover("agent://evil.example.com")
    with pytest.raises(SSRFError):
        async for _ in stream("agent://evil.example.com", task_id="t"):
            pass
    assert record_dials == []


async def test_client_allow_private_opt_out(fake_loop_dns):
    from ampro.client import send

    fake_loop_dns.state["answers"] = [("127.0.0.1",)]
    reply = {
        "sender": "agent://dev.example.com", "recipient": "agent://me.example.com",
        "body_type": "message", "body": {"ok": True},
    }
    with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=httpx.Response(200, json=reply))
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        msg = await send("agent://dev.example.com", body={}, allow_private=True)
    assert msg.body == {"ok": True}
    kwargs = mock_cls.call_args.kwargs
    assert kwargs["follow_redirects"] is False
    assert kwargs["trust_env"] is False


def test_user_agent_tracks_package_version():
    import ampro
    from ampro.client.core import _USER_AGENT

    assert _USER_AGENT == f"ampro-client/{ampro.__version__}"
