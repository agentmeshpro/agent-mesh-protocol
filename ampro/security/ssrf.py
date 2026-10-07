"""
Agent Protocol — Shared SSRF guard.

One place for every "is it safe to make an outbound request to this URL?"
decision in the SDK.

Two levels of checking are provided:

* :func:`check_url_static` / :func:`is_url_safe_static` — pure, no network
  I/O.  Parses the URL, rejects bad schemes, userinfo, internal hostnames
  (``localhost``, ``*.internal``, ``metadata.google.internal`` …) and
  literal IP addresses in a blocked range, including the numeric forms
  accepted by ``inet_aton`` (``0x7f.1``, ``2130706433``, ``0177.0.0.1``).
  Suitable for model validators.

* :func:`validate_url` / :func:`validate_url_async` — everything above,
  then RESOLVES the hostname and checks every returned address.  The
  returned :class:`ValidatedURL` carries the pinned address list.

A resolved-then-checked URL is only safe if the connection is made to the
address that was checked; otherwise the HTTP client re-resolves the name
and a DNS-rebinding attacker can swap in ``127.0.0.1``.
:func:`pinned_async_transport` builds an ``httpx`` transport that dials only
the pinned addresses while keeping the ``Host`` header and TLS SNI /
certificate verification bound to the original hostname.

``httpx`` / ``httpcore`` are imported lazily — they are optional
dependencies of ``ampro``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

__all__ = [
    "SSRFError",
    "ValidatedURL",
    "is_blocked_ip",
    "parse_ip_literal",
    "check_url_static",
    "is_url_safe_static",
    "validate_url",
    "validate_url_async",
    "pinned_async_transport",
]


class SSRFError(ValueError):
    """Raised when a URL is not safe to request."""


@dataclass(frozen=True)
class ValidatedURL:
    """A URL that passed the SSRF guard.

    Attributes:
        url: The original URL string.
        scheme: ``"http"`` or ``"https"``.
        hostname: Lower-cased hostname as it appears in the URL (IPv6
            without brackets).  This is the name used for the ``Host``
            header and TLS SNI.
        port: Explicit port or the scheme default.
        addresses: The resolved IP addresses (as strings) that were checked.
            Connections MUST be made to one of these.
    """

    url: str
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_IPV4_COMPAT = ipaddress.ip_network("::/96")


def is_blocked_ip(addr: IPAddress | str) -> bool:
    """Return True if *addr* must not be contacted (internal / non-routable).

    IPv4: private, loopback, link-local, multicast, reserved, unspecified,
    CGNAT ``100.64.0.0/10`` and anything else that is not globally routable.

    IPv6: the same flags plus site-local; IPv4-mapped addresses are judged by
    their embedded IPv4 address; IPv4-compatible (``::a.b.c.d``), 6to4
    (``2002::/16``), Teredo (``2001::/32``) and NAT64 (``64:ff9b::/96``)
    addresses are always blocked because they tunnel to an IPv4 address
    the caller does not control.
    """
    if isinstance(addr, str):
        try:
            addr = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            return True

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_blocked_ip(addr.ipv4_mapped)
        if addr in _IPV4_COMPAT:
            return True  # ::, ::1 and deprecated ::a.b.c.d
        if addr.sixtofour is not None or addr.teredo is not None:
            return True
        if any(addr in net for net in _NAT64):
            return True
        if addr.is_site_local:
            return True

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT:
        return True
    return not addr.is_global


# ---------------------------------------------------------------------------
# Host parsing
# ---------------------------------------------------------------------------

_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
})
# Any hostname ending in one of these labels is internal by definition.
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".internal",
    ".local",
    ".localdomain",
    ".home.arpa",
)
_HOST_CHARS_RE = re.compile(r"^[a-z0-9._-]+$")
_NUMERIC_PART_RE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


def _parse_inet_aton_part(part: str) -> int:
    if part.startswith("0x"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8)  # raises ValueError on 8/9 digits
    return int(part, 10)


def _parse_ipv4_loose(host: str) -> ipaddress.IPv4Address | None:
    """Parse *host* using ``inet_aton`` semantics.

    Accepts 1–4 dot-separated parts, each decimal, ``0x`` hex or
    ``0``-prefixed octal; the last part fills all remaining bytes
    (``127.1`` → ``127.0.0.1``, ``2130706433`` → ``127.0.0.1``).

    Returns None if *host* does not look numeric at all.  Raises
    :class:`SSRFError` if it looks numeric but is malformed / out of range
    (resolver behaviour for such strings is platform-dependent).
    """
    parts = host.split(".")
    if not all(_NUMERIC_PART_RE.match(p) for p in parts):
        return None
    if len(parts) > 4:
        raise SSRFError(f"Malformed numeric host: {host!r}")
    try:
        values = [_parse_inet_aton_part(p) for p in parts]
    except ValueError as exc:
        raise SSRFError(f"Malformed numeric host: {host!r}") from exc
    *head, last = values
    if any(v > 0xFF for v in head):
        raise SSRFError(f"Malformed numeric host: {host!r}")
    if last >= 1 << (8 * (4 - len(head))):
        raise SSRFError(f"Malformed numeric host: {host!r}")
    value = 0
    for v in head:
        value = (value << 8) | v
    value = (value << (8 * (4 - len(head)))) | last
    return ipaddress.IPv4Address(value)


def parse_ip_literal(host: str) -> IPAddress | None:
    """Return the IP address *host* denotes, or None if it is a DNS name.

    Handles IPv6 literals (with or without brackets / zone ID) and every
    IPv4 spelling accepted by ``inet_aton``.  Raises :class:`SSRFError` for
    malformed numeric hosts.
    """
    h = host.strip("[]")
    if ":" in h:
        try:
            return ipaddress.IPv6Address(h.split("%", 1)[0])
        except ValueError as exc:
            raise SSRFError(f"Malformed IPv6 host: {host!r}") from exc
    return _parse_ipv4_loose(h.rstrip(".") if h != "." else h)


@dataclass(frozen=True)
class _ParsedURL:
    scheme: str
    hostname: str        # as used for Host/SNI (lower-case, no brackets)
    port: int
    literal_ip: IPAddress | None


def _parse(url: str, *, allow_http: bool, allow_private: bool) -> _ParsedURL:
    if not isinstance(url, str) or not url:
        raise SSRFError("URL must be a non-empty string")
    if any(c in url for c in "\r\n\t\x00 \\"):
        raise SSRFError("URL contains forbidden characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise SSRFError(f"Unparseable URL: {exc}") from exc

    scheme = parts.scheme.lower()
    allowed = ("https", "http") if allow_http else ("https",)
    if scheme not in allowed:
        raise SSRFError(f"Scheme {scheme or '(none)'!r} not allowed")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise SSRFError("URLs with userinfo are not allowed")

    raw_host = parts.hostname or ""
    if "%" in raw_host and ":" not in raw_host:
        # Percent-encoded DNS names are never legitimate (``127%2e0%2e0%2e1``).
        raise SSRFError("Percent-encoded hostnames are not allowed")
    host = unquote(raw_host).lower()
    if not host:
        raise SSRFError("URL has no hostname")
    if not host.isascii() and ":" not in host:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SSRFError(f"Invalid internationalised hostname: {host!r}") from exc

    literal = parse_ip_literal(host)
    if literal is None:
        if not _HOST_CHARS_RE.match(host) or ".." in host or host.startswith("."):
            raise SSRFError(f"Invalid hostname: {host!r}")
        bare = host.rstrip(".")
        if not bare:
            raise SSRFError(f"Invalid hostname: {host!r}")
        last_label = bare.rsplit(".", 1)[-1]
        if _NUMERIC_PART_RE.match(last_label):
            # WHATWG treats a numeric final label as IPv4; refuse ambiguity.
            raise SSRFError(f"Ambiguous numeric hostname: {host!r}")
        if not allow_private and (
            bare in _BLOCKED_HOSTNAMES or bare.endswith(_BLOCKED_SUFFIXES)
        ):
            raise SSRFError(f"Hostname {host!r} is internal")
    elif not allow_private and is_blocked_ip(literal):
        raise SSRFError(f"Address {literal} is not publicly routable")

    if port is None:
        port = 443 if scheme == "https" else 80
    hostname = str(literal) if literal is not None else host
    return _ParsedURL(scheme=scheme, hostname=hostname, port=port, literal_ip=literal)


def check_url_static(
    url: str, *, allow_http: bool = False, allow_private: bool = False,
) -> None:
    """Validate *url* without touching the network.  Raises :class:`SSRFError`.

    This catches literal IPs and internal names but NOT public names that
    resolve to internal addresses — use :func:`validate_url` immediately
    before connecting.
    """
    _parse(url, allow_http=allow_http, allow_private=allow_private)


def is_url_safe_static(
    url: str, *, allow_http: bool = False, allow_private: bool = False,
) -> bool:
    """Boolean form of :func:`check_url_static`."""
    try:
        _parse(url, allow_http=allow_http, allow_private=allow_private)
    except SSRFError:
        return False
    return True


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def _check_resolved(
    parsed: _ParsedURL, infos: Iterable[Any], allow_private: bool,
) -> tuple[str, ...]:
    addrs: list[str] = []
    for info in infos:
        ip_str = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFError(f"Resolver returned a non-IP address {ip_str!r}") from exc
        if not allow_private and is_blocked_ip(ip):
            raise SSRFError(
                f"Host {parsed.hostname!r} resolves to non-public address {ip}"
            )
        if str(ip) not in addrs:
            addrs.append(str(ip))
    if not addrs:
        raise SSRFError(f"Host {parsed.hostname!r} did not resolve")
    return tuple(addrs)


def validate_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
    resolver: Callable[..., Sequence[Any]] | None = None,
) -> ValidatedURL:
    """Fully validate *url* and resolve its host.

    Every address the host resolves to must be publicly routable — one
    internal record is enough to reject the URL.

    Args:
        url: The URL to check.
        allow_http: Also accept ``http://`` (default: HTTPS only).
        allow_private: Skip the internal-host / internal-IP checks.  For
            local development only.
        resolver: ``getaddrinfo``-compatible callable (defaults to
            :func:`socket.getaddrinfo`).

    Returns:
        A :class:`ValidatedURL` whose ``addresses`` must be used for the
        connection (see :func:`pinned_async_transport`).

    Raises:
        SSRFError: The URL is unsafe or the host could not be resolved.
    """
    parsed = _parse(url, allow_http=allow_http, allow_private=allow_private)
    if parsed.literal_ip is not None:
        addrs: tuple[str, ...] = (str(parsed.literal_ip),)
    else:
        resolve = resolver or socket.getaddrinfo
        try:
            infos = resolve(parsed.hostname, parsed.port, 0, socket.SOCK_STREAM)
        except (OSError, UnicodeError) as exc:
            raise SSRFError(f"DNS resolution failed for {parsed.hostname!r}: {exc}") from exc
        addrs = _check_resolved(parsed, infos, allow_private)
    return ValidatedURL(
        url=url, scheme=parsed.scheme, hostname=parsed.hostname,
        port=parsed.port, addresses=addrs,
    )


async def validate_url_async(
    url: str, *, allow_http: bool = False, allow_private: bool = False,
) -> ValidatedURL:
    """Async variant of :func:`validate_url` using ``loop.getaddrinfo``."""
    parsed = _parse(url, allow_http=allow_http, allow_private=allow_private)
    if parsed.literal_ip is not None:
        addrs: tuple[str, ...] = (str(parsed.literal_ip),)
    else:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                parsed.hostname, parsed.port, type=socket.SOCK_STREAM,
            )
        except (OSError, UnicodeError) as exc:
            raise SSRFError(f"DNS resolution failed for {parsed.hostname!r}: {exc}") from exc
        addrs = _check_resolved(parsed, infos, allow_private)
    return ValidatedURL(
        url=url, scheme=parsed.scheme, hostname=parsed.hostname,
        port=parsed.port, addresses=addrs,
    )


# ---------------------------------------------------------------------------
# Pinned httpx transport
# ---------------------------------------------------------------------------

_PINNED_CLASSES: dict[str, Any] = {}


def _pinned_backend_class() -> Any:
    if "backend" in _PINNED_CLASSES:
        return _PINNED_CLASSES["backend"]
    import httpcore

    class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
        """Network backend that dials only pre-validated IP addresses.

        httpcore calls ``connect_tcp(host=<url host>)`` and later
        ``start_tls(server_hostname=<url host>)``, so swapping the address
        here leaves SNI and certificate verification on the real hostname.
        Hosts that are not in the pin map (e.g. a redirect target or an
        environment proxy) are refused.
        """

        def __init__(self, pins: Mapping[str, Sequence[str]]) -> None:
            self._pins = {k.lower().strip("[]"): tuple(v) for k, v in pins.items()}
            self._inner = httpcore.AnyIOBackend()

        async def connect_tcp(
            self, host: str, port: int, timeout: float | None = None,
            local_address: str | None = None, socket_options: Any = None,
        ) -> Any:
            ips = self._pins.get(host.lower().strip("[]"))
            if not ips:
                raise httpcore.ConnectError(
                    f"Refusing to connect to unpinned host {host!r}"
                )
            last_exc: Exception | None = None
            for ip in ips:
                try:
                    return await self._inner.connect_tcp(
                        ip, port, timeout=timeout,
                        local_address=local_address, socket_options=socket_options,
                    )
                except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                    last_exc = exc
            assert last_exc is not None
            raise last_exc

        async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
            raise httpcore.ConnectError("Unix sockets are not allowed")

        async def sleep(self, seconds: float) -> None:
            await self._inner.sleep(seconds)

    _PINNED_CLASSES["backend"] = PinnedNetworkBackend
    return PinnedNetworkBackend


def pinned_async_transport(
    pins: ValidatedURL | Mapping[str, Sequence[str]],
    *,
    verify: Any = True,
) -> Any:
    """Return an ``httpx.AsyncHTTPTransport`` that only dials pinned IPs.

    Args:
        pins: A :class:`ValidatedURL`, or a mapping of hostname → IP list.
        verify: ``True``, a CA bundle path, or an ``ssl.SSLContext``
            (passed to ``httpx.create_ssl_context``).

    Use it with ``httpx.AsyncClient(transport=..., trust_env=False,
    follow_redirects=False)`` — ``trust_env=False`` stops an environment
    proxy from being mounted in front of the pinned transport.
    """
    import httpcore
    import httpx

    if isinstance(pins, ValidatedURL):
        pins = {pins.hostname: pins.addresses}
    backend = _pinned_backend_class()(pins)

    ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
    transport = httpx.AsyncHTTPTransport(verify=ssl_context, trust_env=False)
    # httpx does not expose ``network_backend``; swap in an equivalent pool
    # that uses the pinned backend.
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        network_backend=backend,
    )
    return transport
