"""Fetching and caching personal-agent JWKS (PACT §3.1, §3.2).

* :class:`JSONFetcher` — the injectable network seam.  The default,
  :class:`HttpsJSONFetcher`, uses :mod:`ampro.security.ssrf`: ``https``
  only, public addresses only, DNS-pinned connection, no redirects, capped
  response size and time (``allow_hosts`` relaxes this for local testing).
* :class:`JWKSCache` — bounded, TTL'd cache keyed by ``jwks_uri`` with
  refetch-on-unknown-``kid`` that is rate limited per URI, so a stream of
  tokens with random ``kid`` values cannot make the Provider hammer a JWKS.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from ampro.interop.pact.stores import BoundedTTLMap, Clock

logger = logging.getLogger("ampro.interop.pact.jwks")

MAX_JWKS_BYTES = 64 * 1024
MAX_KEYS = 32


class FetchError(Exception):
    """A JWKS / discovery document could not be fetched.  Never shown to clients."""


@runtime_checkable
class JSONFetcher(Protocol):
    async def fetch_json(self, url: str) -> Any:
        """GET *url* and return the decoded JSON body; raise :class:`FetchError`."""


class HttpsJSONFetcher:
    """SSRF-safe JSON GETs over HTTPS (via :mod:`ampro.security.ssrf`).

    The URL is validated and its host resolved; every address must be
    publicly routable, and the connection is pinned to the checked
    addresses (no DNS rebinding).  Redirects are never followed, proxies
    from the environment are ignored, and size and time are capped.

    Args:
        timeout: total seconds per request.
        max_bytes: response size cap.
        allow_hosts: hostnames exempt from the https + public-address rules
            (e.g. ``{"127.0.0.1"}`` for a local conformance run).  Never use
            in production.
        transport: optional ``httpx`` transport (tests); URL validation
            still runs, without DNS pinning.
    """

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        max_bytes: int = MAX_JWKS_BYTES,
        allow_hosts: frozenset[str] | set[str] = frozenset(),
        transport: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allow_hosts = frozenset(h.lower() for h in allow_hosts)
        self._transport = transport

    async def fetch_json(self, url: str) -> Any:
        import httpx

        from ampro.security.ssrf import SSRFError, pinned_async_transport, validate_url_async

        host = (urlsplit(url).hostname or "").lower() if isinstance(url, str) else ""
        relaxed = host in self.allow_hosts
        try:
            validated = await validate_url_async(url, allow_http=relaxed, allow_private=relaxed)
        except SSRFError as exc:
            raise FetchError("URL refused") from exc
        transport = self._transport
        if transport is None and not relaxed:
            transport = pinned_async_transport(validated)
        kwargs: dict[str, Any] = {
            "timeout": self.timeout, "follow_redirects": False, "trust_env": False,
        }
        if transport is not None:
            kwargs["transport"] = transport
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                async with client.stream(
                    "GET", url, headers={"Accept": "application/json"}
                ) as resp:
                    if resp.status_code != 200:
                        raise FetchError(f"HTTP {resp.status_code}")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise FetchError("response too large")
                        chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise FetchError("request failed") from exc
        try:
            return json.loads(b"".join(chunks))
        except ValueError as exc:
            raise FetchError("not JSON") from exc


class JWKSCache:
    """Bounded cache of ``jwks_uri -> {kid: jwk}``.

    Args:
        fetcher: network seam (default :class:`HttpsJSONFetcher`).
        ttl: seconds a fetched JWKS is trusted.
        refetch_interval: minimum seconds between fetches of one URI when a
            token names an unknown ``kid``.
        max_entries: number of distinct JWKS URIs cached.
    """

    def __init__(
        self,
        fetcher: JSONFetcher | None = None,
        *,
        ttl: float = 300.0,
        refetch_interval: float = 30.0,
        max_entries: int = 1024,
        clock: Clock = time.time,
    ) -> None:
        self.fetcher = fetcher or HttpsJSONFetcher()
        self.ttl = ttl
        self.refetch_interval = refetch_interval
        self._clock = clock
        self._keys = BoundedTTLMap(max_entries, ttl, clock)
        self._last_fetch = BoundedTTLMap(max_entries, max(ttl, refetch_interval) * 2, clock)
        self._locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _parse(doc: Any) -> list[dict[str, Any]]:
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise FetchError("not a JWKS")
        keys = [k for k in doc["keys"][:MAX_KEYS] if isinstance(k, dict) and "kty" in k]
        return [{k: v for k, v in key.items() if k not in ("d", "p", "q", "dp", "dq", "qi")}
                for key in keys]

    async def _fetch(self, uri: str) -> list[dict[str, Any]]:
        lock = self._locks.setdefault(uri, asyncio.Lock())
        if len(self._locks) > 4096:  # keep the lock table bounded too
            self._locks = {uri: lock}
        async with lock:
            last = self._last_fetch.get(uri)
            cached = self._keys.get(uri)
            if cached is not None and last is not None and self._clock() - last < self.refetch_interval:
                return cached
            self._last_fetch.set(uri, self._clock())
            try:
                keys = self._parse(await self.fetcher.fetch_json(uri))
            except FetchError as exc:
                logger.warning("pact.jwks.fetch_failed", extra={"jwks_uri": uri, "reason": str(exc)})
                if cached is not None:
                    return cached
                raise
            self._keys.set(uri, keys)
            return keys

    async def keys(self, uri: str, kid: str | None) -> list[dict[str, Any]]:
        """Candidate keys for *kid* (all keys when *kid* is ``None``)."""
        keys = self._keys.get(uri)
        if keys is None:
            keys = await self._fetch(uri)
        matched = _match(keys, kid)
        if not matched and kid is not None:
            keys = await self._fetch(uri)  # rate limited inside
            matched = _match(keys, kid)
        return matched

    def has(self, uri: str) -> bool:
        return self._keys.get(uri) is not None

    def put(self, uri: str, jwks: dict[str, Any]) -> None:
        """Seed the cache (e.g. a statically configured JWKS)."""
        self._keys.set(uri, self._parse(jwks), ttl=10 * 365 * 24 * 3600)
        self._last_fetch.set(uri, self._clock())


def _match(keys: list[dict[str, Any]], kid: str | None) -> list[dict[str, Any]]:
    if kid is None:
        return keys
    return [k for k in keys if k.get("kid") == kid]


__all__ = ["FetchError", "HttpsJSONFetcher", "JSONFetcher", "JWKSCache", "MAX_JWKS_BYTES"]
