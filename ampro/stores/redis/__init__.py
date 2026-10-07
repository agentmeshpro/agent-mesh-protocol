"""Redis backend for every ampro store (``pip install 'ampro[redis]'``).

One call makes an :class:`~ampro.server.core.AgentServer` and everything
mounted on it share state through Redis, so any number of worker
processes / machines behind a load balancer behave like one server::

    from ampro.stores.redis import configure

    server = AgentServer.from_app(agent)
    server.mount(A2AAdapter.for_server(server))
    configure(server, url="redis://redis:6379/0", prefix="weather-agent")

or from the command line: ``ampro-server main:agent --store redis://...``
(``AMPRO_REDIS_URL`` works too).

Synchronous protocols (replay cache, rate / concurrency limits, ...) use
the sync ``redis`` client; the async ones use ``redis.asyncio``.  Keys are
``{prefix}:...``; use one prefix per agent deployment.  Values are JSON,
size-checked, and every key has a TTL except the ones that are explicit
configuration (revocations, API keys, personal-agent registrations).

Needs Redis >= 6.2 (``GETDEL``) — a single node or Sentinel.  For Redis
Cluster put the whole keyspace in one slot with a hash-tag prefix such as
``{ampro}`` (Lua scripts touch several keys).  See ``docs/SCALING.md``.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ampro.stores.redis._base import Keyspace, key_part, require_redis
from ampro.stores.redis.a2a import (
    RedisContextStore,
    RedisIdempotencyStore,
    RedisTaskBroker,
    RedisTaskStore,
)
from ampro.stores.redis.security import (
    RedisApiKeyFailureTracker,
    RedisApiKeyValidator,
    RedisChannelRegistry,
    RedisConcurrencyLimiter,
    RedisFederationNonceCache,
    RedisNonceTracker,
    RedisRateLimiter,
    RedisRevocationStore,
    RedisSenderTracker,
)
from ampro.stores.redis.server import RedisDedupStore, RedisResponseCache

logger = logging.getLogger("ampro.stores.redis")

ENV_URL = "AMPRO_REDIS_URL"
ENV_PREFIX = "AMPRO_REDIS_PREFIX"


class RedisBackend:
    """A pair of Redis clients (sync + asyncio) and a key prefix.

    Pass *url*, or ready-made *client* / *async_client* (e.g. fakeredis
    in tests, or clients with your own TLS / pool settings).
    """

    def __init__(self, url: str | None = None, *, prefix: str = "ampro",
                 client: Any = None, async_client: Any = None) -> None:
        if client is None or async_client is None:
            if not url:
                raise ValueError("configure() needs url=... or both client= and async_client=")
            redis = require_redis()
            import redis.asyncio as aioredis

            if client is None:
                client = redis.Redis.from_url(url)
            if async_client is None:
                async_client = aioredis.Redis.from_url(url)
        self.client = client
        self.async_client = async_client
        self.prefix = Keyspace(prefix).prefix
        self._owns_clients = url is not None

    async def ping(self) -> bool:
        return bool(await self.async_client.ping())

    async def aclose(self) -> None:
        if not self._owns_clients:
            return
        close = getattr(self.async_client, "aclose", None) or self.async_client.close
        await close()
        self.client.close()

    # -- factories ------------------------------------------------------

    def a2a_stores(self, namespace: str) -> dict[str, Any]:
        """``A2AAdapter`` keyword arguments for one A2A interface."""
        c, p = self.async_client, self.prefix
        return {
            "task_store": RedisTaskStore(c, prefix=p, namespace=namespace),
            "context_store": RedisContextStore(c, prefix=p, namespace=namespace),
            "idempotency_store": RedisIdempotencyStore(c, prefix=p, namespace=namespace),
            "task_broker": RedisTaskBroker(c, prefix=p, namespace=namespace),
        }


def _namespace(kind: str, path: str) -> str:
    """``a2a`` + base path, as a safe key part (``/a2a/x`` -> ``a2a.a2a.x``)."""
    parts = [kind, *(p for p in path.split("/") if p)]
    return key_part(".".join(parts))


def configure(server: Any, url: str | None = None, *, prefix: str = "ampro",
              client: Any = None, async_client: Any = None,
              process_globals: bool = True,
              allow_ephemeral_keys: bool = False) -> RedisBackend:
    """Point every store of *server* (and its mounted adapters) at Redis.

    Replaces each **in-memory default** with its Redis implementation,
    keeping the configured limits; stores you plugged in yourself are left
    alone.  Covers the native AMP route (rate limit, concurrency, dedup,
    RFC 9421 nonces), A2A adapters (tasks, contexts, idempotent replies,
    the cross-worker task broker), MCP adapters (sessions) and a PACT
    provider (delegation stores, contexts, receipts, PA-JWT/brand-login
    replay stores, attempt limiters, per-Brand A2A state).

    With *process_globals* (default) it also installs the process-wide
    hooks: the default RFC 9421 replay cache, the DID-proof ``jti`` cache,
    API-key brute-force tracking, the federation nonce cache and — when
    none was registered — a shared key-revocation store.

    A readiness check (``GET /agent/ready``) pinging Redis and a shutdown
    callback closing the clients are registered on *server*.

    Raises ``ValueError`` if a mounted PACT provider signs with an
    ephemeral (per-process) key — tokens it issues would only verify on
    the worker that minted them — unless *allow_ephemeral_keys*.
    """
    backend = RedisBackend(url, prefix=prefix, client=client, async_client=async_client)
    # Old in-memory limiter -> its Redis replacement, so adapters that
    # copied the server's limiter at construction (MCP) follow along.
    swapped: dict[int, Any] = {}
    _configure_policy(server.security, backend, swapped)

    if process_globals:
        _configure_globals(backend)

    for adapter in server.adapters:
        _configure_adapter(adapter, backend, swapped, allow_ephemeral_keys)

    server.readiness_checks.append(backend.ping)
    server.shutdown_callbacks.append(backend.aclose)
    logger.info("ampro state shared through Redis (prefix %r)", backend.prefix)
    return backend


def _configure_policy(policy: Any, backend: RedisBackend, swapped: dict[int, Any]) -> None:
    from ampro.security.concurrency_limiter import ConcurrencyLimiter
    from ampro.security.nonce_tracker import NonceTracker
    from ampro.security.rate_limiter import RateLimiter
    from ampro.server.auth import SignatureAuthenticator
    from ampro.server.security import InMemoryResponseCache

    sync, aio, p = backend.client, backend.async_client, backend.prefix
    old = policy.rate_limiter
    if isinstance(old, RateLimiter):
        policy.rate_limiter = RedisRateLimiter(sync, prefix=p, rpm=old._rpm,
                                               window_seconds=old._window)
        swapped[id(old)] = policy.rate_limiter
    old = policy.concurrency
    if isinstance(old, ConcurrencyLimiter):
        policy.concurrency = RedisConcurrencyLimiter(
            sync, prefix=p, max_total=old._max_total,
            per_sender_pct=old._per_sender_max / old._max_total,
            slot_ttl_seconds=old._slot_ttl if old._slot_ttl > 0 else 600.0)
        policy.concurrency.per_sender_max = old._per_sender_max
        swapped[id(old)] = policy.concurrency
    if isinstance(policy.dedup, InMemoryResponseCache):
        policy.dedup = RedisResponseCache(aio, prefix=p, ttl_seconds=policy.dedup._ttl)
    for auth in policy.authenticators:
        if isinstance(auth, SignatureAuthenticator):
            tracker = auth._nonce_tracker
            if tracker is None or isinstance(tracker, NonceTracker):
                window = tracker._window if isinstance(tracker, NonceTracker) else 3600
                auth._nonce_tracker = RedisNonceTracker(sync, prefix=p, namespace="rfc9421",
                                                        window_seconds=window)


def _configure_globals(backend: RedisBackend) -> None:
    from ampro.registry.federation import register_federation_nonce_cache
    from ampro.security import key_revocation
    from ampro.security.rfc9421 import set_default_nonce_tracker
    from ampro.trust import resolver

    sync, p = backend.client, backend.prefix
    set_default_nonce_tracker(RedisNonceTracker(sync, prefix=p, namespace="rfc9421"))
    did_window = resolver.DID_PROOF_MAX_LIFETIME_SECONDS + 2 * resolver.CLOCK_SKEW_SECONDS
    resolver.set_did_proof_nonce_tracker(
        RedisNonceTracker(sync, prefix=p, namespace="didproof", window_seconds=did_window))
    resolver.set_api_key_failure_tracker(RedisApiKeyFailureTracker(sync, prefix=p))
    register_federation_nonce_cache(RedisFederationNonceCache(sync, prefix=p))
    if isinstance(key_revocation._revocation_store, key_revocation._UnconfiguredRevocationStore):
        key_revocation.register_revocation_store(RedisRevocationStore(sync, prefix=p))


def _configure_adapter(adapter: Any, backend: RedisBackend, swapped: dict[int, Any],
                       allow_ephemeral_keys: bool) -> None:
    for attr in ("rate_limiter", "concurrency"):
        current = getattr(adapter, attr, None)
        if current is not None and id(current) in swapped:
            setattr(adapter, attr, swapped[id(current)])

    kind = type(adapter).__name__
    if kind == "A2AAdapter":
        _replace_a2a(adapter, backend.a2a_stores(_namespace("a2a", adapter.base_path)))
    elif kind == "MCPAdapter":
        from ampro.interop.mcp.server import InMemorySessionStore
        from ampro.stores.redis.mcp import RedisSessionStore

        old = adapter.sessions
        if isinstance(old, InMemorySessionStore):
            adapter.sessions = RedisSessionStore(
                backend.async_client, prefix=backend.prefix,
                namespace=_namespace("mcp", adapter.path),
                max_sessions=max(old.max_sessions, 1), idle_timeout=old.idle_timeout,
                max_lifetime=old.max_lifetime,
                max_sessions_per_owner=old.max_sessions_per_owner)
    elif kind == "PACTProvider":
        _configure_pact(adapter, backend, swapped, allow_ephemeral_keys)


def _configure_pact(provider: Any, backend: RedisBackend, swapped: dict[int, Any],
                    allow_ephemeral_keys: bool) -> None:
    from ampro.interop.pact import stores as mem
    from ampro.stores.redis import pact as rp

    aio, p = backend.async_client, backend.prefix
    keys = getattr(provider, "keys", None)
    if keys is not None and getattr(keys, "ephemeral", False) and not allow_ephemeral_keys:
        raise ValueError(
            "PACT provider uses an ephemeral signing key: delegation tokens and receipts "
            "would only verify on the worker that issued them. Load the same key set in "
            "every worker (PACT_PROVIDER_JWKS / ProviderKeySet.from_env()) or pass "
            "allow_ephemeral_keys=True."
        )
    clock = provider.clock
    auth = provider.authenticator
    if isinstance(auth.replay_store, mem.InMemoryNonceStore):
        auth.replay_store = rp.RedisNonceStore(aio, prefix=p, clock=clock)
    if isinstance(provider.contexts, mem.InMemoryContextStore):
        provider.contexts = rp.RedisPactContextStore(aio, prefix=p, clock=clock)
    if isinstance(provider.receipts, mem.InMemoryReceiptStore):
        provider.receipts = rp.RedisReceiptStore(aio, prefix=p, clock=clock)

    delegation = provider.delegation
    if delegation is not None:
        s = delegation.stores
        if isinstance(s.devices, mem.InMemoryDeviceAuthorizationStore):
            s.devices = rp.RedisDeviceAuthorizationStore(aio, prefix=p, clock=clock)
        if isinstance(s.grants, mem.InMemoryGrantStore):
            s.grants = rp.RedisGrantStore(aio, prefix=p, clock=clock)
        if isinstance(s.refresh_tokens, mem.InMemoryRefreshTokenStore):
            s.refresh_tokens = rp.RedisRefreshTokenStore(aio, prefix=p, clock=clock)
        if isinstance(s.consent_sessions, mem.InMemoryConsentSessionStore):
            s.consent_sessions = rp.RedisConsentSessionStore(aio, prefix=p, clock=clock)
        if isinstance(s.nonces, mem.InMemoryNonceStore):
            s.nonces = rp.RedisNonceStore(aio, prefix=p, clock=clock)
        if isinstance(s.user_code_attempts, mem.InMemoryAttemptLimiter):
            old = s.user_code_attempts
            s.user_code_attempts = rp.RedisAttemptLimiter(
                aio, old.limit, old.window, prefix=p, name="user_code", clock=clock)
        for attr in ("start_limiter", "client_limiter"):
            old = getattr(delegation, attr)
            if isinstance(old, mem.InMemoryAttemptLimiter):
                setattr(delegation, attr, rp.RedisAttemptLimiter(
                    aio, old.limit, old.window, prefix=p, name=attr, clock=clock))

    def brand_stores(brand_id: str) -> dict[str, Any]:
        return backend.a2a_stores(_namespace("pact", brand_id))

    if provider.a2a_stores is None:
        provider.a2a_stores = brand_stores
    for brand_id, hosted in list(provider._brands.items()):
        stores = provider.a2a_stores(brand_id)
        _replace_a2a(hosted.adapter, stores)
        login = getattr(hosted.brand, "login", None)
        if login is not None and isinstance(getattr(login, "nonces", None), mem.InMemoryNonceStore):
            login.nonces = rp.RedisNonceStore(aio, prefix=p, clock=clock)


def _replace_a2a(adapter: Any, stores: dict[str, Any]) -> None:
    """Swap an A2A adapter's in-memory defaults for *stores*."""
    from ampro.interop.a2a.store import (
        InMemoryContextStore,
        InMemoryIdempotencyStore,
        InMemoryTaskBroker,
        InMemoryTaskStore,
    )

    if isinstance(adapter.store, InMemoryTaskStore):
        adapter.store = stores["task_store"]
    if isinstance(adapter.contexts, InMemoryContextStore):
        adapter.contexts = stores["context_store"]
    if isinstance(adapter.replies, InMemoryIdempotencyStore):
        adapter.replies = stores["idempotency_store"]
    if isinstance(adapter.broker, InMemoryTaskBroker):
        adapter.broker = stores["task_broker"]


def url_from_env() -> str | None:
    """``AMPRO_REDIS_URL`` if set (the CLI's ``--store`` default)."""
    return os.environ.get(ENV_URL) or None


__all__ = [
    "ENV_PREFIX",
    "ENV_URL",
    "RedisApiKeyFailureTracker",
    "RedisApiKeyValidator",
    "RedisBackend",
    "RedisChannelRegistry",
    "RedisConcurrencyLimiter",
    "RedisContextStore",
    "RedisDedupStore",
    "RedisFederationNonceCache",
    "RedisIdempotencyStore",
    "RedisNonceTracker",
    "RedisRateLimiter",
    "RedisResponseCache",
    "RedisRevocationStore",
    "RedisSenderTracker",
    "RedisTaskBroker",
    "RedisTaskStore",
    "configure",
    "url_from_env",
]
