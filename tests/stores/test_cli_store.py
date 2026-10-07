"""``ampro-server --store`` / ``AMPRO_REDIS_URL`` wiring."""
from __future__ import annotations

import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.a2a.store import InMemoryTaskStore
from ampro.server import cli
from ampro.stores.redis import RedisRateLimiter, RedisResponseCache, RedisTaskBroker, RedisTaskStore


def _app() -> AgentApp:
    app = AgentApp("agent://cli.example", "https://cli.example")

    @app.on("task.create")
    async def create(msg, ctx):
        return "ok"

    return app


def test_no_store_keeps_in_memory_defaults():
    server = cli.build_server(_app(), ["a2a"])
    assert cli.configure_store(server, None) is None
    assert isinstance(server.adapters[0].store, InMemoryTaskStore)


def test_unsupported_store_scheme_is_refused():
    server = cli.build_server(_app(), [])
    with pytest.raises(SystemExit):
        cli.configure_store(server, "memcached://x")


async def test_store_url_wires_every_component(real_redis_url):
    if real_redis_url is None:
        pytest.skip("redis-server not available")
    server = cli.build_server(_app(), ["a2a", "mcp"])
    backend = cli.configure_store(server, real_redis_url, "clitest")
    try:
        assert isinstance(server.security.rate_limiter, RedisRateLimiter)
        assert isinstance(server.security.dedup, RedisResponseCache)
        a2a, mcp = server.adapters
        assert isinstance(a2a.store, RedisTaskStore) and isinstance(a2a.broker, RedisTaskBroker)
        assert type(mcp.sessions).__name__ == "RedisSessionStore"
        assert mcp.rate_limiter is server.security.rate_limiter
        status, _, _ = await server.route("GET", "/agent/ready")
        assert status == 200
    finally:
        await server.aclose()
    assert backend is not None


def test_env_var_is_the_default(monkeypatch):
    monkeypatch.setenv("AMPRO_REDIS_URL", "redis://example:6379/0")
    seen = {}

    def fake_configure(server, store, prefix=None):
        seen["store"], seen["prefix"] = store, prefix

    monkeypatch.setattr(cli, "configure_store", fake_configure)
    monkeypatch.setattr(cli, "_load_app", lambda _: _app())
    monkeypatch.setattr("ampro.server.core.AgentServer.run", lambda self, **kw: None)
    cli.main(["main:agent"])
    assert seen == {"store": "redis://example:6379/0", "prefix": "ampro"}
