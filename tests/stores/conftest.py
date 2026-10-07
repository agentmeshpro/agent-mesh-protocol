"""Redis fixtures: fakeredis always, a real ``redis-server`` when one exists.

``redis_backend`` is parametrized over ``fake`` and ``real``.  The real
variant starts a throwaway ``redis-server`` on a free port (or uses
``AMPRO_TEST_REDIS_URL``) and is skipped cleanly when neither is available.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any

import pytest

# Optional dependencies: every test that needs one skips cleanly without it.
try:
    import redis
    import redis.asyncio as aioredis
except ImportError:  # pragma: no cover
    redis = aioredis = None
try:
    import fakeredis
    import lupa  # noqa: F401  (fakeredis Lua support)
except ImportError:  # pragma: no cover
    fakeredis = None


@dataclass
class Backend:
    kind: str
    client: Any
    async_client: Any
    prefix: str
    url: str | None = None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def real_redis_url():
    url = os.environ.get("AMPRO_TEST_REDIS_URL")
    if redis is None:
        yield None
        return
    if url:
        yield url
        return
    binary = shutil.which("redis-server")
    if binary is None:
        yield None
        return
    port = _free_port()
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"redis://127.0.0.1:{port}/0"
    client = redis.Redis.from_url(url)
    deadline = time.time() + 10
    while True:
        try:
            client.ping()
            break
        except redis.exceptions.ConnectionError:
            if time.time() > deadline or proc.poll() is not None:
                proc.kill()
                yield None
                return
            time.sleep(0.05)
    client.close()
    try:
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(params=["fake", "real"])
async def redis_backend(request, real_redis_url):
    prefix = "t" + uuid.uuid4().hex[:12]
    if request.param == "fake":
        if fakeredis is None:
            pytest.skip("fakeredis[lua] not installed")
        server = fakeredis.FakeServer()
        sync = fakeredis.FakeRedis(server=server)
        aio = fakeredis.aioredis.FakeRedis(server=server)
        yield Backend("fake", sync, aio, prefix)
        await aio.aclose()
        return
    if real_redis_url is None:
        pytest.skip("redis-server not available (set AMPRO_TEST_REDIS_URL to use one)")
    sync = redis.Redis.from_url(real_redis_url)
    aio = aioredis.Redis.from_url(real_redis_url)
    yield Backend("real", sync, aio, prefix, real_redis_url)
    for key in sync.scan_iter(match=f"{prefix}:*", count=1000):
        sync.delete(key)
    await aio.aclose()
    sync.close()


@pytest.fixture(autouse=True)
def _restore_process_globals():
    """``configure()`` installs process-wide hooks; put the defaults back."""
    from ampro.registry import federation
    from ampro.security import key_revocation, rfc9421
    from ampro.trust import resolver

    saved = (
        rfc9421._DEFAULT_NONCE_TRACKER,
        resolver._DID_PROOF_NONCE_TRACKER,
        resolver._api_key_store,
        federation._FEDERATION_NONCES,
        key_revocation._revocation_store,
    )
    yield
    (
        rfc9421._DEFAULT_NONCE_TRACKER,
        resolver._DID_PROOF_NONCE_TRACKER,
        resolver._api_key_store,
        federation._FEDERATION_NONCES,
        key_revocation._revocation_store,
    ) = saved
