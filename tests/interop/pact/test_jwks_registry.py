"""JWKS fetching/caching, the registry, open mode and SSRF-safe fetching."""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from ampro.interop.pact import (
    HttpsJSONFetcher,
    InMemoryPersonalAgentRegistry,
    JWKSCache,
    PAJwtAuthenticator,
    PersonalAgentRegistration,
)
from ampro.interop.pact.jwks import FetchError
from ampro.server.auth import Unauthorized

from .conftest import AUDIENCE, ISSUER, FakeClock, PAKey


class CountingFetcher:
    def __init__(self, docs: dict[str, Any]) -> None:
        self.docs = docs
        self.calls: list[str] = []

    async def fetch_json(self, url: str) -> Any:
        self.calls.append(url)
        doc = self.docs.get(url)
        if doc is None:
            raise FetchError("404")
        return doc


JWKS_URI = "https://pa.example/jwks.json"


async def test_jwks_fetched_once_and_cached(clock):
    pa = PAKey()
    fetcher = CountingFetcher({JWKS_URI: pa.jwks})
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks_uri=JWKS_URI)])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, http_client=fetcher, clock=clock)
    for _ in range(5):
        await auth.verify(pa.token(clock))
    assert fetcher.calls == [JWKS_URI]


async def test_unknown_kid_refetch_is_rate_limited(clock):
    pa = PAKey()
    fetcher = CountingFetcher({JWKS_URI: pa.jwks})
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks_uri=JWKS_URI)])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, http_client=fetcher, clock=clock)
    await auth.verify(pa.token(clock))
    for i in range(20):
        with pytest.raises(Unauthorized):
            await auth.verify(PAKey(kid=f"random-{i}").token(clock))
    assert len(fetcher.calls) == 1  # within the 30 s refetch window
    clock.advance(31)
    with pytest.raises(Unauthorized):
        await auth.verify(PAKey(kid="later").token(clock))
    assert len(fetcher.calls) == 2


async def test_key_rotation_picked_up_on_unknown_kid(clock):
    old, new = PAKey(), PAKey()
    fetcher = CountingFetcher({JWKS_URI: old.jwks})
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks_uri=JWKS_URI)])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, http_client=fetcher, clock=clock)
    await auth.verify(old.token(clock))
    fetcher.docs[JWKS_URI] = {"keys": old.jwks["keys"] + new.jwks["keys"]}
    clock.advance(31)
    await auth.verify(new.token(clock))


async def test_jwks_ttl_expiry_refetches(clock):
    pa = PAKey()
    fetcher = CountingFetcher({JWKS_URI: pa.jwks})
    cache = JWKSCache(fetcher, ttl=300, clock=clock)
    await cache.keys(JWKS_URI, pa.kid)
    clock.advance(301)
    await cache.keys(JWKS_URI, pa.kid)
    assert len(fetcher.calls) == 2


async def test_stale_keys_kept_when_refetch_fails(clock):
    pa = PAKey()
    fetcher = CountingFetcher({JWKS_URI: pa.jwks})
    cache = JWKSCache(fetcher, ttl=300, clock=clock)
    await cache.keys(JWKS_URI, pa.kid)
    fetcher.docs.clear()
    clock.advance(31)
    assert await cache.keys(JWKS_URI, "unknown") == []


async def test_jwks_cache_is_bounded(clock):
    docs = {f"https://pa{i}.example/jwks": PAKey().jwks for i in range(10)}
    cache = JWKSCache(CountingFetcher(docs), max_entries=3, clock=clock)
    for uri in docs:
        await cache.keys(uri, None)
    assert len(cache._keys) == 3


async def test_jwks_document_private_members_stripped(clock):
    pa = PAKey()
    leaked = {"keys": [{**pa.jwks["keys"][0], "d": pa.jwk["d"]}]}
    cache = JWKSCache(CountingFetcher({JWKS_URI: leaked}), clock=clock)
    keys = await cache.keys(JWKS_URI, pa.kid)
    assert "d" not in keys[0]


@pytest.mark.parametrize("doc", [[], {"keys": "x"}, "nope", {"nokeys": []}])
async def test_malformed_jwks_rejected(clock, doc):
    cache = JWKSCache(CountingFetcher({JWKS_URI: doc}), clock=clock)
    with pytest.raises(FetchError):
        await cache.keys(JWKS_URI, None)


# -- fetcher ---------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://pa.example/jwks.json",          # not https
    "https://127.0.0.1/jwks.json",          # loopback
    "https://10.0.0.5/jwks.json",           # private
    "https://169.254.169.254/latest",       # metadata
    "https://localhost/jwks.json",
    "https://user:pw@pa.example/jwks.json",
    "file:///etc/passwd",
])
async def test_fetcher_refuses_unsafe_urls(url):
    with pytest.raises(FetchError):
        await HttpsJSONFetcher().fetch_json(url)


async def test_fetcher_does_not_follow_redirects():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    fetcher = HttpsJSONFetcher(allow_hosts={"127.0.0.1"}, transport=httpx.MockTransport(handler))
    with pytest.raises(FetchError):
        await fetcher.fetch_json("http://127.0.0.1/jwks.json")


async def test_fetcher_caps_response_size():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[" + b"1," * 50_000 + b"1]")

    fetcher = HttpsJSONFetcher(allow_hosts={"127.0.0.1"}, transport=httpx.MockTransport(handler),
                               max_bytes=1024)
    with pytest.raises(FetchError):
        await fetcher.fetch_json("http://127.0.0.1/jwks.json")


async def test_fetcher_returns_json():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": []})

    fetcher = HttpsJSONFetcher(allow_hosts={"127.0.0.1"}, transport=httpx.MockTransport(handler))
    assert await fetcher.fetch_json("http://127.0.0.1/jwks.json") == {"keys": []}


# -- registry --------------------------------------------------------------


def test_registration_requires_keys_source():
    with pytest.raises(ValueError):
        PersonalAgentRegistration(issuer=ISSUER)
    with pytest.raises(ValueError):
        PersonalAgentRegistration(issuer="", jwks={"keys": []})


def test_registry_is_bounded():
    reg = InMemoryPersonalAgentRegistry(max_registrations=1)
    reg.register(PersonalAgentRegistration(issuer="https://a", jwks={"keys": []}))
    with pytest.raises(ValueError):
        reg.register(PersonalAgentRegistration(issuer="https://b", jwks={"keys": []}))


async def test_closed_registry_rejects_unknown_issuers():
    reg = InMemoryPersonalAgentRegistry()
    assert await reg.lookup("https://unknown.example") is None


async def test_open_mode_discovers_jwks_via_oidc(clock):
    pa = PAKey()
    iss = "https://open-pa.example"
    fetcher = CountingFetcher({
        f"{iss}/.well-known/openid-configuration": {"issuer": iss, "jwks_uri": f"{iss}/keys"},
        f"{iss}/keys": pa.jwks,
    })
    reg = InMemoryPersonalAgentRegistry(open_mode=True, fetcher=fetcher, clock=clock)
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, http_client=fetcher, clock=clock)
    identity = await auth.verify(pa.token(clock, iss=iss))
    assert identity.issuer == iss
    await auth.verify(pa.token(clock, iss=iss))
    assert fetcher.calls.count(f"{iss}/.well-known/openid-configuration") == 1


async def test_open_mode_still_verifies_everything(clock):
    pa = PAKey()
    iss = "https://open-pa.example"
    fetcher = CountingFetcher({
        f"{iss}/.well-known/openid-configuration": {"issuer": iss, "jwks_uri": f"{iss}/keys"},
        f"{iss}/keys": pa.jwks,
    })
    reg = InMemoryPersonalAgentRegistry(open_mode=True, fetcher=fetcher, clock=clock)
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, http_client=fetcher, clock=clock)
    with pytest.raises(Unauthorized):
        await auth.verify(PAKey().token(clock, iss=iss))  # wrong key
    with pytest.raises(Unauthorized):
        await auth.verify(pa.token(clock, iss=iss, aud="other"))


@pytest.mark.parametrize("doc", [
    {"issuer": "https://someone-else.example", "jwks_uri": "https://x/keys"},
    {"issuer": "https://open-pa.example", "jwks_uri": "http://insecure/keys"},
    {"issuer": "https://open-pa.example"},
])
async def test_open_mode_rejects_bad_discovery(clock, doc):
    iss = "https://open-pa.example"
    fetcher = CountingFetcher({f"{iss}/.well-known/openid-configuration": doc})
    reg = InMemoryPersonalAgentRegistry(open_mode=True, fetcher=fetcher, clock=clock)
    assert await reg.lookup(iss) is None


async def test_open_mode_only_https_issuers(clock):
    fetcher = CountingFetcher({})
    reg = InMemoryPersonalAgentRegistry(open_mode=True, fetcher=fetcher, clock=clock)
    assert await reg.lookup("http://pa.example") is None
    assert await reg.lookup("https://pa.example?x=1") is None
    assert fetcher.calls == []


async def test_open_mode_respects_disabled_registration(clock, pa_key):
    reg = InMemoryPersonalAgentRegistry(
        [PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks, enabled=False)],
        open_mode=True, fetcher=CountingFetcher({}), clock=clock)
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, clock=clock)
    with pytest.raises(Unauthorized):
        await auth.verify(pa_key.token(clock))


async def test_open_mode_negative_results_cached(clock):
    iss = "https://nobody.example"
    fetcher = CountingFetcher({})
    reg = InMemoryPersonalAgentRegistry(open_mode=True, fetcher=fetcher, clock=FakeClock())
    assert await reg.lookup(iss) is None
    assert await reg.lookup(iss) is None
    assert len(fetcher.calls) == 1
