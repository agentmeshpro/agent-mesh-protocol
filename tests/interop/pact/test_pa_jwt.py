"""PACT §3.2 — one test per personal-agent JWT rule."""
from __future__ import annotations

import json

import pytest

from ampro.interop.pact import (
    InMemoryPersonalAgentRegistry,
    PAJwtAuthenticator,
    PersonalAgentRegistration,
)
from ampro.interop.pact._jwt import b64url_encode, sign_compact
from ampro.interop.pact.stores import InMemoryNonceStore
from ampro.server.auth import Unauthorized
from ampro.server.http import HTTPRequest
from ampro.trust.tiers import TrustTier

from .conftest import AUDIENCE, ISSUER, PAKey, unsigned_token


def req(token: str | None) -> HTTPRequest:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return HTTPRequest(method="GET", path="/", headers=headers)


async def test_valid_token_yields_verified_principal(authenticator, pa_key, clock):
    p = await authenticator.authenticate(req(pa_key.token(clock)))
    assert p.id == f"pact:{ISSUER}#user-1"
    assert p.trust_tier == TrustTier.VERIFIED
    assert p.auth_method == "pact-pa-jwt"
    assert p.claims["iss"] == ISSUER and p.claims["sub"] == "user-1"


async def test_no_authorization_header_returns_none(authenticator):
    assert await authenticator.authenticate(req(None)) is None


@pytest.mark.parametrize("value", ["Basic abc", "Bearer", "Bearer a b", "bearer"])
async def test_malformed_authorization_rejected(authenticator, value):
    with pytest.raises(Unauthorized):
        await authenticator.authenticate(HTTPRequest("GET", "/", headers={"authorization": value}))


@pytest.mark.parametrize("alg", ["none", "HS256", "ES384", "RS512", "PS256", "EdDSA"])
async def test_disallowed_algorithms_rejected(authenticator, clock, alg):
    now = int(clock())
    tok = unsigned_token({"alg": alg, "typ": "JWT"},
                         {"iss": ISSUER, "sub": "u", "aud": AUDIENCE, "iat": now, "exp": now + 60})
    with pytest.raises(Unauthorized):
        await authenticator.verify(tok)


async def test_hs256_signed_with_public_key_material_rejected(authenticator, pa_key, clock):
    # Classic key-confusion: HMAC "signed" with the public JWK as secret.
    import hashlib
    import hmac

    now = int(clock())
    header = b64url_encode(json.dumps({"alg": "HS256", "kid": pa_key.kid}).encode())
    payload = b64url_encode(json.dumps({"iss": ISSUER, "sub": "u", "aud": AUDIENCE,
                                        "iat": now, "exp": now + 60}).encode())
    secret = json.dumps(pa_key.jwks["keys"][0]).encode()
    sig = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    with pytest.raises(Unauthorized):
        await authenticator.verify(f"{header}.{payload}.{b64url_encode(sig)}")


@pytest.mark.parametrize("extra", [{"jku": "https://evil.example/jwks"}, {"crit": ["exp"]},
                                   {"x5u": "https://evil.example/x"}])
async def test_header_supplied_keys_and_crit_rejected(authenticator, pa_key, clock, extra):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, header=extra))


async def test_embedded_jwk_header_rejected(authenticator, clock):
    attacker = PAKey()
    tok = attacker.token(clock, header={"jwk": attacker.jwks["keys"][0]})
    with pytest.raises(Unauthorized):
        await authenticator.verify(tok)


async def test_bad_signature_rejected(authenticator, clock, pa_key):
    other = PAKey(kid=pa_key.kid)  # same kid, different key
    with pytest.raises(Unauthorized):
        await authenticator.verify(other.token(clock))


async def test_tampered_payload_rejected(authenticator, pa_key, clock):
    h, p, s = pa_key.token(clock).split(".")
    forged = b64url_encode(json.dumps({"iss": ISSUER, "sub": "admin", "aud": AUDIENCE,
                                       "iat": int(clock()), "exp": int(clock()) + 60}).encode())
    with pytest.raises(Unauthorized):
        await authenticator.verify(f"{h}.{forged}.{s}")


async def test_unknown_kid_rejected(authenticator, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(PAKey(kid="unpublished").token(clock))


async def test_missing_kid_tries_published_keys(authenticator, pa_key, clock):
    tok = sign_compact(json.dumps({"iss": ISSUER, "sub": "u", "aud": AUDIENCE, "iat": int(clock()),
                                   "exp": int(clock()) + 60}).encode(), pa_key.key, "ES256", {"typ": "JWT"})
    identity = await authenticator.verify(tok)
    assert identity.sub == "u"


async def test_unknown_issuer_rejected(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iss="https://other.example"))


async def test_issuer_is_exact_match(authenticator, pa_key, clock):
    for iss in (ISSUER + "/", ISSUER.upper(), " " + ISSUER):
        with pytest.raises(Unauthorized):
            await authenticator.verify(pa_key.token(clock, iss=iss))


async def test_disabled_issuer_rejected(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iss=ISSUER + "/disabled"))


async def test_disabling_at_runtime_takes_effect(authenticator, registry, pa_key, clock):
    tok = pa_key.token(clock)
    await authenticator.verify(tok)
    registry.set_enabled(ISSUER, False)
    with pytest.raises(Unauthorized):
        await authenticator.verify(tok)


@pytest.mark.parametrize("aud", ["other-aud", [AUDIENCE], [AUDIENCE, "x"], None])
async def test_audience_must_be_exact_single_string(authenticator, pa_key, clock, aud):
    tok = pa_key.token(clock, aud=aud) if aud is not None else pa_key.token(clock, drop=("aud",))
    with pytest.raises(Unauthorized):
        await authenticator.verify(tok)


async def test_registration_audience_overrides_default(pa_key, clock):
    reg = InMemoryPersonalAgentRegistry([
        PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks, audience="special")])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, clock=clock)
    await auth.verify(pa_key.token(clock, aud="special"))
    with pytest.raises(Unauthorized):
        await auth.verify(pa_key.token(clock))


@pytest.mark.parametrize("sub", [None, "", 42, "x" * 300])
async def test_sub_must_be_present(authenticator, pa_key, clock, sub):
    tok = pa_key.token(clock, sub=sub) if sub is not None else pa_key.token(clock, drop=("sub",))
    with pytest.raises(Unauthorized):
        await authenticator.verify(tok)


async def test_iat_required(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, drop=("iat",)))


async def test_exp_required(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, drop=("exp",)))


@pytest.mark.parametrize("bad", ["123", True, None, 1.5e400])
async def test_iat_must_be_numeric(authenticator, pa_key, clock, bad):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=bad))


async def test_iat_up_to_30s_in_future_allowed(authenticator, pa_key, clock):
    now = int(clock())
    await authenticator.verify(pa_key.token(clock, iat=now + 30, exp=now + 150))


async def test_iat_more_than_30s_in_future_rejected(authenticator, pa_key, clock):
    now = int(clock())
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=now + 31, exp=now + 151))


async def test_expired_rejected(authenticator, pa_key, clock):
    now = int(clock())
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=now - 200, exp=now - 100))


async def test_expiry_has_30s_skew(authenticator, pa_key, clock):
    now = int(clock())
    await authenticator.verify(pa_key.token(clock, iat=now - 100, exp=now - 29))
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=now - 100, exp=now - 30))


async def test_lifetime_at_most_300s(authenticator, pa_key, clock):
    now = int(clock())
    await authenticator.verify(pa_key.token(clock, iat=now, exp=now + 300))
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=now, exp=now + 301))


async def test_exp_before_iat_rejected(authenticator, pa_key, clock):
    now = int(clock())
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, iat=now, exp=now - 1))


async def test_nbf_in_future_rejected(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, nbf=int(clock()) + 100))


async def test_jti_optional_and_not_tracked_by_default(authenticator, pa_key, clock):
    tok = pa_key.token(clock)  # no jti
    await authenticator.verify(tok)
    await authenticator.verify(tok)
    with_jti = pa_key.token(clock, jti="j1")
    await authenticator.verify(with_jti)
    await authenticator.verify(with_jti)


async def test_optional_replay_store_rejects_repeated_jti(registry, pa_key, clock):
    auth = PAJwtAuthenticator(registry, audience=AUDIENCE, clock=clock,
                              replay_store=InMemoryNonceStore(clock=clock))
    tok = pa_key.token(clock, jti="once")
    await auth.verify(tok)
    with pytest.raises(Unauthorized):
        await auth.verify(tok)


async def test_oversized_token_rejected(authenticator, pa_key, clock):
    with pytest.raises(Unauthorized):
        await authenticator.verify(pa_key.token(clock, pad="x" * 10_000))


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "###.###.###", "e30.e30."])
async def test_garbage_rejected(authenticator, token):
    with pytest.raises(Unauthorized):
        await authenticator.verify(token)


async def test_rs256_accepted_with_2048_bit_key(clock):
    from cryptography.hazmat.primitives.asymmetric import rsa

    from ampro.interop.pact._jwt import b64url_encode as enc

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()

    def i2b(i: int) -> str:
        return enc(i.to_bytes((i.bit_length() + 7) // 8, "big"))

    jwk = {"kty": "RSA", "n": i2b(nums.n), "e": i2b(nums.e), "kid": "rsa1"}
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks={"keys": [jwk]})])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, clock=clock)
    now = int(clock())
    tok = sign_compact(json.dumps({"iss": ISSUER, "sub": "u", "aud": AUDIENCE, "iat": now,
                                   "exp": now + 60}).encode(), key, "RS256", {"kid": "rsa1"})
    assert (await auth.verify(tok)).sub == "u"


async def test_rsa_key_cannot_verify_es256_header(clock):
    """A kid pointing at a key of the wrong type never verifies."""
    pa = PAKey()
    jwk = dict(pa.jwks["keys"][0], alg="RS256")
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks={"keys": [jwk]})])
    auth = PAJwtAuthenticator(reg, audience=AUDIENCE, clock=clock)
    with pytest.raises(Unauthorized):
        await auth.verify(pa.token(clock))


async def test_enc_use_key_not_used_for_signatures(clock):
    pa = PAKey()
    jwk = dict(pa.jwks["keys"][0], use="enc")
    reg = InMemoryPersonalAgentRegistry([PersonalAgentRegistration(issuer=ISSUER, jwks={"keys": [jwk]})])
    with pytest.raises(Unauthorized):
        await PAJwtAuthenticator(reg, audience=AUDIENCE, clock=clock).verify(pa.token(clock))
