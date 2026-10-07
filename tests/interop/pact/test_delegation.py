"""PACT Delegated profile (§5) end to end, with a fake Brand login."""
from __future__ import annotations

import re
import secrets
import uuid
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from ampro.ampi.app import AgentApp
from ampro.interop.pact import (
    Brand,
    InMemoryPersonalAgentRegistry,
    JWTBrandLogin,
    PACTClient,
    PACTProvider,
    PASigner,
    PersonalAgentRegistration,
    ProviderKeySet,
    ReceiptError,
    Scope,
    current_delegation,
    record_action,
    requires_scopes,
    verify_receipt,
)
from ampro.interop.pact._jwt import generate_es256_jwk, private_key_from_jwk, public_jwk, sign_jwt
from ampro.interop.pact.scopes import args_hash

from .conftest import AUDIENCE, ISSUER, PAKey

PUBLIC = "https://provider.example"
IFACE = f"{PUBLIC}/a2a/shop"
OAUTH = f"{IFACE}/oauth"
BRAND_ISS = "https://brand.example"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
OTHER_ISSUER = "https://pa2.example"


class FakeBrand:
    """Signs the Brand's login assertions."""

    def __init__(self, clock) -> None:
        jwk = generate_es256_jwk()
        self.key, _ = private_key_from_jwk(jwk)
        self.kid = jwk["kid"]
        self.jwks = {"keys": [{**public_jwk(jwk), "kid": self.kid}]}
        self.clock = clock

    def assertion(self, user_code: str, sub: str = "cust-1", **over: Any) -> str:
        now = int(self.clock())
        claims = {"iss": BRAND_ISS, "aud": f"{OAUTH}/consent", "sub": sub, "email": f"{sub}@x.example",
                  "user_code": user_code, "jti": secrets.token_hex(8), "iat": now, "exp": now + 120}
        claims.update(over)
        return sign_jwt(claims, self.key, "ES256", {"kid": self.kid})


def shop_app() -> AgentApp:
    app = AgentApp(agent_id="agent://shop.example", endpoint="https://shop.example")

    @requires_scopes("orders:read", message="I need permission to look up your orders.")
    async def lookup(msg, ctx):
        record_action("lookup_orders", {"user": current_delegation().sub})
        return f"orders for {current_delegation().sub}: A-1"

    @requires_scopes("orders:read", "orders:cancel", message="I need permission to cancel orders.")
    async def cancel(msg, ctx):
        record_action("lookup_orders")
        record_action("cancel_order", {"order": "A-1"})
        return "cancelled A-1"

    @app.on("task.create")
    async def turn(msg, ctx):
        text = msg.body["text"]
        if "cancel" in text:
            return await cancel(msg, ctx)
        if "orders" in text:
            return await lookup(msg, ctx)
        return "Hello, how can I help?"

    return app


@pytest.fixture
def brand_signer(clock) -> FakeBrand:
    return FakeBrand(clock)


@pytest.fixture
def other_pa() -> PAKey:
    return PAKey()


@pytest.fixture
def keys() -> ProviderKeySet:
    return ProviderKeySet.generate()


@pytest.fixture
def provider(pa_key, other_pa, clock, brand_signer, keys) -> PACTProvider:
    registry = InMemoryPersonalAgentRegistry([
        PersonalAgentRegistration(issuer=ISSUER, jwks=pa_key.jwks),
        PersonalAgentRegistration(issuer=OTHER_ISSUER, jwks=other_pa.jwks),
    ])
    p = PACTProvider(public_url=PUBLIC, registry=registry, audience=AUDIENCE, keys=keys, clock=clock)
    login = JWTBrandLogin(login_page=f"{BRAND_ISS}/login", issuer=BRAND_ISS, jwks=brand_signer.jwks,
                          completion_page=f"{BRAND_ISS}/connected", clock=clock)
    p.add_brand(Brand("shop", shop_app(), name="Shop & Co", scopes=[
        Scope("orders:read", "Look up your orders <and> status"),
        Scope("orders:cancel", "Cancel an order that has not shipped"),
    ], login=login))
    p.add_brand(Brand("plain", shop_app(), name="Plain"))
    return p


@pytest.fixture
async def http(provider):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=provider.asgi()),
                                 base_url=PUBLIC) as client:
        yield client


class Flow:
    """Drives OAuth + consent as the PA and as the User's browser."""

    def __init__(self, http, pa: PAKey, clock, brand: FakeBrand) -> None:
        self.http, self.pa, self.clock, self.brand = http, pa, clock, brand

    def auth(self, sub: str = "user-1", pa: PAKey | None = None, iss: str = ISSUER) -> dict[str, str]:
        return {"Authorization": f"Bearer {(pa or self.pa).token(self.clock, sub=sub, iss=iss)}"}

    async def start(self, scope: str = "orders:read orders:cancel", **kw: Any) -> httpx.Response:
        client_id = kw.pop("client_id", ISSUER)
        return await self.http.post(f"{OAUTH}/device_authorization", headers=self.auth(**kw),
                                    data={"client_id": client_id, "scope": scope})

    async def token(self, form: dict[str, str], **kw: Any) -> httpx.Response:
        iss = kw.get("iss", ISSUER)
        return await self.http.post(f"{OAUTH}/token", headers=self.auth(**kw),
                                    data={"client_id": iss, **form})

    async def poll(self, device_code: str, **kw: Any) -> httpx.Response:
        return await self.token({"grant_type": DEVICE_GRANT, "device_code": device_code}, **kw)

    async def consent(self, user_code: str, *, sub: str = "cust-1", assertion: str | None = None,
                      headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.post(f"{OAUTH}/consent", headers=headers or {},
                                    data={"assertion": assertion or self.brand.assertion(user_code, sub)})

    async def decide(self, session: str, scopes: list[str], decision: str = "allow",
                     headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.post(f"{OAUTH}/consent/decision", headers=headers or {},
                                    data={"session": session, "decision": decision, "scope": scopes})

    async def approve(self, user_code: str, scopes: list[str], decision: str = "allow",
                      sub: str = "cust-1") -> httpx.Response:
        page = await self.consent(user_code, sub=sub)
        assert page.status_code == 200, page.text
        return await self.decide(session_of(page), scopes, decision)

    async def grant(self, scopes: list[str], requested: str = "orders:read orders:cancel",
                    sub: str = "cust-1") -> dict[str, Any]:
        auth = (await self.start(requested)).json()
        await self.approve(auth["user_code"], scopes, sub=sub)
        self.clock.advance(10)
        resp = await self.poll(auth["device_code"])
        assert resp.status_code == 200, resp.text
        return resp.json()

    async def send(self, text: str, *, token: str | None = None, context: str | None = None,
                   sub: str = "user-1", message_id: str | None = None, pa: PAKey | None = None,
                   iss: str = ISSUER, brand: str = "shop") -> httpx.Response:
        m: dict[str, Any] = {"messageId": message_id or str(uuid.uuid4()), "role": "ROLE_USER",
                             "parts": [{"text": text}]}
        if context:
            m["contextId"] = context
        headers = {**self.auth(sub, pa, iss), "Content-Type": "application/json"}
        if token:
            headers["X-A2A-User-Delegation"] = f"Bearer {token}"
        return await self.http.post(f"{PUBLIC}/a2a/{brand}/message:send", headers=headers, json={"message": m})


def session_of(page: httpx.Response) -> str:
    return re.search(r'name="session" value="([^"]+)"', page.text).group(1)


@pytest.fixture
def flow(http, pa_key, clock, brand_signer) -> Flow:
    return Flow(http, pa_key, clock, brand_signer)


# -- §5.1 card and metadata ---------------------------------------------------


async def test_card_declares_device_code_scheme(http):
    card = (await http.get("/a2a/shop/.well-known/agent-card.json")).json()
    ud = card["securitySchemes"]["userDelegation"]["oauth2SecurityScheme"]
    assert ud["flows"]["deviceCode"] == {
        "deviceAuthorizationUrl": f"{OAUTH}/device_authorization", "tokenUrl": f"{OAUTH}/token",
        "scopes": {"orders:read": "Look up your orders <and> status",
                   "orders:cancel": "Cancel an order that has not shipped"}}
    assert ud["oauth2MetadataUrl"] == f"{OAUTH}/.well-known/oauth-authorization-server"
    assert card["securityRequirements"] == [
        {"schemes": {"paJwt": {"list": []}}},
        {"schemes": {"paJwt": {"list": []}, "userDelegation": {"list": []}}}]


async def test_rfc8414_metadata_and_jwks(http, keys):
    meta = (await http.get(f"{OAUTH}/.well-known/oauth-authorization-server")).json()
    assert meta["issuer"] == OAUTH
    assert meta["device_authorization_endpoint"] == f"{OAUTH}/device_authorization"
    assert meta["token_endpoint"] == f"{OAUTH}/token"
    assert meta["jwks_uri"] == f"{OAUTH}/jwks.json"
    assert meta["scopes_supported"] == ["orders:read", "orders:cancel"]
    assert DEVICE_GRANT in meta["grant_types_supported"]
    jwks = (await http.get(meta["jwks_uri"])).json()
    assert jwks["keys"][0]["kid"] == keys.active_kid and "d" not in jwks["keys"][0]


async def test_oauth_routes_404_for_identity_only_brand(http):
    assert (await http.get(f"{PUBLIC}/a2a/plain/oauth/jwks.json")).status_code == 404
    assert (await http.get(f"{PUBLIC}/a2a/nope/oauth/jwks.json")).status_code == 404


# -- §5.3 device authorization ---------------------------------------------


async def test_device_authorization_response(flow):
    resp = await flow.start()
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["device_code"].startswith("dc_") and len(body["device_code"]) > 40
    assert re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}", body["user_code"])
    assert body["expires_in"] == 600 and body["interval"] == 5
    login = urlsplit(body["verification_uri_complete"])
    assert f"{login.scheme}://{login.netloc}{login.path}" == f"{BRAND_ISS}/login"
    return_to = parse_qs(login.query)["return_to"][0]
    assert return_to == f"{OAUTH}/consent?user_code={body['user_code']}"
    assert body["verification_uri"].startswith(f"{BRAND_ISS}/login?return_to=")


async def test_device_authorization_requires_pa_jwt(http):
    resp = await http.post(f"{OAUTH}/device_authorization", data={"client_id": ISSUER, "scope": "orders:read"})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Bearer realm="a2a"'


async def test_client_id_must_equal_pa_issuer(flow):
    resp = await flow.start(client_id="https://other.example")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.parametrize("scope", ["", "orders:delete", "orders:read admin", " "])
async def test_unknown_or_missing_scope_is_invalid_scope(flow, scope):
    resp = await flow.start(scope)
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_scope"


async def test_form_must_be_urlencoded_and_params_single(flow, http):
    resp = await http.post(f"{OAUTH}/device_authorization", headers=flow.auth(),
                           json={"client_id": ISSUER, "scope": "orders:read"})
    assert resp.json()["error"] == "invalid_request"
    resp = await http.post(f"{OAUTH}/device_authorization",
                           headers={**flow.auth(), "Content-Type": "application/x-www-form-urlencoded"},
                           content=f"client_id={ISSUER}&scope=orders:read&scope=orders:cancel")
    assert resp.json()["error"] == "invalid_request"


async def test_device_authorization_rate_limited(flow):
    for _ in range(30):
        assert (await flow.start()).status_code == 200
    assert (await flow.start()).status_code == 429


# -- token endpoint -----------------------------------------------------------


async def test_poll_states_pending_slow_down_then_token(flow, keys, clock):
    auth = (await flow.start()).json()
    first = await flow.poll(auth["device_code"])
    assert first.status_code == 400 and first.json()["error"] == "authorization_pending"
    too_fast = await flow.poll(auth["device_code"])
    assert too_fast.json()["error"] == "slow_down"
    clock.advance(5)
    assert (await flow.poll(auth["device_code"])).json()["error"] == "authorization_pending"

    done = await flow.approve(auth["user_code"], ["orders:read"])
    assert done.status_code == 303
    assert done.headers["location"] == f"{BRAND_ISS}/connected?status=approved&scope=orders%3Aread"
    clock.advance(5)
    tok = await flow.poll(auth["device_code"])
    assert tok.status_code == 200, tok.text
    body = tok.json()
    assert body["token_type"] == "Bearer" and body["scope"] == "orders:read"
    assert body["expires_in"] == 3600 and body["refresh_token"].startswith("rt_")
    claims = keys.verify(body["access_token"], typ="at+jwt")
    assert claims["iss"] == OAUTH and claims["aud"] == IFACE and claims["sub"] == "cust-1"
    assert claims["client_id"] == ISSUER and claims["scope"] == "orders:read"
    assert claims["exp"] - claims["iat"] == 3600 and claims["grant_id"].startswith("pactgrant_")
    clock.advance(5)
    again = await flow.poll(auth["device_code"])
    assert again.json()["error"] == "invalid_grant"


async def test_user_may_uncheck_scopes(flow):
    body = await flow.grant(["orders:cancel"])
    assert body["scope"] == "orders:cancel"


async def test_denied_consent_is_access_denied(flow, clock):
    auth = (await flow.start()).json()
    done = await flow.approve(auth["user_code"], ["orders:read"], decision="deny")
    assert done.headers["location"] == f"{BRAND_ISS}/connected?status=denied"
    clock.advance(10)
    assert (await flow.poll(auth["device_code"])).json()["error"] == "access_denied"


async def test_allow_with_no_scopes_is_denial(flow, clock):
    auth = (await flow.start()).json()
    done = await flow.approve(auth["user_code"], [])
    assert "status=denied" in done.headers["location"]


async def test_expired_device_code(flow, clock):
    auth = (await flow.start()).json()
    clock.advance(601)
    assert (await flow.poll(auth["device_code"])).json()["error"] == "expired_token"


async def test_device_code_bound_to_client(flow, other_pa):
    auth = (await flow.start()).json()
    resp = await flow.poll(auth["device_code"], pa=other_pa, iss=OTHER_ISSUER)
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("form", [
    {"grant_type": DEVICE_GRANT, "device_code": "dc_unknown"},
    {"grant_type": DEVICE_GRANT},
    {"grant_type": "refresh_token", "refresh_token": "rt_unknown"},
])
async def test_unknown_codes_are_invalid_grant(flow, form):
    assert (await flow.token(form)).json()["error"] == "invalid_grant"


async def test_unsupported_grant_type(flow):
    resp = await flow.token({"grant_type": "client_credentials"})
    assert resp.json()["error"] == "unsupported_grant_type"


async def test_token_endpoint_requires_pa_jwt(http):
    resp = await http.post(f"{OAUTH}/token", data={"grant_type": DEVICE_GRANT, "device_code": "x"})
    assert resp.status_code == 401


# -- refresh tokens -----------------------------------------------------------


async def test_refresh_rotates_and_reuse_revokes_grant(flow, clock):
    first = await flow.grant(["orders:read"])
    refreshed = await flow.token({"grant_type": "refresh_token", "refresh_token": first["refresh_token"]})
    assert refreshed.status_code == 200
    second = refreshed.json()
    assert second["scope"] == "orders:read" and second["refresh_token"] != first["refresh_token"]
    assert (await flow.send("my orders", token=second["access_token"])).status_code == 200

    reuse = await flow.token({"grant_type": "refresh_token", "refresh_token": first["refresh_token"]})
    assert reuse.status_code == 400 and reuse.json()["error"] == "invalid_grant"
    # the whole grant is now revoked
    assert (await flow.send("my orders", token=second["access_token"])).status_code == 401
    newer = await flow.token({"grant_type": "refresh_token", "refresh_token": second["refresh_token"]})
    assert newer.json()["error"] == "invalid_grant"


async def test_refresh_bound_to_client(flow, other_pa):
    first = await flow.grant(["orders:read"])
    resp = await flow.token({"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
                            pa=other_pa, iss=OTHER_ISSUER)
    assert resp.json()["error"] == "invalid_grant"


async def test_refresh_tokens_stored_hashed(flow, provider):
    first = await flow.grant(["orders:read"])
    store = provider.delegation.stores.refresh_tokens
    assert first["refresh_token"] not in repr(store._data._data)


# -- consent page -------------------------------------------------------------


async def test_consent_page_is_safe_html(flow):
    auth = (await flow.start()).json()
    page = await flow.consent(auth["user_code"])
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "script-src" not in csp
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["cache-control"] == "no-store"
    assert "Look up your orders &lt;and&gt; status" in page.text
    assert page.text.count('type="checkbox"') == 2 and page.text.count("checked") == 2
    assert "pa.example" in page.text and "Shop &amp; Co" in page.text
    assert re.search(r'<form[^>]*action="' + re.escape(f"{OAUTH}/consent/decision") + '"', page.text)


async def test_consent_rejects_bad_assertions(flow, brand_signer, clock):
    auth = (await flow.start()).json()
    code = auth["user_code"]
    other = FakeBrand(clock)
    for assertion in (other.assertion(code), brand_signer.assertion(code, aud="https://elsewhere"),
                      brand_signer.assertion(code, iss="https://evil.example"),
                      brand_signer.assertion(code, exp=int(clock()) + 3600),
                      brand_signer.assertion(code, iat=int(clock()) - 400, exp=int(clock()) - 200),
                      "not-a-jwt"):
        resp = await flow.consent(code, assertion=assertion)
        assert resp.status_code == 401
        assert "session" not in resp.text


async def test_assertion_is_single_use(flow, brand_signer):
    auth = (await flow.start()).json()
    assertion = brand_signer.assertion(auth["user_code"])
    assert (await flow.consent(auth["user_code"], assertion=assertion)).status_code == 200
    assert (await flow.consent(auth["user_code"], assertion=assertion)).status_code == 401


async def test_unknown_user_code_and_rate_limit(flow):
    for _ in range(10):
        assert (await flow.consent("BBBB-CCCC")).status_code == 400
    assert (await flow.consent("BBBB-CCCC")).status_code == 429


async def test_consent_session_single_use_and_bound(flow):
    auth = (await flow.start()).json()
    page = await flow.consent(auth["user_code"])
    session = session_of(page)
    assert (await flow.decide(session, ["orders:read"])).status_code == 303
    again = await flow.decide(session, ["orders:read"])
    assert again.status_code == 400
    assert (await flow.decide("forged-session", ["orders:read"])).status_code == 400


async def test_decision_checks_origin(flow):
    auth = (await flow.start()).json()
    session = session_of(await flow.consent(auth["user_code"]))
    resp = await flow.decide(session, ["orders:read"], headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    ok = await flow.decide(session, ["orders:read"], headers={"Origin": PUBLIC})
    assert ok.status_code == 303


async def test_consent_accepts_brand_origin_only(flow):
    auth = (await flow.start()).json()
    bad = await flow.consent(auth["user_code"], headers={"Origin": "https://evil.example"})
    assert bad.status_code == 403
    good = await flow.consent(auth["user_code"], headers={"Origin": BRAND_ISS})
    assert good.status_code == 200


async def test_scopes_not_requested_cannot_be_granted(flow):
    body = await flow.grant(["orders:read", "orders:cancel"], requested="orders:read")
    assert body["scope"] == "orders:read"


# -- §5.5 sending with a delegation token -------------------------------------


async def test_step_up_without_token(flow, http):
    resp = await flow.send("show my orders")
    assert resp.status_code == 200
    task = resp.json()["task"]
    assert task["status"]["state"] == "TASK_STATE_AUTH_REQUIRED"
    assert task["status"]["message"]["parts"] == [{"text": "I need permission to look up your orders."}]
    assert task["metadata"]["pact.missingScopes"] == ["orders:read"]
    link = task["metadata"]["pact.verificationUriComplete"]
    assert link.startswith(f"{BRAND_ISS}/login?return_to=")
    # the conversation stays open: plain turns keep working in the same context
    follow = await flow.send("hello", context=task["contextId"])
    assert follow.status_code == 200 and "message" in follow.json()


async def test_delegated_reply_carries_verifiable_receipt(flow, http, clock):
    tok = await flow.grant(["orders:read"])
    resp = await flow.send("my orders", token=tok["access_token"])
    assert resp.status_code == 200, resp.text
    message = resp.json()["message"]
    assert message["parts"] == [{"text": "orders for cust-1: A-1"}]
    receipt = message["metadata"]["pact.receipt"]
    jwks = (await http.get(f"{OAUTH}/jwks.json")).json()
    claims = verify_receipt(receipt, jwks, expected={"pa": ISSUER, "brand": IFACE})
    assert claims["user"] == "cust-1" and claims["grantId"].startswith("pactgrant_")
    assert claims["scopesUsed"] == ["orders:read"]
    assert claims["actions"] == [{"tool": "lookup_orders", "argsHash": args_hash({"user": "cust-1"})}]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", claims["ts"])


async def test_retry_returns_same_receipt(flow):
    tok = await flow.grant(["orders:read"])
    mid = str(uuid.uuid4())
    first = (await flow.send("my orders", token=tok["access_token"], message_id=mid)).json()["message"]
    retry = (await flow.send("my orders", token=tok["access_token"], message_id=mid,
                             context=first["contextId"])).json()["message"]
    assert retry["messageId"] == first["messageId"]
    assert retry["metadata"]["pact.receipt"] == first["metadata"]["pact.receipt"]


async def test_tampered_receipt_detected(flow, http):
    tok = await flow.grant(["orders:read"])
    receipt = (await flow.send("my orders", token=tok["access_token"])).json()["message"]["metadata"]["pact.receipt"]
    jwks = (await http.get(f"{OAUTH}/jwks.json")).json()
    forged = {**receipt, "claims": {**receipt["claims"], "scopesUsed": []}}
    with pytest.raises(ReceiptError):
        verify_receipt(forged, jwks)
    with pytest.raises(ReceiptError):
        verify_receipt(receipt, {"keys": []})
    with pytest.raises(ReceiptError):
        verify_receipt(receipt, jwks, expected={"pa": "https://someone.example"})


async def test_step_up_for_missing_scope_with_token(flow):
    tok = await flow.grant(["orders:read"])
    resp = await flow.send("cancel my order", token=tok["access_token"])
    task = resp.json()["task"]
    assert task["metadata"]["pact.missingScopes"] == ["orders:cancel"]
    tok2 = await flow.grant(["orders:read", "orders:cancel"])
    done = await flow.send("cancel my order", token=tok2["access_token"], context=task["contextId"])
    msg = done.json()["message"]
    assert msg["parts"] == [{"text": "cancelled A-1"}]
    claims = msg["metadata"]["pact.receipt"]["claims"]
    assert claims["scopesUsed"] == ["orders:read", "orders:cancel"]
    assert [a["tool"] for a in claims["actions"]] == ["lookup_orders", "cancel_order"]


async def test_no_receipt_without_delegation(flow):
    msg = (await flow.send("hello")).json()["message"]
    assert "pact.receipt" not in (msg.get("metadata") or {})


async def test_identity_context_may_continue_under_delegation_then_sub_is_bound(flow):
    ctx = (await flow.send("hello")).json()["message"]["contextId"]
    tok1 = await flow.grant(["orders:read"], sub="cust-1")
    assert (await flow.send("my orders", token=tok1["access_token"], context=ctx)).status_code == 200
    tok2 = await flow.grant(["orders:read"], sub="cust-2")
    resp = await flow.send("my orders", token=tok2["access_token"], context=ctx)
    assert resp.status_code == 400
    assert resp.json()["error"]["details"][0]["reason"] == "INVALID_PARAMS"


def _invalid_token(resp: httpx.Response) -> bool:
    return (resp.status_code == 401 and resp.content == b""
            and resp.headers["www-authenticate"] == 'Bearer realm="a2a", error="invalid_token"')


async def test_bad_delegation_tokens_rejected(flow, other_pa, clock, keys, provider):
    tok = (await flow.grant(["orders:read"]))["access_token"]
    assert _invalid_token(await flow.send("my orders", token=tok[:-4] + "AAAA"))
    assert _invalid_token(await flow.send("my orders", token="garbage"))
    # presented by a different personal agent (client_id mismatch)
    assert _invalid_token(await flow.send("my orders", token=tok, pa=other_pa, iss=OTHER_ISSUER))
    # wrong Brand (aud)
    assert _invalid_token(await flow.send("hello", token=tok, brand="plain"))
    # signed by a key the provider does not hold
    foreign = ProviderKeySet.generate().sign_json(keys.verify(tok), "at+jwt")
    assert _invalid_token(await flow.send("my orders", token=foreign))
    # the PA JWT is still checked first
    resp = await flow.http.post(f"{IFACE}/message:send", headers={"X-A2A-User-Delegation": f"Bearer {tok}"},
                                json={"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "x"}]}})
    assert resp.status_code == 401 and resp.headers["www-authenticate"] == 'Bearer realm="a2a"'


async def test_expired_and_revoked_delegation_tokens(flow, clock, keys, provider):
    tok = await flow.grant(["orders:read"])
    assert (await flow.send("my orders", token=tok["access_token"])).status_code == 200
    grant_id = keys.verify(tok["access_token"])["grant_id"]
    await provider.delegation.revoke_grant(grant_id)
    assert _invalid_token(await flow.send("my orders", token=tok["access_token"]))
    tok = await flow.grant(["orders:read"])
    clock.advance(3601)
    assert _invalid_token(await flow.send("my orders", token=tok["access_token"]))


# -- keys ----------------------------------------------------------------------


def test_key_rotation_keeps_old_tokens_valid():
    old_jwk, new_jwk = generate_es256_jwk(), generate_es256_jwk()
    token = ProviderKeySet([old_jwk]).sign_json({"a": 1}, "at+jwt")
    rotated = ProviderKeySet([new_jwk, old_jwk])
    assert rotated.verify(token, typ="at+jwt") == {"a": 1}
    assert rotated.active_kid == new_jwk["kid"]
    assert [k["kid"] for k in rotated.jwks()["keys"]] == [new_jwk["kid"], old_jwk["kid"]]
    assert all("d" not in k for k in rotated.jwks()["keys"])


def test_keys_from_env(monkeypatch, tmp_path):
    import json as _json

    jwk = generate_es256_jwk()
    monkeypatch.setenv("PACT_PROVIDER_JWKS", _json.dumps({"keys": [jwk]}))
    assert ProviderKeySet.from_env().active_kid == jwk["kid"]
    monkeypatch.delenv("PACT_PROVIDER_JWKS")
    path = tmp_path / "keys.json"
    path.write_text(_json.dumps(jwk))
    monkeypatch.setenv("PACT_PROVIDER_JWKS_FILE", str(path))
    assert ProviderKeySet.from_env().active_kid == jwk["kid"]
    monkeypatch.delenv("PACT_PROVIDER_JWKS_FILE")
    with pytest.raises(RuntimeError):
        ProviderKeySet.from_env()


def test_keyset_rejects_weak_or_bad_keys():
    with pytest.raises(ValueError):
        ProviderKeySet([])
    jwk = generate_es256_jwk()
    with pytest.raises(ValueError):
        ProviderKeySet([jwk, dict(jwk)])  # duplicate kid
    from ampro.interop.pact._jwt import JoseError

    with pytest.raises(JoseError):
        ProviderKeySet([{**jwk, "crv": "P-384"}])
    with pytest.raises(JoseError):
        ProviderKeySet([public_jwk(jwk)])


def test_delegating_brand_requires_keys(registry):
    login = JWTBrandLogin(login_page="https://b/login", issuer="https://b", jwks={"keys": []})
    p = PACTProvider(public_url=PUBLIC, registry=registry, audience=AUDIENCE)
    with pytest.raises(ValueError):
        p.add_brand(Brand("x", shop_app(), name="x", scopes=[Scope("a:b", "A")], login=login))


def test_scope_validation():
    with pytest.raises(ValueError):
        Scope("bad scope", "x")
    with pytest.raises(ValueError):
        Scope('quote"', "x")
    with pytest.raises(ValueError):
        Scope("ok", "")


async def test_requires_scopes_outside_pact_uses_ctx_scopes():
    from types import SimpleNamespace

    from ampro.interop.a2a import AuthRequired

    @requires_scopes("a")
    async def handler(msg, ctx):
        return "ok"

    assert await handler(None, SimpleNamespace(scopes=frozenset({"a"}))) == "ok"
    with pytest.raises(AuthRequired) as info:
        await handler(None, SimpleNamespace(scopes=frozenset()))
    assert info.value.missing_scopes == ["a"]


# -- personal-agent client ----------------------------------------------------


async def test_pact_client_runs_device_flow_and_verifies_receipts(http, pa_key, clock, brand_signer):
    flow = Flow(http, pa_key, clock, brand_signer)
    shown: list[str] = []

    async def browser(uri: str) -> None:
        shown.append(uri)
        code = parse_qs(urlsplit(parse_qs(urlsplit(uri).query)["return_to"][0]).query)["user_code"][0]
        await flow.approve(code, ["orders:read"])

    async def fast_sleep(seconds: float) -> None:
        clock.advance(seconds)

    async with PACTClient(PASigner(ISSUER, pa_key.jwk, clock=clock), AUDIENCE, http=http,
                          sleep=fast_sleep) as pa:
        shop = await pa.connect(f"{PUBLIC}/a2a/shop/.well-known/agent-card.json")
        assert set(shop.scopes) == {"orders:read", "orders:cancel"}
        hello = await shop.send("user-1", "hello")
        assert hello.text == "Hello, how can I help?" and hello.receipt is None
        reply = await shop.send("user-1", "my orders", context_id=hello.context_id,
                                on_verification=browser)
        assert len(shown) == 1
        assert reply.text == "orders for cust-1: A-1" and reply.context_id == hello.context_id
        assert reply.receipt_claims["scopesUsed"] == ["orders:read"]
        assert shop.tokens["user-1"].scopes == ["orders:read"]
        refreshed = await shop.refresh("user-1")
        assert refreshed.scopes == ["orders:read"]
        again = await shop.send("user-1", "my orders", context_id=hello.context_id)
        assert again.receipt_claims["user"] == "cust-1"


async def test_pa_signer_mints_spec_tokens(registry, clock, pa_key):
    from ampro.interop.pact import PAJwtAuthenticator

    signer = PASigner(ISSUER, pa_key.jwk, clock=clock)
    token = signer.sign("user-9", AUDIENCE)
    identity = await PAJwtAuthenticator(registry, audience=AUDIENCE, clock=clock).verify(token)
    assert identity.sub == "user-9"
    assert identity.claims["exp"] - identity.claims["iat"] == 120 and identity.claims["jti"]
    with pytest.raises(ValueError):
        signer.sign("u", AUDIENCE, ttl=301)
    with pytest.raises(ValueError):
        PASigner(ISSUER, {k: v for k, v in pa_key.jwk.items() if k != "kid"})
