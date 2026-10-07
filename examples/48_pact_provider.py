"""
48 — A PACT provider: personal-agent identity and delegated authority

# requires: jwt, httpx

PACT (Personal Agent Consent & Trust) lets a User's personal agent talk to a
Brand's support agent over A2A 1.0.  The personal agent signs a short JWT for
every request (Identity profile); a Brand can also let the User log in and
approve scopes so the agent acts on their account (Delegated profile), with a
signed receipt on every reply.

This example hosts two Brands on one provider:

* ``acme``    — identity only;
* ``skyline`` — delegation with three scopes and a demo Brand login.

Running it with no arguments plays the whole flow in-process (no network):
the personal agent asks about its flight, gets ``AUTH_REQUIRED``, the "User"
logs in at the Brand and approves one scope, and the agent gets an answer
with a verified receipt.

    python examples/48_pact_provider.py            # in-process demo
    python examples/48_pact_provider.py --serve    # serve on 127.0.0.1:8048

``build_demo`` is also what ``scripts/run_pact_conformance.py`` serves to the
official PACT conformance suite.
"""
from __future__ import annotations

import asyncio
import html
import json
import os
import re
import secrets
import sys
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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
    Scope,
    close_conversation,
    current_delegation,
    ensure_scopes,
    record_action,
)
from ampro.interop.pact._jwt import generate_es256_jwk, private_key_from_jwk, public_jwk, sign_jwt
from ampro.server.http import HTTPRequest, HTTPResponse

# ---------------------------------------------------------------------------
# The Brand's own data (a real Brand would call its account API)
# ---------------------------------------------------------------------------

USERS = {"alex.rivera@example.com": ("sky-4471", "Alex Rivera", "skyline")}
TRIPS = {
    "sky-4471": {
        "upcoming": [{
            "confirmation": "K7PQ2M", "flight": "SK 482", "from": "SFO", "to": "O'Hare",
            "date": "Friday", "departs": "2:40 PM", "arrives": "8:50 PM", "delay": "4.5 hours",
            "alternatives": [{"flight": "SK 318", "departs": "11:15 AM", "arrives": "5:20 PM"}],
        }],
        "past": [{"flight": "SK 120", "date": "June 3", "from": "O'Hare", "to": "SFO"}],
    },
}
SKYLINE_SCOPES = [
    Scope("flights:upcoming:read", "View upcoming flights"),
    Scope("flights:history:read", "View past flights"),
    Scope("flights:rebook", "Rebook flights"),
]
FLIGHT = re.compile(r"\b([A-Z]{2})\s?(\d{2,4})\b", re.I)


def skyline_app() -> AgentApp:
    app = AgentApp(agent_id="agent://skyline.example", endpoint="https://skyline.example")
    awaiting_code: dict[str, bool] = {}  # contextId -> asked for a confirmation code

    @app.on("task.create")
    async def turn(msg: Any, ctx: Any) -> str:
        """Flight status and trip changes."""
        text: str = msg.body.get("text", "")
        context = ctx.headers.get("Session-Id", "")
        if re.search(r"\b(rebook|switch me|move me)\b", text, re.I):
            await ensure_scopes("flights:upcoming:read", "flights:rebook",
                                message="I need permission to rebook your flights.")
            trip = TRIPS[current_delegation().sub]["upcoming"][0]
            m = FLIGHT.search(text.replace("SK 482", ""))
            target = f"{m.group(1).upper()} {m.group(2)}" if m else trip["alternatives"][0]["flight"]
            record_action("rebook_trip", {"confirmation": trip["confirmation"], "flight": target})
            return f"Done: booking {trip['confirmation']} is now on {target}."
        if re.search(r"\b(past|previous|history)\b", text, re.I):
            await ensure_scopes("flights:history:read",
                                message="I need permission to view your past flights.")
            record_action("list_past_trips")
            past = TRIPS[current_delegation().sub]["past"]
            return "Past flights: " + "; ".join(f"{t['flight']} {t['date']}" for t in past) + "."
        if re.search(r"\b(upcoming|my (booking|trips?))\b", text, re.I) or current_delegation():
            if re.search(r"\bflights?\b|\bbooking\b|\btrips?\b", text, re.I):
                await ensure_scopes("flights:upcoming:read",
                                    message="I need permission to view your upcoming flights.")
                record_action("list_upcoming_trips")
                t = TRIPS[current_delegation().sub]["upcoming"][0]
                return (f"{t['flight']} on {t['date']} is delayed {t['delay']}. It now leaves "
                        f"{t['from']} at {t['departs']} and lands at {t['to']} at {t['arrives']}.")
        if awaiting_code.pop(context, False) and re.fullmatch(r"\s*[A-Z0-9]{6}\s*", text, re.I):
            return ("Flight SK 482 on Friday is delayed 4.5 hours. It now leaves SFO at 2:40 PM "
                    "and lands at O'Hare at 8:50 PM.")
        if re.search(r"\bflights?\b", text, re.I):
            awaiting_code[context] = True
            if len(awaiting_code) > 10_000:
                awaiting_code.pop(next(iter(awaiting_code)))
            return "I can check that. What's your confirmation code?"
        if re.search(r"\b(bye|thanks, that's all)\b", text, re.I):
            close_conversation()
            return "Glad I could help. Goodbye!"
        return "I can help with flight status and trip changes."

    return app


def acme_app() -> AgentApp:
    app = AgentApp(agent_id="agent://acme.example", endpoint="https://acme.example")

    @app.on("task.create")
    async def turn(msg: Any, ctx: Any) -> str:
        """Order status and returns."""
        return "Acme support here. What's your order number?"

    return app


# ---------------------------------------------------------------------------
# A demo Brand login (the Brand's own site: /login and /connected)
# ---------------------------------------------------------------------------


class DemoBrandSite:
    """The Brand's login page.  Never part of the provider in real life.

    After checking email + password it signs a 2-minute, single-use assertion
    bound to the ``user_code`` and POSTs it (via a form) to the provider's
    consent URL.  Mounted on the same server here only to keep the demo small.
    """

    name = "demo-brand-site"

    def __init__(self, public_url: str, consent_url: str) -> None:
        self.public_url = public_url.rstrip("/")
        self.consent_url = consent_url
        self.issuer = f"{self.public_url}/brand"
        jwk = generate_es256_jwk()
        self._key, self._alg = private_key_from_jwk(jwk)
        self._kid = jwk["kid"]
        self.jwks = {"keys": [{**public_jwk(jwk), "kid": jwk["kid"], "alg": "ES256", "use": "sig"}]}

    def login(self) -> JWTBrandLogin:
        return JWTBrandLogin(login_page=f"{self.public_url}/login", issuer=self.issuer,
                             jwks=self.jwks, completion_page=f"{self.public_url}/connected")

    def assertion(self, user_id: str, email: str, user_code: str) -> str:
        now = int(time.time())
        return sign_jwt({"iss": self.issuer, "aud": self.consent_url, "sub": user_id,
                         "email": email, "user_code": user_code, "jti": secrets.token_urlsafe(16),
                         "iat": now, "exp": now + 120}, self._key, self._alg, {"kid": self._kid})

    @staticmethod
    def _page(body: str, status: int = 200) -> HTTPResponse:
        return HTTPResponse(status=status, headers={
            "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        }, body=f"<!doctype html><meta charset=utf-8><body>{body}</body>".encode())

    def _target(self, return_to: str) -> str | None:
        parts = urlsplit(return_to)
        if f"{parts.scheme}://{parts.netloc}{parts.path}" != self.consent_url:
            return None
        return dict(parse_qsl(parts.query)).get("user_code", "")

    async def handle(self, request: HTTPRequest) -> HTTPResponse | None:
        if request.path == "/connected" and request.method == "GET":
            status = html.escape(request.query.get("status", ""))
            return self._page(f"<h1>Skyline</h1><p>Connection {status}.</p>")
        if request.path != "/login":
            return None
        if request.method == "GET":
            return_to = request.query.get("return_to", "")
            if self._target(return_to) is None:
                return self._page("<p>Unknown sign-in request.</p>", 400)
            return self._page(
                '<form method="post" action="/login"><h1>Sign in to Skyline</h1>'
                f'<input type="hidden" name="return_to" value="{html.escape(return_to)}">'
                '<input name="email" placeholder="Email"> <input name="password" type="password">'
                "<button>Sign in</button></form>")
        if request.method != "POST" or len(request.body) > 4096:
            return HTTPResponse.empty(405)
        form = dict(parse_qsl(request.body.decode("utf-8", "replace")))
        code = self._target(form.get("return_to", ""))
        user = USERS.get(form.get("email", ""))
        if code is None or user is None or not secrets.compare_digest(user[2], form.get("password", "")):
            return self._page("<p>That email and password don't match a Skyline account.</p>", 401)
        assertion = self.assertion(user[0], form["email"], (form.get("user_code") or code).upper())
        return self._page(
            f'<form method="post" action="{html.escape(self.consent_url)}">'
            f'<input type="hidden" name="assertion" value="{assertion}">'
            f"<p>Signed in as {html.escape(form['email'])}.</p><button>Continue</button></form>")


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def build_demo(
    public_url: str,
    *,
    pa_registrations: list[PersonalAgentRegistration],
    audience: str,
    http_client: Any = None,
    identity_scheme: str = "paJwt",
    poll_interval: int = 5,
    keys: ProviderKeySet | None = None,
) -> tuple[Any, PACTProvider, DemoBrandSite]:
    """``(AgentServer, provider, brand_site)`` hosting ``acme`` and ``skyline``."""
    registry = InMemoryPersonalAgentRegistry(pa_registrations)
    provider = PACTProvider(
        public_url=public_url, registry=registry, audience=audience,
        keys=keys or ProviderKeySet.from_env(allow_generate=True),
        http_client=http_client, provider_name="ampro PACT demo provider",
        identity_scheme=identity_scheme, poll_interval=poll_interval,
    )
    site = DemoBrandSite(public_url, f"{provider.interface_url('skyline')}/oauth/consent")
    provider.add_brand(Brand(
        "skyline", skyline_app(), name="Skyline Airways",
        description="Flight status and trip changes.",
        skills=[{"id": "flight-status", "name": "Flight status",
                 "description": "Check departure and arrival times for a booked flight.",
                 "tags": ["flight", "delay", "trip"],
                 "examples": ["Is my Friday flight on time?"]}],
        scopes=SKYLINE_SCOPES, login=site.login(),
    ))
    provider.add_brand(Brand(
        "acme", acme_app(), name="Acme Store", description="Order status and returns.",
        skills=[{"id": "orders", "name": "Orders", "description": "Order status.", "tags": ["orders"]}],
    ))
    server = provider.as_server()
    server.mount(site)
    return server, provider, site


async def demo() -> None:
    import httpx

    public = "https://provider.example"
    pa_jwk = generate_es256_jwk()
    pa_issuer = "https://pa.example"
    registration = PersonalAgentRegistration(
        issuer=pa_issuer, audience="ampro-demo-provider",
        jwks={"keys": [{**public_jwk(pa_jwk), "kid": pa_jwk["kid"]}]})
    server, provider, site = build_demo(public, pa_registrations=[registration],
                                        audience="ampro-demo-provider", poll_interval=1)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=server.asgi()), base_url=public)

    async def no_wait(_: float) -> None:
        await asyncio.sleep(0)

    async def user_approves(uri: str) -> None:
        """Play the User in a browser: log in at the Brand, allow one scope."""
        print("  User opens:", uri)
        login = urlsplit(uri)
        return_to = dict(parse_qsl(login.query))["return_to"]
        page = await http.post("/login", data={"return_to": return_to,
                                               "email": "alex.rivera@example.com", "password": "skyline"})
        assertion = re.search(r'name="assertion" value="([^"]+)"', page.text).group(1)
        consent = await http.post(urlsplit(site.consent_url).path, data={"assertion": assertion})
        session = re.search(r'name="session" value="([^"]+)"', consent.text).group(1)
        done = await http.post(urlsplit(site.consent_url).path + "/decision",
                               data={"session": session, "decision": "allow",
                                     "scope": ["flights:upcoming:read"]})
        print("  Brand says:", done.headers.get("location"))

    async with PACTClient(PASigner(pa_issuer, pa_jwk), "ampro-demo-provider",
                          http=http, sleep=no_wait) as pa:
        skyline = await pa.connect(f"{public}/a2a/skyline/.well-known/agent-card.json")
        print("Card:", skyline.card["name"], "scopes:", list(skyline.scopes))

        first = await skyline.send("user-1", "Is my Friday flight on time?")
        print("Identity:", first.text)
        second = await skyline.send("user-1", "ABC123", context_id=first.context_id)
        print("Identity:", second.text)

        reply = await skyline.send("user-1", "Can you check my upcoming flights?",
                                   context_id=first.context_id, on_verification=user_approves)
        print("Delegated:", reply.text)
        print("Receipt:", json.dumps(reply.receipt_claims, indent=2))
    await http.aclose()


def serve(port: int = 8048) -> None:
    import uvicorn

    public = f"http://127.0.0.1:{port}"
    pa_jwks = os.environ.get("PACT_DEMO_PA_JWKS")
    regs = []
    if pa_jwks:
        regs.append(PersonalAgentRegistration(issuer=os.environ["PACT_DEMO_PA_ISSUER"],
                                              jwks=json.loads(pa_jwks)))
    server, _, _ = build_demo(public, pa_registrations=regs,
                              audience=os.environ.get("PACT_DEMO_AUDIENCE", "ampro-demo-provider"))
    uvicorn.run(server.asgi(), host="127.0.0.1", port=port)


if __name__ == "__main__":
    if "--serve" in sys.argv and not os.environ.get("AMPRO_EXAMPLE_NO_SERVE"):
        serve()
    else:
        asyncio.run(demo())
