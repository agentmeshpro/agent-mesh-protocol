# PACT interop (Personal Agent Consent & Trust)

`ampro.interop.pact` implements PACT 1.0 on top of the A2A 1.0 adapter
(`ampro.interop.a2a`):

* **PACT Identity** (§2–4, §6): each request carries a JWT that the personal
  agent signs. The Provider verifies it against the personal agent's JWKS.
* **PACT Delegated** (§5): the User logs in with the Brand and approves
  scopes through an RFC 8628 device flow. The Brand's agent then acts on the
  User's account, and every reply carries a signed receipt.

Install the extra with `pip install 'ampro[pact]'` (PyJWT with crypto).

## Provider

```python
from ampro.interop.pact import (
    Brand, InMemoryPersonalAgentRegistry, JWTBrandLogin, PACTProvider,
    PersonalAgentRegistration, ProviderKeySet, Scope,
)

registry = InMemoryPersonalAgentRegistry([
    PersonalAgentRegistration(issuer="https://pa.example.com",
                              jwks_uri="https://pa.example.com/.well-known/jwks.json"),
])
provider = PACTProvider(
    public_url="https://provider.example.com",
    registry=registry,
    audience="provider-aud-7f3c",          # what PAs put in `aud` (§3.1)
    keys=ProviderKeySet.from_env(),        # needed only for delegation
)
provider.add_brand(Brand("acme", acme_app, name="Acme Support"))
provider.add_brand(Brand(
    "skyline", skyline_app, name="Skyline Airways",
    scopes=[Scope("flights:upcoming:read", "View upcoming flights")],
    login=JWTBrandLogin(login_page="https://skyline.example/login",
                        issuer="https://skyline.example",
                        jwks_uri="https://skyline.example/.well-known/jwks.json",
                        completion_page="https://skyline.example/connected"),
))

server = provider.as_server()      # or: your_server.mount(provider)
asgi_app = server.asgi()
```

Each Brand is an ordinary `AgentApp`. A new A2A message reaches the app as
AMP `task.create` with `body["text"]`, and `ctx.headers["Session-Id"]` holds
the `contextId`. If the handler returns a `str`, the reply is a `Message`.

### Routes per Brand (`{public_url}/a2a/{brandId}`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `.well-known/agent-card.json` | none | `404` with no body for an unknown Brand |
| POST | `message:send` | PA JWT (+ delegation) | §4 |
| GET | `tasks` | PA JWT | always empty; `pageSize` must be 1–100, default 50 |
| GET | `tasks/{id}`, POST `tasks/{id}:cancel` | PA JWT | `TASK_NOT_FOUND: Task not found: {id}` |
| POST | `message:stream`, `tasks/{id}:subscribe`; GET `extendedAgentCard` | PA JWT | `UNSUPPORTED_OPERATION` |
| any | `tasks/{id}/pushNotificationConfigs[/{c}]` | PA JWT | `PUSH_NOTIFICATION_NOT_SUPPORTED` |
| GET | `oauth/.well-known/oauth-authorization-server` | none | RFC 8414 |
| GET | `oauth/jwks.json` | none | keys for delegation tokens and receipts |
| POST | `oauth/device_authorization`, `oauth/token` | PA JWT | RFC 8628; `client_id` must equal the PA's `iss` |
| POST | `oauth/consent`, `oauth/consent/decision` | Brand assertion / consent session | browser |

Requests are processed in this order:

1. Route matching. An unknown path gets `404` and a wrong method gets `405`,
   both with no body.
2. PA-JWT verification. On failure the response is `401` with
   `WWW-Authenticate: Bearer realm="a2a"` and no body.
3. Optional rate limiting, which returns `429` with `Retry-After`.
4. Brand lookup. An unknown Brand gets `404`.
5. Delegation-token verification. On failure the response is `401` with
   `error="invalid_token"`.
6. PACT §4 validation.
7. The Brand's `A2AAdapter`. Request headers are forwarded to it, so
   `traceparent` / `tracestate` / `AMP-Hop-Count` (and `metadata["amp.hopCount"]`)
   are validated and mapped exactly as in
   [INTEROP-A2A.md](INTEROP-A2A.md#trace-context-and-hop-count): malformed
   values or a hop count above the limit get `400 INVALID_PARAMS`.
8. Response normalization and the receipt.

### Personal-agent JWT rules (§3.2)

Every rule below causes a `401` when it fails, and each one has a unit test
in `tests/interop/pact/test_pa_jwt.py`.

* The header `alg` must be `ES256` or `RS256`. The token is rejected if the
  header carries `jwk`, `jku`, `x5u` or `crit`.
* The key is found by `kid` in the registered JWKS. The key type must match
  the algorithm (EC P-256, or RSA with at least 2048 bits). A key marked
  `use: enc` is not accepted.
* `iss` must exactly match a registered issuer that is **enabled**.
* `aud` must exactly match the assigned audience, as one string.
* `sub` must be a non-empty string of at most 256 characters.
* `iat` must be at most `now + 30`. `exp` must be greater than `now - 30`.
  `exp - iat` must be at most 300.
* `jti` is optional. Replay tracking is off by default. To turn it on, pass
  `replay_store=InMemoryNonceStore()`.

The User is the pair (PA, sub). The principal id is `pact:{iss}#{sub}`, at
trust tier `VERIFIED`.

JWKS are fetched with `ampro.security.ssrf`. The fetcher accepts HTTPS only,
connects only to public addresses pinned against DNS rebinding, never follows
redirects, ignores proxy settings from the environment, and caps responses at
64 KiB and 5 s. The JWKS cache is bounded and has a TTL. When a token names a
`kid` the cache doesn't have, the JWKS is fetched again, at most once every
30 s for each URI.

**Open mode.** With `InMemoryPersonalAgentRegistry(open_mode=True)`, the
Provider accepts any `https` issuer whose
`{iss}/.well-known/openid-configuration` names an `https` `jwks_uri`. These
issuers get the same full checks. Issuers you have explicitly disabled stay
rejected.

### Delegated authority (§5)

```python
from ampro.interop.pact import requires_scopes, record_action, current_delegation

@app.on("task.create")
@requires_scopes("orders:cancel", message="I need permission to cancel orders.")
async def cancel(msg, ctx):
    user = current_delegation().sub            # the Brand's own user id
    record_action("cancel_order", {"order": "A-1"})   # args are hashed into the receipt
    return "Cancelled."
```

* `requires_scopes` and `ensure_scopes` check the scopes. If a scope is
  missing, they raise `AuthRequired` with the missing ids and a new login
  link. The reply is then a task in `TASK_STATE_AUTH_REQUIRED` that carries
  `pact.missingScopes` and `pact.verificationUriComplete`, and the
  conversation stays open (§5.5 step-up).
* Required scopes that were granted become the receipt's `scopesUsed`.
  `record_action` adds entries to `actions`.
* `close_conversation()` closes the `contextId`. Later messages to it get
  `UNSUPPORTED_OPERATION`.

**Brand login.** `BrandLogin` is the pluggable hook. It has three methods:

* `login_url(return_to)` returns the Brand's login URL.
* `verify_assertion(assertion, audience=consent_url)` checks the assertion
  and returns `(BrandUser, user_code)`.
* `completion_url(status, scopes)` returns where to redirect after consent,
  or `None` to show a simple page instead.

`JWTBrandLogin` verifies an ES256 or RS256 assertion from the Brand. It
checks `iss`, that `aud` equals the consent URL, `sub`, `user_code`, that
`jti` is used only once, and that `exp - iat` is at most 300.

**Tokens.** The delegation token is an ES256 or RS256 JWT with
`typ: at+jwt`. Its claims are:

* `iss`: `{interface}/oauth`
* `aud`: the interface URL
* `sub`: the Brand user id
* `client_id`: the PA's issuer
* `scope`, `grant_id`, `iat`, `exp` (at most 1 h), `jti`

Refresh tokens rotate on every use. If a used refresh token is presented
again, the whole grant is revoked, so every access token and refresh token
issued under it stops working.

**Receipts.** A receipt is added to every `message:send` reply that was
served under a delegation token. It is stored under
`metadata["pact.receipt"]` as `{jws, claims}`, where `jws` is the compact JWS
of the claims (`typ: pact-receipt+jws`), signed with the same keys as the
tokens. A retried `messageId` returns the original receipt.

**Keys.** `ProviderKeySet.from_env()` reads `PACT_PROVIDER_JWKS` (JSON) or
`PACT_PROVIDER_JWKS_FILE`. The first key signs. To rotate, put the new key
first and keep the old key until the tokens it signed have expired (1 h). The
JWKS publishes every key.

### Security properties

* **State.** Every store is a `Protocol` with a bounded, expiring in-memory
  default: registry, JWKS cache, contexts, device authorizations, grants,
  refresh tokens, consent sessions, nonces (`jti`) and attempt limiters. They
  are in `ampro.interop.pact.stores`, and you pass your own through
  `DelegationStores` or `context_store=`. Each mutating method is a single
  compare-and-set step.
* **Secrets.** Device codes, refresh tokens and consent sessions are 256-bit
  values from `secrets`, stored only as SHA-256 hashes.
* **User codes.** A user code is 8 characters from a 20-letter alphabet
  (about 34.6 bits). Consent submissions are limited per Brand user and per
  client IP. `device_authorization` is limited per (PA, sub).
* **Consent page.** The page is protected by a single-use session token
  bound to the `user_code` and the logged-in user, and by an `Origin` check.
  It is served with `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `no-store`, `no-referrer`, and no scripts. Every value on the page is
  HTML-escaped.
* **Errors.** Responses carry only fixed messages; exception text is never
  sent. Logging is structured (`pact.*` event names with `extra` fields) and
  never includes tokens.

## Personal agent

```python
from ampro.interop.pact import PACTClient, PASigner

signer = PASigner("https://pa.example.com", private_jwk)        # ES256, 120 s, jti
async with PACTClient(signer, audience="provider-aud-7f3c") as pa:
    brand = await pa.connect("https://skyline.example/.well-known/agent-card.json")
    reply = await brand.send("user-123", "Rebook me onto SK 318",
                             on_verification=lambda uri: show_link_to_user(uri))
    print(reply.text, reply.receipt_claims)      # receipts are verified against jwks_uri
```

`send` handles `AUTH_REQUIRED` with these steps:

1. It runs the device flow for the missing scopes.
2. It hands `verification_uri_complete` to your callback. The personal agent
   never sees the login itself.
3. It polls the token endpoint, respecting `interval` and `slow_down`.
4. It sends the message again in the same `contextId`.

Delegation tokens are kept per `sub` and refreshed when they are close to
expiry.

`message:send` carries `traceparent`, `tracestate` and `AMP-Hop-Count`
headers, and `metadata["amp.hopCount"]`, taken from the handler the client is
called from (a new trace at hop 1 otherwise). `PACTClient(max_hops=20)`
raises `HopLimitExceeded` instead of sending when the next hop would exceed
it.

| PACT / A2A carrier | AMPContext |
|---|---|
| `traceparent` header | `trace_id`, `parent_span_id` |
| `tracestate` header | `trace_state` |
| `AMP-Hop-Count` header, `metadata["amp.hopCount"]` | `hop_count` (largest value wins) |

## Conformance

`scripts/run_pact_conformance.py --pact-repo <openpactprotocol checkout>`
does the following:

1. Serves the PACT example from `examples/48_pact_provider.py` on
   127.0.0.1.
2. Serves a throwaway PA JWKS. The fetcher allows plain HTTP for 127.0.0.1
   only, and only for this run.
3. Runs the official `e2e/pact.test.ts` and `e2e/delegated.test.ts` with
   `E2E_PROVIDER=any`.

Result: **pact.test.ts 10/10 and delegated.test.ts 9/9 pass.**

The suite looks for the identity scheme under the name `platformJwt`, while
§2.1 of the spec text names it `paJwt`. Our cards use `paJwt` by default. The
conformance run passes `identity_scheme="platformJwt"`.

## Limitations

* The defaults keep state in one process. With several workers, plug in
  shared stores.
* Consent is always shown. The optional skip in §5.3, for when an unexpired
  grant already covers the request, is not implemented.
* A step-up link creates a device authorization that the PA never polls. The
  PA starts its own flow, as in the reference implementation. These records
  expire after `device_code_ttl`.
