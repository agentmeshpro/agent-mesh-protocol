"""PACT Delegated authority — the per-Brand authorization server (§5).

Endpoints, relative to ``{interfaceUrl}/oauth``:

==========================================  ====================================
``GET  .well-known/oauth-authorization-server``  RFC 8414 metadata
``GET  jwks.json``                           Provider keys (tokens + receipts)
``POST device_authorization``                RFC 8628 §3.1 (PA-JWT client auth)
``POST token``                               device_code / refresh_token grants
``POST consent``                             Brand login returns here (assertion)
``POST consent/decision``                    the User's consent form
==========================================  ====================================

Security properties:

* device codes, refresh tokens and consent sessions are 256-bit random
  values stored only as SHA-256 hashes;
* user codes are 8 letters from a 20-letter alphabet (~34.6 bits, RFC 8628
  §6.1) and lookups are rate limited per Brand user and per client address;
* refresh tokens rotate on every use; presenting a used one revokes the
  whole grant (reuse detection);
* the consent form is protected by a single-use, unguessable session token
  bound to the ``user_code`` and the logged-in Brand user (synchronizer
  token), an ``Origin`` check, and anti-framing headers;
* every error is a fixed string — no exception text reaches a client.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from ampro.interop.pact._jwt import JoseError
from ampro.interop.pact.auth import PAIdentity, PAJwtAuthenticator, bearer_token
from ampro.interop.pact.brand import USER_CODE_RE, Brand, BrandAssertionError
from ampro.interop.pact.errors import oauth_error, oauth_json, too_many_requests, unauthorized
from ampro.interop.pact.keys import ProviderKeySet
from ampro.interop.pact.pages import consent_page, message_page
from ampro.interop.pact.scopes import Delegation
from ampro.interop.pact.stores import (
    AttemptLimiter,
    Clock,
    ConsentSession,
    DelegationStores,
    DeviceAuthorization,
    Grant,
    InMemoryAttemptLimiter,
    RefreshToken,
    secret_key,
)
from ampro.server.auth import Unauthorized
from ampro.server.http import HTTPRequest, HTTPResponse

logger = logging.getLogger("ampro.interop.pact.delegation")

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_GRANT = "refresh_token"
ACCESS_TOKEN_TYP = "at+jwt"
RECEIPT_TYP = "pact-receipt+jws"
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
MAX_FORM_BYTES = 8192
MAX_SCOPES = 32


@dataclass(frozen=True)
class OAuthURLs:
    interface: str
    issuer: str
    metadata: str
    jwks: str
    device_authorization: str
    token: str
    consent: str
    decision: str

    @classmethod
    def for_interface(cls, interface_url: str) -> OAuthURLs:
        base = interface_url.rstrip("/")
        issuer = f"{base}/oauth"
        return cls(
            interface=base, issuer=issuer,
            metadata=f"{issuer}/.well-known/oauth-authorization-server",
            jwks=f"{issuer}/jwks.json",
            device_authorization=f"{issuer}/device_authorization",
            token=f"{issuer}/token",
            consent=f"{issuer}/consent",
            decision=f"{issuer}/consent/decision",
        )


class InvalidDelegation(Exception):
    """A delegation token failed verification (logged, never shown)."""


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _user_code() -> str:
    chars = [secrets.choice(USER_CODE_ALPHABET) for _ in range(8)]
    return "".join(chars[:4]) + "-" + "".join(chars[4:])


def _parse_form(request: HTTPRequest, *, multi: frozenset[str] = frozenset()) -> dict[str, Any] | None:
    """Strictly parse a urlencoded body; ``None`` when invalid.

    Parameters may appear once, except those in *multi* (returned as lists).
    """
    ctype = (request.header("content-type") or "").split(";")[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded" or len(request.body) > MAX_FORM_BYTES:
        return None
    try:
        pairs = parse_qsl(request.body.decode("utf-8"), keep_blank_values=True,
                          strict_parsing=False, max_num_fields=64)
    except (UnicodeDecodeError, ValueError):
        return None
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in multi:
            out.setdefault(k, []).append(v)
        elif k in out:
            return None
        else:
            out[k] = v
    return out


def _parse_scope(value: str) -> list[str]:
    return list(dict.fromkeys(s for s in value.split(" ") if s))


class DelegationServer:
    """Authorization server shared by every delegating Brand of a provider.

    Args:
        keys: provider signing keys (delegation tokens, receipts).
        authenticator: verifies the PA JWT on client endpoints.
        stores: persistence (bounded in-memory by default).
        access_token_ttl: seconds (≤ 3600, §5.4).
        grant_ttl: lifetime of a grant (refresh tokens die with it).
        device_code_ttl / poll_interval: RFC 8628 ``expires_in`` / ``interval``.
        consent_ttl: lifetime of a consent session.
        start_limiter: rate limit for ``device_authorization`` per ``(PA, sub)``.
        client_limiter: rate limit for consent submissions per client address.
    """

    def __init__(
        self,
        keys: ProviderKeySet,
        authenticator: PAJwtAuthenticator,
        *,
        stores: DelegationStores | None = None,
        access_token_ttl: int = 3600,
        grant_ttl: int = 30 * 24 * 3600,
        device_code_ttl: int = 600,
        poll_interval: int = 5,
        consent_ttl: int = 600,
        start_limiter: AttemptLimiter | None = None,
        client_limiter: AttemptLimiter | None = None,
        clock: Clock = time.time,
    ) -> None:
        if not 0 < access_token_ttl <= 3600:
            raise ValueError("access_token_ttl must be 1..3600 seconds")
        self.keys = keys
        self.authenticator = authenticator
        self.stores = stores or DelegationStores()
        self.access_token_ttl = access_token_ttl
        self.grant_ttl = grant_ttl
        self.device_code_ttl = device_code_ttl
        self.poll_interval = poll_interval
        self.consent_ttl = consent_ttl
        self.start_limiter = start_limiter or InMemoryAttemptLimiter(limit=30, window=600, clock=clock)
        self.client_limiter = client_limiter or InMemoryAttemptLimiter(limit=30, window=600, clock=clock)
        self.clock = clock

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    async def handle(self, request: HTTPRequest, brand: Brand, interface_url: str,
                     rest: list[str]) -> HTTPResponse:
        """Serve ``{interface}/oauth/<rest>``; *brand* must offer delegation."""
        urls = OAuthURLs.for_interface(interface_url)
        method = request.method.upper()
        route = "/".join(rest)
        try:
            if route == ".well-known/oauth-authorization-server":
                return self._metadata(brand, urls) if method == "GET" else _405("GET")
            if route == "jwks.json":
                return self._jwks() if method == "GET" else _405("GET")
            if route == "device_authorization":
                return await self._device_authorization(request, brand, urls) if method == "POST" else _405("POST")
            if route == "token":
                return await self._token(request, brand, urls) if method == "POST" else _405("POST")
            if route == "consent":
                return await self._consent(request, brand, urls) if method == "POST" else _405("POST")
            if route == "consent/decision":
                return await self._decision(request, brand, urls) if method == "POST" else _405("POST")
        except Exception:
            logger.exception("pact.oauth.internal_error", extra={"brand": brand.brand_id, "route": route})
            if route in ("consent", "consent/decision"):
                return message_page("Something went wrong", "Start again from your agent.", 500)
            return oauth_error("server_error", "Internal error", 500)
        return HTTPResponse.empty(404)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def metadata(self, brand: Brand, urls: OAuthURLs) -> dict[str, Any]:
        return {
            "issuer": urls.issuer,
            "device_authorization_endpoint": urls.device_authorization,
            "token_endpoint": urls.token,
            "jwks_uri": urls.jwks,
            "scopes_supported": [s.id for s in brand.scopes],
            "grant_types_supported": [DEVICE_CODE_GRANT, REFRESH_GRANT],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        }

    def _metadata(self, brand: Brand, urls: OAuthURLs) -> HTTPResponse:
        return HTTPResponse.json(self.metadata(brand, urls), headers={
            "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300"})

    def _jwks(self) -> HTTPResponse:
        return HTTPResponse.json(self.keys.jwks(), headers={
            "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300"})

    # ------------------------------------------------------------------
    # Client endpoints (PA-JWT authenticated)
    # ------------------------------------------------------------------

    async def _client(self, request: HTTPRequest) -> PAIdentity | None:
        try:
            return await self.authenticator.verify(bearer_token(request.header("authorization")))
        except Unauthorized:
            return None

    async def create_device_authorization(
        self, brand: Brand, urls: OAuthURLs, identity: PAIdentity, scopes: list[str],
    ) -> dict[str, Any]:
        """Start an RFC 8628 flow for *scopes* (also used for step-up links)."""
        assert brand.login is not None
        device_code = "dc_" + secrets.token_urlsafe(32)
        for _ in range(5):
            code = _user_code()
            if await self.stores.devices.by_user_code(brand.brand_id, code) is None:
                break
        else:  # pragma: no cover - 20^8 space
            raise RuntimeError("could not allocate a user_code")
        now = self.clock()
        await self.stores.devices.create(DeviceAuthorization(
            device_code_hash=secret_key(device_code), user_code=code, brand_id=brand.brand_id,
            client_id=identity.issuer, pa_subject=identity.sub, scopes=tuple(scopes),
            interval=self.poll_interval, expires_at=now + self.device_code_ttl,
        ))
        logger.info("pact.oauth.device_authorization", extra={
            "brand": brand.brand_id, "client_id": identity.issuer, "scopes": " ".join(scopes)})
        return {
            "device_code": device_code,
            "user_code": code,
            "verification_uri": brand.login.login_url(urls.consent),
            "verification_uri_complete": brand.login.login_url(
                f"{urls.consent}?user_code={quote(code)}"),
            "expires_in": self.device_code_ttl,
            "interval": self.poll_interval,
        }

    async def step_up_link(self, brand: Brand, interface_url: str, identity: PAIdentity,
                           scopes: list[str]) -> str | None:
        if not brand.delegation_enabled:
            return None
        known = [s for s in scopes if brand.scope(s) is not None]
        if not known:
            return None
        if not await self.start_limiter.hit(f"{brand.brand_id}|{identity.principal_id}"):
            return None
        auth = await self.create_device_authorization(
            brand, OAuthURLs.for_interface(interface_url), identity, known)
        return auth["verification_uri_complete"]

    async def _device_authorization(self, request: HTTPRequest, brand: Brand,
                                    urls: OAuthURLs) -> HTTPResponse:
        identity = await self._client(request)
        if identity is None:
            return unauthorized()
        form = _parse_form(request)
        if form is None:
            return oauth_error("invalid_request", "Malformed request")
        if form.get("client_id") != identity.issuer:
            return oauth_error("invalid_client", "client_id must equal the personal-agent issuer", 401)
        scope_param = form.get("scope", "")
        scopes = _parse_scope(scope_param) if len(scope_param) <= 4096 else []
        if not scopes or len(scopes) > MAX_SCOPES or any(brand.scope(s) is None for s in scopes):
            return oauth_error("invalid_scope", "Request scope ids listed on the Agent Card")
        if not await self.start_limiter.hit(f"{brand.brand_id}|{identity.principal_id}"):
            return too_many_requests(60)
        return oauth_json(await self.create_device_authorization(brand, urls, identity, scopes))

    async def _token(self, request: HTTPRequest, brand: Brand, urls: OAuthURLs) -> HTTPResponse:
        identity = await self._client(request)
        if identity is None:
            return unauthorized()
        form = _parse_form(request)
        if form is None:
            return oauth_error("invalid_request", "Malformed request")
        if form.get("client_id") != identity.issuer:
            return oauth_error("invalid_client", "client_id must equal the personal-agent issuer", 401)
        grant_type = form.get("grant_type")
        if grant_type == DEVICE_CODE_GRANT:
            return await self._device_code_grant(form.get("device_code", ""), brand, urls, identity)
        if grant_type == REFRESH_GRANT:
            return await self._refresh_grant(form.get("refresh_token", ""), brand, urls, identity)
        return oauth_error("unsupported_grant_type", "Unsupported grant_type")

    async def _device_code_grant(self, device_code: str, brand: Brand, urls: OAuthURLs,
                                 identity: PAIdentity) -> HTTPResponse:
        if not device_code or len(device_code) > 256:
            return oauth_error("invalid_grant", "Unknown device_code")
        h = secret_key(device_code)
        rec = await self.stores.devices.by_device_code(h)
        if rec is None or rec.brand_id != brand.brand_id or rec.client_id != identity.issuer:
            return oauth_error("invalid_grant", "Unknown device_code")
        now = self.clock()
        if rec.status == "denied":
            return oauth_error("access_denied", "The user denied access")
        if rec.status == "consumed":
            return oauth_error("invalid_grant", "device_code was already used")
        if now >= rec.expires_at:
            return oauth_error("expired_token", "The device code expired")
        if rec.status == "pending":
            previous = await self.stores.devices.touch_poll(h, now)
            if previous is not None and now - previous < rec.interval - 1:
                return oauth_error("slow_down", "Poll less often")
            return oauth_error("authorization_pending", "Waiting for the user")
        consumed = await self.stores.devices.transition(h, "approved", "consumed")
        grant = await self.stores.grants.get(consumed.grant_id) if consumed and consumed.grant_id else None
        if grant is None or grant.revoked:
            return oauth_error("invalid_grant", "device_code was already used")
        logger.info("pact.oauth.token_issued", extra={
            "brand": brand.brand_id, "grant_id": grant.grant_id, "client_id": identity.issuer})
        return oauth_json(await self._issue(grant, urls))

    async def _refresh_grant(self, refresh_token: str, brand: Brand, urls: OAuthURLs,
                             identity: PAIdentity) -> HTTPResponse:
        if not refresh_token or len(refresh_token) > 256:
            return oauth_error("invalid_grant", "Unknown or expired refresh_token")
        rec = await self.stores.refresh_tokens.consume(secret_key(refresh_token))
        if rec is None:
            return oauth_error("invalid_grant", "Unknown or expired refresh_token")
        grant = await self.stores.grants.get(rec.grant_id)
        if rec.used:
            await self.stores.grants.revoke(rec.grant_id)
            logger.warning("pact.oauth.refresh_reuse", extra={
                "brand": brand.brand_id, "grant_id": rec.grant_id, "client_id": identity.issuer})
            return oauth_error("invalid_grant", "Unknown or expired refresh_token")
        now = self.clock()
        if (grant is None or grant.revoked or grant.expires_at <= now or rec.expires_at <= now
                or grant.brand_id != brand.brand_id or grant.client_id != identity.issuer):
            return oauth_error("invalid_grant", "Unknown or expired refresh_token")
        return oauth_json(await self._issue(grant, urls))

    async def _issue(self, grant: Grant, urls: OAuthURLs) -> dict[str, Any]:
        now = int(self.clock())
        exp = min(now + self.access_token_ttl, int(grant.expires_at))
        scope = " ".join(grant.scopes)
        access = self.keys.sign_json({
            "iss": urls.issuer, "aud": urls.interface, "sub": grant.brand_user,
            "client_id": grant.client_id, "scope": scope, "grant_id": grant.grant_id,
            "iat": now, "exp": exp, "jti": secrets.token_urlsafe(16),
        }, ACCESS_TOKEN_TYP)
        refresh = "rt_" + secrets.token_urlsafe(32)
        await self.stores.refresh_tokens.create(RefreshToken(
            token_hash=secret_key(refresh), grant_id=grant.grant_id, expires_at=grant.expires_at))
        return {"token_type": "Bearer", "access_token": access, "refresh_token": refresh,
                "expires_in": max(1, exp - now), "scope": scope}

    # ------------------------------------------------------------------
    # Browser endpoints (Brand login -> consent)
    # ------------------------------------------------------------------

    def _origin_ok(self, request: HTTPRequest, allowed: set[str]) -> bool:
        """Browsers send ``Origin`` on form POSTs; when present it must be expected."""
        origin = request.header("origin")
        return origin is None or origin in allowed

    async def _consent(self, request: HTTPRequest, brand: Brand, urls: OAuthURLs) -> HTTPResponse:
        assert brand.login is not None
        allowed = {_origin(urls.consent), _origin(brand.login.login_url(urls.consent))}
        if not self._origin_ok(request, allowed):
            return message_page("Request refused", "This request did not come from a sign-in page.", 403)
        if not await self.client_limiter.hit(f"consent|{request.client or '-'}"):
            return message_page("Too many attempts", "Wait a few minutes and try again.", 429)
        form = _parse_form(request)
        if form is None or not isinstance(form.get("assertion"), str):
            return message_page("Sign-in failed", "The sign-in could not be verified. Try again.", 400)
        try:
            user, user_code = await brand.login.verify_assertion(form["assertion"], audience=urls.consent)
        except BrandAssertionError as exc:
            logger.info("pact.consent.assertion_rejected", extra={"brand": brand.brand_id, "reason": str(exc)})
            return message_page("Sign-in failed", "The sign-in could not be verified. Try again.", 401)
        if not await self.stores.user_code_attempts.hit(f"{brand.brand_id}|{user.id}"):
            logger.warning("pact.consent.user_code_rate_limited", extra={"brand": brand.brand_id})
            return message_page("Too many attempts", "Wait a few minutes and try again.", 429)
        rec = None
        if USER_CODE_RE.match(user_code):
            rec = await self.stores.devices.by_user_code(brand.brand_id, user_code)
        if rec is None or rec.status != "pending" or rec.expires_at <= self.clock():
            return message_page("Request expired", "This request expired. Start again from your agent.", 400)
        session = secrets.token_urlsafe(32)
        await self.stores.consent_sessions.create(ConsentSession(
            session_hash=secret_key(session), brand_id=brand.brand_id, user_code=user_code,
            brand_user=user.id, display_name=user.display,
            expires_at=min(self.clock() + self.consent_ttl, rec.expires_at),
        ))
        scopes = [(s, brand.scope(s).description) for s in rec.scopes if brand.scope(s)]  # type: ignore[union-attr]
        completion = brand.login.completion_url("approved", [])
        return consent_page(
            brand_name=brand.name, agent_origin=_origin(rec.client_id) if "://" in rec.client_id else rec.client_id,
            user_display=user.display, scopes=scopes, action=urls.decision, session=session,
            form_targets=(completion,) if completion else (),
        )

    async def _decision(self, request: HTTPRequest, brand: Brand, urls: OAuthURLs) -> HTTPResponse:
        assert brand.login is not None
        if not self._origin_ok(request, {_origin(urls.decision)}):
            return message_page("Request refused", "This request did not come from the consent page.", 403)
        form = _parse_form(request, multi=frozenset({"scope"}))
        if form is None or not isinstance(form.get("session"), str):
            return message_page("Consent expired", "This consent page expired. Start again from your agent.", 400)
        session = await self.stores.consent_sessions.take(secret_key(form["session"]))
        now = self.clock()
        if session is None or session.brand_id != brand.brand_id or session.expires_at <= now:
            return message_page("Consent expired", "This consent page expired. Start again from your agent.", 400)
        rec = await self.stores.devices.by_user_code(brand.brand_id, session.user_code)
        if rec is None or rec.status != "pending" or rec.expires_at <= now:
            return message_page("Request expired", "This request expired. Start again from your agent.", 400)
        chosen = set(form.get("scope", []))
        granted = [s for s in rec.scopes if s in chosen]
        if form.get("decision") != "allow" or not granted:
            await self.stores.devices.transition(rec.device_code_hash, "pending", "denied",
                                                 brand_user=session.brand_user)
            logger.info("pact.consent.denied", extra={"brand": brand.brand_id, "client_id": rec.client_id})
            return self._done(brand, "denied", [])
        grant = Grant(
            grant_id="pactgrant_" + secrets.token_urlsafe(18), brand_id=brand.brand_id,
            client_id=rec.client_id, brand_user=session.brand_user, scopes=tuple(granted),
            created_at=now, expires_at=now + self.grant_ttl,
        )
        updated = await self.stores.devices.transition(
            rec.device_code_hash, "pending", "approved", brand_user=session.brand_user,
            grant_id=grant.grant_id)
        if updated is None:
            return message_page("Request expired", "This request expired. Start again from your agent.", 400)
        await self.stores.grants.create(grant)
        logger.info("pact.consent.approved", extra={
            "brand": brand.brand_id, "grant_id": grant.grant_id, "client_id": rec.client_id,
            "scopes": " ".join(granted)})
        return self._done(brand, "approved", granted)

    def _done(self, brand: Brand, status: str, scopes: list[str]) -> HTTPResponse:
        assert brand.login is not None
        target = brand.login.completion_url(status, scopes)
        if target:
            return HTTPResponse.empty(303, {"Location": target, "Cache-Control": "no-store"})
        if status == "approved":
            return message_page("Connected", "You can close this window and return to your agent.", 200)
        return message_page("Not connected", "Nothing was shared. You can close this window.", 200)

    # ------------------------------------------------------------------
    # Resource side (§5.5) and receipts (§5.6)
    # ------------------------------------------------------------------

    async def verify_delegation(self, header: str, brand: Brand, interface_url: str,
                                identity: PAIdentity) -> Delegation:
        """Verify ``X-A2A-User-Delegation``; raises :class:`InvalidDelegation`."""
        urls = OAuthURLs.for_interface(interface_url)
        token = bearer_token(header)
        if token is None:
            raise InvalidDelegation("not a bearer token")
        try:
            c = self.keys.verify(token, typ=ACCESS_TOKEN_TYP)
        except JoseError as exc:
            raise InvalidDelegation(str(exc)) from None
        now = self.clock()
        if c.get("iss") != urls.issuer or c.get("aud") != urls.interface:
            raise InvalidDelegation("iss/aud mismatch")
        exp, iat = c.get("exp"), c.get("iat")
        if not isinstance(exp, int) or isinstance(exp, bool) or exp <= now:
            raise InvalidDelegation("expired")
        if not isinstance(iat, int) or iat > now + 30:
            raise InvalidDelegation("bad iat")
        if c.get("client_id") != identity.issuer:
            raise InvalidDelegation("client_id does not match the personal agent")
        sub, scope, grant_id = c.get("sub"), c.get("scope"), c.get("grant_id")
        if not isinstance(sub, str) or not isinstance(scope, str) or not isinstance(grant_id, str):
            raise InvalidDelegation("missing claims")
        grant = await self.stores.grants.get(grant_id)
        if (grant is None or grant.revoked or grant.expires_at <= now
                or grant.brand_id != brand.brand_id or grant.client_id != identity.issuer
                or grant.brand_user != sub):
            raise InvalidDelegation("grant unknown, revoked or expired")
        scopes = frozenset(_parse_scope(scope)) & frozenset(grant.scopes)
        return Delegation(sub=sub, scopes=scopes, grant_id=grant_id, client_id=identity.issuer,
                          token=token, exp=exp)

    async def revoke_grant(self, grant_id: str) -> None:
        await self.stores.grants.revoke(grant_id)

    def sign_receipt(self, *, grant_id: str, user: str, pa: str, brand: str,
                     scopes_used: list[str], actions: list[dict[str, str]]) -> dict[str, Any]:
        ts = datetime.fromtimestamp(self.clock(), tz=timezone.utc)
        claims = {
            "grantId": grant_id, "user": user, "pa": pa, "brand": brand,
            "scopesUsed": list(scopes_used), "actions": [dict(a) for a in actions],
            "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
        }
        return {"jws": self.keys.sign_json(claims, RECEIPT_TYP), "claims": claims}


def _405(allow: str) -> HTTPResponse:
    return HTTPResponse.empty(405, {"Allow": allow})


__all__ = [
    "ACCESS_TOKEN_TYP",
    "DEVICE_CODE_GRANT",
    "DelegationServer",
    "InvalidDelegation",
    "OAuthURLs",
    "RECEIPT_TYP",
    "REFRESH_GRANT",
]
