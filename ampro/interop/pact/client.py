"""Personal-agent side of PACT: sign PA JWTs, talk to Brands, verify receipts.

::

    signer = PASigner("https://pa.example.com", private_jwk)
    async with PACTClient(signer, audience="provider-aud-1") as pa:
        brand = await pa.connect("https://brand.example/.well-known/agent-card.json")
        reply = await brand.send("user-123", "Cancel order A-88213",
                                 on_verification=lambda uri: print("Open", uri))
        print(reply.text, reply.receipt)

``send`` handles ``TASK_STATE_AUTH_REQUIRED`` by running the RFC 8628 device
flow for the missing scopes (the User opens ``verification_uri_complete``),
then re-sends with the delegation token in the same ``contextId``.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ampro.interop.pact._jwt import (
    JoseError,
    check_header_alg,
    private_key_from_jwk,
    public_key_from_jwk,
    sign_jwt,
    split_compact,
    verify_signature,
)
from ampro.interop.pact.delegation import DEVICE_CODE_GRANT, REFRESH_GRANT
from ampro.interop.propagation import (
    DEFAULT_MAX_HOPS,
    HOP_COUNT_METADATA_KEY,
    check_max_hops,
    outbound_propagation,
)

PACT_HEADERS = {"A2A-Version": "1.0", "Content-Type": "application/json"}


class PACTClientError(Exception):
    """An HTTP or protocol error talking to a PACT provider."""

    def __init__(self, message: str, *, status: int | None = None, reason: str | None = None,
                 body: Any = None) -> None:
        self.status = status
        self.reason = reason
        self.body = body
        super().__init__(message)


class OAuthError(PACTClientError):
    def __init__(self, error: str, description: str | None, status: int) -> None:
        self.error = error
        super().__init__(f"{error}: {description}" if description else error, status=status, reason=error)


class ReceiptError(Exception):
    pass


class PASigner:
    """Mint PA JWTs (§3.2): ``ES256``/``RS256``, ``kid``, ``jti``, 120 s lifetime."""

    def __init__(self, issuer: str, private_jwk: dict[str, Any] | str, *,
                 clock: Callable[[], float] = time.time) -> None:
        jwk = json.loads(private_jwk) if isinstance(private_jwk, str) else dict(private_jwk)
        if not isinstance(jwk.get("kid"), str) or not jwk["kid"]:
            raise ValueError("private JWK must include kid")
        self.issuer = issuer
        self.kid = jwk["kid"]
        self._key, self.alg = private_key_from_jwk(jwk)
        self._clock = clock

    def sign(self, sub: str, audience: str, *, ttl: int = 120) -> str:
        if not 0 < ttl <= 300:
            raise ValueError("ttl must be 1..300 seconds")
        if not sub:
            raise ValueError("sub is required")
        iat = int(self._clock())
        return sign_jwt(
            {"iss": self.issuer, "sub": sub, "aud": audience, "iat": iat, "exp": iat + ttl,
             "jti": str(uuid.uuid4())},
            self._key, self.alg, {"kid": self.kid},
        )


@dataclass
class DelegationToken:
    access_token: str
    refresh_token: str | None
    scopes: list[str]
    expires_at: float


@dataclass
class Reply:
    """A ``message:send`` result: a Message or an ``AUTH_REQUIRED`` task."""

    raw: dict[str, Any]
    context_id: str | None = None
    text: str = ""
    receipt: dict[str, Any] | None = None
    receipt_claims: dict[str, Any] | None = None
    missing_scopes: list[str] = field(default_factory=list)
    verification_uri_complete: str | None = None

    @property
    def auth_required(self) -> bool:
        return "task" in self.raw


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def verify_receipt(receipt: dict[str, Any], jwks: dict[str, Any], *,
                   expected: dict[str, Any] | None = None) -> dict[str, Any]:
    """Verify a ``pact.receipt`` against the provider JWKS; returns its claims."""
    jws = receipt.get("jws") if isinstance(receipt, dict) else None
    if not isinstance(jws, str):
        raise ReceiptError("receipt has no jws")
    try:
        header, payload, _ = split_compact(jws)
        alg = check_header_alg(header)
    except JoseError as exc:
        raise ReceiptError(str(exc)) from None
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")]
    for jwk in keys:
        try:
            verify_signature(jws, public_key_from_jwk(jwk, alg), alg)
            break
        except JoseError:
            continue
    else:
        raise ReceiptError("receipt signature is invalid")
    if not isinstance(payload, dict):
        raise ReceiptError("receipt payload is not an object")
    if _canonical(payload) != _canonical(receipt.get("claims")):
        raise ReceiptError("receipt claims do not match the signed payload")
    for key, value in (expected or {}).items():
        if value is not None and payload.get(key) != value:
            raise ReceiptError(f"receipt {key} does not match")
    return payload


class PACTClient:
    """HTTP client for personal agents.

    Args:
        signer: the personal agent's :class:`PASigner`.
        audience: the ``aud`` the Provider assigned (never derived from a card).
        http: an ``httpx.AsyncClient`` (e.g. with ``ASGITransport`` in tests).
        sleep: async sleep used while polling (tests pass a fast one).
        max_hops: refuse to send (``HopLimitExceeded``) when the outbound hop
            count would exceed this.  ``message:send`` carries W3C
            ``traceparent`` / ``tracestate`` and ``AMP-Hop-Count`` from the
            calling handler, and ``amp.hopCount`` in the message metadata.
    """

    def __init__(self, signer: PASigner, audience: str, *, http: Any = None,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                 max_hops: int = DEFAULT_MAX_HOPS) -> None:
        import httpx

        self.max_hops = check_max_hops(max_hops)
        self.signer = signer
        self.audience = audience
        self.http = http or httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        self._owns_http = http is None
        self.sleep = sleep

    async def __aenter__(self) -> PACTClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._owns_http:
            await self.http.aclose()

    def _auth(self, sub: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.signer.sign(sub, self.audience)}"}

    async def connect(self, card_url: str) -> BrandSession:
        resp = await self.http.get(card_url, follow_redirects=True)
        if resp.status_code != 200:
            raise PACTClientError("agent card not found", status=resp.status_code)
        card = resp.json()
        url = next((i["url"] for i in card.get("supportedInterfaces", [])
                    if i.get("protocolBinding") == "HTTP+JSON" and i.get("protocolVersion") == "1.0"),
                   None)
        if not url:
            raise PACTClientError("card has no HTTP+JSON 1.0 interface")
        return BrandSession(self, card, url)


class BrandSession:
    """One Brand's interface, with delegation tokens kept per user ``sub``."""

    def __init__(self, client: PACTClient, card: dict[str, Any], url: str) -> None:
        self.client = client
        self.card = card
        self.url = url.rstrip("/")
        self.tokens: dict[str, DelegationToken] = {}
        self.receipts: list[dict[str, Any]] = []
        self._metadata: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self.delegation = self._delegation_scheme(card)

    @staticmethod
    def _delegation_scheme(card: dict[str, Any]) -> dict[str, Any] | None:
        schemes = card.get("securitySchemes") or {}
        for req in card.get("securityRequirements") or []:
            names = list((req.get("schemes") or {}).keys())
            if len(names) != 2:
                continue
            for name in names:
                s = schemes.get(name, {}).get("oauth2SecurityScheme")
                if s and "deviceCode" in (s.get("flows") or {}):
                    return {**s["flows"]["deviceCode"], "metadata": s.get("oauth2MetadataUrl")}
        return None

    @property
    def scopes(self) -> dict[str, str]:
        return dict((self.delegation or {}).get("scopes") or {})

    # -- messages ---------------------------------------------------------

    async def send(
        self,
        sub: str,
        text: str,
        *,
        context_id: str | None = None,
        on_verification: Callable[[str], Any] | None = None,
        max_step_ups: int = 1,
        verify_receipts: bool = True,
    ) -> Reply:
        reply = await self._send_once(sub, text, context_id)
        steps = 0
        while reply.auth_required and on_verification is not None and steps < max_step_ups:
            steps += 1
            token = await self.authorize(sub, reply.missing_scopes, on_verification)
            if token is None:
                return reply
            reply = await self._send_once(sub, text, reply.context_id)
        if verify_receipts and reply.receipt is not None:
            jwks = await self.jwks()
            reply.receipt_claims = verify_receipt(
                reply.receipt, jwks, expected={"pa": self.client.signer.issuer, "brand": self.url})
            self.receipts.append(reply.receipt)
        return reply

    async def _send_once(self, sub: str, text: str, context_id: str | None) -> Reply:
        message: dict[str, Any] = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
                                   "parts": [{"text": text}]}
        if context_id:
            message["contextId"] = context_id
        prop = outbound_propagation(self.client.max_hops)
        trace_headers = prop.outbound_headers(self.client.max_hops)
        message["metadata"] = {HOP_COUNT_METADATA_KEY: prop.next_hop(self.client.max_hops)}
        headers = {**PACT_HEADERS, **trace_headers, **self.client._auth(sub)}
        token = await self._valid_token(sub)
        if token is not None:
            headers["X-A2A-User-Delegation"] = f"Bearer {token.access_token}"
        resp = await self.client.http.post(f"{self.url}/message:send", headers=headers,
                                           content=json.dumps({"message": message}))
        if resp.status_code == 401 and token is not None and "invalid_token" in resp.headers.get(
                "www-authenticate", ""):
            self.tokens.pop(sub, None)
            raise PACTClientError("delegation token rejected", status=401, reason="invalid_token")
        if resp.status_code != 200:
            reason = None
            body: Any = None
            try:
                body = resp.json()
                reason = body["error"]["details"][0]["reason"]
            except (ValueError, KeyError, IndexError, TypeError):
                pass
            raise PACTClientError(f"message:send failed ({resp.status_code})",
                                  status=resp.status_code, reason=reason, body=body)
        payload = resp.json()
        if "task" in payload:
            task = payload["task"]
            meta = task.get("metadata") or {}
            return Reply(raw=payload, context_id=task.get("contextId"),
                         text=" ".join(p.get("text", "") for p in
                                       (task.get("status", {}).get("message") or {}).get("parts", [])),
                         missing_scopes=list(meta.get("pact.missingScopes") or []),
                         verification_uri_complete=meta.get("pact.verificationUriComplete"))
        msg = payload["message"]
        return Reply(raw=payload, context_id=msg.get("contextId"),
                     text="\n".join(p.get("text", "") for p in msg.get("parts", [])),
                     receipt=(msg.get("metadata") or {}).get("pact.receipt"))

    # -- delegation ---------------------------------------------------------

    async def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            if not self.delegation or not self.delegation.get("metadata"):
                raise PACTClientError("brand does not offer delegation")
            resp = await self.client.http.get(self.delegation["metadata"])
            if resp.status_code != 200:
                raise PACTClientError("metadata unavailable", status=resp.status_code)
            self._metadata = resp.json()
        return self._metadata

    async def jwks(self) -> dict[str, Any]:
        if self._jwks is None:
            resp = await self.client.http.get((await self.metadata())["jwks_uri"])
            if resp.status_code != 200:
                raise PACTClientError("jwks unavailable", status=resp.status_code)
            self._jwks = resp.json()
        return self._jwks

    async def _form(self, url: str, sub: str, form: dict[str, str]) -> dict[str, Any]:
        resp = await self.client.http.post(url, headers={
            **self.client._auth(sub), "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"},
            data={**form, "client_id": self.client.signer.issuer})
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code == 200 and isinstance(body, dict):
            return body
        if resp.status_code != 401 and isinstance(body, dict) and isinstance(body.get("error"), str):
            raise OAuthError(body["error"], body.get("error_description"), resp.status_code)
        raise PACTClientError("OAuth request failed", status=resp.status_code, body=body)

    async def start_device_flow(self, sub: str, scopes: list[str]) -> dict[str, Any]:
        unknown = [s for s in scopes if s not in self.scopes]
        if not scopes or unknown:
            raise ValueError(f"scopes not on the Agent Card: {unknown}")
        return await self._form(self.delegation["deviceAuthorizationUrl"], sub,  # type: ignore[index]
                                {"scope": " ".join(dict.fromkeys(scopes))})

    async def poll(self, sub: str, device_code: str) -> DelegationToken | None:
        try:
            body = await self._form(self.delegation["tokenUrl"], sub,  # type: ignore[index]
                                    {"grant_type": DEVICE_CODE_GRANT, "device_code": device_code})
        except OAuthError as exc:
            if exc.error in ("authorization_pending", "slow_down"):
                return None
            raise
        return self._store(sub, body)

    def _store(self, sub: str, body: dict[str, Any]) -> DelegationToken:
        token = DelegationToken(
            access_token=body["access_token"], refresh_token=body.get("refresh_token"),
            scopes=[s for s in str(body.get("scope", "")).split(" ") if s],
            expires_at=time.time() + int(body.get("expires_in", 0)),
        )
        self.tokens[sub] = token
        return token

    async def authorize(self, sub: str, scopes: list[str],
                        on_verification: Callable[[str], Any]) -> DelegationToken | None:
        """Run the device flow; *on_verification* gets ``verification_uri_complete``."""
        current = self.tokens.get(sub)
        wanted = list(dict.fromkeys([*(current.scopes if current else []), *scopes]))
        auth = await self.start_device_flow(sub, [s for s in wanted if s in self.scopes])
        shown = on_verification(auth["verification_uri_complete"])
        if asyncio.iscoroutine(shown):
            await shown
        interval = int(auth.get("interval", 5))
        deadline = time.monotonic() + int(auth["expires_in"])
        while time.monotonic() < deadline:
            await self.client.sleep(interval)
            try:
                token = await self.poll(sub, auth["device_code"])
            except OAuthError as exc:
                if exc.error == "slow_down":
                    interval += 5
                    continue
                if exc.error in ("access_denied", "expired_token"):
                    return None
                raise
            if token is not None:
                return token
        return None

    async def refresh(self, sub: str) -> DelegationToken:
        current = self.tokens.get(sub)
        if current is None or not current.refresh_token:
            raise PACTClientError("no refresh token")
        body = await self._form(self.delegation["tokenUrl"], sub,  # type: ignore[index]
                                {"grant_type": REFRESH_GRANT, "refresh_token": current.refresh_token})
        return self._store(sub, body)

    async def _valid_token(self, sub: str) -> DelegationToken | None:
        token = self.tokens.get(sub)
        if token is None:
            return None
        if token.expires_at - 60 <= time.time() and token.refresh_token:
            try:
                return await self.refresh(sub)
            except PACTClientError:
                self.tokens.pop(sub, None)
                return None
        return token


__all__ = [
    "BrandSession",
    "DelegationToken",
    "OAuthError",
    "PACTClient",
    "PACTClientError",
    "PASigner",
    "ReceiptError",
    "Reply",
    "verify_receipt",
]
