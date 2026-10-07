"""PACT Provider — many Brands, one host (PACT §2–§6).

:class:`PACTProvider` is a :class:`~ampro.server.http.ProtocolAdapter`
serving every Brand at ``{public_url}/a2a/{brandId}``::

    provider = PACTProvider(public_url="https://provider.example.com",
                            registry=registry, audience="provider-aud-1",
                            keys=ProviderKeySet.from_env())
    provider.add_brand(Brand("acme", acme_app, name="Acme Support"))
    server = AgentServer(agent_id="agent://provider", endpoint=...)
    server.mount(provider)

Request pipeline (order matters, §2.2 / §3.4):

1. **route** — unknown paths/methods are ``404``/``405`` with no body, before
   any authentication; the card and the OAuth endpoints need no PA JWT;
2. **authenticate** the PA JWT — any failure is ``401`` + ``WWW-Authenticate:
   Bearer realm="a2a"`` and no body; the body is not parsed before this;
3. optional rate limit per personal agent and per ``(PA, sub)`` → ``429``;
4. **Brand** lookup — unknown Brands are ``404`` even with a valid token;
5. ``X-A2A-User-Delegation`` verification → ``401 error="invalid_token"``;
6. PACT §4 validation (role, text-only parts, ``taskId``, ``contextId``
   ownership, closed contexts, delegated ``sub`` binding);
7. the Brand's A2A adapter runs the AMPI handler (idempotent ``messageId``
   retries, ``AuthRequired`` → ``TASK_STATE_AUTH_REQUIRED``);
8. the reply is normalised (``application/a2a+json``, PACT reason names) and,
   under delegation, gets a signed ``pact.receipt``.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from ampro.interop.a2a import PACT_AUTH_KEYS, TEXT_MODES, A2AAdapter, Principal, Unauthorized
from ampro.interop.pact.auth import PAIdentity, PAJwtAuthenticator, bearer_token
from ampro.interop.pact.brand import Brand
from ampro.interop.pact.card import DEFAULT_SCHEME, build_pact_card
from ampro.interop.pact.delegation import DelegationServer, InvalidDelegation
from ampro.interop.pact.errors import (
    PACTError,
    a2a_error,
    a2a_json,
    method_not_allowed,
    normalize_a2a_response,
    not_found,
    too_many_requests,
    unauthorized,
)
from ampro.interop.pact.jwks import JSONFetcher, JWKSCache
from ampro.interop.pact.keys import ProviderKeySet
from ampro.interop.pact.registry import PersonalAgentRegistry
from ampro.interop.pact.scopes import Delegation, Turn, _turn
from ampro.interop.pact.stores import (
    Clock,
    ContextRecord,
    ContextStore,
    DelegationStores,
    InMemoryContextStore,
    InMemoryReceiptStore,
    NonceStore,
    ReceiptStore,
)
from ampro.server.http import HTTPRequest, HTTPResponse

logger = logging.getLogger("ampro.interop.pact.provider")

DELEGATION_HEADER = "x-a2a-user-delegation"
MAX_ID_LEN = 256
MAX_PARTS = 32
_PART_KINDS = ("text", "raw", "url", "data")
_PART_FIELDS = frozenset({*_PART_KINDS, "metadata", "filename", "mediaType"})
_MESSAGE_FIELDS = frozenset({
    "messageId", "contextId", "taskId", "role", "parts", "metadata", "extensions", "referenceTaskIds",
})

# Principal the provider authenticated, handed to the Brand's A2A adapter.
_principal: ContextVar[Principal | None] = ContextVar("pact_principal", default=None)


class _PreAuthenticated:
    """Authenticator for the per-Brand A2A adapters: the provider already
    verified the PA JWT (and delegation), so return that principal."""

    async def authenticate(self, request: HTTPRequest) -> Principal | None:
        p = _principal.get()
        if p is None:
            raise Unauthorized("request did not pass through the PACT provider")
        return p


@dataclass
class _Hosted:
    brand: Brand
    adapter: Any
    interface_url: str


class PACTProvider:
    """Serve PACT Identity (and, per Brand, Delegated) on A2A 1.0 HTTP+JSON.

    Args:
        public_url: externally visible origin (``https://provider.example``);
            interface URLs, token audiences and receipts derive from it.
        registry: registered personal agents (§3.1).
        audience: the ``aud`` this Provider assigned to personal agents.
        brands: initial Brands (see :meth:`add_brand`).
        keys: provider signing keys — required once any Brand delegates.
        delegation_stores / context_store: persistence (bounded in-memory
            defaults; plug a database for several workers).
        http_client: JWKS fetcher (default: SSRF-safe HTTPS).
        identity_scheme: card name of the PA-JWT scheme (spec: ``paJwt``).
        rate_limiter: optional object with ``check(key) -> (allowed, info)``
            (e.g. :class:`ampro.security.rate_limiter.RateLimiter`); applied
            per personal agent and per ``(PA, sub)``.
        replay_store: optional :class:`NonceStore` to reject a repeated PA-JWT ``jti``.
        receipt_store: where signed receipts are kept for idempotent retries.
        a2a_stores: ``brand_id -> dict`` of extra :class:`A2AAdapter` keyword
            arguments (``task_store``, ``context_store``, ``idempotency_store``,
            ``task_broker``) for each Brand's A2A interface; how several
            workers share Brand task state (see ``docs/SCALING.md``).
        poll_interval: RFC 8628 ``interval`` for device flows.
    """

    #: PACT applies its own Origin rules: A2A routes require a signed
    #: personal-agent JWT (not a browser credential) and the consent pages
    #: check Origin against the Brand's login origin themselves.
    enforces_origin = True

    name = "pact"

    def __init__(
        self,
        *,
        public_url: str,
        registry: PersonalAgentRegistry,
        audience: str,
        brands: list[Brand] | tuple[Brand, ...] = (),
        keys: ProviderKeySet | None = None,
        delegation_stores: DelegationStores | None = None,
        context_store: ContextStore | None = None,
        http_client: JSONFetcher | None = None,
        jwks_cache: JWKSCache | None = None,
        provider_name: str = "PACT provider",
        identity_scheme: str = DEFAULT_SCHEME,
        base_path: str = "/a2a",
        rate_limiter: Any = None,
        replay_store: NonceStore | None = None,
        receipt_store: ReceiptStore | None = None,
        a2a_stores: Callable[[str], dict[str, Any]] | None = None,
        max_text_chars: int = 16_000,
        poll_interval: int = 5,
        access_token_ttl: int = 3600,
        clock: Clock = time.time,
    ) -> None:
        if not public_url.startswith(("https://", "http://")):
            raise ValueError("public_url must be an absolute http(s) URL")
        if not audience:
            raise ValueError("audience is required (§3.1)")
        self.public_url = public_url.rstrip("/")
        self.base_path = "/" + base_path.strip("/")
        self.provider_name = provider_name
        self.identity_scheme = identity_scheme
        self.rate_limiter = rate_limiter
        self.max_text_chars = max_text_chars
        self.clock = clock
        self.authenticator = PAJwtAuthenticator(
            registry, audience=audience, http_client=http_client, jwks_cache=jwks_cache,
            clock=clock, replay_store=replay_store,
        )
        self.keys = keys
        self.delegation: DelegationServer | None = None
        if keys is not None:
            self.delegation = DelegationServer(
                keys, self.authenticator, stores=delegation_stores, clock=clock,
                poll_interval=poll_interval, access_token_ttl=access_token_ttl,
            )
        self.contexts = context_store or InMemoryContextStore(clock=clock)
        self.receipts: ReceiptStore = receipt_store or InMemoryReceiptStore(clock=clock)
        self.a2a_stores = a2a_stores
        self._brands: dict[str, _Hosted] = {}
        for brand in brands:
            self.add_brand(brand)

    # ------------------------------------------------------------------
    # Brands
    # ------------------------------------------------------------------

    def interface_url(self, brand_id: str) -> str:
        return f"{self.public_url}{self.base_path}/{brand_id}"

    def add_brand(self, brand: Brand) -> Brand:
        from ampro.server.core import AgentServer

        if brand.delegation_enabled and self.delegation is None:
            raise ValueError("Brands with delegation need PACTProvider(keys=ProviderKeySet...)")
        server = AgentServer.from_app(brand.app)
        adapter = A2AAdapter.for_server(
            server,
            base_path=f"{self.base_path}/{brand.brand_id}",
            public_url=self.public_url,
            authenticators=(_PreAuthenticated(),),
            require_auth=True,
            input_modes=TEXT_MODES,
            output_modes=("text/plain",),
            auth_required_keys=PACT_AUTH_KEYS,
            serve_root_card=False,
            streaming=False,
            max_text_chars=self.max_text_chars,
            **(self.a2a_stores(brand.brand_id) if self.a2a_stores is not None else {}),
        )
        self._brands[brand.brand_id] = _Hosted(brand, adapter, self.interface_url(brand.brand_id))
        return brand

    def remove_brand(self, brand_id: str) -> None:
        self._brands.pop(brand_id, None)

    def card(self, brand_id: str) -> dict[str, Any] | None:
        hosted = self._brands.get(brand_id)
        if hosted is None:
            return None
        return build_pact_card(
            hosted.brand, interface_url=hosted.interface_url, provider_url=self.public_url,
            provider_name=self.provider_name, identity_scheme=self.identity_scheme,
            delegation=hosted.brand.delegation_enabled and self.delegation is not None,
        )

    # ------------------------------------------------------------------
    # ProtocolAdapter
    # ------------------------------------------------------------------

    async def handle(self, request: HTTPRequest) -> HTTPResponse | None:
        prefix = self.base_path + "/"
        if not request.path.startswith(prefix):
            return None
        segments = request.path[len(prefix):].split("/")
        brand_id, rest = segments[0], segments[1:]
        method = request.method.upper()
        if not brand_id or len(brand_id) > MAX_ID_LEN:
            return not_found()

        if rest == [".well-known", "agent-card.json"]:
            if method != "GET":
                return method_not_allowed("GET")
            card = self.card(brand_id)
            if card is None:
                return not_found()
            return a2a_json(card, headers={"Cache-Control": "public, max-age=300",
                                           "Access-Control-Allow-Origin": "*"})

        if rest and rest[0] == "oauth":
            hosted = self._brands.get(brand_id)
            if hosted is None or self.delegation is None or not hosted.brand.delegation_enabled:
                return not_found()
            return await self.delegation.handle(request, hosted.brand, hosted.interface_url, rest[1:])

        route = _match(method, rest)
        if route is None:
            return not_found()
        if route[0] == "405":
            return method_not_allowed(route[1])

        try:
            identity = await self.authenticator.verify(bearer_token(request.header("authorization")))
        except Unauthorized:
            return unauthorized()

        limited = self._rate_limited(identity)
        if limited is not None:
            return limited

        hosted = self._brands.get(brand_id)
        if hosted is None:
            return not_found()

        delegation: Delegation | None = None
        header = request.header(DELEGATION_HEADER)
        if header is not None:
            if self.delegation is None or not hosted.brand.delegation_enabled:
                return unauthorized("invalid_token")
            try:
                delegation = await self.delegation.verify_delegation(
                    header, hosted.brand, hosted.interface_url, identity)
            except InvalidDelegation as exc:
                logger.info("pact.delegation.rejected", extra={
                    "brand": brand_id, "client_id": identity.issuer, "reason": str(exc)})
                return unauthorized("invalid_token")

        try:
            kind = route[0]
            if kind == "send":
                return await self._send(request, hosted, identity, delegation)
            if kind == "list":
                return _list_tasks(request)
            if kind in ("get", "cancel"):
                return await self._task_route(request, hosted, identity, delegation, route[1])
            if kind == "unsupported":
                return a2a_error("UNSUPPORTED_OPERATION", "Unsupported operation")
            if kind == "push":
                return a2a_error("PUSH_NOTIFICATION_NOT_SUPPORTED", "Push notifications are not supported")
        except PACTError as exc:
            return exc.response()
        except Exception:
            logger.exception("pact.provider.internal_error", extra={"brand": brand_id, "route": route[0]})
            return a2a_error("INTERNAL", "Internal error")
        return not_found()  # pragma: no cover

    def _rate_limited(self, identity: PAIdentity) -> HTTPResponse | None:
        if self.rate_limiter is None:
            return None
        for key in (f"pact-pa:{identity.issuer}", f"pact-user:{identity.principal_id}"):
            allowed, info = self.rate_limiter.check(key)
            if not allowed:
                reset = getattr(info, "reset", None)
                retry = int(reset - time.time()) if isinstance(reset, (int, float)) else 60
                logger.info("pact.provider.rate_limited", extra={"key": key})
                return too_many_requests(retry)
        return None

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def _principal(self, identity: PAIdentity, delegation: Delegation | None) -> Principal:
        p = self.authenticator.principal(
            identity, delegation.scopes if delegation else frozenset())
        if delegation is not None:
            p.claims["pact.delegation"] = {
                "sub": delegation.sub, "grantId": delegation.grant_id, "scope": sorted(delegation.scopes)}
        return p

    async def _forward(self, request: HTTPRequest, hosted: _Hosted, principal: Principal,
                       turn: Turn | None) -> HTTPResponse | None:
        headers = {k: v for k, v in request.headers.items()
                   if k not in ("content-type", "a2a-version", "content-length")}
        headers["content-type"] = "application/json"
        headers["a2a-version"] = "1.0"
        forwarded = HTTPRequest(method=request.method, path=request.path, headers=headers,
                                query=dict(request.query), body=request.body,
                                client=request.client)
        p_token = _principal.set(principal)
        t_token = _turn.set(turn)
        try:
            return await hosted.adapter.handle(forwarded)
        finally:
            _turn.reset(t_token)
            _principal.reset(p_token)

    async def _task_route(self, request: HTTPRequest, hosted: _Hosted, identity: PAIdentity,
                          delegation: Delegation | None, task_id: str) -> HTTPResponse:
        if not task_id or len(task_id) > MAX_ID_LEN:
            return a2a_error("TASK_NOT_FOUND", f"Task not found: {task_id[:MAX_ID_LEN]}")
        response = await self._forward(request, hosted, self._principal(identity, delegation), None)
        if response is None:
            return a2a_error("TASK_NOT_FOUND", f"Task not found: {task_id}")
        return normalize_a2a_response(response, task_id=task_id)

    async def _send(self, request: HTTPRequest, hosted: _Hosted, identity: PAIdentity,
                    delegation: Delegation | None) -> HTTPResponse:
        brand = hosted.brand
        message = _validate_send(request.body, self.max_text_chars)
        context_id = message.get("contextId")
        if context_id is not None:
            record = await self.contexts.get(context_id)
            if (record is None or record.brand_id != brand.brand_id
                    or record.owner != identity.principal_id):
                raise PACTError("INVALID_PARAMS", "Unknown contextId")
            if record.closed:
                raise PACTError("UNSUPPORTED_OPERATION", "This conversation is closed")
            if delegation is not None and record.brand_user not in (None, delegation.sub):
                raise PACTError("INVALID_PARAMS", "contextId already runs as a different Brand user")

        turn = Turn(brand_id=brand.brand_id, interface_url=hosted.interface_url,
                    issuer=identity.issuer, pa_sub=identity.sub, context_id=context_id,
                    delegation=delegation)
        if self.delegation is not None and brand.delegation_enabled:
            server = self.delegation

            async def step_up(scopes: list[str]) -> str | None:
                return await server.step_up_link(brand, hosted.interface_url, identity, scopes)

            turn.step_up = step_up

        response = await self._forward(request, hosted, self._principal(identity, delegation), turn)
        if response is None:
            raise PACTError("INTERNAL", "Internal error")
        response = normalize_a2a_response(response)
        if response.status != 200:
            return response
        payload = json.loads(response.body)  # type: ignore[arg-type]
        reply_message = payload.get("message") if isinstance(payload, dict) else None
        task = payload.get("task") if isinstance(payload, dict) else None
        obj = reply_message if isinstance(reply_message, dict) else task
        if not isinstance(obj, dict) or not isinstance(obj.get("contextId"), str):
            logger.error("pact.provider.bad_adapter_reply", extra={"brand": brand.brand_id})
            raise PACTError("INTERNAL", "Internal error")
        reply_context = obj["contextId"]
        if context_id is None:
            bound = await self.contexts.bind(ContextRecord(
                context_id=reply_context, brand_id=brand.brand_id, owner=identity.principal_id))
            if bound.owner != identity.principal_id or bound.brand_id != brand.brand_id:
                logger.error("pact.provider.context_collision", extra={"brand": brand.brand_id})
                raise PACTError("INTERNAL", "Internal error")
        elif reply_context != context_id:
            raise PACTError("INTERNAL", "Internal error")

        if isinstance(reply_message, dict):
            reply_message.pop("taskId", None)
            if delegation is not None and self.delegation is not None:
                receipt = await self._receipt(turn, delegation, hosted, reply_context,
                                              reply_message)
                reply_message.setdefault("metadata", {})["pact.receipt"] = receipt
                await self.contexts.set_brand_user(reply_context, delegation.sub)
        elif isinstance(task, dict):
            _pact_task_metadata(task)
        if turn.close_requested:
            await self.contexts.close(reply_context)
            await hosted.adapter.close_context(reply_context)
        return a2a_json(payload)

    async def _receipt(self, turn: Turn, delegation: Delegation, hosted: _Hosted, context_id: str,
                 reply: dict[str, Any]) -> dict[str, Any]:
        assert self.delegation is not None
        key = json.dumps([hosted.brand.brand_id, context_id, str(reply.get("messageId"))])
        cached = await self.receipts.get(key)
        if cached is not None:  # an idempotent retry returns the original receipt
            return cached
        receipt = self.delegation.sign_receipt(
            grant_id=delegation.grant_id, user=delegation.sub, pa=delegation.client_id,
            brand=hosted.interface_url, scopes_used=turn.scopes_used, actions=turn.actions,
        )
        return await self.receipts.put_if_absent(key, receipt)

    # ------------------------------------------------------------------
    # Hosting helpers
    # ------------------------------------------------------------------

    def as_server(self, *, agent_id: str = "agent://pact-provider") -> Any:
        """An :class:`~ampro.server.core.AgentServer` with only this provider mounted."""
        from ampro.server.core import AgentServer

        server = AgentServer(agent_id=agent_id, endpoint=self.public_url)
        server.mount(self)
        return server

    def asgi(self) -> Any:
        return self.as_server().asgi()


# ----------------------------------------------------------------------
# Routing and validation helpers
# ----------------------------------------------------------------------


def _match(method: str, rest: list[str]) -> tuple[str, str] | None:
    """``(kind, arg)`` for an A2A HTTP+JSON operation, ``("405", allow)``, or ``None``."""
    if len(rest) == 1:
        seg = rest[0]
        if seg == "message:send":
            return ("send", "") if method == "POST" else ("405", "POST")
        if seg == "message:stream":
            return ("unsupported", "") if method == "POST" else ("405", "POST")
        if seg == "tasks":
            return ("list", "") if method == "GET" else ("405", "GET")
        if seg == "extendedAgentCard":
            return ("unsupported", "") if method == "GET" else ("405", "GET")
        return None
    if len(rest) >= 2 and rest[0] == "tasks" and rest[1]:
        task = rest[1]
        if len(rest) == 2:
            if task.endswith(":subscribe"):
                return ("unsupported", "") if method == "POST" else ("405", "POST")
            if task.endswith(":cancel"):
                return ("cancel", task[: -len(":cancel")]) if method == "POST" else ("405", "POST")
            return ("get", task) if method == "GET" else ("405", "GET")
        if rest[2] != "pushNotificationConfigs":
            return None
        if len(rest) == 3:
            return ("push", "") if method in ("GET", "POST") else ("405", "GET, POST")
        if len(rest) == 4 and rest[3]:
            return ("push", "") if method in ("GET", "DELETE") else ("405", "GET, DELETE")
    return None


def _list_tasks(request: HTTPRequest) -> HTTPResponse:
    raw = request.query.get("pageSize")
    size = 50
    if raw is not None:
        if not raw.isdigit() or len(raw) > 3 or not 1 <= int(raw) <= 100:
            raise PACTError("INVALID_PARAMS", "Invalid pageSize")
        size = int(raw)
    return a2a_json({"tasks": [], "nextPageToken": "", "pageSize": size, "totalSize": 0})


def _bad(message: str = "Invalid request body") -> PACTError:
    return PACTError("INVALID_PARAMS", message)


def _validate_send(body: bytes | Any, max_text_chars: int) -> dict[str, Any]:
    """PACT §4.1 checks on a ``SendMessageRequest``; returns ``message``."""
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        raise _bad("Invalid JSON request body") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("message"), dict):
        raise _bad()
    for key in ("configuration", "metadata"):
        if key in payload and not isinstance(payload[key], dict):
            raise _bad()
    message = payload["message"]
    if not set(message) <= _MESSAGE_FIELDS:
        raise _bad()
    mid = message.get("messageId")
    if not isinstance(mid, str) or not mid or len(mid) > MAX_ID_LEN:
        raise _bad()
    for key in ("contextId", "taskId"):
        v = message.get(key)
        if v is not None and (not isinstance(v, str) or not v or len(v) > MAX_ID_LEN):
            raise _bad()
    if message.get("role") not in ("ROLE_UNSPECIFIED", "ROLE_USER", "ROLE_AGENT"):
        raise _bad()
    if "metadata" in message and not isinstance(message["metadata"], dict):
        raise _bad()
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts or len(parts) > MAX_PARTS:
        raise _bad()
    for part in parts:
        if not isinstance(part, dict) or not set(part) <= _PART_FIELDS:
            raise _bad()
        kinds = [k for k in _PART_KINDS if k in part]
        if len(kinds) != 1:
            raise _bad()
        if kinds[0] in ("text", "raw", "url") and not isinstance(part[kinds[0]], str):
            raise _bad()
    if message.get("taskId") is not None:
        raise PACTError("TASK_NOT_FOUND", "Task not found")
    if message["role"] != "ROLE_USER":
        raise _bad("Message role must be ROLE_USER")
    if any("text" not in p for p in parts):
        raise PACTError("CONTENT_TYPE_NOT_SUPPORTED", "Only text parts are supported")
    text = "\n".join(p["text"] for p in parts)
    if not text.strip():
        raise _bad("Message text must not be blank")
    if len(text) > max_text_chars:
        raise _bad("Message text is too long")
    return message


def _pact_task_metadata(task: dict[str, Any]) -> None:
    """Make sure an AUTH_REQUIRED task uses the ``pact.*`` metadata keys (§5.5)."""
    status = task.get("status")
    if not isinstance(status, dict) or status.get("state") != "TASK_STATE_AUTH_REQUIRED":
        return
    meta = task.setdefault("metadata", {})
    if "pact.missingScopes" not in meta and "missingScopes" in meta:
        meta["pact.missingScopes"] = meta.pop("missingScopes")
    if "pact.verificationUriComplete" not in meta and "verificationUriComplete" in meta:
        meta["pact.verificationUriComplete"] = meta.pop("verificationUriComplete")


__all__ = ["PACTProvider"]
