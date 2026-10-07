"""A2A symbols PACT depends on — real ones when available, stand-ins otherwise.

# ======================================================================
#  MERGE NOTE — TEMPORARY STAND-INS
#  PACT builds on the generic A2A adapter in ``ampro.interop.a2a``.  When
#  that package is importable, every name below is re-exported from it and
#  the stand-ins are never defined.  Until it is merged, minimal local
#  versions implementing the agreed contract are used so PACT can run and
#  be tested.  Delete everything under ``else:`` once ``ampro.interop.a2a``
#  ships these symbols:
#
#      A2AAdapter      .for_server(server, *, base_path, public_url,
#                                  authenticators, require_auth, task_store)
#                      async .handle(HTTPRequest) -> HTTPResponse | None
#      AuthRequired    (missing_scopes, verification_uri, *, message, metadata)
#
#  Principal / Unauthorized / Authenticator always come from the canonical
#  ``ampro.server.auth`` (which ``ampro.interop.a2a`` re-exports).
# ======================================================================
"""
from __future__ import annotations

from ampro.server.auth import Authenticator, Principal, Unauthorized

try:  # pragma: no cover - exercised once ampro.interop.a2a is merged
    from ampro.interop.a2a import (  # type: ignore[attr-defined]
        A2AAdapter,
        AuthRequired,
    )

    HAS_A2A = True
except ImportError:
    HAS_A2A = False

    import json
    import logging
    import uuid
    from collections import OrderedDict
    from collections.abc import Iterable
    from typing import Any

    from ampro.ampi.dispatch import build_context, dispatch
    from ampro.core.envelope import AgentMessage
    from ampro.server.http import HTTPRequest, HTTPResponse

    _log = logging.getLogger("ampro.interop.pact.compat")

    class AuthRequired(Exception):  # type: ignore[no-redef]
        """STAND-IN for ``ampro.interop.a2a.AuthRequired``."""

        def __init__(
            self,
            missing_scopes: Iterable[str] = (),
            verification_uri: str | None = None,
            *,
            message: str = "Additional authorization is required.",
            metadata: dict[str, Any] | None = None,
        ) -> None:
            self.missing_scopes = list(missing_scopes)
            self.verification_uri = verification_uri
            self.message = message
            self.metadata = dict(metadata or {})
            super().__init__(message)

    _STATUS = {
        "INVALID_PARAMS": (400, "INVALID_ARGUMENT"),
        "CONTENT_TYPE_NOT_SUPPORTED": (400, "INVALID_ARGUMENT"),
        "UNSUPPORTED_OPERATION": (400, "FAILED_PRECONDITION"),
        "TASK_NOT_FOUND": (404, "NOT_FOUND"),
        "INTERNAL": (500, "INTERNAL"),
    }

    def _error(reason: str, message: str) -> HTTPResponse:
        code, status = _STATUS[reason]
        return HTTPResponse.json(
            {"error": {"code": code, "status": status, "message": message, "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason, "domain": "a2a-protocol.org"}]}},
            status=code, content_type="application/a2a+json",
        )

    class _LRU:
        def __init__(self, n: int) -> None:
            self.n = n
            self.d: OrderedDict[Any, Any] = OrderedDict()

        def get(self, k: Any) -> Any:
            v = self.d.get(k)
            if v is not None:
                self.d.move_to_end(k)
            return v

        def set(self, k: Any, v: Any) -> None:
            self.d[k] = v
            self.d.move_to_end(k)
            while len(self.d) > self.n:
                self.d.popitem(last=False)

    class _PENDING:
        pass

    class A2AAdapter:  # type: ignore[no-redef]
        """STAND-IN for ``ampro.interop.a2a.A2AAdapter`` (HTTP+JSON subset).

        Serves ``message:send``, ``tasks``, ``tasks/{id}`` and
        ``tasks/{id}:cancel`` under *base_path*; maps a message to AMP
        ``task.create`` ``{description, text, task_id}`` with header
        ``Session-Id: <contextId>``; replies ``str``/``{"text"}`` as a
        Message; ``AuthRequired`` becomes an ``AUTH_REQUIRED`` Task.
        """

        name = "a2a"

        def __init__(
            self,
            server: Any,
            *,
            base_path: str = "/a2a",
            public_url: str | None = None,
            authenticators: Iterable[Any] = (),
            require_auth: bool = False,
            task_store: Any = None,
            max_entries: int = 50_000,
        ) -> None:
            self.server = server
            self.app = getattr(server, "app", None) or server
            self.agent_id = getattr(server, "agent_id", "agent://pact")
            self.base_path = "/" + base_path.strip("/")
            self.public_url = public_url
            self.authenticators = list(authenticators)
            self.require_auth = require_auth
            self._contexts = _LRU(max_entries)  # context -> owner
            self._replies = _LRU(max_entries)  # (context, messageId) -> reply | _PENDING
            self._tasks = _LRU(max_entries)  # task id -> (owner, task)

        @classmethod
        def for_server(cls, server: Any, **kwargs: Any) -> A2AAdapter:
            return cls(server, **kwargs)

        async def _principal(self, request: HTTPRequest) -> Principal | None:
            for auth in self.authenticators:
                p = await auth.authenticate(request)
                if p is not None:
                    return p
            if self.require_auth:
                return None
            return Principal(id="a2a://anonymous", auth_method="none")

        async def handle(self, request: HTTPRequest) -> HTTPResponse | None:
            if request.path != self.base_path and not request.path.startswith(self.base_path + "/"):
                return None
            rest = request.path[len(self.base_path):].strip("/")
            seg = rest.split("/") if rest else []
            method = request.method.upper()
            if method == "POST" and seg == ["message:send"]:
                op = "send"
            elif method == "GET" and seg == ["tasks"]:
                op = "list"
            elif len(seg) == 2 and seg[0] == "tasks" and seg[1]:
                op = "cancel" if (method == "POST" and seg[1].endswith(":cancel")) else (
                    "get" if method == "GET" else "")
            else:
                op = ""
            if not op:
                return None
            try:
                principal = await self._principal(request)
            except Unauthorized:
                principal = None
            if principal is None:
                return HTTPResponse.empty(401, {"WWW-Authenticate": 'Bearer realm="a2a"'})
            try:
                if op == "send":
                    return await self._send(request, principal)
                if op == "list":
                    tasks = [t for (o, t) in self._tasks.d.values() if o == principal.id]
                    return HTTPResponse.json({"tasks": tasks, "nextPageToken": "",
                                              "pageSize": 50, "totalSize": len(tasks)},
                                             content_type="application/a2a+json")
                task_id = seg[1][: -len(":cancel")] if op == "cancel" else seg[1]
                rec = self._tasks.get(task_id)
                if rec is None or rec[0] != principal.id or op == "cancel":
                    return _error("TASK_NOT_FOUND", f"Task not found: {task_id}")
                return HTTPResponse.json(rec[1], content_type="application/a2a+json")
            except Exception:
                _log.exception("a2a stand-in failure")
                return _error("INTERNAL", "Internal error")

        async def _send(self, request: HTTPRequest, principal: Principal) -> HTTPResponse:
            try:
                body = json.loads(request.body or b"null")
                message = body["message"]
                message_id = message["messageId"]
                parts = message["parts"]
            except (ValueError, KeyError, TypeError):
                return _error("INVALID_PARAMS", "Invalid request body")
            context_id = message.get("contextId")
            if context_id is None:
                context_id = str(uuid.uuid4())
                self._contexts.set(context_id, principal.id)
            elif self._contexts.get(context_id) != principal.id:
                return _error("INVALID_PARAMS", "Unknown contextId")
            key = (context_id, message_id)
            stored = self._replies.get(key)
            if isinstance(stored, _PENDING):
                return _error("INVALID_PARAMS", "messageId has no stored reply yet")
            if stored is not None:
                return HTTPResponse.json(stored, content_type="application/a2a+json")
            self._replies.set(key, _PENDING())
            text = "\n".join(p.get("text", "") for p in parts if isinstance(p, dict))
            task_id = str(uuid.uuid4())
            amp = AgentMessage(
                id=message_id, sender=principal.id, recipient=self.agent_id,
                body_type="task.create",
                body={"description": text[:8192], "text": text, "task_id": task_id},
                headers={"Session-Id": context_id},
            )
            ctx = build_context(self.agent_id, amp, trust_tier=principal.trust_tier)
            for attr, value in (("principal", principal), ("scopes", principal.scopes),
                                ("protocol", "a2a"), ("metadata", {})):
                setattr(ctx, attr, value)
            try:
                result = await dispatch(self.app, amp, ctx)
            except AuthRequired as exc:
                meta = dict(exc.metadata)
                meta["pact.missingScopes"] = list(exc.missing_scopes)
                if exc.verification_uri:
                    meta["pact.verificationUriComplete"] = exc.verification_uri
                task = {"id": task_id, "contextId": context_id, "status": {
                    "state": "TASK_STATE_AUTH_REQUIRED",
                    "message": {"messageId": str(uuid.uuid4()), "contextId": context_id,
                                "taskId": task_id, "role": "ROLE_AGENT",
                                "parts": [{"text": exc.message}]}},
                    "metadata": meta}
                self._tasks.set(task_id, (principal.id, task))
                reply = {"task": task}
                self._replies.set(key, reply)
                return HTTPResponse.json(reply, content_type="application/a2a+json")
            except Exception:
                self._replies.d.pop(key, None)
                raise
            if isinstance(result, dict) and isinstance(result.get("text"), str):
                text_out = result["text"]
            elif isinstance(result, str):
                text_out = result
            else:
                text_out = json.dumps(result, default=str)
            reply = {"message": {"messageId": str(uuid.uuid4()), "contextId": context_id,
                                 "role": "ROLE_AGENT", "parts": [{"text": text_out}]}}
            self._replies.set(key, reply)
            return HTTPResponse.json(reply, content_type="application/a2a+json")


__all__ = ["A2AAdapter", "AuthRequired", "Authenticator", "HAS_A2A", "Principal", "Unauthorized"]
