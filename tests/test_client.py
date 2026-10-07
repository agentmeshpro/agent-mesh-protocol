"""Tests for the AMP Client SDK (ampro.client).

Uses httpx mock transport to test all client functions without network access.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ampro.client.errors import AmpProtocolError
from ampro.core.envelope import AgentMessage
from ampro.wire.errors import ErrorType, ProblemDetail


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch):
    """The client now resolves (and pins) every target host before
    connecting — make every name resolve to a public address so these
    tests never touch real DNS."""

    async def fake_getaddrinfo(self, host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)


# ---------------------------------------------------------------------------
# Helpers — mock HTTP transport
# ---------------------------------------------------------------------------


def _ok_response(body: dict[str, Any], status_code: int = 200) -> httpx.Response:
    """Build a mock httpx.Response with JSON body."""
    return httpx.Response(
        status_code=status_code,
        json=body,
        request=httpx.Request("POST", "https://example.com"),
    )


def _error_response(problem: ProblemDetail) -> httpx.Response:
    """Build a mock httpx.Response with an RFC 7807 error."""
    return httpx.Response(
        status_code=problem.status,
        json=problem.model_dump(mode="json"),
        request=httpx.Request("POST", "https://example.com"),
    )


def _agent_message_response(
    sender: str = "@target",
    recipient: str = "@caller",
    body: Any = None,
    body_type: str = "message",
) -> httpx.Response:
    """Build a mock response containing an AgentMessage."""
    msg = AgentMessage(
        sender=sender,
        recipient=recipient,
        body=body or {"reply": "ok"},
        body_type=body_type,
    )
    return _ok_response(msg.model_dump(mode="json"))


def _agent_json_response() -> httpx.Response:
    """Build a mock /.well-known/agent.json response."""
    return _ok_response({
        "protocol_version": "1.0.0",
        "identifiers": ["agent://target.example.com"],
        "endpoint": "https://target.example.com",
        "capabilities": {"groups": ["messaging"], "level": 1},
    })


# ---------------------------------------------------------------------------
# Mock transport that intercepts httpx requests
# ---------------------------------------------------------------------------


class MockTransport(httpx.AsyncBaseTransport):
    """Configurable async transport for testing."""

    def __init__(self) -> None:
        self.responses: list[httpx.Response] = []
        self.requests: list[httpx.Request] = []
        self._call_index = 0

    def add_response(self, response: httpx.Response) -> None:
        self.responses.append(response)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._call_index < len(self.responses):
            resp = self.responses[self._call_index]
            self._call_index += 1
            return resp
        raise RuntimeError(f"No mock response for request #{self._call_index}")


# ---------------------------------------------------------------------------
# Tests — send()
# ---------------------------------------------------------------------------


class TestSend:
    @pytest.mark.asyncio
    async def test_send_basic(self):
        """send() resolves URI, builds envelope, and returns response."""
        from ampro.client.send import send

        transport = MockTransport()
        transport.add_response(_agent_message_response(body={"weather": "sunny"}))

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=httpx.Response(
                200,
                json=AgentMessage(
                    sender="@target",
                    recipient="@caller",
                    body={"weather": "sunny"},
                    body_type="message",
                ).model_dump(mode="json"),
                request=httpx.Request("POST", "https://target.example.com/agent/message"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            reply = await send(
                "agent://target.example.com",
                body={"q": "forecast"},
            )

            assert reply.body == {"weather": "sunny"}
            assert reply.sender == "@target"
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            assert "/agent/message" in call_kwargs[0][0]

    @pytest.mark.asyncio
    async def test_send_custom_body_type(self):
        """send() passes body_type through to the envelope."""
        from ampro.client.send import send

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=httpx.Response(
                200,
                json=AgentMessage(
                    sender="@target",
                    recipient="@caller",
                    body={"task_id": "t-1"},
                    body_type="task.acknowledge",
                ).model_dump(mode="json"),
                request=httpx.Request("POST", "https://target.example.com/agent/message"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            reply = await send(
                "agent://target.example.com",
                body={"task": "do something"},
                body_type="task.create",
                sender="agent://my-agent.example.com",
            )

            assert reply.body_type == "task.acknowledge"
            # Verify the outgoing message used the right body_type
            call_json = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[1].get("json")
            assert call_json["body_type"] == "task.create"
            assert call_json["sender"] == "agent://my-agent.example.com"


# ---------------------------------------------------------------------------
# Tests — discover()
# ---------------------------------------------------------------------------


class TestDiscover:
    @pytest.mark.asyncio
    async def test_discover_success(self):
        """discover() fetches and parses agent.json."""
        from ampro.client.discover import discover

        agent_json_data = {
            "protocol_version": "1.0.0",
            "identifiers": ["agent://weather.example.com"],
            "endpoint": "https://weather.example.com",
            "capabilities": {"groups": ["messaging", "tools"], "level": 2},
        }

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=httpx.Response(
                200,
                json=agent_json_data,
                request=httpx.Request("GET", "https://weather.example.com/.well-known/agent.json"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            info = await discover("agent://weather.example.com")

            assert info.protocol_version == "1.0.0"
            assert info.endpoint == "https://weather.example.com"
            assert info.capabilities["level"] == 2
            mock_client.get.assert_called_once()
            call_url = mock_client.get.call_args[0][0]
            assert "/.well-known/agent.json" in call_url

    @pytest.mark.asyncio
    async def test_discover_slug_uri_raises(self):
        """discover() raises ValueError for slug-form URIs."""
        from ampro.client.discover import discover

        with pytest.raises(ValueError, match="HOST-form"):
            await discover("agent://sales@registry.example.com")


# ---------------------------------------------------------------------------
# Tests — AmpProtocolError
# ---------------------------------------------------------------------------


class TestAmpProtocolError:
    @pytest.mark.asyncio
    async def test_error_on_429(self):
        """Non-2xx responses raise AmpProtocolError with ProblemDetail."""
        from ampro.client.send import send

        problem = ProblemDetail(
            type=ErrorType.RATE_LIMITED,
            title="Rate limit exceeded",
            status=429,
            detail="Too many requests from @alice",
            retry_after_seconds=60,
        )

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=httpx.Response(
                429,
                json=problem.model_dump(mode="json"),
                request=httpx.Request("POST", "https://target.example.com/agent/message"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(AmpProtocolError) as exc_info:
                await send("agent://target.example.com", body={"q": "hi"})

            err = exc_info.value
            assert err.status_code == 429
            assert err.error_type == ErrorType.RATE_LIMITED
            assert err.retry_after == 60

    @pytest.mark.asyncio
    async def test_error_on_403(self):
        """403 responses raise AmpProtocolError with forbidden detail."""
        from ampro.client.send import send

        problem = ProblemDetail(
            type=ErrorType.FORBIDDEN,
            title="Forbidden",
            status=403,
            detail="Access denied",
        )

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=httpx.Response(
                403,
                json=problem.model_dump(mode="json"),
                request=httpx.Request("POST", "https://target.example.com/agent/message"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(AmpProtocolError) as exc_info:
                await send("agent://target.example.com", body={"q": "hi"})

            err = exc_info.value
            assert err.status_code == 403
            assert err.error_type == ErrorType.FORBIDDEN
            assert err.retry_after is None


# ---------------------------------------------------------------------------
# Tests — Session (3-phase handshake)
# ---------------------------------------------------------------------------


class TestSession:
    @pytest.mark.asyncio
    async def test_session_connect_handshake(self):
        """connect() performs the 3-phase handshake and returns a Session."""
        from ampro.client.session import connect
        from ampro.session.handshake import (
            HandshakeStateMachine,
            SessionConfirmBody,
            SessionInitBody,
            server_accept_init,
            server_verify_confirm,
        )

        server_sm = HandshakeStateMachine()
        server_state: dict = {}

        # Phase 3 response: session.confirm ack
        confirm_ack = AgentMessage(
            sender="@target",
            recipient="@caller",
            body={"status": "active"},
            body_type="session.active",
        )

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Phase 1 response: real key agreement, binding key never sent
                init = SessionInitBody.model_validate(kwargs["json"]["body"])
                est, binding = server_accept_init(
                    init,
                    server_sm,
                    session_id="sess-abc",
                    negotiated_capabilities=["messaging"],
                    negotiated_version="1.0.0",
                    trust_tier="verified",
                    trust_score=500,
                )
                server_state["binding"] = binding
                established_msg = AgentMessage(
                    sender="@target",
                    recipient="@caller",
                    body=est.model_dump(mode="json"),
                    body_type="session.established",
                )
                return httpx.Response(
                    200,
                    json=established_msg.model_dump(mode="json"),
                    request=httpx.Request("POST", args[0] if args else kwargs.get("url", "")),
                )
            else:
                # Phase 3: server MUST verify the binding proof
                confirm = SessionConfirmBody.model_validate(kwargs["json"]["body"])
                server_verify_confirm(confirm, server_state["binding"], server_sm)
                return httpx.Response(
                    200,
                    json=confirm_ack.model_dump(mode="json"),
                    request=httpx.Request("POST", args[0] if args else kwargs.get("url", "")),
                )

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=mock_post)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            session = await connect(
                "agent://target.example.com",
                sender="agent://my-agent.example.com",
            )

            assert session.session_id == "sess-abc"
            # Two calls: session.init + session.confirm
            assert call_count == 2

            # Verify phase 1 sent session.init
            first_call_json = mock_client.post.call_args_list[0].kwargs.get("json") or mock_client.post.call_args_list[0][1].get("json")
            assert first_call_json["body_type"] == "session.init"
            assert "client_nonce" in first_call_json["body"]

            # Verify phase 3 sent session.confirm
            second_call_json = mock_client.post.call_args_list[1].kwargs.get("json") or mock_client.post.call_args_list[1][1].get("json")
            assert second_call_json["body_type"] == "session.confirm"
            assert second_call_json["body"]["session_id"] == "sess-abc"
            assert "binding_proof" in second_call_json["body"]
            assert second_call_json["body"]["confirm_nonce"]
            assert "client_ephemeral_key" in first_call_json["body"]

    @pytest.mark.asyncio
    async def test_session_send_with_binding(self):
        """Session.send() attaches Session-Id and Session-Binding headers."""
        from ampro.client.session import Session

        session = Session(
            endpoint="https://target.example.com",
            target_uri="agent://target.example.com",
            sender="agent://my-agent.example.com",
            session_id="sess-xyz",
            binding_token="token_abc",
        )

        reply_msg = AgentMessage(
            sender="@target",
            recipient="@caller",
            body={"answer": "42"},
            body_type="message",
        )

        with patch("ampro.client.core.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=httpx.Response(
                200,
                json=reply_msg.model_dump(mode="json"),
                request=httpx.Request("POST", "https://target.example.com/agent/message"),
            ))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            reply = await session.send({"question": "meaning of life"})

            assert reply.body == {"answer": "42"}

            # Verify the envelope includes Session-Id header
            call_json = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[1].get("json")
            assert call_json["headers"]["Session-Id"] == "sess-xyz"

            # Verify HTTP headers include Session-Binding
            call_headers = mock_client.post.call_args.kwargs.get("headers") or mock_client.post.call_args[1].get("headers")
            assert "Session-Binding" in call_headers


# ---------------------------------------------------------------------------
# Tests — errors module
# ---------------------------------------------------------------------------


class TestErrors:
    def test_amp_protocol_error_properties(self):
        """AmpProtocolError exposes status_code, error_type, retry_after."""
        problem = ProblemDetail(
            type=ErrorType.RATE_LIMITED,
            title="Rate limit exceeded",
            status=429,
            detail="Slow down",
            retry_after_seconds=30,
        )
        err = AmpProtocolError(problem)

        assert err.status_code == 429
        assert err.error_type == ErrorType.RATE_LIMITED
        assert err.retry_after == 30
        assert "Rate limit exceeded" in str(err)
        assert "Slow down" in str(err)

    def test_amp_protocol_error_no_retry(self):
        """AmpProtocolError.retry_after is None when not set."""
        problem = ProblemDetail(
            type=ErrorType.FORBIDDEN,
            title="Forbidden",
            status=403,
            detail="No access",
        )
        err = AmpProtocolError(problem)
        assert err.retry_after is None


# ---------------------------------------------------------------------------
# Tests — core helpers
# ---------------------------------------------------------------------------


class TestCoreHelpers:
    @pytest.mark.asyncio
    async def test_resolve_endpoint_host(self):
        """_resolve_endpoint resolves HOST-form URIs."""
        from ampro.client.core import _resolve_endpoint
        endpoint = await _resolve_endpoint("agent://weather.example.com")
        assert endpoint == "https://weather.example.com"

    @pytest.mark.asyncio
    async def test_resolve_endpoint_slug_raises(self):
        """_resolve_endpoint raises for slug URIs."""
        from ampro.client.core import _resolve_endpoint
        with pytest.raises(ValueError, match="Slug-based"):
            await _resolve_endpoint("agent://sales@registry.example.com")

    @pytest.mark.asyncio
    async def test_resolve_endpoint_did_raises(self):
        """_resolve_endpoint raises for DID URIs."""
        from ampro.client.core import _resolve_endpoint
        with pytest.raises(ValueError, match="DID-based"):
            await _resolve_endpoint("agent://did:web:example.com")
