"""Tests for the AMP Reference Server."""

import asyncio
import json

from ampro.core.envelope import AgentMessage
from ampro.core.versioning import CURRENT_VERSION
from ampro.server import AgentServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _make_envelope(**overrides) -> dict:
    """Build a minimal valid envelope dict."""
    base = {
        "sender": "@alice",
        "recipient": "@test-agent",
        "body_type": "message",
        "body": {"text": "hello"},
    }
    base.update(overrides)
    return base


def _make_server(**kwargs) -> AgentServer:
    """Create a server with sensible defaults."""
    defaults = {"agent_id": "@test-agent", "endpoint": "https://test.example.com"}
    defaults.update(kwargs)
    return AgentServer(**defaults)


# ===========================================================================
# TestAgentServerBasic
# ===========================================================================


class TestAgentServerBasic:
    """Basic server construction and built-in endpoint tests."""

    def test_init_minimal(self):
        server = _make_server()
        assert server.agent_id == "@test-agent"
        assert server.endpoint == "https://test.example.com"
        # Auto-generated agent_json should contain our agent_id.
        assert "@test-agent" in server.agent_json.identifiers
        assert server.agent_json.protocol_version == CURRENT_VERSION

    def test_agent_json_endpoint(self):
        server = _make_server()
        status, headers, body_str = _run(
            server.route("GET", "/.well-known/agent.json")
        )
        assert status == 200
        assert headers["Content-Type"] == "application/json"
        data = json.loads(body_str)
        assert data["protocol_version"] == CURRENT_VERSION
        assert "@test-agent" in data["identifiers"]

    def test_health_endpoint(self):
        server = _make_server()
        status, headers, body_str = _run(server.route("GET", "/agent/health"))
        assert status == 200
        data = json.loads(body_str)
        assert data["status"] == "healthy"
        assert data["protocol_version"] == CURRENT_VERSION
        assert "uptime_seconds" in data

    def test_404_unknown(self):
        server = _make_server()
        status, headers, body_str = _run(server.route("GET", "/nonexistent"))
        assert status == 404
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:not-found"

    def test_stream_placeholder(self):
        server = _make_server()
        status, headers, body_str = _run(server.route("GET", "/agent/stream"))
        assert status == 200
        assert headers["Content-Type"] == "text/event-stream"
        assert "event: ping" in body_str


# ===========================================================================
# TestHandlerRegistry
# ===========================================================================


class TestHandlerRegistry:
    """Test handler registration and message routing."""

    def test_on_decorator(self):
        server = _make_server()

        @server.on("task.create")
        async def handle(msg):
            return {"status": "ok"}

        assert "task.create" in server._handlers

    def test_default_decorator(self):
        server = _make_server()

        @server.default
        async def fallback(msg):
            return {"echo": True}

        assert server._default_handler is not None

    def test_message_routed(self):
        server = _make_server()
        received = []

        @server.on("task.create")
        async def handle(msg):
            received.append(msg)
            return {"task_id": "t-1", "status": "accepted"}

        envelope = _make_envelope(
            body_type="task.create",
            body={"description": "Find me a hotel"},
        )
        status, headers, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202
        assert len(received) == 1
        assert received[0].body_type == "task.create"
        data = json.loads(body_str)
        assert data["task_id"] == "t-1"

    def test_sync_handler(self):
        """Sync (non-async) handlers should also work."""
        server = _make_server()

        @server.on("message")
        def handle(msg):
            return {"echo": msg.body}

        envelope = _make_envelope(body_type="message", body={"text": "hi"})
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202
        data = json.loads(body_str)
        assert data["echo"] == {"text": "hi"}

    def test_default_on_unknown(self):
        server = _make_server()

        @server.default
        async def fallback(msg):
            return {"fallback": True, "body_type": msg.body_type}

        envelope = _make_envelope(body_type="x-custom.unknown", body={"x": 1})
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202
        data = json.loads(body_str)
        assert data["fallback"] is True
        assert data["body_type"] == "x-custom.unknown"

    def test_handler_returns_agent_message(self):
        """Handler returning an AgentMessage should be serialized."""
        server = _make_server()

        @server.on("message")
        async def handle(msg):
            return AgentMessage(
                sender="@test-agent",
                recipient="@alice",
                body_type="task.response",
                body={"text": "done", "task_id": "t-1"},
            )

        envelope = _make_envelope()
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202
        data = json.loads(body_str)
        assert data["sender"] == "@test-agent"
        assert data["body_type"] == "task.response"

    def test_handler_returns_base_model(self):
        """Handler returning a Pydantic BaseModel should be serialized."""
        from ampro.agent.health import HealthResponse

        server = _make_server()

        @server.on("message")
        async def handle(msg):
            return HealthResponse(
                status="healthy",
                protocol_version="1.0.0",
            )

        envelope = _make_envelope()
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202
        data = json.loads(body_str)
        assert data["status"] == "healthy"


# ===========================================================================
# TestValidation
# ===========================================================================


class TestValidation:
    """Test envelope and body validation."""

    def test_invalid_envelope_400(self):
        """Missing required fields should return 400."""
        server = _make_server()
        # Missing 'sender' and 'recipient'.
        bad_envelope = {"body_type": "message", "body": {"text": "hi"}}
        status, _, body_str = _run(
            server.route("POST", "/agent/message", bad_envelope)
        )
        assert status == 400
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:invalid-message"

    def test_invalid_body_400(self):
        """Body that fails body_type schema validation should return 400."""
        server = _make_server()

        @server.on("task.create")
        async def handle(msg):
            return {"ok": True}

        # task.create requires 'description', which is missing.
        envelope = _make_envelope(
            body_type="task.create",
            body={"priority": "normal"},
        )
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 400
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:invalid-message"
        assert "task.create" in data["detail"]

    def test_null_body_accepted(self):
        """Messages with None body should skip body validation."""
        server = _make_server()

        @server.on("message")
        async def handle(msg):
            return {"received": True}

        envelope = _make_envelope(body=None)
        status, _, _ = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 202

    def test_none_request_body_400(self):
        """POST /agent/message with no request body returns 400."""
        server = _make_server()
        status, _, body_str = _run(
            server.route("POST", "/agent/message", None)
        )
        assert status == 400
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:invalid-message"


# ===========================================================================
# TestErrorHandling
# ===========================================================================


class TestErrorHandling:
    """Test error scenarios."""

    def test_handler_exception_500(self):
        server = _make_server()

        @server.on("message")
        async def handle(msg):
            raise RuntimeError("boom")

        envelope = _make_envelope()
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 500
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:internal-error"
        # Exception message must NOT leak to the caller (sanitised).
        assert "boom" not in data["detail"]
        assert "unexpected error" in data["detail"].lower()

    def test_no_handler_501(self):
        """No handler and no default → 501."""
        server = _make_server()
        envelope = _make_envelope(body_type="task.create", body={"description": "test"})
        status, _, body_str = _run(
            server.route("POST", "/agent/message", envelope)
        )
        assert status == 501
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:not-implemented"
        assert "task.create" in data["detail"]

    def test_trailing_slash_normalised(self):
        """Paths with trailing slashes should still match."""
        server = _make_server()
        status, _, _ = _run(server.route("GET", "/agent/health/"))
        assert status == 200


# ===========================================================================
# TestFromApp
# ===========================================================================


class TestFromApp:
    """Test AgentServer.from_app() classmethod."""

    def test_agent_server_from_app(self):
        from ampro.ampi.app import AgentApp
        from ampro.server.core import AgentServer

        app = AgentApp("agent://test.com", "https://test.com")

        @app.on("task.create")
        async def handle(msg, ctx):
            return {"tier": "verified"}

        server = AgentServer.from_app(app)
        assert server.agent_id == "agent://test.com"
        assert "task.create" in server._handlers

    async def test_from_app_calls_handler_with_ctx(self):
        """AMPI handlers take (msg, ctx); the server must supply ctx."""
        from ampro.ampi.app import AgentApp

        app = AgentApp("agent://ctx.example.com", "https://ctx.example.com")

        @app.on("task.create")
        async def handle(msg, ctx):
            return {"tier": ctx.trust_tier.value, "agent": ctx.agent_address}

        server = AgentServer.from_app(app)
        status, _, body = await server.route("POST", "/agent/message", {
            "sender": "agent://caller.example.com",
            "recipient": "agent://ctx.example.com",
            "body_type": "task.create",
            "body": {"description": "hi"},
        })
        assert status == 202
        payload = json.loads(body)
        # The reference server does not authenticate, so callers are EXTERNAL.
        assert payload == {"tier": "external", "agent": "agent://ctx.example.com"}

    async def test_from_app_runs_middleware_and_error_hook(self):
        from ampro.ampi.app import AgentApp

        app = AgentApp("agent://err.example.com", "https://err.example.com")
        seen = []

        @app.middleware
        async def mw(msg, ctx, nxt):
            seen.append("mw")
            return await nxt(msg, ctx)

        @app.on("task.create")
        async def handle(msg, ctx):
            raise RuntimeError("boom")

        @app.on_error
        async def on_err(exc, msg, ctx):
            return {"error": str(exc)}

        server = AgentServer.from_app(app)
        assert server.app is app
        status, _, body = await server.route("POST", "/agent/message", {
            "sender": "agent://a.example.com",
            "recipient": "agent://err.example.com",
            "body_type": "task.create",
            "body": {"description": "hi"},
        })
        assert status == 202
        assert json.loads(body) == {"error": "boom"}
        assert seen == ["mw"]

    def test_from_app_preserves_agent_json(self):
        from ampro.ampi.app import AgentApp

        app = AgentApp("agent://json.example.com", "https://json.example.com")
        server = AgentServer.from_app(app)
        assert server.agent_json.endpoint == "https://json.example.com"
        assert "agent://json.example.com" in server.agent_json.identifiers
