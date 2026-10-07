"""TestServer — the simplest AMPI server for unit testing.

No HTTP, no network. Just: build context, call handler, return result.
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
#
# Intended for `pip install agent-protocol && python -m ampro.server`.
# Full-stack implementers mount AMPI handlers into their own HTTP
# framework and do not use this server.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

from typing import Any

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.ampi.dispatch import build_context, dispatch, run_hooks
from ampro.core.envelope import AgentMessage
from ampro.trust.tiers import TrustTier


def _app_from_dict(spec: dict) -> AgentApp:
    app = AgentApp(spec.get("agent_id", "agent://test"), spec.get("endpoint", "http://localhost"))
    app.handlers.update(spec.get("handlers", {}))
    app.middleware_chain.extend(spec.get("middleware", []))
    app.startup_hooks.extend(spec.get("startup", []))
    app.shutdown_hooks.extend(spec.get("shutdown", []))
    app.error_handler = spec.get("error_handler")
    return app


class TestServer:
    """AMPI test harness — dispatch messages to handlers without transport."""

    def __init__(
        self,
        app: AgentApp | dict,
        *,
        trust_tier: TrustTier = TrustTier.VERIFIED,
    ) -> None:
        self._app = _app_from_dict(app) if isinstance(app, dict) else app
        self._agent_id = self._app.agent_id
        self._trust_tier = trust_tier

    def _build_context(self, message: AgentMessage) -> AMPContext:
        return build_context(self._agent_id, message, trust_tier=self._trust_tier)

    async def send(self, message: AgentMessage) -> Any:
        """Dispatch *message* through middleware and handler. Returns handler result."""
        return await dispatch(self._app, message, self._build_context(message))

    async def startup(self) -> None:
        """Run all registered startup hooks."""
        await run_hooks(self._app.startup_hooks)

    async def shutdown(self) -> None:
        """Run all registered shutdown hooks."""
        await run_hooks(self._app.shutdown_hooks)
