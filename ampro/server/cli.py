"""ampro-server CLI — run any AMPI agent.

Usage::
    ampro-server main:agent --port 8000
    python -m ampro.server main:agent --port 8000
    ampro-server main:agent --store redis://redis:6379/0   # share state across workers

``--store`` defaults to ``$AMPRO_REDIS_URL``; ``--store-prefix`` to
``$AMPRO_REDIS_PREFIX`` (else ``ampro``).
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
#
# Intended for `pip install ampro && python -m ampro.server`.
# Full-stack implementers mount AMPI handlers into their own HTTP
# framework and do not use this server.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

import argparse
import importlib
import os
import sys


def _parse_app_string(app_str: str) -> tuple[str, str]:
    """Parse 'module:attribute' string. Default attribute is 'agent'."""
    if ":" in app_str:
        module, attr = app_str.rsplit(":", 1)
    else:
        module, attr = app_str, "agent"
    return module, attr


def _load_app(app_str: str):
    """Import module and return the app object."""
    module_name, attr_name = _parse_app_string(app_str)
    if "." not in sys.path:
        sys.path.insert(0, ".")
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


def build_server(app, protocols: list[str] | None = None):
    """Wrap *app* (an ``AgentApp`` or ``AgentServer``) in a server.

    *protocols* lists the extra wire protocols to mount next to AMP,
    e.g. ``["a2a", "mcp"]``.
    """
    from ampro.server.core import AgentServer

    server = AgentServer.from_app(app) if hasattr(app, "handlers") else app
    for name in protocols or []:
        if name == "amp":
            continue
        from ampro.interop import load_adapter

        server.mount(load_adapter(name, server))
    return server


def configure_store(server, store: str | None, prefix: str | None = None):
    """Wire *server*'s state to a shared store URL (``redis://`` / ``rediss://``).

    ``None`` / empty keeps the per-process in-memory defaults.
    """
    if not store:
        return None
    if not store.startswith(("redis://", "rediss://", "unix://")):
        raise SystemExit(f"Unsupported --store {store!r}: expected redis://, rediss:// or unix://")
    from ampro.stores.redis import configure

    return configure(server, url=store, prefix=prefix or "ampro")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ampro-server",
        description="Run an AMP agent via AMPI.",
    )
    parser.add_argument("app", help="App to run, e.g. 'main:agent'")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1; use 0.0.0.0 to expose)",
    )
    parser.add_argument(
        "--protocols",
        default="amp",
        help="Comma-separated wire protocols to serve: amp,a2a,mcp (default: amp)",
    )

    parser.add_argument(
        "--store",
        default=os.environ.get("AMPRO_REDIS_URL") or None,
        help="Shared state store URL, e.g. redis://localhost:6379/0 "
             "(default: $AMPRO_REDIS_URL; unset = per-process memory)",
    )
    parser.add_argument(
        "--store-prefix",
        default=os.environ.get("AMPRO_REDIS_PREFIX") or "ampro",
        help="Key prefix in the shared store (default: $AMPRO_REDIS_PREFIX or 'ampro')",
    )

    args = parser.parse_args(argv)
    app = _load_app(args.app)
    protocols = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    server = build_server(app, protocols)
    configure_store(server, args.store, args.store_prefix)

    print(f"\n  AMP agent running on http://{args.host}:{args.port}")
    print(f"  Agent ID:  {getattr(server, 'agent_id', 'unknown')}")
    print(f"  Protocols: {', '.join(['amp'] + [a.name for a in server.adapters])}")
    print(f"  State:     {'shared (' + args.store_prefix + ')' if args.store else 'per-process'}")
    print()

    server.run(port=args.port, host=args.host)
