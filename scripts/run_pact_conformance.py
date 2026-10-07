#!/usr/bin/env python
"""Run the official PACT conformance suite against an ampro PACT provider.

Usage::

    python scripts/run_pact_conformance.py --pact-repo /path/to/openpactprotocol
    python scripts/run_pact_conformance.py --pact-repo ... --serve-only   # keep servers up

What it does:

1. generates a throwaway personal-agent ES256 key and serves its JWKS from
   an ephemeral HTTP server on 127.0.0.1;
2. serves ``examples/48_pact_provider.py``'s provider on 127.0.0.1 with
   two Brands — ``skyline`` (Identity + Delegated, with the demo Brand login
   the delegated suite drives) and ``acme`` (Identity only) — registering
   the PA issuer and a *disabled* ``{issuer}/disabled-pa``;
3. runs ``pnpm e2e`` (``e2e/pact.test.ts`` and ``e2e/delegated.test.ts``)
   in the PACT repo with ``E2E_PROVIDER=any``.

The JWKS fetcher allows plain http only for 127.0.0.1 — never do that in
production.  The suite expects the identity scheme to be called
``platformJwt`` (the spec text says ``paJwt``), so the card uses that name.
Requires node 22 + pnpm with ``pnpm install`` done in the PACT repo.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ampro.interop.pact import PersonalAgentRegistration  # noqa: E402
from ampro.interop.pact._jwt import generate_es256_jwk, public_jwk  # noqa: E402
from ampro.interop.pact.jwks import HttpsJSONFetcher  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(app, port: int):  # type: ignore[no-untyped-def]
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError(f"server on {port} did not start")


def _jwks_app(jwks: dict):  # type: ignore[no-untyped-def]
    body = json.dumps(jwks).encode()

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            return
        ok = scope["path"] == "/jwks.json"
        await send({"type": "http.response.start", "status": 200 if ok else 404,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body if ok else b""})

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--pact-repo", default=os.environ.get("PACT_REPO"))
    parser.add_argument("--serve-only", action="store_true")
    parser.add_argument("--test", default="", help="vitest filter, e.g. 'pact' or 'delegated'")
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("pact_example", ROOT / "examples" / "48_pact_provider.py")
    example = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(example)  # type: ignore[union-attr]

    issuer = "https://pa.conformance.test"
    audience = "ampro-conformance-provider"
    pa_jwk = generate_es256_jwk()
    jwks = {"keys": [{**public_jwk(pa_jwk), "kid": pa_jwk["kid"], "alg": "ES256", "use": "sig"}]}

    jwks_port, provider_port = _free_port(), _free_port()
    _serve(_jwks_app(jwks), jwks_port)
    jwks_uri = f"http://127.0.0.1:{jwks_port}/jwks.json"
    public = f"http://127.0.0.1:{provider_port}"
    server, provider, _site = example.build_demo(
        public,
        pa_registrations=[
            PersonalAgentRegistration(issuer=issuer, jwks_uri=jwks_uri),
            PersonalAgentRegistration(issuer=f"{issuer}/disabled-pa", jwks_uri=jwks_uri, enabled=False),
        ],
        audience=audience,
        http_client=HttpsJSONFetcher(allow_hosts={"127.0.0.1"}),
        identity_scheme="platformJwt",
        poll_interval=2,
    )
    _serve(server.asgi(), provider_port)

    env = {
        **os.environ,
        "PROVIDER_URL": public,
        "CUSTOMER_ID": "skyline",
        "OTHER_CUSTOMER_ID": "acme",
        "DELEGATED_CUSTOMER_ID": "skyline",
        "PA_ISSUER": issuer,
        "PA_AUDIENCE": audience,
        "PA_PRIVATE_JWK": json.dumps(pa_jwk),
        "E2E_PROVIDER": "any",
    }
    print(f"provider: {public}/a2a/skyline  jwks: {jwks_uri}", flush=True)
    if args.serve_only or not args.pact_repo:
        print("export " + " ".join(f"{k}='{env[k]}'" for k in (
            "PROVIDER_URL", "CUSTOMER_ID", "OTHER_CUSTOMER_ID", "DELEGATED_CUSTOMER_ID",
            "PA_ISSUER", "PA_AUDIENCE", "PA_PRIVATE_JWK", "E2E_PROVIDER")), flush=True)
        if not args.pact_repo:
            print("no --pact-repo given; serving until interrupted", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
    cmd = ["pnpm", "--filter", "@openpactprotocol/e2e", "exec", "vitest", "run",
           "--sequence.concurrent=false"]
    if args.test:
        cmd.append(args.test)
    return subprocess.call(cmd, cwd=args.pact_repo, env=env)


if __name__ == "__main__":
    sys.exit(main())
