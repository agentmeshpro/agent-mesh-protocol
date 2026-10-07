"""The black-box conformance suite (``ampro.conformance``) against our own server.

Runs every Level 0-1 check against :class:`AgentServer` in-process (httpx
``ASGITransport``) and over real HTTP (uvicorn on 127.0.0.1), anonymously
and with RFC 9421 signatures, and requires zero MUST failures.  It also
checks that the suite *detects* broken servers, so a pass means something.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ampro.conformance import Signer, check_specs, run_conformance
from ampro.conformance.cli import main as cli_main
from ampro.conformance.signing import load_signing_key
from ampro.core.envelope import AgentMessage
from ampro.security.nonce_tracker import NonceTracker
from ampro.server import AgentServer
from ampro.server.auth import SignatureAuthenticator
from ampro.server.security import SecurityPolicy
from ampro.wire.config import WireConfig

AGENT = "agent://conformance-target.example"
CLIENT = "agent://conformance-client.example"
KEYID = CLIENT + "#key-1"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUB = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_server(base_url: str, *, signed: bool = False, rpm: int = 60) -> AgentServer:
    config = WireConfig(rate_limit_rpm=rpm)
    security = None
    if signed:
        auth = SignatureAuthenticator(
            base_url,
            key_resolver=lambda kid: PUB if kid == KEYID else None,
            key_owner=lambda kid: CLIENT if kid == KEYID else None,
            nonce_tracker=NonceTracker(),
        )
        security = SecurityPolicy.production([auth], config=config)
    server = AgentServer(
        agent_id=AGENT, endpoint=base_url + "/agent/message", config=config, security=security
    )

    @server.on("message")
    async def reply(msg: AgentMessage) -> AgentMessage:
        return AgentMessage(
            sender=AGENT,
            recipient=msg.sender,
            body_type="task.complete",
            headers={"In-Reply-To": msg.id},
            body={"task_id": msg.id, "result": {"echo": msg.body.get("text", "")}},
        )

    return server


def _by_id(report) -> dict:
    return {r.id: r for r in report.results}


def _assert_conformant(report) -> None:
    failures = [(r.id, r.detail) for r in report.results if r.status == "fail"]
    assert report.ok and not failures, report.to_table()


async def test_in_process_anonymous_level_1() -> None:
    base = "http://testserver"
    server = make_server(base)
    report = await run_conformance(
        base, transport=httpx.ASGITransport(app=server.asgi()), probe_rate_limit=80
    )
    _assert_conformant(report)
    results = _by_id(report)
    assert report.level == 1
    # Signature checks need a key; everything else at L0-L1 must have run.
    skipped = {r.id for r in report.results if r.status == "skip"}
    assert skipped == {s.id for s in check_specs() if s.needs_key}
    assert results["ratelimit.429"].status == "pass"
    assert results["message.duplicate-id"].status == "pass"
    assert len(report.results) >= 30


async def test_in_process_signed_level_1() -> None:
    base = "http://testserver"
    server = make_server(base, signed=True)
    report = await run_conformance(
        base,
        transport=httpx.ASGITransport(app=server.asgi()),
        signer=Signer(SEED, KEYID),
        sender_bound=True,
    )
    _assert_conformant(report)
    results = _by_id(report)
    for spec in check_specs():
        if spec.needs_key:
            assert results[spec.id].status == "pass", (spec.id, results[spec.id].detail)
    assert all(r.status == "pass" for r in report.results if r.id != "ratelimit.429")


async def test_signed_server_without_key_skips_message_checks() -> None:
    base = "http://testserver"
    server = make_server(base, signed=True)
    report = await run_conformance(base, transport=httpx.ASGITransport(app=server.asgi()))
    results = _by_id(report)
    assert results["discovery.agent-json"].status == "pass"
    assert results["message.accepted"].status == "skip"
    assert "requires authentication" in results["message.accepted"].detail
    assert report.ok


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_over_real_http_with_uvicorn() -> None:
    uvicorn = pytest.importorskip("uvicorn")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = make_server(base, signed=True)
    config = uvicorn.Config(server.asgi(), host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not srv.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.05)
        report = asyncio.run(run_conformance(
            base, signer=Signer(SEED, KEYID), sender_bound=True, probe_rate_limit=80,
        ))
    finally:
        srv.should_exit = True
        thread.join(timeout=10)
    _assert_conformant(report)
    results = _by_id(report)
    assert results["auth.signature-replay"].status == "pass"
    assert results["message.size-limit"].status == "pass"
    assert results["ratelimit.429"].status == "pass"


# ---------------------------------------------------------------------------
# The suite detects non-conformance
# ---------------------------------------------------------------------------


def _broken_app(**overrides):
    """A tiny ASGI app that answers like an AMP agent, with chosen defects."""

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        path = scope["path"]
        status, ctype, payload = 404, "text/plain", b"nope"
        if path == "/.well-known/agent.json":
            doc = {"protocol_version": "1.0.0", "identifiers": [AGENT], "endpoint": "http://x/agent/message"}
            doc.update(overrides.get("agent_json", {}))
            status, ctype, payload = 200, "application/json", json.dumps(doc).encode()
        elif path == "/agent/health":
            status, ctype, payload = 200, "application/json", b'{"status": "ok"}'
        elif path == "/agent/message":
            status, ctype, payload = 400, "application/json", b'{"error": "bad"}'
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", ctype.encode())]})
        await send({"type": "http.response.body", "body": payload})

    return app


async def test_suite_reports_must_failures_for_a_broken_server() -> None:
    report = await run_conformance(
        "http://broken", transport=httpx.ASGITransport(app=_broken_app()), skip_large=True
    )
    results = _by_id(report)
    assert not report.ok
    assert results["discovery.agent-json"].status == "pass"
    assert results["discovery.health"].status == "fail"          # status "ok"
    assert results["errors.unknown-route"].status == "fail"      # text/plain 404
    assert results["message.accepted"].status == "fail"
    assert results["message.invalid-json"].status == "fail"      # not problem+json
    assert results["message.unknown-body-type"].status == "fail"  # 400
    as_json = report.to_dict()
    assert as_json["conformant"] is False
    assert as_json["summary"]["must_failures"] >= 5


async def test_invalid_agent_json_fails_discovery() -> None:
    report = await run_conformance(
        "http://broken",
        transport=httpx.ASGITransport(app=_broken_app(agent_json={"identifiers": "agent://x"})),
        level=0,
    )
    results = _by_id(report)
    assert results["discovery.agent-json"].status == "fail"
    assert all(r.level == 0 for r in report.results)


# ---------------------------------------------------------------------------
# CLI and key loading
# ---------------------------------------------------------------------------


def test_cli_list_and_usage_errors(capsys) -> None:
    assert cli_main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "auth.signature-replay" in out and "MUST" in out
    assert cli_main([]) == 2
    assert cli_main(["--url", "http://x", "--keyid", "k"]) == 2


def test_cli_json_report_against_uvicorn(tmp_path, capsys) -> None:
    uvicorn = pytest.importorskip("uvicorn")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    srv = uvicorn.Server(uvicorn.Config(make_server(base).asgi(), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    try:
        while not srv.started:
            time.sleep(0.05)
        out_file = tmp_path / "report.json"
        code = cli_main(["--url", base, "--report", "json", "--skip-large", "--output", str(out_file)])
    finally:
        srv.should_exit = True
        thread.join(timeout=10)
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["conformant"] is True
    assert json.loads(out_file.read_text()) == doc
    assert {r["status"] for r in doc["results"]} <= {"pass", "skip"}


def test_load_signing_key_formats(tmp_path) -> None:
    import base64

    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    pem = Ed25519PrivateKey.from_private_bytes(SEED).private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    f = tmp_path / "k.pem"
    f.write_bytes(pem)
    assert load_signing_key(str(f)) == SEED
    assert load_signing_key(SEED.hex()) == SEED
    assert load_signing_key(base64.urlsafe_b64encode(SEED).decode().rstrip("=")) == SEED
    with pytest.raises(ValueError):
        load_signing_key("abcd")
