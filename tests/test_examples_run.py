"""Smoke test: every ``examples/*.py`` runs to completion with exit code 0.

Each example runs in its own subprocess against THIS checkout (not an
installed copy of ampro), with:

* a network sandbox — DNS lookups and socket connects to anything other
  than loopback raise, so no example can reach the real network (client
  examples exercise their "no server running" error paths instead);
* ``AMPRO_EXAMPLE_NO_SERVE=1`` — server examples build their app but skip
  the blocking ``run()`` call;
* a per-example timeout.

Optional third-party dependencies are declared with a header comment in
the example, e.g. ``# requires: fastapi, uvicorn``; the example is skipped
when any of them is not importable.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = sorted((ROOT / "examples").glob("*.py"))
TIMEOUT = 20

# Examples that fail because of a library bug outside the example itself.
# Non-strict so the entry can simply be deleted once the bug is fixed.
KNOWN_FAILURES = {
    "39_two_agents_talking.py": (
        "ampro/server/core.py FastAPI adapter: `request: Request` is imported "
        "inside _run_fastapi but the module uses `from __future__ import "
        "annotations`, so FastAPI cannot resolve the annotation and treats "
        "`request` as a required query param -> POST /agent/message returns 422"
    ),
}

_REQUIRES_RE = re.compile(r"^#\s*requires:\s*([^(\n]+)", re.M)

# Runs inside the subprocess before the example: block non-loopback network.
_BOOTSTRAP = r'''
import ipaddress, runpy, socket, sys

def _is_loopback(host):
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode()
    host = str(host).strip("[]").split("%")[0].lower()
    if host in ("localhost", "localhost.", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

_real_gai = socket.getaddrinfo

def _gai(host, *args, **kwargs):
    if not _is_loopback(host):
        raise socket.gaierror(socket.EAI_NONAME, f"network disabled in example tests: {host}")
    return _real_gai(host, *args, **kwargs)

socket.getaddrinfo = _gai

def _guard(addr):
    if isinstance(addr, tuple) and not _is_loopback(addr[0]):
        raise ConnectionRefusedError(f"network disabled in example tests: {addr[0]}")

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex

def _connect(self, addr):
    _guard(addr)
    return _real_connect(self, addr)

def _connect_ex(self, addr):
    _guard(addr)
    return _real_connect_ex(self, addr)

socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex

path = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path[0] = __import__("os").path.dirname(path)
runpy.run_path(path, run_name="__main__")
'''


def _requirements(path: Path) -> list[str]:
    reqs: list[str] = []
    for match in _REQUIRES_RE.finditer(path.read_text(encoding="utf-8")):
        reqs += [r.strip() for r in match.group(1).split(",") if r.strip()]
    return reqs


def test_examples_discovered():
    assert len(EXAMPLES) >= 40


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_example_runs(path: Path, request: pytest.FixtureRequest) -> None:
    if path.name in KNOWN_FAILURES:
        request.applymarker(pytest.mark.xfail(reason=KNOWN_FAILURES[path.name], strict=False))
    missing = [m for m in _requirements(path) if importlib.util.find_spec(m) is None]
    if missing:
        pytest.skip(f"{path.name} requires {', '.join(missing)}")

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    env["AMPRO_EXAMPLE_NO_SERVE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(var, None)

    try:
        proc = subprocess.run(
            [sys.executable, "-c", _BOOTSTRAP, str(path)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"{path.name} did not finish within {TIMEOUT}s:\n{exc.stdout}\n{exc.stderr}")

    assert proc.returncode == 0, (
        f"{path.name} exited with {proc.returncode}\n"
        f"--- stdout (tail) ---\n{proc.stdout[-2000:]}\n"
        f"--- stderr (tail) ---\n{proc.stderr[-4000:]}"
    )
