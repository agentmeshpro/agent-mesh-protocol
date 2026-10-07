"""MCPAdapter — the stateless 2026-07-28 revision (per-request envelope)."""
from __future__ import annotations

import base64

import pytest

from ._support import MODERN, Wire, body_of, modern_headers, modern_params


async def modern_rpc(wire: Wire, method: str, params: dict | None = None, headers: dict | None = None):
    hdrs = modern_headers(method, (params or {}).get("name"))
    hdrs.update(headers or {})
    return await wire.rpc(method, modern_params(params), headers=hdrs)


async def test_discover(wire: Wire):
    resp, body = await modern_rpc(wire, "server/discover")
    assert resp.status == 200
    result = body["result"]
    assert result["supportedVersions"] == [MODERN]
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 0 and result["cacheScope"] == "private"
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"]
    assert "mcp-session-id" not in resp.headers


async def test_tools_list_and_call_without_session(wire: Wire):
    _, body = await modern_rpc(wire, "tools/list")
    result = body["result"]
    assert {"add", "amp_task"} <= {t["name"] for t in result["tools"]}
    assert result["resultType"] == "complete" and "ttlMs" in result and "cacheScope" in result
    resp, body = await modern_rpc(wire, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}})
    assert resp.status == 200
    assert body["result"]["structuredContent"] == {"sum": 3}
    assert body["result"]["resultType"] == "complete"


async def test_missing_meta_is_invalid_params(wire: Wire):
    resp, body = await wire.rpc("tools/list", {}, headers=modern_headers("tools/list"))
    assert resp.status == 400
    assert body["error"]["code"] == -32602


async def test_missing_capabilities_key(wire: Wire):
    params = modern_params()
    del params["_meta"]["io.modelcontextprotocol/clientCapabilities"]
    resp, body = await wire.rpc("tools/list", params, headers=modern_headers("tools/list"))
    assert resp.status == 400 and body["error"]["code"] == -32602


@pytest.mark.parametrize(
    "headers",
    [
        {"mcp-method": "tools/list"},
        {"mcp-method": None},
        {"mcp-name": "greet"},
        {"mcp-name": None},
    ],
)
async def test_header_mismatch(wire: Wire, headers):
    resp, body = await modern_rpc(wire, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}}, headers)
    assert resp.status == 400
    assert body["error"]["code"] == -32020


async def test_version_header_must_match_envelope(wire: Wire):
    hdrs = modern_headers("tools/list", version="2099-01-01")
    resp, body = await wire.rpc("tools/list", modern_params(), headers=hdrs)
    assert resp.status == 400 and body["error"]["code"] == -32020


async def test_mcp_name_base64_sentinel(wire: Wire):
    encoded = "=?base64?" + base64.b64encode(b"add").decode() + "?="
    resp, body = await modern_rpc(
        wire, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}, {"mcp-name": encoded}
    )
    assert resp.status == 200, body


async def test_unsupported_version(wire: Wire):
    hdrs = modern_headers("tools/list", version="2099-01-01")
    resp, body = await wire.rpc("tools/list", modern_params(version="2099-01-01"), headers=hdrs)
    assert resp.status == 400
    assert body["error"]["code"] == -32022
    assert body["error"]["data"] == {"supported": [MODERN], "requested": "2099-01-01"}


@pytest.mark.parametrize("method", ["initialize", "ping", "resources/list"])
async def test_unknown_or_removed_methods_404(wire: Wire, method):
    resp, body = await modern_rpc(wire, method)
    assert resp.status == 404
    assert body["error"]["code"] == -32601


async def test_unknown_tool(wire: Wire):
    resp, body = await modern_rpc(wire, "tools/call", {"name": "nope", "arguments": {}})
    assert resp.status == 400 and body["error"]["code"] == -32602


async def test_notification_accepted(wire: Wire):
    resp = await wire.http(
        body={"jsonrpc": "2.0", "method": "notifications/cancelled"}, headers={"mcp-protocol-version": MODERN}
    )
    assert resp.status == 202


async def test_notification_unsupported_version(wire: Wire):
    resp = await wire.http(
        body={"jsonrpc": "2.0", "method": "notifications/x"}, headers={"mcp-protocol-version": "2099-01-01"}
    )
    assert resp.status == 400
    assert body_of(resp)["error"]["code"] == -32022


@pytest.mark.parametrize("payload", [[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}], "x", {"jsonrpc": "2.0", "id": 1}])
async def test_batches_and_junk_rejected(wire: Wire, payload):
    resp = await wire.http(body=payload, headers={"mcp-protocol-version": MODERN})
    assert resp.status == 400
    assert body_of(resp)["error"]["code"] == -32600


async def test_get_and_delete_are_405(wire: Wire):
    for method in ("GET", "DELETE"):
        resp = await wire.http(method, headers={"mcp-protocol-version": MODERN})
        assert resp.status == 405 and resp.headers["allow"] == "POST"


async def test_parse_error(wire: Wire):
    resp = await wire.http(raw=b"[", headers={"mcp-protocol-version": MODERN})
    assert resp.status == 400 and body_of(resp)["error"]["code"] == -32700


async def test_origin_enforced_on_modern_path(wire: Wire):
    resp, _ = await modern_rpc(wire, "server/discover", headers={"origin": "https://evil.example"})
    assert resp.status == 403
