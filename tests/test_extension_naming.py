"""Naming rules for third-party extensions (docs/EXTENSIONS.md)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ampro.core.body_schemas import validate_body
from ampro.core.envelope import AgentMessage
from ampro.wire.extensions import (
    extension_error_type_error,
    extension_header_error,
    extension_name_error,
    extension_uri_error,
    is_extension_name,
)

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("name", [
    "com.acme.order_confirmation",
    "org.openai.function_call",
    "io.anthropic.tool_use",
    "x-acme.order",
    "x-acme.billing.invoice_v2",
    "https://acme.example/amp/order/v1",
])
def test_valid_extension_names(name: str) -> None:
    assert is_extension_name(name), extension_name_error(name)


@pytest.mark.parametrize("name", [
    "task.custom",            # reserved namespace
    "session.extra.thing",    # reserved namespace
    "amp.anything.here",      # reserved namespace
    "acme.order",             # too short to be reverse-DNS
    "Com.Acme.Order",         # upper case
    "x-acme",                 # no name after vendor
    "http://acme.example/x",  # not https
    "https://acme.example/x#frag",
    "",
    " com.acme.order",
])
def test_invalid_extension_names(name: str) -> None:
    assert not is_extension_name(name)


def test_header_error_type_and_uri_rules() -> None:
    assert extension_header_error("X-Acme-Request-Id") is None
    assert extension_header_error("X-AMP-Ext-Foo") is not None
    assert extension_header_error("Acme-Request-Id") is not None
    assert extension_header_error("X-Acme") is not None
    assert extension_error_type_error("urn:com.example:error:custom") is None
    assert extension_error_type_error("urn:amp:error:custom") is not None
    assert extension_error_type_error("urn:com.example:custom") is not None
    assert extension_uri_error("https://acme.example/amp-ext/v1") is None
    assert extension_uri_error("acme.example/amp-ext/v1") is not None


def test_receivers_pass_extension_bodies_through() -> None:
    body = {"order": 42, "nested": {"anything": True}}
    for name in ("com.acme.order", "x-acme.order", "https://acme.example/amp/order/v1"):
        assert validate_body(name, body) == body
        msg = AgentMessage(sender="agent://a.example", recipient="agent://b.example",
                           body_type=name, headers={"X-Acme-Trace": "1"}, body=body)
        assert msg.body == body


def _generator():
    spec = importlib.util.spec_from_file_location("generate_spec", ROOT / "scripts" / "generate_spec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_third_party_registrations_are_validated(tmp_path: Path) -> None:
    gen = _generator()
    entry = {"owner": "Acme", "contact": "amp@acme.example",
             "spec": "https://acme.example/amp", "description": "Order confirmations"}
    good = tmp_path / "good.json"
    good.write_text(json.dumps({
        "body_types": [{"name": "com.acme.order_confirmation", **entry}],
        "headers": [{"name": "X-Acme-Request-Id", **entry}],
        "error_types": [{"type": "urn:com.acme:error:out-of-stock", "status": 409, **entry}],
        "extension_uris": [{"uri": "https://acme.example/amp-ext/v1", **entry}],
    }))
    loaded = gen.load_third_party(good)
    assert loaded["body_types"][0]["name"] == "com.acme.order_confirmation"

    for bad in (
        {"body_types": [{"name": "task.mine", **entry}]},
        {"headers": [{"name": "X-AMP-Mine", **entry}]},
        {"body_types": [{"name": "com.acme.thing"}]},
        {"error_types": [{"type": "urn:com.acme:error:x", **entry}]},
        {"surprise": []},
    ):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(bad))
        with pytest.raises(SystemExit):
            gen.load_third_party(path)


def test_committed_third_party_file_is_valid() -> None:
    _generator().load_third_party()
