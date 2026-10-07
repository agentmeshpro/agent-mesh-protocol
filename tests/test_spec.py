"""The machine-readable spec under ``spec/`` is current, valid, and agrees with the vectors.

* ``scripts/generate_spec.py --check`` passes (no drift between the
  reference models / WIRE-BINDING tables and the committed files).
* Every JSON Schema is a valid 2020-12 schema with a stable ``$id``.
* Every schema-shaped case in ``tests/vectors/`` is accepted or rejected
  by the published JSON Schemas exactly as the vector records, so a
  non-Python implementation can validate with the schemas alone.  The
  only exceptions are listed in ``SEMANTIC_ONLY`` (cross-field rules JSON
  Schema cannot express); those schemas carry ``x-amp-constraints``.
* ``spec/openapi.yaml`` is a valid OpenAPI 3.1 document.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec"
VECTORS = ROOT / "tests" / "vectors"

jsonschema = pytest.importorskip("jsonschema")

from ampro.wire.schemas import (  # noqa: E402
    SCHEMA_BASE,
    body_schema_path,
    build_schemas,
    schema_registry,
    stream_schema_path,
)

#: Vector cases a JSON Schema validator cannot reject on its own.
#: (file, section, index) -> the schema whose x-amp-constraints covers it.
SEMANTIC_ONLY: dict[tuple[str, str, int], str] = {
    ("identity_link.json", "vectors", 10): "body/identity.link_proof.json",
}


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_spec", ROOT / "scripts" / "generate_spec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def docs() -> dict[str, dict[str, Any]]:
    """The committed schemas (what implementers download)."""
    out = {}
    for p in sorted((SPEC / "schemas").rglob("*.json")):
        out[p.relative_to(SPEC / "schemas").as_posix()] = json.loads(p.read_text(encoding="utf-8"))
    return out


@pytest.fixture(scope="module")
def registry(docs):
    return schema_registry(docs)


def test_spec_is_up_to_date() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_spec.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_committed_schemas_match_models(docs) -> None:
    assert docs == build_schemas()


def test_schemas_are_valid_2020_12_with_stable_ids(docs) -> None:
    for path, doc in docs.items():
        jsonschema.Draft202012Validator.check_schema(doc)
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert doc["$id"] == SCHEMA_BASE + path


def test_every_relative_ref_resolves(docs, registry) -> None:
    def refs(node: Any):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref" and not v.startswith("#"):
                    yield v
                else:
                    yield from refs(v)
        elif isinstance(node, list):
            for item in node:
                yield from refs(item)

    from urllib.parse import urljoin

    for doc in docs.values():
        for ref in refs(doc):
            assert urljoin(doc["$id"], ref) in {d["$id"] for d in docs.values()}, ref


def test_registries_reference_existing_schemas(docs) -> None:
    from ampro.core.body_schemas import _BODY_TYPE_REGISTRY
    from ampro.wire.errors import ErrorType

    body = json.loads((SPEC / "registry" / "body-types.json").read_text())
    names = {e["name"] for e in body["entries"]}
    assert names == set(_BODY_TYPE_REGISTRY)
    for e in body["entries"]:
        assert (SPEC / "registry" / e["schema"]).resolve().exists()
        for r in (e["valid_responses"] or []) + [e["expected_response"]] * bool(e["expected_response"]):
            assert r in names, (e["name"], r)

    errors = json.loads((SPEC / "registry" / "errors.json").read_text())
    assert {e["type"] for e in errors["entries"]} == {
        v for k, v in vars(ErrorType).items() if k.isupper()
    }
    exts = json.loads((SPEC / "registry" / "extensions.json").read_text())
    assert "https://github.com/CatlystAI/agent-mesh-protocol/ext/amp/v1" in {
        e["uri"] for e in exts["entries"]
    }
    events = json.loads((SPEC / "registry" / "stream-events.json").read_text())
    for e in events["entries"]:
        if e["data_schema"]:
            assert (SPEC / "registry" / e["data_schema"]).resolve().exists()


# ---------------------------------------------------------------------------
# Vectors against the published schemas
# ---------------------------------------------------------------------------

_STREAM_TYPES = {
    "StreamChannelOpenEvent": "stream.channel_open",
    "StreamChannelCloseEvent": "stream.channel_close",
    "StreamCheckpointEvent": "stream.checkpoint",
}


def _schema_cases() -> list[tuple[str, str, int, str, Any, bool]]:
    from ampro.core.body_schemas import _BODY_TYPE_REGISTRY

    out = []
    for f in sorted(VECTORS.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        for section, cases in doc.items():
            if section == "keys" or not isinstance(cases, list):
                continue
            for i, c in enumerate(cases):
                if not isinstance(c, dict) or "valid" not in c:
                    continue
                target: tuple[str, Any] | None = None
                if f.name in ("stream_channel.json", "stream_checkpoint.json"):
                    t = c.get("expected", {}).get("type")
                    if t in _STREAM_TYPES:
                        target = (stream_schema_path(_STREAM_TYPES[t]), c["input"])
                    elif t is None:
                        cid = c["id"]
                        et = (
                            "stream.checkpoint"
                            if any(w in cid for w in ("checkpoint", "seq", "timestamp"))
                            else "stream.channel_close" if "close" in cid else "stream.channel_open"
                        )
                        target = (stream_schema_path(et), c["input"])
                    elif t == "AgentMessage":
                        target = ("envelope.json", c["input"])
                elif f.name == "backpressure.json":
                    target = (stream_schema_path(c["event_type"]), c["body"])
                elif f.name == "envelope.json":
                    target = ("envelope.json", c["input"])
                elif "envelope" in c:
                    target = ("envelope.json", c["envelope"])
                elif "encrypted_body" in c:
                    target = ("encrypted-body.json", c["encrypted_body"])
                elif "agent_json" in c:
                    target = ("agent-json.json", c["agent_json"])
                elif c.get("body_type") in _BODY_TYPE_REGISTRY and isinstance(
                    c.get("body", c.get("input")), dict
                ):
                    target = (body_schema_path(c["body_type"]), c.get("body", c.get("input")))
                if target is not None:
                    out.append((f.name, section, i, target[0], target[1], c["valid"]))
    return out


_CASES = _schema_cases()


def test_schema_vector_coverage() -> None:
    files = {c[0] for c in _CASES}
    # Every schema-shaped vector file is exercised.
    assert {
        "audit_attestation.json", "backpressure.json", "body_types.json", "challenge.json",
        "consent_revoke.json", "encryption.json", "envelope.json", "erasure_propagation.json",
        "identity_link.json", "identity_migration.json", "stream_channel.json",
        "stream_checkpoint.json", "task_revoke.json", "tool_consent.json", "trust_proof.json",
        "trust_upgrade.json", "agent_lifecycle.json", "certifications.json",
    } <= files
    assert len(_CASES) >= 200


@pytest.mark.parametrize(
    ("filename", "section", "index", "schema", "instance", "valid"),
    _CASES,
    ids=[f"{c[0].removesuffix('.json')}:{c[1]}[{c[2]}]" for c in _CASES],
)
def test_vector_against_schema(docs, registry, filename, section, index, schema, instance, valid) -> None:
    validator = jsonschema.Draft202012Validator(docs[schema], registry=registry)
    ok = validator.is_valid(instance)
    key = (filename, section, index)
    if key in SEMANTIC_ONLY:
        assert ok and not valid, "schema now rejects this case; drop it from SEMANTIC_ONLY"
        assert docs[SEMANTIC_ONLY[key]].get("x-amp-constraints")
        return
    if ok != valid:
        errs = [e.message for e in validator.iter_errors(instance)][:3]
        pytest.fail(f"schema {schema}: expected valid={valid}, got {ok} {errs}")


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


def test_openapi_yaml_matches_generator() -> None:
    yaml = pytest.importorskip("yaml")
    loaded = yaml.safe_load((SPEC / "openapi.yaml").read_text(encoding="utf-8"))
    assert loaded == _load_generator().build_openapi()


def test_openapi_is_valid_3_1() -> None:
    validator = pytest.importorskip("openapi_spec_validator")
    readers = pytest.importorskip("openapi_spec_validator.readers")
    spec_dict, base_uri = readers.read_from_filename(str(SPEC / "openapi.yaml"))
    assert spec_dict["openapi"].startswith("3.1")
    validator.validate(spec_dict, base_uri=base_uri)


def test_openapi_covers_the_mandatory_endpoints() -> None:
    oa = _load_generator().build_openapi()
    for path, method in [
        ("/.well-known/agent.json", "get"),
        ("/agent/health", "get"),
        ("/agent/message", "post"),
        ("/agent/stream", "get"),
    ]:
        assert method in oa["paths"][path]
    codes = set(oa["paths"]["/agent/message"]["post"]["responses"])
    assert {"200", "202", "400", "401", "403", "406", "409", "413", "415", "429", "501"} <= codes
    assert set(oa["components"]["securitySchemes"]) == {"rfc9421", "bearer", "did", "apiKey", "mtls"}


def test_envelope_and_stream_dispatch(docs, registry) -> None:
    env = jsonschema.Draft202012Validator(docs["envelope.json"], registry=registry)
    base = {"sender": "agent://a.example", "recipient": "agent://b.example", "id": "m-1"}
    assert env.is_valid({**base, "body_type": "task.create", "body": {"description": "x"}})
    assert not env.is_valid({**base, "body_type": "task.create", "body": {}})
    # Unknown body types pass through unvalidated (WIRE-BINDING 5.1.4).
    assert env.is_valid({**base, "body_type": "com.example.custom", "body": {"any": 1}})
    # A missing body_type defaults to "message".
    assert not env.is_valid({**base, "body": {"no_text": True}})
    # Content-Encryption switches body validation to EncryptedBody.
    enc = {**base, "body_type": "task.create", "headers": {"Content-Encryption": "A256GCM"}}
    assert not env.is_valid({**enc, "body": {"description": "plaintext"}})
    assert env.is_valid({**enc, "body": {
        "ciphertext": "AA", "iv": "AA", "tag": "AA", "algorithm": "A256GCM", "recipient_key_id": "k",
    }})
    assert not env.is_valid({**base, "headers": {"Priority": 1}})

    ev = jsonschema.Draft202012Validator(docs["stream/event.json"], registry=registry)
    assert ev.is_valid({"event": "thinking", "data": {"seq": 1, "message": "hm"}})
    assert ev.is_valid({"event": "x-vendor.custom", "data": {}})
    assert not ev.is_valid({"event": "stream.ack", "data": {"seq": 2}})
    assert ev.is_valid({"event": "stream.ack", "data": {"last_seq": 2, "timestamp": "2026-01-01T00:00:00Z"}})
