#!/usr/bin/env python
"""Generate the machine-readable AMP specification under ``spec/``.

Usage::

    python scripts/generate_spec.py          # (re)write spec/
    python scripts/generate_spec.py --check  # exit 1 if spec/ is stale

Outputs:

* ``spec/schemas/``  JSON Schema 2020-12 documents built from the reference
  Pydantic models (``ampro.wire.schemas``): envelope, every registered body
  type, agent.json, health, RFC 7807 problem details, encrypted body and
  streaming events.
* ``spec/openapi.yaml``  OpenAPI 3.1 description of the HTTP binding.
* ``spec/registry/``  registries of body types, headers, error types,
  extension URIs and streaming event types.

Metadata that the code does not carry (descriptions, categories,
idempotency, header direction and format, request/response pairs) is read
from the normative tables in ``docs/WIRE-BINDING.md``, and the script
fails if the document and the code disagree on which names exist.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ampro.core.envelope import STANDARD_HEADERS  # noqa: E402
from ampro.core.versioning import CURRENT_VERSION, SUPPORTED_VERSIONS  # noqa: E402
from ampro.streaming.events import StreamingEventType  # noqa: E402
from ampro.wire.body_type_map import BODY_TYPE_BINDINGS  # noqa: E402
from ampro.wire.endpoints import ALL_ENDPOINTS  # noqa: E402
from ampro.wire.errors import ErrorType  # noqa: E402
from ampro.wire.extensions import (  # noqa: E402
    RESERVED_NAMESPACES,
    extension_error_type_error,
    extension_header_error,
    extension_name_error,
    extension_uri_error,
)
from ampro.wire.schemas import (  # noqa: E402
    SPEC_BASE,
    body_schema_path,
    build_schemas,
    schema_id,
    stream_event_models,
    stream_schema_path,
)

SPEC_DIR = ROOT / "spec"
WIRE_BINDING = ROOT / "docs" / "WIRE-BINDING.md"
REGISTRY_BASE = SPEC_BASE + "registry/"

A2A_EXTENSION_URI = "https://github.com/CatlystAI/agent-mesh-protocol/ext/amp/v1"

# ---------------------------------------------------------------------------
# Version history (reference-implementation release that introduced a name).
# Releases before protocol 1.0.0 are ampro 0.x releases; see CHANGELOG.md.
# ---------------------------------------------------------------------------

BODY_TYPE_SINCE: dict[str, str] = {
    **dict.fromkeys(
        [
            "session.init", "session.established", "session.confirm", "session.ping",
            "session.pong", "session.pause", "session.resume", "session.close",
        ],
        "0.1.1",
    ),
    **dict.fromkeys(
        [
            "key.revocation", "task.challenge", "task.challenge_response",
            "tool.consent_request", "tool.consent_grant",
            "trust.upgrade_request", "trust.upgrade_response",
        ],
        "0.1.2",
    ),
    "agent.deactivation_notice": "0.1.3",
    "task.redirect": "0.1.4",
    "task.revoke": "0.1.5",
    "erasure.propagation_status": "0.1.6",
    "data.consent_revoke": "0.1.6",
    **dict.fromkeys(
        [
            "identity.link_proof", "identity.migration", "audit.attestation",
            "registry.federation_request", "registry.federation_response",
        ],
        "0.1.8",
    ),
    "trust.proof": "0.1.9",
    **dict.fromkeys(
        [
            "agent.metadata_invalidate", "registry.federation_revoke",
            "registry.federation_sync", "registry.federation_sync_response",
        ],
        "0.3.3",
    ),
}
DEFAULT_SINCE = "0.1.0"

HEADER_SINCE: dict[str, str] = {
    **dict.fromkeys(
        ["Session-Binding", "Trust-Score", "Context-Schema", "Transaction-Id",
         "Correlation-Group", "Commitment-Level"],
        "0.1.1",
    ),
    "Key-Revoked-At": "0.1.2",
    "Anonymous-Sender-Hint": "0.1.2",
    "Hop-Timeout": "0.1.3",
    "X-Load-Level": "0.1.4",
    "Trace-Id": "0.1.5",
    "Span-Id": "0.1.5",
    "Jurisdiction": "0.1.6",
    "Data-Residency": "0.1.6",
    "Stream-Channel": "0.1.7",
    "Content-Encryption": "0.1.9",
}

STREAM_EVENT_SINCE: dict[str, str] = {
    "stream.ack": "0.1.7", "stream.pause": "0.1.7", "stream.resume": "0.1.7",
    "stream.channel_open": "0.1.7", "stream.channel_close": "0.1.7",
    "stream.checkpoint": "0.1.7", "stream.auth_refresh": "0.1.7",
}

#: Envelope headers that also travel as HTTP header fields.
HTTP_ALSO = {
    "Protocol-Version", "Accept-Version", "Content-Type", "Authorization", "Retry-After",
    "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
    "Accept-Language", "Content-Language",
}

#: HTTP-only header fields used by the binding.
HTTP_HEADERS: list[dict[str, Any]] = [
    {"name": "Signature", "direction": "request", "format": "RFC 9421 Signature",
     "description": "Ed25519 HTTP message signature (label sig1)", "section": "12.15.1"},
    {"name": "Signature-Input", "direction": "request", "format": "RFC 9421 Signature-Input",
     "description": "Covered components and created/keyid/alg/nonce parameters", "section": "12.15.1"},
    {"name": "Content-Digest", "direction": "request", "format": "RFC 9530 sha-256",
     "description": "Digest of the request body; MUST be covered when the body is non-empty",
     "section": "12.15.2"},
    {"name": "WWW-Authenticate", "direction": "response", "format": "RFC 9110",
     "description": "Accepted authentication schemes on a 401", "section": "7.2.2"},
    {"name": "Sunset", "direction": "response", "format": "HTTP-date",
     "description": "Deprecation date of the protocol version in use", "section": "18.5"},
    {"name": "Last-Event-ID", "direction": "request", "format": "SSE event id",
     "description": "Resume a stream after the given event", "section": "8.5"},
]

#: Error URN -> (HTTP status, title, WIRE-BINDING section).
ERRORS: dict[str, tuple[int, str, str]] = {
    ErrorType.INVALID_MESSAGE: (400, "Invalid message", "7.2.1"),
    ErrorType.INVALID_CALLBACK_URL: (400, "Invalid callback URL", "12.8"),
    ErrorType.HEADER_INJECTION: (400, "Header injection detected", "14"),
    ErrorType.UNAUTHORIZED: (401, "Unauthorized", "7.2.2"),
    ErrorType.FORBIDDEN: (403, "Forbidden", "7.2.3"),
    ErrorType.CAPABILITY_NOT_NEGOTIATED: (403, "Capability not negotiated", "17.4"),
    ErrorType.CONTACT_POLICY_VIOLATION: (403, "Contact policy violation", "7.2.3"),
    ErrorType.DELEGATION_DENIED: (403, "Delegation denied", "11.11"),
    ErrorType.DELEGATION_VALIDATION_FAILED: (403, "Delegation validation failed", "11.11.1"),
    ErrorType.JURISDICTION_CONFLICT: (403, "Jurisdiction conflict", "13.5"),
    ErrorType.RESIDENCY_VIOLATION: (403, "Data residency violation", "13.6"),
    ErrorType.CONSENT_DENIED: (403, "Consent denied", "13.3"),
    ErrorType.NOT_FOUND: (404, "Not found", "7.2.4"),
    ErrorType.VERSION_MISMATCH: (406, "Protocol version mismatch", "7.2.5"),
    ErrorType.TIMEOUT: (408, "Request timeout", "7.2.6"),
    ErrorType.NONCE_REPLAY: (409, "Nonce replay detected", "7.2.7"),
    ErrorType.LOOP_DETECTED: (409, "Loop detected", "Appendix D"),
    ErrorType.SESSION_EXPIRED: (410, "Session expired", "7.2.8"),
    ErrorType.PAYLOAD_TOO_LARGE: (413, "Payload too large", "7.2.9"),
    ErrorType.CONTENT_TYPE_MISMATCH: (415, "Content type mismatch", "3.2"),
    ErrorType.RATE_LIMITED: (429, "Rate limit exceeded", "7.2.10"),
    ErrorType.STREAM_LIMIT_EXCEEDED: (429, "Stream limit exceeded", "8.7"),
    ErrorType.INTERNAL_ERROR: (500, "Internal error", "7.2.11"),
    ErrorType.NOT_IMPLEMENTED: (501, "Not implemented", "7.2.12"),
    ErrorType.UNAVAILABLE: (503, "Service unavailable", "7.2.13"),
}

#: Extension URIs and namespaces assigned by this specification.
EXTENSIONS: list[dict[str, Any]] = [
    {
        "uri": A2A_EXTENSION_URI,
        "name": "AMP extension for A2A",
        "kind": "a2a-extension",
        "status": "stable",
        "since": "0.4.0",
        "owner": "AMP maintainers",
        "description": (
            "Carries AMP delegation chains, jurisdiction, data residency, trace "
            "context and cost receipts in A2A message metadata. Activated with "
            "the A2A-Extensions header; listed in the Agent Card with required=false."
        ),
        "params": ["agent_id", "amp_endpoint", "protocol_version"],
        "spec": "docs/INTEROP-A2A.md#amp-extension",
    },
]

RESERVED_BODY_TYPE_NAMESPACES = sorted(RESERVED_NAMESPACES)

#: Hand-maintained third-party registrations (docs/EXTENSIONS.md).
THIRD_PARTY = SPEC_DIR / "third-party.json"
_THIRD_PARTY_SECTIONS = {
    "body_types": ("name", extension_name_error),
    "stream_events": ("name", extension_name_error),
    "headers": ("name", extension_header_error),
    "error_types": ("type", extension_error_type_error),
    "extension_uris": ("uri", extension_uri_error),
}
_THIRD_PARTY_REQUIRED = ("owner", "contact", "spec", "description")


def load_third_party(path: Path = THIRD_PARTY) -> dict[str, list[dict[str, Any]]]:
    """Load and validate third-party registrations; exit on any violation."""
    if not path.exists():
        return {k: [] for k in _THIRD_PARTY_SECTIONS}
    doc = json.loads(path.read_text(encoding="utf-8"))
    problems: list[str] = []
    out: dict[str, list[dict[str, Any]]] = {}
    for section, (key, rule) in _THIRD_PARTY_SECTIONS.items():
        entries = doc.get(section, [])
        seen: set[str] = set()
        for i, entry in enumerate(entries):
            name = entry.get(key, "")
            where = f"{path.name}:{section}[{i}] {name!r}"
            why = rule(name)
            if why:
                problems.append(f"{where}: {why}")
            missing = [f for f in _THIRD_PARTY_REQUIRED if not entry.get(f)]
            if missing:
                problems.append(f"{where}: missing {missing}")
            if name in seen:
                problems.append(f"{where}: duplicate")
            seen.add(name)
            if section == "error_types" and not isinstance(entry.get("status"), int):
                problems.append(f"{where}: missing integer status")
        out[section] = sorted(entries, key=lambda e: e.get(key, ""))
    unknown = set(doc) - set(_THIRD_PARTY_SECTIONS) - {"description", "$comment"}
    if unknown:
        problems.append(f"{path.name}: unknown sections {sorted(unknown)}")
    if problems:
        raise SystemExit("generate_spec: invalid third-party registration\n" + "\n".join(problems))
    return out


def _registered(entry: dict[str, Any]) -> dict[str, Any]:
    return {**entry, "status": "registered"}


# ---------------------------------------------------------------------------
# WIRE-BINDING table parsing
# ---------------------------------------------------------------------------


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def _rows(text: str) -> list[list[str]]:
    """Cells of every markdown table row whose first cell is a `code` name."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        cells[0] = cells[0].strip("`")
        rows.append(cells)
    return rows


def parse_wire_binding() -> dict[str, Any]:
    text = WIRE_BINDING.read_text(encoding="utf-8")

    # Section 16.1: body types grouped by subsection.
    body: dict[str, dict[str, Any]] = {}
    reg = _section(text, "### 16.1 Body Type Registry", "### 16.2")
    for block in re.split(r"^#### ", reg, flags=re.M)[1:]:
        heading = block.splitlines()[0]
        m = re.match(r"(16\.1\.\d+) (.+?)(?: \(.*\))?$", heading)
        assert m, heading
        for cells in _rows(block):
            body[cells[0]] = {
                "section": m.group(1),
                "category": m.group(2),
                "description": cells[1],
                "idempotent": cells[2].lower() == "yes",
            }

    # Section 16.2: request/response pairs.
    pairs: dict[str, list[str]] = {}
    for cells in _rows(_section(text, "### 16.2 Request-Response Pairs", "## 17.")):
        pairs[cells[0]] = re.findall(r"`([^`]+)`", cells[1])

    # Section 14: headers.
    headers: dict[str, dict[str, Any]] = {}
    hsec = _section(text, "## 14. Standard Headers", "## 15. Status Codes")
    for block in re.split(r"^### ", hsec, flags=re.M)[1:]:
        heading = block.splitlines()[0]
        m = re.match(r"(14\.\d+) (.+)$", heading)
        assert m, heading
        for cells in _rows(block):
            headers[cells[0]] = {
                "section": m.group(1),
                "group": m.group(2),
                "direction": cells[1].lower(),
                "format": cells[3],
                "description": cells[4],
            }

    # Section 8.4: streaming event types.
    events: dict[str, dict[str, Any]] = {}
    for cells in _rows(_section(text, "### 8.4 Event Types", "#### 8.4.1")):
        events[cells[0]] = {"description": cells[1], "category": cells[2]}

    return {"body": body, "pairs": pairs, "headers": headers, "events": events}


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


def _registry_doc(name: str, description: str, entries: list[dict[str, Any]],
                  **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "$id": REGISTRY_BASE + f"{name}.json",
        "registry": name,
        "description": description,
        "protocol_version": CURRENT_VERSION,
        "change_process": "GOVERNANCE.md; third-party registrations per docs/EXTENSIONS.md",
    }
    doc.update(extra)
    doc["entries"] = entries
    return doc


def build_registries(wb: dict[str, Any], schemas: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from ampro.core.body_schemas import _BODY_TYPE_REGISTRY

    errors: list[str] = []
    code_types = set(_BODY_TYPE_REGISTRY)
    doc_types = set(wb["body"])
    if code_types != doc_types:
        errors.append(
            "body types differ between code and WIRE-BINDING 16.1: "
            f"code-only={sorted(code_types - doc_types)} doc-only={sorted(doc_types - code_types)}"
        )
    if set(BODY_TYPE_BINDINGS) != code_types:
        errors.append(
            "body types without an HTTP binding: "
            f"{sorted(code_types ^ set(BODY_TYPE_BINDINGS))}"
        )
    if set(wb["headers"]) != set(STANDARD_HEADERS):
        errors.append(
            "headers differ between code and WIRE-BINDING 14: "
            f"{sorted(set(wb['headers']) ^ set(STANDARD_HEADERS))}"
        )
    code_events = {e.value for e in StreamingEventType}
    if set(wb["events"]) != code_events:
        errors.append(f"stream events differ: {sorted(set(wb['events']) ^ code_events)}")
    error_urns = {v for k, v in vars(ErrorType).items() if k.isupper()}
    if error_urns != set(ERRORS):
        errors.append(f"error URNs differ: {sorted(error_urns ^ set(ERRORS))}")
    if errors:
        raise SystemExit("generate_spec: " + "\n".join(errors))

    body_entries = []
    for name in sorted(code_types):
        meta = wb["body"][name]
        binding = BODY_TYPE_BINDINGS[name]
        path = body_schema_path(name)
        assert path in schemas
        body_entries.append({
            "name": name,
            "category": meta["category"],
            "description": meta["description"],
            "schema": f"../schemas/{path}",
            "schema_id": schema_id(path),
            "section": meta["section"],
            "since": BODY_TYPE_SINCE.get(name, DEFAULT_SINCE),
            "status": "stable",
            "semantics": binding.http_method,
            "response_mode": binding.response_mode.value,
            "expected_response": binding.expected_response,
            "valid_responses": wb["pairs"].get(name),
            "idempotent": meta["idempotent"],
            "streaming_capable": binding.streaming_capable,
            "requires_nonce": binding.requires_nonce,
        })

    header_entries = []
    for name in sorted(STANDARD_HEADERS, key=str.lower):
        meta = wb["headers"][name]
        header_entries.append({
            "name": name,
            "locations": ["envelope", "http"] if name in HTTP_ALSO else ["envelope"],
            "group": meta["group"],
            "direction": meta["direction"],
            "format": meta["format"],
            "description": meta["description"],
            "section": meta["section"],
            "since": HEADER_SINCE.get(name, DEFAULT_SINCE),
            "status": "stable",
        })
    for h in sorted(HTTP_HEADERS, key=lambda x: x["name"].lower()):
        header_entries.append({
            "name": h["name"],
            "locations": ["http"],
            "group": "HTTP binding",
            "direction": h["direction"],
            "format": h["format"],
            "description": h["description"],
            "section": h["section"],
            "since": None,
            "status": "stable",
        })

    error_entries = [
        {"type": urn, "status": status, "title": title, "section": section}
        for urn, (status, title, section) in sorted(ERRORS.items(), key=lambda kv: (kv[1][0], kv[0]))
    ]

    models = stream_event_models()
    event_entries = []
    for et in StreamingEventType:
        meta = wb["events"][et.value]
        path = stream_schema_path(et.value)
        event_entries.append({
            "name": et.value,
            "category": meta["category"],
            "description": meta["description"],
            "data_schema": f"../schemas/{path}" if et.value in models else None,
            "data_schema_id": schema_id(path) if et.value in models else None,
            "section": "8.4",
            "since": STREAM_EVENT_SINCE.get(et.value, DEFAULT_SINCE),
            "status": "stable",
        })

    third = load_third_party()
    std_names = (
        {e["name"] for e in body_entries}
        | {e["name"] for e in header_entries}
        | {e["name"] for e in event_entries}
    )
    clashes = [
        e.get("name") for s in ("body_types", "headers", "stream_events") for e in third[s]
        if e.get("name") in std_names
    ]
    if clashes:
        raise SystemExit(f"generate_spec: third-party names clash with AMP names: {clashes}")
    body_entries += [_registered(e) for e in third["body_types"]]
    header_entries += [{**_registered(e), "locations": e.get("locations", ["envelope"])}
                       for e in third["headers"]]
    error_entries += [_registered(e) for e in third["error_types"]]
    event_entries += [_registered(e) for e in third["stream_events"]]
    extension_entries = list(EXTENSIONS) + [_registered(e) for e in third["extension_uris"]]

    return {
        "body-types.json": _registry_doc(
            "body-types",
            "AMP body types (WIRE-BINDING section 16) and registered third-party body "
            "types. Receivers MUST accept unknown body types (section 5.1.4).",
            body_entries,
            reserved_namespaces=RESERVED_BODY_TYPE_NAMESPACES,
        ),
        "headers.json": _registry_doc(
            "headers",
            "AMP envelope headers (WIRE-BINDING section 14) and the HTTP header fields "
            "the binding uses. Receivers MUST ignore headers they do not understand.",
            header_entries,
        ),
        "errors.json": _registry_doc(
            "errors",
            "RFC 7807 problem `type` URNs (WIRE-BINDING section 7). Clients SHOULD match "
            "on the URN rather than the HTTP status.",
            error_entries,
            urn_prefix="urn:amp:error:",
        ),
        "extensions.json": _registry_doc(
            "extensions",
            "Extension URIs assigned by AMP and registered by third parties "
            "(docs/EXTENSIONS.md).",
            extension_entries,
        ),
        "stream-events.json": _registry_doc(
            "stream-events",
            "Server-Sent Event types on GET /agent/stream (WIRE-BINDING section 8.4). "
            "Receivers MUST ignore unknown event types.",
            event_entries,
        ),
    }


# ---------------------------------------------------------------------------
# OpenAPI 3.1
# ---------------------------------------------------------------------------


def _problem(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/ProblemDetails"}}},
    }


PROBLEM_RESPONSES = {
    "400": "Envelope or body validation failed, or recipient mismatch (urn:amp:error:invalid-message)",
    "401": "Credential missing (when required) or invalid, including any failed RFC 9421 signature",
    "403": "Sender binding, contact policy, Origin or authorization failure",
    "406": "Accept-Version is malformed or names no supported MAJOR (urn:amp:error:version-mismatch)",
    "408": "Handler did not finish within the timeout",
    "409": "Loop detected, nonce replay, or a duplicate message still in flight",
    "410": "Referenced session has expired",
    "413": "Body exceeds the receiver's maximum message size",
    "415": "Content-Type is present and not application/json (or +json)",
    "429": "Rate limited; Retry-After is REQUIRED",
    "500": "Internal error; detail does not expose internals",
    "501": "No handler for the body type, or capability not implemented",
    "503": "Temporarily unavailable or at capacity; Retry-After SHOULD be sent",
}


def build_openapi() -> dict[str, Any]:
    rl_headers = {
        "X-RateLimit-Limit": {"$ref": "#/components/headers/X-RateLimit-Limit"},
        "X-RateLimit-Remaining": {"$ref": "#/components/headers/X-RateLimit-Remaining"},
        "X-RateLimit-Reset": {"$ref": "#/components/headers/X-RateLimit-Reset"},
        "Protocol-Version": {"$ref": "#/components/headers/Protocol-Version"},
    }
    message_responses: dict[str, Any] = {
        "200": {
            "description": "Synchronous result (WIRE-BINDING 5.2.1)",
            "headers": rl_headers,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AgentMessageOrResult"}}},
        },
        "202": {
            "description": "Accepted for asynchronous processing (5.2.2)",
            "headers": rl_headers,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AgentMessageOrResult"}}},
        },
    }
    for code, desc in PROBLEM_RESPONSES.items():
        resp = _problem(desc)
        if code == "429":
            resp["headers"] = {"Retry-After": {"$ref": "#/components/headers/Retry-After"}, **rl_headers}
        elif code == "401":
            resp["headers"] = {"WWW-Authenticate": {"schema": {"type": "string"}}}
        else:
            resp["headers"] = {"Protocol-Version": {"$ref": "#/components/headers/Protocol-Version"}}
        message_responses[code] = resp

    auth_alternatives = [{}, {"rfc9421": []}, {"bearer": []}, {"did": []}, {"apiKey": []}, {"mtls": []}]

    paths: dict[str, Any] = {
        "/.well-known/agent.json": {
            "get": {
                "operationId": "getAgentJson",
                "summary": "Agent identity document",
                "tags": ["discovery"],
                "x-amp-level": 0,
                "x-amp-section": "4.1",
                "security": [{}],
                "responses": {
                    "200": {
                        "description": "agent.json",
                        "headers": {"Cache-Control": {"schema": {"type": "string"}}},
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AgentJson"}}},
                    },
                    "401": _problem("PRIVATE visibility and caller not authorised (4.1.6)"),
                    "404": _problem("HIDDEN visibility (4.1.6)"),
                },
            },
        },
        "/agent/health": {
            "get": {
                "operationId": "getHealth",
                "summary": "Health check",
                "tags": ["discovery"],
                "x-amp-level": 0,
                "x-amp-section": "4.2",
                "security": [{}],
                "responses": {
                    "200": {
                        "description": "Healthy",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HealthResponse"}}},
                    },
                    "503": {
                        "description": "Unhealthy or temporarily unavailable",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HealthResponse"}}},
                    },
                },
            },
        },
        "/.well-known/agent-keys.json": {
            "get": {
                "operationId": "getJwks",
                "summary": "JWKS for the agent's Ed25519 public keys",
                "tags": ["discovery"],
                "x-amp-level": 0,
                "x-amp-section": "4.3",
                "x-amp-optional": True,
                "security": [{}],
                "responses": {
                    "200": {
                        "description": "JSON Web Key Set (RFC 7517)",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Jwks"}}},
                    },
                },
            },
        },
        "/agent/message": {
            "post": {
                "operationId": "postMessage",
                "summary": "Deliver an AMP message (every body type)",
                "description": (
                    "Single message endpoint (WIRE-BINDING section 5). The security "
                    "pipeline order is normative in Appendix D. A request without "
                    "Content-Type is treated as application/json (3.2). Unknown body "
                    "types MUST NOT be rejected with 400 (5.1.4)."
                ),
                "tags": ["messaging"],
                "x-amp-level": 1,
                "x-amp-section": "5.1",
                "security": auth_alternatives,
                "parameters": [
                    {"$ref": "#/components/parameters/AcceptVersion"},
                    {"$ref": "#/components/parameters/SignatureInput"},
                    {"$ref": "#/components/parameters/Signature"},
                    {"$ref": "#/components/parameters/ContentDigest"},
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/AgentMessage"}},
                    },
                },
                "responses": message_responses,
            },
        },
        "/agent/stream": {
            "get": {
                "operationId": "getStream",
                "summary": "Server-Sent Events stream",
                "description": (
                    "Each event is `id:` / `event:` / `data:` lines; `data` is a JSON "
                    "object matching schemas/stream/event.json (WIRE-BINDING section 8)."
                ),
                "tags": ["streaming"],
                "x-amp-level": 3,
                "x-amp-section": "8.2",
                "security": auth_alternatives,
                "parameters": [
                    {"name": "session_id", "in": "query", "schema": {"type": "string"}},
                    {"name": "task_id", "in": "query", "schema": {"type": "string"}},
                    {"name": "channel_id", "in": "query", "schema": {"type": "string"}},
                    {"name": "last_seq", "in": "query", "schema": {"type": "integer", "minimum": 0}},
                    {"name": "Last-Event-ID", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {
                        "description": "text/event-stream of AMP stream events",
                        "content": {
                            "text/event-stream": {
                                "schema": {"type": "string"},
                                "x-amp-event-schema": "schemas/stream/event.json",
                            },
                        },
                    },
                    "401": _problem("Authentication required or invalid"),
                    "429": _problem("Stream limit exceeded (urn:amp:error:stream-limit-exceeded)"),
                    "501": _problem("Streaming not implemented"),
                },
            },
        },
    }

    # Higher-level endpoints from ampro.wire.endpoints, with generic payloads.
    covered = {(p, m) for p, item in paths.items() for m in item}
    for ep in ALL_ENDPOINTS:
        method = ep.method.value.lower()
        if (ep.path, method) in covered:
            continue
        op: dict[str, Any] = {
            "operationId": _op_id(method, ep.path),
            "summary": ep.description,
            "tags": [f"level-{ep.level.value}"],
            "x-amp-level": ep.level.value,
            "security": auth_alternatives[1:] if ep.auth_required else auth_alternatives,
            "responses": {
                "200": {"description": "Success", "content": {"application/json": {"schema": {"type": "object"}}}},
                "404": _problem("Unknown resource"),
                "501": _problem("Not implemented at this agent's level"),
            },
        }
        params = re.findall(r"{(\w+)}", ep.path)
        if params:
            op["parameters"] = [
                {"name": p, "in": "path", "required": True, "schema": {"type": "string"}} for p in params
            ]
        if method in ("post", "put", "patch"):
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object"}}}}
        paths.setdefault(ep.path, {})[method] = op

    return {
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "Agent Mesh Protocol (AMP) HTTP binding",
            "version": CURRENT_VERSION,
            "summary": "Machine-readable description of docs/WIRE-BINDING.md",
            "description": (
                "Generated by scripts/generate_spec.py. docs/WIRE-BINDING.md is "
                "normative; this document and spec/schemas/ are kept in sync with "
                "the reference implementation by CI. Supported protocol versions: "
                + ", ".join(SUPPORTED_VERSIONS) + "."
            ),
            "license": {"name": "Apache 2.0", "identifier": "Apache-2.0"},
        },
        "externalDocs": {
            "description": "WIRE-BINDING (normative)",
            "url": "https://github.com/CatlystAI/agent-mesh-protocol/blob/main/docs/WIRE-BINDING.md",
        },
        "servers": [{"url": "https://agent.example.com", "description": "Any AMP agent origin"}],
        "tags": [
            {"name": "discovery", "description": "Level 0 (MANDATORY)"},
            {"name": "messaging", "description": "Level 1"},
            {"name": "streaming", "description": "Level 3"},
        ],
        "paths": paths,
        "components": {
            "schemas": {
                "AgentMessage": {"$ref": "schemas/envelope.json"},
                "AgentMessageOrResult": {
                    "description": (
                        "An AgentMessage envelope (5.2), or a handler-defined JSON "
                        "object for agents that reply with a bare result."
                    ),
                    "anyOf": [{"$ref": "schemas/envelope.json"}, {"type": "object"}],
                },
                "AgentJson": {"$ref": "schemas/agent-json.json"},
                "HealthResponse": {"$ref": "schemas/health-response.json"},
                "ProblemDetails": {"$ref": "schemas/problem-details.json"},
                "StreamEvent": {"$ref": "schemas/stream/event.json"},
                "Jwks": {
                    "type": "object",
                    "required": ["keys"],
                    "properties": {"keys": {"type": "array", "items": {"type": "object"}}},
                },
            },
            "parameters": {
                "AcceptVersion": {
                    "name": "Accept-Version", "in": "header",
                    "description": "Comma-separated preferred protocol versions (18.4)",
                    "schema": {"type": "string"},
                },
                "Signature": {
                    "name": "Signature", "in": "header",
                    "description": "RFC 9421 signature (12.15)", "schema": {"type": "string"},
                },
                "SignatureInput": {
                    "name": "Signature-Input", "in": "header",
                    "description": "RFC 9421 Signature-Input (12.15)", "schema": {"type": "string"},
                },
                "ContentDigest": {
                    "name": "Content-Digest", "in": "header",
                    "description": "RFC 9530 sha-256 digest of the body (12.15.2)",
                    "schema": {"type": "string"},
                },
            },
            "headers": {
                "Protocol-Version": {
                    "description": "Negotiated protocol version (18.4); MUST be sent on /agent/message responses",
                    "schema": {"type": "string"},
                },
                "Retry-After": {"description": "Seconds to wait", "schema": {"type": "integer"}},
                "X-RateLimit-Limit": {"schema": {"type": "integer"}},
                "X-RateLimit-Remaining": {"schema": {"type": "integer"}},
                "X-RateLimit-Reset": {"description": "Unix time", "schema": {"type": "integer"}},
            },
            "securitySchemes": {
                "rfc9421": {
                    "type": "apiKey", "in": "header", "name": "Signature",
                    "description": (
                        "RFC 9421 HTTP Message Signatures with Ed25519, profiled in "
                        "WIRE-BINDING 12.15 (Signature, Signature-Input and Content-Digest "
                        "headers; created, keyid, alg=\"ed25519\" and nonce REQUIRED)."
                    ),
                    "x-amp-scheme": "rfc9421",
                },
                "bearer": {
                    "type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                    "description": "Bearer JWT verified against the issuer's JWKS (12.1.1)",
                },
                "did": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "description": "`Authorization: DID <compact JWS>` signed by a did:key (12.1.2)",
                    "x-amp-scheme": "did",
                },
                "apiKey": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "description": "`Authorization: ApiKey <key>` (12.1.3)",
                    "x-amp-scheme": "apikey",
                },
                "mtls": {"type": "mutualTLS", "description": "Client certificate verified by the transport (12.1.4)"},
            },
        },
    }


def _op_id(method: str, path: str) -> str:
    parts = [p for p in re.split(r"[/{}.\-]", path) if p and p != "agent"]
    return method + "".join(p[:1].upper() + p[1:] for p in parts)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_ ./()-]*$")
_YAML_WORDS = {"true", "false", "null", "yes", "no", "on", "off", "~", "y", "n"}


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    s = str(value)
    if _PLAIN.match(s) and s.lower() not in _YAML_WORDS and not s.endswith(" ") and ": " not in s:
        return s
    return json.dumps(s, ensure_ascii=False)


def to_yaml(value: Any, indent: int = 0) -> str:
    """Deterministic block-style YAML for JSON-compatible data."""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        if not value:
            return pad + "{}\n"
        for k, v in value.items():
            key = _scalar(k)
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{key}:\n{to_yaml(v, indent + 1)}")
            elif isinstance(v, dict):
                lines.append(f"{pad}{key}: {{}}\n")
            elif isinstance(v, list):
                lines.append(f"{pad}{key}: []\n")
            else:
                lines.append(f"{pad}{key}: {_scalar(v)}\n")
        return "".join(lines)
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item:
                body = to_yaml(item, indent + 1)
                lines.append(f"{pad}- {body[len(pad) + 2:]}")
            elif isinstance(item, list) and item:
                lines.append(f"{pad}-\n{to_yaml(item, indent + 1)}")
            elif isinstance(item, dict):
                lines.append(f"{pad}- {{}}\n")
            elif isinstance(item, list):
                lines.append(f"{pad}- []\n")
            else:
                lines.append(f"{pad}- {_scalar(item)}\n")
        return "".join(lines)
    return pad + _scalar(value) + "\n"


def _json(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def build_all() -> dict[str, str]:
    """Every generated file, keyed by path relative to ``spec/``."""
    schemas = build_schemas()
    wb = parse_wire_binding()
    files: dict[str, str] = {}
    for path, doc in schemas.items():
        files[f"schemas/{path}"] = _json(doc)
    for path, doc in build_registries(wb, schemas).items():
        files[f"registry/{path}"] = _json(doc)
    files["openapi.yaml"] = (
        "# Generated by scripts/generate_spec.py -- do not edit by hand.\n"
        + to_yaml(build_openapi())
    )
    return files


def _existing(spec_dir: Path) -> set[str]:
    out = set()
    for sub in ("schemas", "registry"):
        base = spec_dir / sub
        if base.exists():
            out |= {p.relative_to(spec_dir).as_posix() for p in base.rglob("*.json")}
    if (spec_dir / "openapi.yaml").exists():
        out.add("openapi.yaml")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if spec/ is out of date")
    parser.add_argument("--spec-dir", type=Path, default=SPEC_DIR)
    args = parser.parse_args(argv)

    files = build_all()
    stale = sorted(_existing(args.spec_dir) - set(files))
    changed = sorted(
        p for p, content in files.items()
        if not (args.spec_dir / p).exists()
        or (args.spec_dir / p).read_text(encoding="utf-8") != content
    )

    if args.check:
        if changed or stale:
            for p in changed:
                print(f"out of date: spec/{p}")
            for p in stale:
                print(f"no longer generated: spec/{p}")
            print("Run: python scripts/generate_spec.py")
            return 1
        print(f"spec/ is up to date ({len(files)} files)")
        return 0

    for p in stale:
        (args.spec_dir / p).unlink()
    for p in changed:
        target = args.spec_dir / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(files[p], encoding="utf-8")
    print(f"wrote {len(changed)} file(s), removed {len(stale)}; {len(files)} total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
