"""Regenerate the cryptographic AMP conformance vectors.

Run from the repository root::

    python tests/vectors/_generate.py          # rewrite vectors in place
    python tests/vectors/_generate.py --check  # exit 1 if anything would change

Every value is deterministic: Ed25519 signatures (RFC 8032) are
deterministic, the X25519 / AES keys are fixed, and all timestamps,
nonces and ids are literals below. Re-running the script on an unchanged
codebase is a no-op; a diff after a code change means the wire format
changed.

What the script does:

* Fully writes ``rfc9421.json``, ``session_binding.json`` and
  ``delegation_chain.json`` from the case specs in this file.
* Walks every other ``*.json`` vector and, for each case carrying a
  ``"sign"`` directive (``{"kind": ..., "key": ...}``), recomputes the
  canonical bytes (``expected_canonical``) and the signature fields
  in place. Kinds: ``key_revocation``, ``cost_receipt``,
  ``federation_trust_proof``, ``federation_revoke``, ``a256gcm``. A
  case's optional ``"tamper"`` object is applied to the body AFTER
  signing (negative cases).
* Writes the shared test-key table into the top-level ``"keys"`` object
  of every file that uses a key.

All signing goes through ampro's own canonicalisation helpers, so the
vectors pin what the reference implementation actually puts on the wire.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from ampro.delegation.chain import (  # noqa: E402
    DelegationLink,
    _canonical_link_bytes,
)
from ampro.delegation.cost_receipt import CostReceipt  # noqa: E402
from ampro.delegation.v2 import (  # noqa: E402
    DelegationLinkV2,
    canonical_link_v2_bytes,
)
from ampro.registry.federation import (  # noqa: E402
    federation_revoke_payload,
    federation_trust_proof_payload,
)
from ampro.security.rfc9421 import (  # noqa: E402
    _content_digest_sha256,
    create_signature_base,
)
from ampro.session.binding import (  # noqa: E402
    _b64url_encode,
    _confirm_transcript,
    _message_binding_input,
    canonical_body_digest,
    compute_binding_proof,
    create_message_binding,
    derive_session_binding_key,
)

# ---------------------------------------------------------------------------
# Fixed test keys. NEVER use these outside test vectors.
# ---------------------------------------------------------------------------

_X25519_SERVER_LABEL = "ampro test vector x25519 server"
_AES_LABEL = "ampro test vector a256gcm key"

_ED25519_SEEDS = {
    "ed25519-a": (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "RFC 8032 section 7.1 TEST 1 secret key",
    ),
    "ed25519-b": (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "RFC 8032 section 7.1 TEST 2 secret key",
    ),
    "ed25519-c": (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "RFC 8032 section 7.1 TEST 3 secret key",
    ),
}

_X25519_PRIVATE = {
    "x25519-client": (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "RFC 7748 section 6.1 Alice's private key",
    ),
    "x25519-server": (
        hashlib.sha256(_X25519_SERVER_LABEL.encode()).hexdigest(),
        f'SHA-256("{_X25519_SERVER_LABEL}")',
    ),
}

_AES_KEYS = {
    "a256gcm": (
        hashlib.sha256(_AES_LABEL.encode()).hexdigest(),
        f'SHA-256("{_AES_LABEL}")',
    ),
}


def _key_table() -> dict[str, dict[str, str]]:
    table: dict[str, dict[str, str]] = {}
    for name, (seed, source) in _ED25519_SEEDS.items():
        pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key()
        table[name] = {
            "type": "Ed25519",
            "private_seed_hex": seed,
            "public_hex": pub.public_bytes_raw().hex(),
            "source": source,
        }
    for name, (priv, source) in _X25519_PRIVATE.items():
        pub = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv)).public_key()
        raw = pub.public_bytes_raw()
        table[name] = {
            "type": "X25519",
            "private_hex": priv,
            "public_hex": raw.hex(),
            "public_b64url": _b64url_encode(raw),
            "source": source,
        }
    for name, (key, source) in _AES_KEYS.items():
        table[name] = {"type": "AES-256", "key_hex": key, "source": source}
    return table


KEYS = _key_table()


def ed_sign(key: str, data: bytes) -> bytes:
    seed = bytes.fromhex(KEYS[key]["private_seed_hex"])
    return Ed25519PrivateKey.from_private_bytes(seed).sign(data)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _used_keys(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("key", "verify_key", "client_key", "server_key") and isinstance(v, str) and v in KEYS:
                found.add(v)
            elif k in ("keys_by_agent",) and isinstance(v, dict):
                found.update(x for x in v.values() if x in KEYS)
            else:
                found |= _used_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            found |= _used_keys(item)
    return found


def _attach_keys(doc: dict) -> dict:
    used = _used_keys({k: v for k, v in doc.items() if k != "keys"})
    if not used:
        doc.pop("keys", None)
        return doc
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if k == "keys":
            continue
        out[k] = v
        if k == "description":
            out["keys"] = {name: KEYS[name] for name in sorted(used)}
    if "keys" not in out:
        out["keys"] = {name: KEYS[name] for name in sorted(used)}
    return out


# ---------------------------------------------------------------------------
# RFC 9421 HTTP message signatures
# ---------------------------------------------------------------------------

_CREATED = 1775743200  # 2026-04-09T14:00:00Z

_RFC9421_CASES: list[dict[str, Any]] = [
    {
        "name": "post-json-body",
        "description": "POST with JSON body: content-digest and content-type covered, nonce present",
        "method": "POST",
        "url": "https://bakery.example.com/agent/message",
        "headers": {"Content-Type": "application/json"},
        "body": '{"sender":"agent://alice.example.com","recipient":"agent://bakery.example.com","body_type":"message","body":{"text":"hi"}}',
        "covered": ["@method", "@target-uri", "@authority", "content-digest", "content-type"],
        "nonce": "n-7f3c1a9e5b2d4c60",
        "verify": {"at": _CREATED + 10, "expect": True},
    },
    {
        "name": "get-no-body",
        "description": "GET without a body: only the derived components are covered",
        "method": "GET",
        "url": "https://bakery.example.com/agent/tasks/t-42?view=full",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-0b6e2d9a71c84f35",
        "verify": {"at": _CREATED, "expect": True},
    },
    {
        "name": "authority-non-default-port",
        "description": "@authority keeps a non-default port and lowercases the host",
        "method": "POST",
        "url": "https://API.Example.com:8443/agent/message",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":"port"}',
        "covered": ["@method", "@target-uri", "@authority", "content-digest", "content-type"],
        "nonce": "n-port-8443-000001",
        "expected_authority": "api.example.com:8443",
        "verify": {"at": _CREATED, "expect": True},
    },
    {
        "name": "authority-default-port-dropped",
        "description": "@authority omits the scheme's default port and strips userinfo",
        "method": "GET",
        "url": "https://user@bakery.example.com:443/agent.json",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-port-443-000002",
        "expected_authority": "bakery.example.com",
        "verify": {"at": _CREATED, "expect": True},
    },
    {
        "name": "freshness-boundary",
        "description": "created exactly 300 s before verification is still fresh",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-fresh-boundary-01",
        "verify": {"at": _CREATED + 300, "expect": True},
    },
    {
        "name": "stale-signature",
        "description": "created more than 300 s before verification is rejected",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-stale-000000001",
        "verify": {"at": _CREATED + 301, "expect": False, "reason": "created outside the 300 s window"},
    },
    {
        "name": "future-signature",
        "description": "created more than 300 s in the future is rejected",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-future-00000001",
        "verify": {"at": _CREATED - 301, "expect": False, "reason": "created outside the 300 s window"},
    },
    {
        "name": "missing-nonce",
        "description": "a signature without a nonce parameter is rejected",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": None,
        "verify": {"at": _CREATED, "expect": False, "reason": "nonce is REQUIRED"},
    },
    {
        "name": "body-tampered",
        "description": "the verifier receives a different body than the one digested",
        "method": "POST",
        "url": "https://bakery.example.com/agent/message",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":"pay 10"}',
        "covered": ["@method", "@target-uri", "@authority", "content-digest", "content-type"],
        "nonce": "n-tamper-00000001",
        "verify": {
            "at": _CREATED,
            "expect": False,
            "body": '{"text":"pay 99"}',
            "reason": "content-digest does not match the body",
        },
    },
    {
        "name": "body-not-digest-covered",
        "description": "a request with a body whose signature does not cover content-digest is rejected",
        "method": "POST",
        "url": "https://bakery.example.com/agent/message",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":"unbound"}',
        "covered": ["@method", "@target-uri", "@authority", "content-type"],
        "nonce": "n-nodigest-000001",
        "verify": {"at": _CREATED, "expect": False, "reason": "content-digest MUST be covered when a body is present"},
    },
    {
        "name": "unsupported-alg",
        "description": "Signature-Input declaring an algorithm other than ed25519 is rejected",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-alg-00000000001",
        "signature_input_alg": "rsa-v1_5-sha256",
        "verify": {"at": _CREATED, "expect": False, "reason": "alg allow-list is {ed25519}"},
    },
    {
        "name": "covered-header-stripped",
        "description": "a covered header removed in transit fails verification (absent is not empty)",
        "method": "POST",
        "url": "https://bakery.example.com/agent/message",
        "headers": {"Content-Type": "application/json", "X-Amp-Tenant": "t-01"},
        "body": '{"text":"tenant"}',
        "covered": ["@method", "@target-uri", "@authority", "content-digest", "content-type", "x-amp-tenant"],
        "nonce": "n-strip-000000001",
        "verify": {
            "at": _CREATED,
            "expect": False,
            "strip_headers": ["X-Amp-Tenant"],
            "reason": "covered component absent",
        },
    },
    {
        "name": "method-changed",
        "description": "replaying the signature with a different method fails",
        "method": "POST",
        "url": "https://bakery.example.com/agent/message",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":"m"}',
        "covered": ["@method", "@target-uri", "@authority", "content-digest", "content-type"],
        "nonce": "n-method-00000001",
        "verify": {"at": _CREATED, "expect": False, "method": "PUT", "reason": "@method mismatch"},
    },
    {
        "name": "wrong-key",
        "description": "verifying under a different public key fails",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-wrongkey-000001",
        "verify": {"at": _CREATED, "expect": False, "verify_key": "ed25519-b", "reason": "signature invalid"},
    },
    {
        "name": "derived-components-not-covered",
        "description": (
            "a signature whose covered set omits @method, @target-uri and @authority "
            "MUST be rejected (it would verify for any method and URL)"
        ),
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": [],
        "nonce": "n-nocover-0000001",
        "verify": {
            "at": _CREATED,
            "expect": False,
            "method": "DELETE",
            "reason": "required covered components missing",
        },
    },
    {
        "name": "nonce-replay",
        "description": "the same (keyid, nonce) is accepted once; the second verification is a replay",
        "method": "GET",
        "url": "https://bakery.example.com/agent/health",
        "headers": {},
        "body": None,
        "covered": ["@method", "@target-uri", "@authority"],
        "nonce": "n-replay-00000001",
        "verify": {"at": _CREATED, "expect": [True, False], "reason": "nonce replay (scoped per keyid)"},
    },
]


def build_rfc9421() -> dict:
    cases = []
    for spec in _RFC9421_CASES:
        spec = copy.deepcopy(spec)
        key = spec.pop("key", "ed25519-a")
        keyid = spec.pop("keyid", "agent://alice.example.com#key-1")
        alg = spec.pop("signature_input_alg", "ed25519")
        headers = dict(spec["headers"])
        body = spec["body"]
        if body is not None:
            headers["content-digest"] = _content_digest_sha256(body.encode("utf-8"))
        base = create_signature_base(
            spec["method"],
            spec["url"],
            headers,
            spec["covered"],
            created=_CREATED,
            keyid=keyid,
            nonce=spec["nonce"],
        )
        sig = ed_sign(key, base.encode("utf-8"))
        comp_list = " ".join(f'"{c}"' for c in spec["covered"])
        sig_input = f'sig1=({comp_list});created={_CREATED};keyid="{keyid}";alg="{alg}"'
        if spec["nonce"] is not None:
            sig_input += f';nonce="{spec["nonce"]}"'
        case = {
            "name": spec["name"],
            "description": spec["description"],
            "key": key,
            "keyid": keyid,
            "method": spec["method"],
            "url": spec["url"],
            "headers": headers,
            "body": body,
            "created": _CREATED,
            "nonce": spec["nonce"],
            "covered": spec["covered"],
            "expected": {
                "content_digest": headers.get("content-digest"),
                "signature_base": base,
                "signature_input": sig_input,
                "signature": f"sig1=:{b64(sig)}:",
            },
            "verify": spec["verify"],
        }
        if "expected_authority" in spec:
            case["expected"]["authority"] = spec["expected_authority"]
        cases.append(case)
    return {
        "description": (
            "RFC 9421 HTTP Message Signatures profile (WIRE-BINDING section 12.15). "
            "Each case pins the content-digest (RFC 9530), the signature base, "
            "Signature-Input and the deterministic Ed25519 signature, then states "
            "whether a verifier running at verify.at (unix seconds) with a fresh "
            "replay cache MUST accept it. 'expect' as a list means: verify that "
            "many times in a row with the same replay cache."
        ),
        "profile": {
            "algorithm": "ed25519",
            "max_age_seconds": 300,
            "required_params": ["created", "keyid", "nonce"],
            "signature_label": "sig1",
        },
        "vectors": cases,
    }


# ---------------------------------------------------------------------------
# Session binding (X25519 + HKDF-SHA256 + HMAC-SHA256)
# ---------------------------------------------------------------------------

_SESSION_CASES = [
    {
        "name": "basic",
        "session_id": "sess-a1b2c3d4",
        "client_nonce": hashlib.sha256(b"ampro vector client_nonce 1").hexdigest(),
        "server_nonce": hashlib.sha256(b"ampro vector server_nonce 1").hexdigest(),
        "confirm_nonce": hashlib.sha256(b"ampro vector confirm_nonce 1").hexdigest()[:32],
        "messages": [
            {"message_id": "msg-0001", "body": {"text": "hello"}},
            {"message_id": "msg-0002", "body": {"description": "Bake 12 croissants", "priority": "high"}},
            {"message_id": "msg-0003", "body": None},
            {"message_id": "msg-0004", "body": {"text": "café ☕", "n": [1, 2, 3]}},
        ],
    },
]


def _x_priv(name: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["private_hex"]))


def build_session_binding() -> dict:
    cases = []
    for spec in _SESSION_CASES:
        client_pub = KEYS["x25519-client"]["public_b64url"]
        server_pub = KEYS["x25519-server"]["public_b64url"]
        params = {
            "session_id": spec["session_id"],
            "client_nonce": spec["client_nonce"],
            "server_nonce": spec["server_nonce"],
            "client_public_key": client_pub,
            "server_public_key": server_pub,
        }
        key_c = derive_session_binding_key(_x_priv("x25519-client"), server_pub, **params)
        key_s = derive_session_binding_key(_x_priv("x25519-server"), client_pub, **params)
        assert key_c == key_s
        shared = _x_priv("x25519-client").exchange(
            _x_priv("x25519-server").public_key()
        )
        transcript = _confirm_transcript(confirm_nonce=spec["confirm_nonce"], **params)
        proof = compute_binding_proof(key_c, confirm_nonce=spec["confirm_nonce"], **params)
        messages = []
        for m in spec["messages"]:
            canonical = json.dumps(
                m["body"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            messages.append(
                {
                    "message_id": m["message_id"],
                    "body": m["body"],
                    "body_canonical_json": canonical,
                    "body_sha256_hex": canonical_body_digest(m["body"]),
                    "hmac_input": _message_binding_input(
                        spec["session_id"], m["message_id"], m["body"]
                    ).decode("utf-8"),
                    "session_binding": create_message_binding(
                        spec["session_id"], m["message_id"], key_c, body=m["body"]
                    ),
                }
            )
        cases.append(
            {
                "name": spec["name"],
                "client_key": "x25519-client",
                "server_key": "x25519-server",
                "session_id": spec["session_id"],
                "client_nonce": spec["client_nonce"],
                "server_nonce": spec["server_nonce"],
                "confirm_nonce": spec["confirm_nonce"],
                "session_init": {
                    "proposed_capabilities": ["messaging", "tools"],
                    "proposed_version": "1.0.0",
                    "client_nonce": spec["client_nonce"],
                    "client_ephemeral_key": client_pub,
                },
                "session_established": {
                    "session_id": spec["session_id"],
                    "negotiated_capabilities": ["messaging", "tools"],
                    "negotiated_version": "1.0.0",
                    "trust_tier": "verified",
                    "trust_score": 650,
                    "session_ttl_seconds": 3600,
                    "server_nonce": spec["server_nonce"],
                    "server_ephemeral_key": server_pub,
                    "confirm_nonce": spec["confirm_nonce"],
                    "resumed": False,
                },
                "session_confirm": {
                    "session_id": spec["session_id"],
                    "binding_proof": proof,
                    "confirm_nonce": spec["confirm_nonce"],
                },
                "expected": {
                    "x25519_shared_secret_hex": shared.hex(),
                    "hkdf_salt": spec["client_nonce"] + "\u0000" + spec["server_nonce"],
                    "hkdf_info": "\u0000".join(
                        ("ampro-session-binding-v1", spec["session_id"], client_pub, server_pub)
                    ),
                    "binding_key_hex": key_c,
                    "confirm_transcript": transcript.decode("utf-8"),
                    "binding_proof": proof,
                },
                "messages": messages,
            }
        )
    return {
        "description": (
            "Session binding key agreement (WIRE-BINDING sections 9.2-9.3). "
            "key = HKDF-SHA256(ikm = X25519(priv, peer_pub), salt = client_nonce || 0x00 || "
            "server_nonce, info = 'ampro-session-binding-v1' || 0x00 || session_id || 0x00 || "
            "client_pub || 0x00 || server_pub, L = 32), lowercase hex. binding_proof = "
            "HMAC-SHA256(key = UTF-8 bytes of the hex key, msg = confirm_transcript). "
            "Session-Binding = HMAC-SHA256(same key, session_id || 0x00 || message_id || 0x00 || "
            "hex(SHA-256(canonical JSON body))). Public keys are raw 32-byte X25519 keys, "
            "base64url without padding, and enter HKDF/HMAC inputs in that encoded form. "
            "All strings are UTF-8; 0x00 is a single NUL byte."
        ),
        "vectors": cases,
        "negative_vectors": [
            {
                "name": "low-order-peer-key",
                "description": "an all-zero X25519 public key yields an all-zero shared secret and MUST be rejected",
                "peer_public_b64url": b64url_nopad(bytes(32)),
                "expect_error": True,
            },
            {
                "name": "short-peer-key",
                "description": "a peer key that is not 32 bytes MUST be rejected",
                "peer_public_b64url": b64url_nopad(bytes(31)),
                "expect_error": True,
            },
            {
                "name": "established-without-server-key",
                "description": "clients MUST refuse session.established without server_ephemeral_key",
                "drop_field": "server_ephemeral_key",
                "expect_error": True,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Delegation chains
# ---------------------------------------------------------------------------

_AGENT_KEYS = {
    "agent://owner.example.com": "ed25519-a",
    "agent://manager.example.com": "ed25519-b",
    "agent://worker.example.com": "ed25519-c",
}


def _link(delegator: str, delegate: str, scopes: list[str], **kw: Any) -> dict:
    link = {
        "delegator": delegator,
        "delegate": delegate,
        "scopes": scopes,
        "max_depth": kw.pop("max_depth", 3),
        "created_at": kw.pop("created_at", "2026-01-01T00:00:00Z"),
        "expires_at": kw.pop("expires_at", "2099-01-01T00:00:00Z"),
        "max_fan_out": kw.pop("max_fan_out", 3),
        "trust_tier": kw.pop("trust_tier", "verified"),
        "jwks_url": kw.pop("jwks_url", ""),
        "chain_budget": kw.pop("chain_budget", ""),
    }
    assert not kw, kw
    return link


_O, _M, _W = (
    "agent://owner.example.com",
    "agent://manager.example.com",
    "agent://worker.example.com",
)

_DELEGATION_CASES: list[dict[str, Any]] = [
    {
        "description": "Valid single-hop delegation",
        "links": [_link(_O, _M, ["task:create"], max_depth=1)],
        "valid": True,
    },
    {
        "description": "Valid two-hop delegation; scopes narrow, max_depth decreases, budget non-increasing",
        "links": [
            _link(_O, _M, ["task:*", "data:read"], max_depth=3,
                  chain_budget="remaining=5.00USD;max=5.00USD",
                  jwks_url="https://owner.example.com/.well-known/jwks.json"),
            _link(_M, _W, ["task:create"], max_depth=2,
                  created_at="2026-01-01T00:01:00Z", expires_at="2098-12-31T00:00:00Z",
                  chain_budget="remaining=3.50USD;max=5.00USD"),
        ],
        "valid": True,
    },
    {
        "description": "Timestamps with a non-UTC offset are signed in canonical UTC 'Z' form",
        "links": [_link(_O, _M, ["task:create"], created_at="2026-01-01T05:30:00+05:30",
                        expires_at="2099-01-01T00:00:00.250000+00:00")],
        "valid": True,
    },
    {
        "description": "Invalid: scope widening at hop 2",
        "links": [
            _link(_O, _M, ["task:create"]),
            _link(_M, _W, ["task:create", "task:assign"], max_depth=2),
        ],
        "valid": False,
        "error_contains": "not subset of parent",
    },
    {
        "description": "Invalid: child max_depth not below parent's",
        "links": [
            _link(_O, _M, ["task:*"], max_depth=3),
            _link(_M, _W, ["task:create"], max_depth=3),
        ],
        "valid": False,
        "error_contains": "must be <= parent max_depth - 1",
    },
    {
        "description": "Invalid: chain longer than root max_depth",
        "links": [
            _link(_O, _M, ["task:*"], max_depth=1),
            _link(_M, _W, ["task:create"], max_depth=0),
        ],
        "valid": False,
        "error_contains": "exceeds root max_depth",
    },
    {
        "description": "Invalid: a signed field (trust_tier) altered after signing",
        "links": [_link(_O, _M, ["task:create"], trust_tier="verified")],
        "tamper": {"link": 0, "field": "trust_tier", "value": "owner"},
        "valid": False,
        "error_contains": "invalid signature",
    },
    {
        "description": "Invalid: link signed for another chain position (parent_delegate binding)",
        "links": [
            _link(_O, _M, ["task:*"]),
            _link(_M, _W, ["task:create"], max_depth=2),
        ],
        "sign_parent_override": {"1": "agent://elsewhere.example.com"},
        "valid": False,
        "error_contains": "link 1: invalid signature",
    },
    {
        "description": "Invalid: child budget remaining exceeds parent's",
        "links": [
            _link(_O, _M, ["task:*"], chain_budget="remaining=2.00USD;max=5.00USD"),
            _link(_M, _W, ["task:create"], max_depth=2, chain_budget="remaining=3.00USD;max=5.00USD"),
        ],
        "valid": False,
        "error_contains": "exceeds parent budget",
    },
    {
        "description": "Invalid: child drops the parent's budget",
        "links": [
            _link(_O, _M, ["task:*"], chain_budget="remaining=2.00USD;max=5.00USD"),
            _link(_M, _W, ["task:create"], max_depth=2),
        ],
        "valid": False,
        "error_contains": "chain_budget dropped",
    },
    {
        "description": "Invalid: budget string not in the exact 'remaining=<n>USD;max=<n>USD' form",
        "links": [_link(_O, _M, ["task:*"], chain_budget="remaining=2USD;max=5USD;x=1")],
        "valid": False,
        "error_contains": "invalid chain_budget",
    },
    {
        "description": "Invalid: remaining exceeds max",
        "links": [_link(_O, _M, ["task:*"], chain_budget="remaining=6.00USD;max=5.00USD")],
        "valid": False,
        "error_contains": "exceeds max",
    },
    {
        "description": "Invalid: fan-out exhausted on the parent link (stateful check)",
        "links": [
            _link(_O, _M, ["task:*"], max_fan_out=2),
            _link(_M, _W, ["task:create"], max_depth=2),
        ],
        "fan_out_counts": {"0": 2},
        "valid": False,
        "error_contains": "max_fan_out 2 exhausted",
    },
    {
        "description": "Valid: fan-out below the limit",
        "links": [
            _link(_O, _M, ["task:*"], max_fan_out=2),
            _link(_M, _W, ["task:create"], max_depth=2),
        ],
        "fan_out_counts": {"0": 1},
        "valid": True,
    },
    {
        "description": "Invalid: expired link",
        "links": [_link(_O, _M, ["task:create"], expires_at="2026-02-01T00:00:00Z")],
        "valid": False,
        "error_contains": "expired",
    },
    {
        "description": "Invalid: chain discontinuity (delegator != previous delegate)",
        "links": [
            _link(_O, _M, ["task:*"]),
            _link(_O, _W, ["task:create"], max_depth=2),
        ],
        "valid": False,
        "error_contains": "previous delegate",
    },
    {
        "description": "Invalid: naive timestamp (no offset) is rejected at parse time",
        "links": [_link(_O, _M, ["task:create"], created_at="2026-01-01T00:00:00")],
        "unsigned": True,
        "valid": False,
        "error_contains": "timezone-aware",
    },
]


def build_delegation() -> dict:
    cases = []
    for spec in _DELEGATION_CASES:
        spec = copy.deepcopy(spec)
        links = spec["links"]
        signed: list[str | None] = []
        if not spec.get("unsigned"):
            overrides = spec.get("sign_parent_override", {})
            for i, link in enumerate(links):
                parent = links[i - 1]["delegate"] if i else None
                parent = overrides.get(str(i), parent)
                model = DelegationLink.model_validate(link)
                payload = _canonical_link_bytes(model, parent_delegate=parent)
                link["signature"] = b64(ed_sign(_AGENT_KEYS[link["delegator"]], payload))
                signed.append(payload.decode("utf-8"))
        else:
            for link in links:
                link["signature"] = ""
        tamper = spec.pop("tamper", None)
        if tamper:
            links[tamper["link"]][tamper["field"]] = tamper["value"]
        case = {
            "description": spec["description"],
            "links": links,
            "valid": spec["valid"],
        }
        if signed:
            case["signed_canonical"] = signed
        if tamper or spec.get("sign_parent_override"):
            case["canonical_matches_signed"] = False
        if "fan_out_counts" in spec:
            case["fan_out_counts"] = spec["fan_out_counts"]
        if "error_contains" in spec:
            case["error_contains"] = spec["error_contains"]
        cases.append(case)
    return {
        "description": (
            "Delegation chain validation (WIRE-BINDING section 11.11.1). Each link is "
            "signed by its delegator over canonical JSON (sorted keys, ',' ':' separators, "
            "UTF-8, no ASCII escaping) of every DelegationLink field except 'signature', with "
            "'scopes' sorted, timestamps rendered as RFC 3339 UTC with 'Z' (fraction only when "
            "non-zero, 6 digits), plus 'parent_delegate' (the previous link's delegate, null for "
            "the root). signed_canonical[i] is the exact byte string signed for link i. "
            "fan_out_counts maps a link index to the number of sub-delegations already issued "
            "under that link (keyed by delegation_link_id in the reference implementation). "
            "Links expire in 2099; the 'expired' case expired in 2026."
        ),
        "keys_by_agent": _AGENT_KEYS,
        "vectors": cases,
    }


# ---------------------------------------------------------------------------
# Delegation chains, format v2
# ---------------------------------------------------------------------------

_V2_NOW = "2026-01-01T00:30:00Z"
_V2_PRINCIPAL = {"iss": "https://id.example.com", "sub": "pairwise-7f3c", "acr": "phr",
                 "present": True}
_V2_INTENT = "sha-256:" + b64url_nopad(hashlib.sha256(
    b'{"currency":"USD","merchant":"agent://shop.example.com","total_minor":4200}').digest())
_V2_REFS = [{"type": "oauth-grant", "ref": "grant_8Hq2", "expires_at": "2026-01-01T02:00:00Z"}]


def _link_v2(n: int, delegator: str, delegate: str, scopes: list[str], **kw: Any) -> dict:
    link: dict[str, Any] = {
        "v": 2,
        "link_id": f"vector-link-{n:02d}-0123456789abcdef",
        "delegator": delegator,
        "delegate": delegate,
        "scopes": scopes,
        "max_depth": kw.pop("max_depth", 3),
        "created_at": kw.pop("created_at", "2026-01-01T00:00:00Z"),
        "expires_at": kw.pop("expires_at", "2026-01-01T01:00:00Z"),
        "alg": "EdDSA",
        "kid": "k1",
    }
    link.update(kw)
    return link


def _v2_root(**kw: Any) -> dict:
    base = dict(
        aud=["agent://shop.example.com"], principal=_V2_PRINCIPAL, origin="oauth",
        intent_hash=_V2_INTENT, credential_refs=_V2_REFS,
        constraints=[{"type": "amount", "currency": "USD", "max_minor": 5000}],
    )
    base.update(kw)
    return _link_v2(1, _O, _M, ["orders:*"], **base)


def _v2_child(**kw: Any) -> dict:
    base = dict(
        max_depth=2, created_at="2026-01-01T00:01:00Z",
        aud=["agent://shop.example.com"], principal=_V2_PRINCIPAL, origin="oauth",
        intent_hash=_V2_INTENT, credential_refs=_V2_REFS,
        constraints=[{"type": "amount", "currency": "USD", "max_minor": 4200}],
    )
    base.update(kw)
    return _link_v2(2, _M, _W, ["orders:pay"], **base)


_DELEGATION_V2_CASES: list[dict[str, Any]] = [
    {
        "description": "Valid single hop: principal, audience, amount cap, credential reference",
        "links": [_v2_root()],
        "valid": True,
    },
    {
        "description": "Valid two hops: scopes and amount cap narrow; root-bound members repeat",
        "links": [_v2_root(), _v2_child()],
        "valid": True,
    },
    {
        "description": "Valid: understood critical extension member is signed and accepted",
        "links": [_v2_root(**{"com.example.region": "eu", "crit": ["com.example.region"]})],
        "understood_extensions": ["com.example.region"],
        "valid": True,
    },
    {
        "description": "Invalid: critical extension the verifier does not understand",
        "links": [_v2_root(**{"com.example.region": "eu", "crit": ["com.example.region"]})],
        "valid": False,
        "error_contains": "not understood",
    },
    {
        "description": "Invalid: extension member altered after signing",
        "links": [_v2_root(**{"com.example.note": "a"})],
        "tamper": {"link": 0, "field": "com.example.note", "value": "b"},
        "valid": False,
        "error_contains": "invalid signature",
    },
    {
        "description": "Invalid: verifier is not in the audience",
        "links": [_v2_root()],
        "audience": "agent://other.example.com",
        "valid": False,
        "error_contains": "not permitted",
    },
    {
        "description": "Invalid: child raises the amount cap",
        "links": [_v2_root(), _v2_child(constraints=[
            {"type": "amount", "currency": "USD", "max_minor": 6000}])],
        "valid": False,
        "error_contains": "raises the amount cap",
    },
    {
        "description": "Invalid: child changes the principal",
        "links": [_v2_root(), _v2_child(principal={**_V2_PRINCIPAL, "sub": "someone-else"})],
        "valid": False,
        "error_contains": "principal differs from the root",
    },
    {
        "description": "Invalid: link without status_url lives longer than 24 h",
        "links": [_v2_root(origin="agent", principal=None, intent_hash=None, credential_refs=[],
                           expires_at="2026-01-03T00:00:00Z")],
        "valid": False,
        "error_contains": "cannot be revoked",
    },
    {
        "description": "Invalid: link signed under a different parent link (parent_link_id binding)",
        "links": [_v2_root(), _v2_child()],
        "sign_parent_override": {"1": "vector-link-99-0123456789abcdef"},
        "valid": False,
        "error_contains": "link 1: invalid signature",
    },
    {
        "description": "Invalid: link outlives the credential it references",
        "links": [_v2_root(expires_at="2026-01-01T03:00:00Z")],
        "valid": False,
        "error_contains": "outlives referenced credential",
    },
]


def _strip_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def build_delegation_v2() -> dict:
    cases = []
    for spec in _DELEGATION_V2_CASES:
        spec = copy.deepcopy(spec)
        links = [_strip_none(link) for link in spec["links"]]
        models: list[DelegationLinkV2] = []
        signed: list[str] = []
        overrides = spec.get("sign_parent_override", {})
        for i, link in enumerate(links):
            model = DelegationLinkV2.model_validate(link)
            parent = models[i - 1] if i else None
            if str(i) in overrides and parent is not None:
                parent = parent.model_copy(update={"link_id": overrides[str(i)]})
            payload = canonical_link_v2_bytes(model, parent)
            link["signature"] = b64url_nopad(ed_sign(_AGENT_KEYS[link["delegator"]], payload))
            models.append(model)
            signed.append(payload.decode("utf-8"))
        tamper = spec.get("tamper")
        if tamper:
            links[tamper["link"]][tamper["field"]] = tamper["value"]
        case: dict[str, Any] = {
            "description": spec["description"],
            "now": _V2_NOW,
            "audience": spec.get("audience", "agent://shop.example.com"),
            "understood_extensions": spec.get("understood_extensions", []),
            "links": links,
            "signed_canonical": signed,
            "valid": spec["valid"],
        }
        if tamper or overrides:
            case["canonical_matches_signed"] = False
        if "error_contains" in spec:
            case["error_contains"] = spec["error_contains"]
        cases.append(case)
    return {
        "description": (
            "Delegation link format v2 (WIRE-BINDING section 11.11.2). Each link is signed "
            "(EdDSA, base64url without padding) over canonical JSON (sorted keys, ',' ':' "
            "separators, UTF-8, no ASCII escaping, integers only) of every member except "
            "'signature', extension members included, absent optional members omitted, "
            "'scopes' sorted, timestamps in RFC 3339 UTC with 'Z', plus 'parent_link_id' and "
            "'parent_delegate' (null for the root). Keys are looked up by (delegator, kid); "
            "every key here has kid 'k1'. Validate each case at 'now' with the given audience "
            "and understood extensions."
        ),
        "keys_by_agent": _AGENT_KEYS,
        "vectors": cases,
    }


# ---------------------------------------------------------------------------
# In-place signing directives for the other vector files
# ---------------------------------------------------------------------------


def _case_body(case: dict) -> dict:
    if "envelope" in case:
        return case["envelope"]["body"]
    if "encrypted_body" in case:
        return case["encrypted_body"]
    return case["body"]


def _revocation_canonical(body: dict) -> bytes:
    from ampro.security.key_revocation import KeyRevocationBody

    model = KeyRevocationBody.model_validate(body)
    fields = {k: v for k, v in model.model_dump(mode="json").items() if k != "signature"}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _receipts(case: dict) -> list[dict]:
    body = _case_body(case)
    if case.get("schema") == "cost_receipt":
        return [body]
    if case.get("schema") == "cost_receipt_chain":
        return body["receipts"]
    if case.get("body_type") == "task.complete":
        return body["cost_receipt"]["receipts"]
    raise ValueError(f"no receipts in {case['description']}")


def apply_sign(case: dict) -> None:
    directive = case["sign"]
    kind, key = directive["kind"], directive.get("key")
    # A tampered case is signed with its "signed" values, then sent with
    # its "sent" values: {"tamper": {field: {"signed": .., "sent": ..}}}.
    for field, change in case.get("tamper", {}).items():
        _case_body(case)[field] = change["signed"]
    if kind == "key_revocation":
        body = _case_body(case)
        body["signature"] = "placeholder"
        canonical = _revocation_canonical(body)
        body["signature"] = b64url_nopad(ed_sign(key, canonical))
        case["expected_canonical"] = canonical.decode("utf-8")
    elif kind == "cost_receipt":
        canon = []
        for r in _receipts(case):
            r["signature"] = "placeholder"
            payload = CostReceipt.model_validate(r).canonical_for_signing()
            r["signature"] = b64url_nopad(ed_sign(key, payload))
            canon.append(payload.decode("utf-8"))
        case["expected_canonical"] = canon
    elif kind == "federation_trust_proof":
        body = _case_body(case)
        payload = federation_trust_proof_payload(
            body["registry_id"],
            body["capabilities"],
            body["audience"],
            datetime.fromisoformat(body["issued_at"].replace("Z", "+00:00")),
            body["nonce"],
        )
        body["trust_proof"] = b64(ed_sign(key, payload))
        case["expected_canonical"] = payload.decode("utf-8")
    elif kind == "federation_revoke":
        body = _case_body(case)
        payload = federation_revoke_payload(body)
        body["signature"] = b64(ed_sign(key, payload))
        case["expected_canonical"] = payload.decode("utf-8")
    elif kind == "a256gcm":
        body = _case_body(case)
        plaintext = json.dumps(
            directive["plaintext"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        iv = bytes.fromhex(directive["iv_hex"])
        sealed = AESGCM(bytes.fromhex(KEYS[key]["key_hex"])).encrypt(iv, plaintext, None)
        body["ciphertext"] = b64url_nopad(sealed[:-16])
        body["iv"] = b64url_nopad(iv)
        body["tag"] = b64url_nopad(sealed[-16:])
    else:
        raise ValueError(f"unknown sign kind {kind!r}")
    # Optional post-signing mutation, for "signature must fail" cases.
    for field, change in case.get("tamper", {}).items():
        _case_body(case)[field] = change["sent"]


def _walk_cases(doc: dict):
    for k, v in doc.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    yield item


def process_file(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    for case in _walk_cases(doc):
        if "sign" in case:
            apply_sign(case)
    return _attach_keys(doc)


GENERATED = {
    "rfc9421.json": build_rfc9421,
    "session_binding.json": build_session_binding,
    "delegation_chain.json": build_delegation,
    "delegation_chain_v2.json": build_delegation_v2,
}


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    changed = []
    outputs: dict[Path, str] = {}
    for name, builder in GENERATED.items():
        outputs[HERE / name] = render(_attach_keys(builder()))
    for path in sorted(HERE.glob("*.json")):
        if path.name in GENERATED:
            continue
        original = path.read_text(encoding="utf-8")
        if '"sign"' not in original and '"keys"' not in original:
            continue
        outputs[path] = render(process_file(path))
    for path, text in outputs.items():
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != text:
            changed.append(path.name)
            if not check:
                path.write_text(text, encoding="utf-8")
    if changed:
        print(("would change: " if check else "wrote: ") + ", ".join(changed))
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
