"""Conformance-vector runner: executes every case in ``tests/vectors/*.json``.

Each JSON file is a portable conformance suite (see
``tests/vectors/README.md``). This module is the Python reference runner:
it feeds every case to ampro and asserts the outcome the vector records.
For cryptographic vectors it additionally recomputes the canonical bytes
with ampro's own helpers and checks the committed signature byte for byte
(Ed25519 is deterministic), so any wire-format drift fails here.

Regenerate the crypto values with ``python tests/vectors/_generate.py``;
``test_generator_is_up_to_date`` fails if they are stale.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import types
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ValidationError

from ampro.core.body_schemas import validate_body
from ampro.core.envelope import STANDARD_HEADERS, AgentMessage
from ampro.security.encryption import CONTENT_ENCRYPTION_HEADER, EncryptedBody

VECTOR_DIR = Path(__file__).parent / "vectors"
_FILES = sorted(p for p in VECTOR_DIR.glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _cases(doc: dict) -> list[tuple[str, int, Any]]:
    out = []
    for section, value in doc.items():
        if section == "keys" or not isinstance(value, list):
            continue
        for i, item in enumerate(value):
            if isinstance(item, dict):
                out.append((section, i, item))
    return out


_PARAMS = [
    pytest.param(path.name, section, i, id=f"{path.stem}:{section}[{i}]")
    for path in _FILES
    for section, i, _ in _cases(_load(path))
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(fn) -> tuple[bool, str]:
    """Run *fn*; return (succeeded, error text)."""
    try:
        fn()
    except (ValidationError, ValueError, TypeError) as exc:
        return False, str(exc)
    return True, ""


def _assert_outcome(case: dict, valid: bool, err: str) -> None:
    expected = case.get("valid", True)
    assert valid is expected, f"expected valid={expected}, got {valid}: {err}"
    hint = case.get("expected_error")
    if not expected and hint and isinstance(hint, str):
        # The hint names the offending field or a phrase from the error.
        words = [w for w in re.split(r"\W+", hint) if len(w) > 2]
        assert any(w.lower() in err.lower() for w in words) or hint in err, (hint, err)


def _envelope_body_ok(env: dict) -> None:
    """Validate an envelope and its body per WIRE-BINDING 5.1.3 / 12.11."""
    msg = AgentMessage.model_validate(env)
    if not isinstance(msg.body, dict):
        return
    if CONTENT_ENCRYPTION_HEADER in msg.headers:
        EncryptedBody.model_validate(msg.body)
    else:
        validate_body(msg.body_type, msg.body)


def _key(doc: dict, name: str) -> dict:
    return doc["keys"][name]


def _ed_pub(doc: dict, name: str) -> bytes:
    return bytes.fromhex(_key(doc, name)["public_hex"])


def _ed_sign(doc: dict, name: str, data: bytes) -> bytes:
    seed = bytes.fromhex(_key(doc, name)["private_seed_hex"])
    return Ed25519PrivateKey.from_private_bytes(seed).sign(data)


def _b64any(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    if "-" in value or "_" in value:
        return base64.urlsafe_b64decode(value + pad)
    return base64.b64decode(value + pad)


def _check_ed25519(doc: dict, key: str, canonical: str, sig_b64: str) -> None:
    """Signature verifies over *canonical* and equals the deterministic one."""
    data = canonical.encode("utf-8")
    sig = _b64any(sig_b64)
    Ed25519PublicKey.from_public_bytes(_ed_pub(doc, key)).verify(sig, data)
    assert sig == _ed_sign(doc, key, data), "signature is not the deterministic RFC 8032 value"


# ---------------------------------------------------------------------------
# Test keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.stem)
def test_committed_keys_are_consistent(path: Path) -> None:
    doc = _load(path)
    for name, key in doc.get("keys", {}).items():
        if key["type"] == "Ed25519":
            seed = bytes.fromhex(key["private_seed_hex"])
            pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
            assert pub.hex() == key["public_hex"], name
        elif key["type"] == "X25519":
            priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(key["private_hex"]))
            raw = priv.public_key().public_bytes_raw()
            assert raw.hex() == key["public_hex"], name
            assert base64.urlsafe_b64encode(raw).decode().rstrip("=") == key["public_b64url"]
        else:
            assert len(bytes.fromhex(key["key_hex"])) == 32


def test_generator_is_up_to_date() -> None:
    spec = importlib.util.spec_from_file_location("_vector_gen", VECTOR_DIR / "_generate.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.main(["--check"]) == 0, "run: python tests/vectors/_generate.py"


# ---------------------------------------------------------------------------
# Per-file handlers
# ---------------------------------------------------------------------------


def _h_addressing(doc, section, case, mp):
    from ampro.core.addressing import parse_agent_uri

    holder: dict[str, Any] = {}
    valid, err = _ok(lambda: holder.setdefault("a", parse_agent_uri(case["input"])))
    _assert_outcome(case, valid, err)
    if valid:
        addr = holder["a"]
        for k, v in case["expected"].items():
            got = getattr(addr, "address_type" if k == "type" else k)
            got = getattr(got, "value", got)
            assert got == v, (k, got, v)


def _h_body_type_case(doc, section, case, mp):
    """Generic ``body_type`` + ``body`` / ``envelope`` / ``input`` case."""
    if "envelope" in case:
        valid, err = _ok(lambda: _envelope_body_ok(case["envelope"]))
    else:
        body = case.get("body", case.get("input"))
        valid, err = _ok(lambda: validate_body(case["body_type"], body))
    _assert_outcome(case, valid, err)


def _h_agent_json(case):
    from ampro.agent.schema import AgentJson

    return _ok(lambda: AgentJson.model_validate(case["agent_json"]))


def _h_lifecycle(doc, section, case, mp):
    from ampro.agent.schema import AgentJson
    from ampro.registry.types import RegistryResolution

    if case.get("test_type") == "agent_json" or "agent_json" in case:
        _assert_outcome(case, *_h_agent_json(case))
        return
    schema = {"agent.json": AgentJson, "registry_resolution": RegistryResolution}.get(
        case.get("schema", "")
    )
    if schema is not None:
        _assert_outcome(case, *_ok(lambda: schema.model_validate(case["body"])))
        return
    _h_body_type_case(doc, section, case, mp)


def _h_backpressure(doc, section, case, mp):
    from ampro.streaming.backpressure import (
        StreamAckEvent,
        StreamPauseEvent,
        StreamResumeEvent,
    )

    model = {
        "stream.ack": StreamAckEvent,
        "stream.pause": StreamPauseEvent,
        "stream.resume": StreamResumeEvent,
    }[case["event_type"]]
    _assert_outcome(case, *_ok(lambda: model.model_validate(case["body"])))


def _h_certifications(doc, section, case, mp):
    from ampro.compliance.certifications import CertificationLink

    if "agent_json" in case:
        _assert_outcome(case, *_h_agent_json(case))
    else:
        _assert_outcome(case, *_ok(lambda: CertificationLink.model_validate(case["certification"])))


def _h_context_schema(doc, section, case, mp):
    from ampro.agent.context_schema import check_schema_supported, parse_schema_urn

    if section == "match_vectors":
        assert check_schema_supported(case["urn"], case["supported"]) is case["expected"]
        return
    holder: dict[str, Any] = {}
    valid, err = _ok(lambda: holder.setdefault("i", parse_schema_urn(case["input"])))
    _assert_outcome(case, valid, err)
    if valid:
        for k, v in case["expected"].items():
            assert getattr(holder["i"], k) == v


def _receipts(case: dict) -> list[dict]:
    body = case["body"]
    if case.get("schema") == "cost_receipt":
        return [body]
    if case.get("schema") == "cost_receipt_chain":
        return body["receipts"]
    if case.get("body_type") == "task.complete":
        return body["cost_receipt"]["receipts"]
    return []


def _h_cost_receipt(doc, section, case, mp):
    from ampro.delegation.cost_receipt import (
        CostReceipt,
        CostReceiptChain,
        CostReceiptVerificationError,
    )

    schema = case.get("schema")
    if schema == "cost_receipt":
        valid, err = _ok(lambda: CostReceipt.model_validate(case["body"]))
    elif schema == "cost_receipt_chain":
        valid, err = _ok(lambda: CostReceiptChain.model_validate(case["body"]))
    else:
        valid, err = _ok(lambda: validate_body(case["body_type"], case["body"]))
        if valid:
            valid, err = _ok(lambda: CostReceiptChain.model_validate(case["body"]["cost_receipt"]))
    _assert_outcome(case, valid, err)
    if "sign" not in case:
        return

    key = case["sign"]["key"]
    receipts = [CostReceipt.model_validate(r) for r in _receipts(case)]
    assert [r.canonical_for_signing().decode() for r in receipts] == case["expected_canonical"]
    for r, canonical in zip(receipts, case["expected_canonical"], strict=True):
        _check_ed25519(doc, key, canonical, r.signature)

    # End-to-end: CostReceiptChain.add_receipt verifies each signature via
    # the registered public-key resolver.
    import ampro.trust.resolver as resolver

    mp.setattr(resolver, "get_public_key", lambda kid: _ed_pub(doc, key))
    chain = CostReceiptChain()
    try:
        for r in receipts:
            chain.add_receipt(r)
    except CostReceiptVerificationError as exc:
        assert case.get("expect_chain_error"), str(exc)
        assert case["expect_chain_error"] in str(exc)
        return
    assert not case.get("expect_chain_error"), "chain accepted a receipt it must reject"
    if "expected_total_cost_usd" in case:
        assert chain.total_cost_usd == Decimal(case["expected_total_cost_usd"])

    # A flipped amount must not verify.
    forged = receipts[0].model_copy(update={"cost_usd": receipts[0].cost_usd + 1})
    mp.setattr(resolver, "get_public_key", lambda kid: _ed_pub(doc, key))
    with pytest.raises(CostReceiptVerificationError):
        CostReceiptChain().add_receipt(forged)


def _h_data_residency(doc, section, case, mp):
    from ampro.compliance.data_residency import (
        DataResidency,
        check_residency_violation,
        validate_residency_region,
    )

    tt = case.get("test_type")
    if tt == "validate_region":
        for sub in case["cases"]:
            assert validate_residency_region(sub["region"]) is sub["expected"], sub
    elif tt == "violation_check":
        violated, detail = check_residency_violation(
            DataResidency.model_validate(case["message_residency"]),
            DataResidency.model_validate(case["agent_residency"]),
        )
        assert violated is case["expected_violation"], detail
        if "expected_detail_contains" in case:
            assert case["expected_detail_contains"] in (detail or "")
    elif tt == "envelope":
        def check():
            _envelope_body_ok(case["envelope"])
            DataResidency.model_validate_json(case["envelope"]["headers"]["Data-Residency"])
        _assert_outcome(case, *_ok(check))
    else:
        _assert_outcome(case, *_ok(lambda: DataResidency.model_validate(case["input"])))


def _h_delegation_v2(doc, section, case, mp):
    from datetime import datetime

    from ampro.delegation.v2 import (
        DelegationLinkV2,
        VerificationKey,
        canonical_link_v2_bytes,
        validate_chain_v2,
    )

    agent_keys = doc["keys_by_agent"]
    links = [DelegationLinkV2.model_validate(link) for link in case["links"]]
    for i, (link, signed) in enumerate(zip(links, case["signed_canonical"], strict=True)):
        sig = base64.urlsafe_b64decode(link.signature + "=" * (-len(link.signature) % 4))
        _check_ed25519(doc, agent_keys[link.delegator], signed, base64.b64encode(sig).decode())
        actual = canonical_link_v2_bytes(link, links[i - 1] if i else None).decode("utf-8")
        if case.get("canonical_matches_signed", True):
            assert actual == signed, f"link {i} canonical drifted"
    keys = {
        (agent, "k1"): VerificationKey("EdDSA", _ed_pub(doc, k))
        for agent, k in agent_keys.items()
    }
    ok, reason = validate_chain_v2(
        links,
        keys,
        audience=case["audience"],
        understood_extensions=case["understood_extensions"],
        now=datetime.fromisoformat(case["now"].replace("Z", "+00:00")),
    )
    assert ok is case["valid"], reason
    if not ok:
        assert case["error_contains"] in reason, reason


def _h_delegation(doc, section, case, mp):
    from ampro.delegation.chain import (
        DelegationChain,
        DelegationLink,
        _canonical_link_bytes,
        delegation_link_id,
        validate_chain,
    )

    agent_keys = doc["keys_by_agent"]
    try:
        links = [DelegationLink.model_validate(link) for link in case["links"]]
    except ValidationError as exc:
        assert case["valid"] is False
        assert case["error_contains"] in str(exc)
        return

    # Canonical bytes + deterministic signatures.
    for i, (link, signed) in enumerate(zip(links, case.get("signed_canonical", []), strict=True)):
        _check_ed25519(doc, agent_keys[link.delegator], signed, link.signature)
        parent = links[i - 1].delegate if i else None
        actual = _canonical_link_bytes(link, parent_delegate=parent).decode("utf-8")
        if case.get("canonical_matches_signed", True):
            assert actual == signed, f"link {i} canonical drifted"

    fan_out = None
    if "fan_out_counts" in case:
        fan_out = {
            delegation_link_id(links[int(i)]): n for i, n in case["fan_out_counts"].items()
        }
    public_keys = {agent: _ed_pub(doc, k) for agent, k in agent_keys.items()}
    ok, reason = validate_chain(
        DelegationChain(links=links), public_keys, fan_out_counts=fan_out
    )
    assert ok is case["valid"], reason
    if not ok:
        assert case["error_contains"] in reason, reason


def _h_encryption(doc, section, case, mp):
    if "envelope" in case:
        valid, err = _ok(lambda: _envelope_body_ok(case["envelope"]))
        body = case["envelope"]["body"]
    else:
        valid, err = _ok(lambda: EncryptedBody.model_validate(case["encrypted_body"]))
        body = case["encrypted_body"]
    _assert_outcome(case, valid, err)
    directive = case.get("sign")
    if directive:
        key = bytes.fromhex(_key(doc, directive["key"])["key_hex"])
        assert _b64any(body["iv"]).hex() == directive["iv_hex"]
        plaintext = AESGCM(key).decrypt(
            _b64any(body["iv"]), _b64any(body["ciphertext"]) + _b64any(body["tag"]), None
        )
        assert json.loads(plaintext) == directive["plaintext"]


def _h_envelope(doc, section, case, mp):
    holder: dict[str, Any] = {}
    valid, err = _ok(lambda: holder.setdefault("m", AgentMessage.model_validate(case["input"])))
    _assert_outcome(case, valid, err)
    if valid:
        msg = holder["m"]
        exp = case.get("expected", {})
        if exp.get("has_id"):
            assert msg.id
        if "body_type" in exp:
            assert msg.body_type == exp["body_type"]


def _h_handshake(doc, section, case, mp):
    from ampro.session.handshake import HandshakeState, HandshakeStateMachine

    for step in case["steps"]:
        sm = HandshakeStateMachine()
        sm._state = HandshakeState(step["from_state"])
        sm._started_at = None  # timeout clock not under test
        if step["valid"]:
            assert sm.transition(step["event"]) == HandshakeState(step["to_state"])
        else:
            with pytest.raises(ValueError):
                sm.transition(step["event"])


def _h_headers(doc, section, case, mp):
    if section == "header_examples":
        assert case["header"] in STANDARD_HEADERS


def _h_jurisdiction(doc, section, case, mp):
    from ampro.compliance.jurisdiction import (
        JurisdictionInfo,
        check_jurisdiction_conflict,
        validate_jurisdiction_code,
    )

    tt = case.get("test_type")
    if tt == "validate_code":
        for sub in case["cases"]:
            assert validate_jurisdiction_code(sub["code"]) is sub["expected"], sub
    elif tt == "conflict_check":
        conflict, detail = check_jurisdiction_conflict(
            JurisdictionInfo.model_validate(case["sender"]),
            JurisdictionInfo.model_validate(case["receiver"]),
        )
        assert conflict is case["expected_conflict"], detail
    elif tt == "envelope":
        def check():
            _envelope_body_ok(case["envelope"])
            JurisdictionInfo.model_validate_json(case["envelope"]["headers"]["Jurisdiction"])
        _assert_outcome(case, *_ok(check))
    else:
        _assert_outcome(case, *_ok(lambda: JurisdictionInfo.model_validate(case["input"])))


def _h_key_revocation(doc, section, case, mp):
    from ampro.security.key_revocation import (
        KeyRevocationBody,
        validate_revocation_signature,
    )

    _h_body_type_case(doc, section, case, mp)
    if "sign" not in case:
        return
    key = case["sign"]["key"]
    body = KeyRevocationBody.model_validate(case["body"])
    # Canonical form: every field except signature, model defaults (null)
    # included, sorted keys, compact separators.
    fields = {k: v for k, v in body.model_dump(mode="json").items() if k != "signature"}
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    expect_valid = case.get("signature_valid", True)
    assert (canonical == case["expected_canonical"]) is expect_valid
    sig = _b64any(body.signature)
    assert sig == _ed_sign(doc, key, case["expected_canonical"].encode("utf-8"))
    assert validate_revocation_signature(body, _ed_pub(doc, key)) is expect_valid


def _h_priority(doc, section, case, mp):
    from ampro.core.priority import Priority

    _assert_outcome(case, *_ok(lambda: Priority(case["value"])))


def _h_registry_federation(doc, section, case, mp):
    import ampro.registry.federation as fed

    _h_body_type_case(doc, section, case, mp)
    if "sign" not in case:
        return
    key = case["sign"]["key"]
    body = case["envelope"]["body"] if "envelope" in case else case["body"]
    mp.setattr(fed, "_TRUST_PROOF_RESOLVER", lambda rid: _ed_pub(doc, key))
    mp.setattr(fed, "_FEDERATION_NONCES", fed._NonceCache())

    if case["sign"]["kind"] == "federation_revoke":
        model = fed.RegistryFederationRevokeBody.model_validate(body)
        payload = fed.federation_revoke_payload(model.model_dump()).decode("utf-8")
        assert payload == case["expected_canonical"]
        _check_ed25519(doc, key, payload, model.signature)
        assert fed.verify_federation_revoke(model, expected_revoked_registry=doc["audience"])
        assert not fed.verify_federation_revoke(model, expected_revoked_registry="agent://other.example.com")
        forged = model.model_copy(update={"reason": model.reason + "!"})
        assert not fed.verify_federation_revoke(forged, expected_revoked_registry=doc["audience"])
        return

    req = fed.RegistryFederationRequest.model_validate(body)
    payload = fed.federation_trust_proof_payload(
        req.registry_id, req.capabilities, req.audience, req.issued_at, req.nonce
    ).decode("utf-8")
    assert payload == case["expected_canonical"]
    _check_ed25519(doc, key, payload, req.trust_proof)

    # Receiver policy, exercised with proofs issued "now" by the same key.
    seed = bytes.fromhex(_key(doc, key)["private_seed_hex"])

    def fresh(offset: int = 0, nonce: str = "fresh-nonce-0123456789") -> Any:
        return fed.sign_federation_trust_proof(
            seed, req.registry_id, req.capabilities, audience=req.audience,
            issued_at=datetime.now(UTC) + timedelta(seconds=offset), nonce=nonce,
        )

    aud = req.audience
    assert fed.verify_federation_trust_proof(fresh(), expected_audience=aud)
    assert not fed.verify_federation_trust_proof(fresh(), expected_audience=aud), "replay"
    assert not fed.verify_federation_trust_proof(fresh(nonce="n" * 20), expected_audience="agent://x")
    assert not fed.verify_federation_trust_proof(fresh(-301, "stale-nonce-0123456"), expected_audience=aud)
    assert not fed.verify_federation_trust_proof(fresh(301, "future-nonce-012345"), expected_audience=aud)
    assert not fed.verify_federation_trust_proof(fresh(nonce="m" * 20), expected_audience=None)


def _h_registry_search(doc, section, case, mp):
    from ampro.registry.search import (
        RegistrySearchMatch,
        RegistrySearchRequest,
        RegistrySearchResult,
    )

    model = {
        "registry_search_request": RegistrySearchRequest,
        "registry_search_match": RegistrySearchMatch,
        "registry_search_result": RegistrySearchResult,
    }[case["schema"]]
    _assert_outcome(case, *_ok(lambda: model.model_validate(case["body"])))


def _h_rfc9421(doc, section, case, mp):
    from ampro.security import rfc9421
    from ampro.security.nonce_tracker import NonceTracker

    exp = case["expected"]
    body = case["body"].encode("utf-8") if case["body"] is not None else None
    if body is not None:
        assert rfc9421._content_digest_sha256(body) == exp["content_digest"]
    if "authority" in exp:
        assert rfc9421._authority(case["url"]) == exp["authority"]
    base = rfc9421.create_signature_base(
        case["method"], case["url"], case["headers"], case["covered"],
        created=case["created"], keyid=case["keyid"], nonce=case["nonce"],
    )
    assert base == exp["signature_base"]
    sig = re.fullmatch(r"sig1=:(.+):", exp["signature"]).group(1)
    _check_ed25519(doc, case["key"], base, sig)

    v = case["verify"]
    headers = {**case["headers"], "Signature": exp["signature"], "Signature-Input": exp["signature_input"]}
    for name in v.get("strip_headers", []):
        headers.pop(name, None)
    vbody = v["body"].encode("utf-8") if "body" in v else body
    mp.setattr(rfc9421, "time", types.SimpleNamespace(time=lambda: float(v["at"])))
    tracker = NonceTracker(window_seconds=600)
    expects = v["expect"] if isinstance(v["expect"], list) else [v["expect"]]
    for expected in expects:
        got = rfc9421.verify_request(
            _ed_pub(doc, v.get("verify_key", case["key"])),
            v.get("method", case["method"]), case["url"], headers, vbody,
            nonce_tracker=tracker,
        )
        if "known_gap" in v:
            # Documented deviation of the reference implementation: xfail
            # while it persists, fail loudly once fixed so the marker is removed.
            if got is not expected:
                pytest.xfail(v["known_gap"])
            pytest.fail(f"known gap fixed, drop 'known_gap' from {case['name']}")
        assert got is expected, v.get("reason")


def _h_session_binding(doc, section, case, mp):
    from ampro.session import binding as sb
    from ampro.session.handshake import (
        ClientHandshakeState,
        HandshakeStateMachine,
        SessionBindingError,
        SessionConfirmBody,
        SessionEstablishedBody,
        SessionInitBody,
        client_finish_handshake,
    )

    if section == "negative_vectors":
        client = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(doc["keys"]["x25519-client"]["private_hex"])
        )
        if "peer_public_b64url" in case:
            with pytest.raises(ValueError):
                sb.derive_session_binding_key(
                    client, case["peer_public_b64url"], session_id="s", client_nonce="c",
                    server_nonce="s", client_public_key="a", server_public_key="b",
                )
        else:
            good = _load(VECTOR_DIR / "session_binding.json")["vectors"][0]
            est = dict(good["session_established"])
            est.pop(case["drop_field"])
            state = ClientHandshakeState(
                good["client_nonce"], good["session_init"]["client_ephemeral_key"], client
            )
            with pytest.raises(SessionBindingError):
                client_finish_handshake(state, SessionEstablishedBody.model_validate(est))
        return

    keys = doc["keys"]
    cpriv = X25519PrivateKey.from_private_bytes(bytes.fromhex(keys[case["client_key"]]["private_hex"]))
    spriv = X25519PrivateKey.from_private_bytes(bytes.fromhex(keys[case["server_key"]]["private_hex"]))
    cpub, spub = keys[case["client_key"]]["public_b64url"], keys[case["server_key"]]["public_b64url"]
    exp = case["expected"]

    # Bodies are schema-valid.
    SessionInitBody.model_validate(case["session_init"])
    est = SessionEstablishedBody.model_validate(case["session_established"])
    confirm = SessionConfirmBody.model_validate(case["session_confirm"])
    assert est.binding_token is None

    assert cpriv.exchange(spriv.public_key()).hex() == exp["x25519_shared_secret_hex"]
    params = dict(
        session_id=case["session_id"], client_nonce=case["client_nonce"],
        server_nonce=case["server_nonce"], client_public_key=cpub, server_public_key=spub,
    )
    assert sb.derive_session_binding_key(cpriv, spub, **params) == exp["binding_key_hex"]
    assert sb.derive_session_binding_key(spriv, cpub, **params) == exp["binding_key_hex"]
    transcript = sb._confirm_transcript(confirm_nonce=case["confirm_nonce"], **params)
    assert transcript.decode("utf-8") == exp["confirm_transcript"]
    key = exp["binding_key_hex"]
    assert sb.compute_binding_proof(key, confirm_nonce=case["confirm_nonce"], **params) == exp["binding_proof"]
    assert confirm.binding_proof == exp["binding_proof"]
    assert sb.verify_binding_proof(key, exp["binding_proof"], confirm_nonce=case["confirm_nonce"], **params)
    assert not sb.verify_binding_proof(key, exp["binding_proof"], confirm_nonce="0" * 32, **params)

    # Client side of the real handshake helper reproduces the confirm body.
    state = ClientHandshakeState(case["client_nonce"], cpub, cpriv)
    sm = HandshakeStateMachine()
    sm.transition("send_init")
    built, _ = client_finish_handshake(state, est, sm)
    assert built.binding_proof == exp["binding_proof"]
    assert built.confirm_nonce == case["confirm_nonce"]

    for m in case["messages"]:
        assert json.dumps(m["body"], sort_keys=True, separators=(",", ":"), ensure_ascii=False) == m["body_canonical_json"]
        assert sb.canonical_body_digest(m["body"]) == m["body_sha256_hex"]
        assert sb._message_binding_input(case["session_id"], m["message_id"], m["body"]).decode() == m["hmac_input"]
        mac = sb.create_message_binding(case["session_id"], m["message_id"], key, body=m["body"])
        assert mac == m["session_binding"]
        assert sb.verify_message_binding(case["session_id"], m["message_id"], key, mac, body=m["body"])
        assert not sb.verify_message_binding(
            case["session_id"], m["message_id"], key, mac, body={"tampered": True}
        )
        assert not sb.verify_message_binding(case["session_id"], m["message_id"] + "x", key, mac, body=m["body"])


def _h_stream_channel(doc, section, case, mp):
    from ampro.streaming.channel import StreamChannelCloseEvent, StreamChannelOpenEvent
    from ampro.streaming.checkpoint import StreamCheckpointEvent
    from ampro.streaming.events import StreamingEvent

    models: dict[str, type[BaseModel]] = {
        "StreamChannelOpenEvent": StreamChannelOpenEvent,
        "StreamChannelCloseEvent": StreamChannelCloseEvent,
        "StreamCheckpointEvent": StreamCheckpointEvent,
        "StreamingEvent": StreamingEvent,
        "AgentMessage": AgentMessage,
    }
    exp = case.get("expected", {})
    if "type" in exp:
        model = models[exp["type"]]
    elif "checkpoint" in case["id"] or "seq" in case["id"] or "timestamp" in case["id"]:
        model = StreamCheckpointEvent
    elif "close" in case["id"]:
        model = StreamChannelCloseEvent
    else:
        model = StreamChannelOpenEvent
    holder: dict[str, Any] = {}
    valid, err = _ok(lambda: holder.setdefault("m", model.model_validate(case["input"])))
    _assert_outcome(case, valid, err)
    if not valid:
        return
    obj = holder["m"]
    dumped = obj.model_dump(mode="json")
    for k, v in exp.items():
        if k == "type":
            continue
        if k == "headers_contains":
            assert v.items() <= obj.headers.items()
        elif k == "sse_contains":
            assert v in obj.to_sse()
        else:
            got = dumped[k]
            if isinstance(v, str) and isinstance(got, str) and k.endswith(("_at", "timestamp")):
                assert datetime.fromisoformat(got.replace("Z", "+00:00")) == datetime.fromisoformat(
                    v.replace("Z", "+00:00")
                )
            else:
                assert got == v, (k, got, v)


def _h_task_redirect(doc, section, case, mp):
    if case.get("schema") == "redirect_flow":
        for step in case["steps"]:
            for name in step["headers"]:
                assert name in STANDARD_HEADERS, name
        return
    _h_body_type_case(doc, section, case, mp)
    if "headers" in case:
        AgentMessage.model_validate(
            {"sender": "agent://a", "recipient": "agent://b", "headers": case["headers"]}
        )


_HEX = re.compile(r"[0-9a-f]+")


def _trace_ok(ctx: dict) -> None:
    """WIRE-BINDING 12.14 format: 32 / 16 lowercase hex characters.

    ``ampro.delegation.tracing.TraceContext`` is a plain dataclass with no
    validation, so the rule is checked here, then the context is
    round-tripped through inject/extract.
    """
    from ampro.delegation.tracing import (
        TraceContext,
        extract_trace_context,
        inject_trace_headers,
    )

    for field, n in (("trace_id", 32), ("span_id", 16), ("parent_span_id", 16)):
        value = ctx.get(field)
        if value is None and field == "parent_span_id":
            continue
        if not value:
            raise ValueError(f"{field} must not be empty")
        if len(value) != n or not _HEX.fullmatch(value):
            raise ValueError(f"{field} must be {n} hex characters")
    tc = TraceContext(**{k: v for k, v in ctx.items() if k != "label"})
    assert extract_trace_context(inject_trace_headers(tc)).trace_id == tc.trace_id


def _h_tracing(doc, section, case, mp):
    from ampro.delegation.tracing import TraceContext, inject_trace_headers

    if "spans" in case:
        for span in case["spans"]:
            _trace_ok(span)
        ids = {s["trace_id"] for s in case["spans"]}
        assert len(ids) == 1
        for parent, child in zip(case["spans"], case["spans"][1:], strict=False):
            assert child["parent_span_id"] == parent["span_id"]
        return
    _assert_outcome(case, *_ok(lambda: _trace_ok(case["input"])))
    if "expected_headers" in case:
        assert inject_trace_headers(TraceContext(**case["input"])) == case["expected_headers"]


def _h_trust_scoring(doc, section, case, mp):
    from ampro.trust.score import calculate_trust_score

    score = calculate_trust_score(**case["input"])
    exp = case["expected"]
    assert score.score == exp["score"]
    tier = getattr(score.tier, "value", score.tier)
    assert tier == exp["tier"]
    factors = {getattr(k, "value", k).lower(): v for k, v in score.factors.items()}
    assert factors == exp["factors"]


def _h_visibility(doc, section, case, mp):
    from ampro.agent.visibility import (
        ContactPolicy,
        VisibilityLevel,
        check_contact_allowed,
        filter_agent_json,
    )

    if section == "contact_policy_vectors":
        assert check_contact_allowed(case["sender_tier"], ContactPolicy(case["policy"])) is case["allowed"]
        return
    full = {
        "protocol_version": "1.0.0",
        "identifiers": ["agent://x.example.com"],
        "endpoint": "https://x.example.com/agent/message",
        "visibility": {"level": case["visibility"]},
        "capabilities": {"groups": ["messaging"], "level": 1},
        "constraints": {"max_concurrent_tasks": 5},
    }
    out = filter_agent_json(full, case["caller_tier"], VisibilityLevel(case["visibility"]))
    expected = sorted(full) if case["expected_keys"] == "all" else sorted(case["expected_keys"])
    assert sorted(out) == expected


def _h_stream_checkpoint(doc, section, case, mp):
    _h_stream_channel(doc, section, case, mp)


_HANDLERS = {
    "addressing.json": _h_addressing,
    "agent_lifecycle.json": _h_lifecycle,
    "audit_attestation.json": _h_body_type_case,
    "backpressure.json": _h_backpressure,
    "body_types.json": _h_body_type_case,
    "certifications.json": _h_certifications,
    "challenge.json": _h_body_type_case,
    "consent_revoke.json": _h_body_type_case,
    "context_schema.json": _h_context_schema,
    "cost_receipt.json": _h_cost_receipt,
    "data_residency.json": _h_data_residency,
    "delegation_chain.json": _h_delegation,
    "delegation_chain_v2.json": _h_delegation_v2,
    "encryption.json": _h_encryption,
    "envelope.json": _h_envelope,
    "erasure_propagation.json": _h_body_type_case,
    "handshake.json": _h_handshake,
    "headers.json": _h_headers,
    "identity_link.json": _h_body_type_case,
    "identity_migration.json": _h_lifecycle,
    "jurisdiction.json": _h_jurisdiction,
    "key_revocation.json": _h_key_revocation,
    "priority.json": _h_priority,
    "registry_federation.json": _h_registry_federation,
    "registry_search.json": _h_registry_search,
    "rfc9421.json": _h_rfc9421,
    "session_binding.json": _h_session_binding,
    "stream_channel.json": _h_stream_channel,
    "stream_checkpoint.json": _h_stream_checkpoint,
    "task_redirect.json": _h_task_redirect,
    "task_revoke.json": _h_body_type_case,
    "tool_consent.json": _h_body_type_case,
    "tracing.json": _h_tracing,
    "trust_proof.json": _h_body_type_case,
    "trust_scoring.json": _h_trust_scoring,
    "trust_upgrade.json": _h_body_type_case,
    "visibility.json": _h_visibility,
}


def test_every_vector_file_has_a_handler() -> None:
    assert sorted(p.name for p in _FILES) == sorted(_HANDLERS)


def test_headers_vector_matches_standard_headers() -> None:
    doc = _load(VECTOR_DIR / "headers.json")
    assert set(doc["standard_headers"]) <= STANDARD_HEADERS


@pytest.mark.parametrize(("filename", "section", "index"), _PARAMS)
def test_vector(filename: str, section: str, index: int, monkeypatch: pytest.MonkeyPatch) -> None:
    doc = _load(VECTOR_DIR / filename)
    case = doc[section][index]
    _HANDLERS[filename](doc, section, case, monkeypatch)
