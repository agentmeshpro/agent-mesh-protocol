"""Foreign identifiers in agent.json (WIRE-BINDING Appendix E.4).

A foreign identifier (MCP client ID metadata URL, did:web / did:wba /
did:key, Web Bot Auth key directory) is only syntax until an identity
link proof verifies.  These tests cover canonicalisation, every
rejection path, and spoofing attempts against the alias helper.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ampro.agent.schema import AgentJson
from ampro.core.addressing import (
    FOREIGN_DID_METHODS,
    normalize_foreign_did,
    normalize_foreign_https_id,
)
from ampro.identity.link import (
    MAX_FOREIGN_IDENTIFIERS,
    ForeignIdentifier,
    IdentityLinkProofBody,
    verified_foreign_aliases,
)

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
AGENT = "agent://assistant.example.com"
CLIENT_URL = "https://app.example.com/oauth/client-metadata.json"
DIRECTORY = "https://bot.example.com/.well-known/http-message-signatures-directory"
DID_WBA = "did:wba:example.com:user:alice"
DID_KEY = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


# ---------------------------------------------------------------------------
# https identifiers
# ---------------------------------------------------------------------------


class TestHttpsSyntax:
    @pytest.mark.parametrize("raw, canonical", [
        (CLIENT_URL, CLIENT_URL),
        ("HTTPS://App.Example.COM/oauth/client-metadata.json", CLIENT_URL),
        ("https://app.example.com:443/oauth/client-metadata.json", CLIENT_URL),
        ("https://app.example.com:8443/x", "https://app.example.com:8443/x"),
        ("https://app.example.com", "https://app.example.com/"),
        ("https://app.example.com/%7Euser/%61b", "https://app.example.com/~user/ab"),
        ("https://app.example.com/a%c3%a9", "https://app.example.com/a%C3%A9"),
        ("https://bücher.example/c.json", "https://xn--bcher-kva.example/c.json"),
    ])
    def test_canonical(self, raw, canonical):
        assert normalize_foreign_https_id(raw) == canonical

    @pytest.mark.parametrize("raw", [
        "http://app.example.com/c.json",                 # http scheme
        "ftp://app.example.com/c.json",
        "app.example.com/c.json",                        # no scheme
        "https://user:pw@app.example.com/c.json",        # userinfo
        "https://app.example.com@evil.example/c.json",   # userinfo spoof
        "https://app.example.com/c.json#frag",           # fragment
        "https://app.example.com/c.json?x=1",            # query
        "https://127.0.0.1/c.json",                      # IPv4 literal
        "https://[::1]/c.json",                          # IPv6 literal
        "https://localhost/c.json",                      # single label
        "https://app.example.com./c.json",               # trailing dot
        "https://app%2eexample.com/c.json",              # encoded host
        "https://app.example.com:0/x",                   # port 0
        "https://app.example.com:65536/x",               # port range
        "https://app.example.com:/x",                    # empty port
        "https://app.example.com:44a/x",
        "https://app.example.com/a b",                   # whitespace
        "https://app.example.com/a\r\nX: y",             # CRLF
        "https://app.example.com\\@evil.example/",       # backslash
        "https://app.example.com/%2e%2e/admin",          # encoded dot segment
        "https://app.example.com/../admin",              # dot segment
        "https://app.example.com/a%2Fb",                 # encoded slash
        "https://app.example.com/a%00",                  # encoded NUL
        "https://app.example.com/a%zz",                  # bad escape
        "https://app.example.com/a%4",                   # truncated escape
        "https://app.example.com/é",                     # raw non-ASCII path
        "https://app.example.com/a<b>",                  # forbidden char
        "https://-bad.example.com/",                     # LDH
        "https://a_b.example.com/",                      # underscore
        "https://app.123/",                              # numeric TLD
        "https://" + "a" * 64 + ".example.com/",         # label > 63
        "https://app.example.com/" + "a" * 2048,         # oversized
        "",
    ])
    def test_rejected(self, raw):
        with pytest.raises(ValueError):
            normalize_foreign_https_id(raw)

    def test_non_string(self):
        with pytest.raises(ValueError):
            normalize_foreign_https_id(None)  # type: ignore[arg-type]

    def test_homograph_does_not_collapse_onto_ascii(self):
        # Cyrillic "а" (U+0430) instead of Latin "a".
        spoof = normalize_foreign_https_id("https://аpp.example.com/oauth/client-metadata.json")
        assert spoof.startswith("https://xn--")
        assert spoof != CLIENT_URL


# ---------------------------------------------------------------------------
# DIDs
# ---------------------------------------------------------------------------


class TestDidSyntax:
    def test_allowlist(self):
        assert FOREIGN_DID_METHODS == {"key", "web", "wba"}

    @pytest.mark.parametrize("raw, canonical", [
        (DID_KEY, DID_KEY),
        ("did:web:example.com", "did:web:example.com"),
        ("did:web:Example.COM:agents:billing", "did:web:example.com:agents:billing"),
        ("did:web:example.com%3a8443:a", "did:web:example.com%3A8443:a"),
        (DID_WBA, DID_WBA),
    ])
    def test_canonical(self, raw, canonical):
        assert normalize_foreign_did(raw) == canonical

    @pytest.mark.parametrize("raw", [
        "did:ion:EiAbc",                                  # method not allowed
        "did:plc:abc",
        "did:WEB:example.com",                            # method case
        "did:web",                                        # too short
        "did:web:",                                       # empty domain
        "dId:web:example.com",
        "did:web:example.com/path",                       # DID URL path
        "did:web:example.com#key-1",                      # fragment
        "did:web:example.com?service=x",                  # query
        "did:web:localhost",                              # single label
        "did:web:127.0.0.1",                              # IP literal
        "did:web:exa%6Dple.com",                          # encoded domain
        "did:web:example.com%3A99999",                    # port range
        "did:web:example.com%3Aabc",
        "did:web:example.com:a b",                        # whitespace
        "did:web:example.com:a%20b",                      # escape in segment
        "did:web:example.com::x",                         # empty segment
        "did:wba:bücher.example",                         # non-ASCII
        "did:key:z6MkTooShort",                           # malformed did:key
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",  # secp256k1
        "did:key:" + "z6Mk" + "0" * 44,                   # non-base58
        "did:key:" + DID_KEY[8:] + ":extra",
        "did:web:example.com:" + "a" * 600,               # oversized
    ])
    def test_rejected(self, raw):
        with pytest.raises(ValueError):
            normalize_foreign_did(raw)


# ---------------------------------------------------------------------------
# ForeignIdentifier model and agent.json
# ---------------------------------------------------------------------------


def _proof(source=AGENT, target=CLIENT_URL, *, expires=None, ts="2026-10-01T00:00:00Z",
           proof="sig-ok") -> dict:
    return {
        "source_id": source,
        "target_id": target,
        "proof_type": "ed25519_cross_sign",
        "proof": proof,
        "timestamp": ts,
        "expires_at": expires or "2027-10-01T00:00:00Z",
    }


def _entry(id_=CLIENT_URL, kind="oauth-client-id", scheme="https", **proof_kw) -> dict:
    entry = {"scheme": scheme, "id": id_, "kind": kind}
    if proof_kw.get("with_proof", True):
        proof_kw.pop("with_proof", None)
        entry["proof"] = _proof(target=proof_kw.pop("target", id_), **proof_kw)
    return entry


class TestModel:
    def test_canonicalises_id(self):
        fid = ForeignIdentifier(scheme="https", id="HTTPS://APP.example.com:443/c",
                                kind="http-signature-directory")
        assert fid.id == "https://app.example.com/c"

    @pytest.mark.parametrize("scheme, id_, kind", [
        ("https", DID_WBA, "did"),                 # kind/scheme mismatch
        ("did", CLIENT_URL, "oauth-client-id"),
        ("https", DID_WBA, "oauth-client-id"),     # id does not match scheme
        ("did", CLIENT_URL, "did"),
        ("https", "http://app.example.com/", "oauth-client-id"),
        ("did", "did:ion:abc", "did"),
        ("ftp", "ftp://a.example.com/", "oauth-client-id"),
        ("https", CLIENT_URL, "a2a-card"),         # unknown kind
    ])
    def test_rejected(self, scheme, id_, kind):
        with pytest.raises(ValidationError):
            ForeignIdentifier(scheme=scheme, id=id_, kind=kind)

    def test_agent_json_roundtrip_and_backward_compat(self):
        doc = {
            "protocol_version": "1.0.0",
            "identifiers": [AGENT],
            "endpoint": "https://assistant.example.com/agent/message",
        }
        assert AgentJson.model_validate(doc).foreign_identifiers == []
        doc["foreign_identifiers"] = [_entry(), _entry(DID_WBA, "did", "did")]
        aj = AgentJson.model_validate(doc)
        assert [f.id for f in aj.foreign_identifiers] == [CLIENT_URL, DID_WBA]
        assert aj.identifiers == [AGENT]

    def test_agent_json_drops_unparseable_entries(self):
        doc = {
            "protocol_version": "1.0.0",
            "identifiers": [AGENT],
            "endpoint": "https://assistant.example.com/agent/message",
            "foreign_identifiers": [
                _entry("http://app.example.com/c", with_proof=False),
                _entry(CLIENT_URL, "a2a-card"),
                "https://app.example.com/plain-string",
                _entry(),
            ],
        }
        aj = AgentJson.model_validate(doc)
        assert [f.id for f in aj.foreign_identifiers] == [CLIENT_URL]

    def test_agent_json_bounds(self):
        base = {
            "protocol_version": "1.0.0",
            "identifiers": [AGENT],
            "endpoint": "https://assistant.example.com/agent/message",
        }
        with pytest.raises(ValidationError):
            AgentJson.model_validate(
                {**base, "foreign_identifiers": [_entry()] * (MAX_FOREIGN_IDENTIFIERS + 1)})
        with pytest.raises(ValidationError):
            AgentJson.model_validate({**base, "foreign_identifiers": {"a": 1}})


# ---------------------------------------------------------------------------
# verified_foreign_aliases
# ---------------------------------------------------------------------------


def _ok(proof: IdentityLinkProofBody) -> bool:
    return proof.proof == "sig-ok"


class TestVerifiedAliases:
    def _run(self, entries, own=(AGENT,), verify=_ok, now=NOW):
        return verified_foreign_aliases(own, entries, verify_proof=verify, now=now)

    def test_proven_aliases(self):
        entries = [
            _entry(),
            _entry(DIRECTORY, "http-signature-directory"),
            _entry(DID_WBA, "did", "did"),
            _entry(DID_KEY, "did", "did"),
        ]
        assert self._run(entries) == {CLIENT_URL, DIRECTORY, DID_WBA, DID_KEY}

    def test_reverse_direction_proof_accepted(self):
        entry = _entry(with_proof=False)
        entry["proof"] = _proof(source=CLIENT_URL, target=AGENT)
        assert self._run([entry]) == {CLIENT_URL}

    def test_proof_target_compared_canonically(self):
        entry = _entry(target="HTTPS://APP.example.com:443/oauth/client-metadata.json")
        assert self._run([entry]) == {CLIENT_URL}

    def test_own_id_compared_canonically(self):
        entry = _entry(source="agent://Assistant.Example.com")
        assert self._run([entry]) == {CLIENT_URL}

    def test_unproven_alias_ignored(self):
        assert self._run([_entry(with_proof=False)]) == frozenset()

    def test_failed_proof_ignored(self):
        assert self._run([_entry(proof="forged")]) == frozenset()

    def test_proof_for_other_agent_ignored(self):
        assert self._run([_entry(source="agent://evil.example.com")]) == frozenset()

    def test_proof_for_other_foreign_id_ignored(self):
        # A valid proof for one URL replayed onto a different URL.
        entry = _entry("https://victim.example.com/oauth/client.json", target=CLIENT_URL)
        assert self._run([entry]) == frozenset()

    def test_homograph_proof_ignored(self):
        entry = _entry(target="https://аpp.example.com/oauth/client-metadata.json")
        assert self._run([entry]) == frozenset()

    def test_proof_between_two_foreign_ids_ignored(self):
        entry = _entry(source=DIRECTORY)
        assert self._run([entry]) == frozenset()

    def test_expired_proof_ignored(self):
        entry = _entry(ts="2025-01-01T00:00:00Z", expires="2026-01-01T00:00:00Z")
        assert self._run([entry]) == frozenset()

    def test_future_proof_ignored(self):
        entry = _entry(ts="2026-10-08T00:00:00Z")
        assert self._run([entry]) == frozenset()

    def test_small_future_skew_tolerated(self):
        entry = _entry(ts="2026-10-07T12:04:00Z")
        assert self._run([entry]) == {CLIENT_URL}

    def test_unparseable_timestamp_ignored(self):
        entry = _entry(ts="not-a-time", expires="2099-01-01T00:00:00Z")
        assert self._run([entry]) == frozenset()

    def test_verifier_exception_fails_closed(self):
        def boom(_):
            raise RuntimeError("network down")
        assert self._run([_entry()], verify=boom) == frozenset()

    @pytest.mark.parametrize("result", [1, "yes", None, object()])
    def test_verifier_must_return_true(self, result):
        assert self._run([_entry()], verify=lambda _p: result) == frozenset()

    def test_invalid_entries_ignored_individually(self):
        entries = [
            _entry("http://app.example.com/c"),
            _entry("https://user@app.example.com/c"),
            _entry("did:ion:abc", "did", "did"),
            {"garbage": True},
            "not-an-object",
            _entry(),
        ]
        assert self._run(entries) == {CLIENT_URL}

    def test_no_own_identifiers(self):
        assert self._run([_entry()], own=()) == frozenset()
        assert self._run([_entry()], own=("agent://bad\nhost",)) == frozenset()

    def test_too_many_entries(self):
        with pytest.raises(ValueError):
            self._run([_entry()] * (MAX_FOREIGN_IDENTIFIERS + 1))

    def test_naive_now_rejected(self):
        with pytest.raises(ValueError):
            self._run([_entry()], now=datetime(2026, 10, 7))

    def test_accepts_models(self):
        aj = AgentJson.model_validate({
            "protocol_version": "1.0.0",
            "identifiers": [AGENT],
            "endpoint": "https://assistant.example.com/agent/message",
            "foreign_identifiers": [_entry(), _entry(DIRECTORY, "http-signature-directory",
                                                     with_proof=False)],
        })
        assert verified_foreign_aliases(
            aj.identifiers, aj.foreign_identifiers, verify_proof=_ok, now=NOW
        ) == {CLIENT_URL}

    def test_default_now(self):
        entry = _entry(ts=(datetime.now(UTC) - timedelta(days=1)).isoformat(),
                       expires=(datetime.now(UTC) + timedelta(days=1)).isoformat())
        assert verified_foreign_aliases([AGENT], [entry], verify_proof=_ok) == {CLIENT_URL}


def test_exports():
    import ampro
    import ampro.identity as ident

    for name in ("ForeignIdentifier", "verified_foreign_aliases", "LinkProofVerifier",
                 "MAX_FOREIGN_IDENTIFIERS", "normalize_foreign_identifier"):
        assert name in ampro.__all__ and name in ident.__all__
    for name in ("normalize_foreign_https_id", "normalize_foreign_did", "FOREIGN_DID_METHODS"):
        assert name in ampro.__all__


def test_agent_schema_first_import_keeps_body_registry_complete():
    """agent.schema imports identity.link late; importing it first must not
    break the body-type registry (which imports agent.schema back)."""
    import subprocess
    import sys

    code = (
        "import ampro.agent.schema\n"
        "from ampro.core.body_schemas import _BODY_TYPE_REGISTRY as r\n"
        "assert 'agent.metadata_invalidate' in r and 'identity.link_proof' in r\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
