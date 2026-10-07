"""Key compromise vs rotation semantics (WIRE-BINDING 12.12.1).

Covers the strict RFC 3339 timestamps and ``compromised_at`` on
``key.revocation``, :func:`signature_allowed`, and the bounded
:class:`InMemoryKeyStatusResolver` (authenticated ingest only, no
downgrades, signer bound to the revoked agent, pools that
revocation floods cannot exhaust).
"""
from __future__ import annotations

import base64
import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from ampro.security.key_revocation import (
    InMemoryKeyStatusResolver,
    KeyRevocationBody,
    KeyStatus,
    KeyStatusRecord,
    KeyStatusResolver,
    RevocationReason,
    canonical_agent_id,
    canonical_revocation_bytes,
    delegation_key_check,
    key_status_for_reason,
    parse_rfc3339_timestamp,
    signature_allowed,
    validate_revocation_signature,
)

AGENT = "agent://victim.example.com"
T0 = datetime(2026, 4, 9, 14, 30, tzinfo=UTC)


@pytest.fixture(scope="module")
def signer() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk


def _signed(sk: Ed25519PrivateKey, **fields) -> KeyRevocationBody:
    data = {
        "agent_id": AGENT,
        "revoked_key_id": "kid-1",
        "revoked_at": "2026-04-09T14:30:00Z",
        "reason": "key_compromise",
        "signature": "x",
        **fields,
    }
    body = KeyRevocationBody.model_validate(data)
    sig = sk.sign(canonical_revocation_bytes(body))
    return body.model_copy(
        update={"signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}
    )


# ---------------------------------------------------------------------------
# Timestamps and body validation
# ---------------------------------------------------------------------------


class TestRfc3339:
    @pytest.mark.parametrize("value, expected", [
        ("2026-04-09T14:30:00Z", T0),
        ("2026-04-09t14:30:00z", T0),
        ("2026-04-09T16:30:00+02:00", T0),
        ("2026-04-09T14:30:00.123456Z", T0.replace(microsecond=123456)),
    ])
    def test_valid(self, value, expected):
        parsed = parse_rfc3339_timestamp(value)
        assert parsed == expected
        assert parsed.tzinfo is UTC

    @pytest.mark.parametrize("value", [
        "2026-04-09T14:30:00",          # naive
        "2026-04-09",                   # date only
        "2026-04-09 14:30:00Z",         # space separator
        "2026-02-30T00:00:00Z",         # impossible date
        "2026-04-09T24:00:00Z",         # hour 24
        "2026-04-09T14:30:60Z",         # leap second
        "2026-04-09T14:30:00+0200",     # offset without colon
        "2026-04-09T14:30:00Z\n",       # trailing newline
        "２０２６-04-09T14:30:00Z",      # non-ASCII digits
        "1" * 100,                      # oversized
        "",
    ])
    def test_rejected(self, value):
        with pytest.raises(ValueError):
            parse_rfc3339_timestamp(value)

    def test_non_string_rejected(self):
        with pytest.raises(ValueError):
            parse_rfc3339_timestamp(12345)  # type: ignore[arg-type]


class TestBodyValidation:
    base = {
        "agent_id": AGENT,
        "revoked_key_id": "kid-1",
        "revoked_at": "2026-04-09T14:30:00Z",
        "reason": "key_compromise",
        "signature": "sig",
    }

    def test_naive_revoked_at_rejected(self):
        with pytest.raises(ValidationError, match="revoked_at"):
            KeyRevocationBody(**{**self.base, "revoked_at": "2026-04-09T14:30:00"})

    def test_impossible_revoked_at_rejected(self):
        with pytest.raises(ValidationError):
            KeyRevocationBody(**{**self.base, "revoked_at": "2026-02-30T00:00:00Z"})

    def test_compromised_at_accepted_for_compromise(self):
        body = KeyRevocationBody(**{**self.base, "compromised_at": "2026-04-01T00:00:00Z"})
        assert body.compromised_at == "2026-04-01T00:00:00Z"

    @pytest.mark.parametrize("reason", ["key_rotation", "agent_decommissioned"])
    def test_compromised_at_rejected_for_other_reasons(self, reason):
        with pytest.raises(ValidationError, match="compromised_at"):
            KeyRevocationBody(**{**self.base, "reason": reason,
                                 "compromised_at": "2026-04-01T00:00:00Z"})

    def test_compromised_at_after_revoked_at_rejected(self):
        with pytest.raises(ValidationError, match="compromised_at"):
            KeyRevocationBody(**{**self.base, "compromised_at": "2026-04-10T00:00:00Z"})

    def test_naive_compromised_at_rejected(self):
        with pytest.raises(ValidationError):
            KeyRevocationBody(**{**self.base, "compromised_at": "2026-04-01T00:00:00"})

    def test_replacement_equal_to_revoked_rejected(self):
        with pytest.raises(ValidationError, match="replacement_key_id"):
            KeyRevocationBody(**{**self.base, "replacement_key_id": "kid-1"})

    @pytest.mark.parametrize("field, value", [
        ("revoked_key_id", ""),
        ("revoked_key_id", "kid 1"),
        ("revoked_key_id", "kid\n1"),
        ("revoked_key_id", "k" * 257),
        ("agent_id", ""),
        ("agent_id", "agent://a.example.com\r\nX: y"),
        ("agent_id", "agent://" + "a" * 2050),
        ("replacement_key_id", "bad\u0000kid"),
        ("jwks_url", "https://x.example/" + "a" * 2048),
        ("signature", "A" * 257),
    ])
    def test_field_bounds(self, field, value):
        with pytest.raises(ValidationError):
            KeyRevocationBody(**{**self.base, field: value})


class TestCanonicalForm:
    def test_absent_compromised_at_is_omitted(self):
        body = KeyRevocationBody(**TestBodyValidation.base)
        assert b"compromised_at" not in canonical_revocation_bytes(body)
        assert b'"jwks_url":null' in canonical_revocation_bytes(body)

    def test_present_compromised_at_is_signed(self, signer):
        sk, pk = signer
        body = _signed(sk, compromised_at="2026-04-01T00:00:00Z")
        assert b'"compromised_at":"2026-04-01T00:00:00Z"' in canonical_revocation_bytes(body)
        assert validate_revocation_signature(body, pk)
        # Stripping it breaks the signature.
        stripped = body.model_copy(update={"compromised_at": None})
        assert not validate_revocation_signature(stripped, pk)

    def test_adding_compromised_at_after_signing_breaks_signature(self, signer):
        sk, pk = signer
        body = _signed(sk)
        forged = body.model_copy(update={"compromised_at": "2026-04-01T00:00:00Z"})
        assert validate_revocation_signature(body, pk)
        assert not validate_revocation_signature(forged, pk)


# ---------------------------------------------------------------------------
# signature_allowed
# ---------------------------------------------------------------------------


class TestSignatureAllowed:
    before = T0 - timedelta(days=1)
    after = T0 + timedelta(seconds=1)

    def test_active(self):
        assert signature_allowed(KeyStatus.ACTIVE, signed_at=self.after, revoked_at=None)

    def test_rotated_before(self):
        assert signature_allowed(KeyStatus.ROTATED, signed_at=self.before, revoked_at=T0)

    def test_rotated_at_or_after(self):
        assert not signature_allowed(KeyStatus.ROTATED, signed_at=T0, revoked_at=T0)
        assert not signature_allowed(KeyStatus.ROTATED, signed_at=self.after, revoked_at=T0)

    def test_rotated_without_revoked_at_fails_closed(self):
        assert not signature_allowed(KeyStatus.ROTATED, signed_at=self.before, revoked_at=None)

    def test_rotated_with_offset_timezones(self):
        plus2 = timezone(timedelta(hours=2))
        assert signature_allowed(
            KeyStatus.ROTATED, signed_at=datetime(2026, 4, 9, 16, 29, tzinfo=plus2),
            revoked_at=T0,
        )
        assert not signature_allowed(
            KeyStatus.ROTATED, signed_at=datetime(2026, 4, 9, 16, 31, tzinfo=plus2),
            revoked_at=T0,
        )

    @pytest.mark.parametrize("status", [
        KeyStatus.COMPROMISED, KeyStatus.DECOMMISSIONED, KeyStatus.UNKNOWN,
    ])
    def test_never_allowed_even_when_backdated(self, status):
        backdated = datetime(1970, 1, 1, tzinfo=UTC)
        assert not signature_allowed(status, signed_at=backdated, revoked_at=T0)
        assert not signature_allowed(status, signed_at=backdated, revoked_at=None)

    def test_naive_signed_at_fails_closed(self):
        naive = datetime(2026, 1, 1)
        assert not signature_allowed(KeyStatus.ACTIVE, signed_at=naive, revoked_at=None)
        assert not signature_allowed(KeyStatus.ROTATED, signed_at=naive, revoked_at=T0)

    def test_naive_revoked_at_fails_closed(self):
        assert not signature_allowed(
            KeyStatus.ROTATED, signed_at=self.before, revoked_at=datetime(2026, 4, 9)
        )

    @pytest.mark.parametrize("status", ["active", None, 1])
    def test_non_enum_status_fails_closed(self, status):
        assert not signature_allowed(status, signed_at=self.before, revoked_at=T0)  # type: ignore[arg-type]

    def test_non_datetime_signed_at_fails_closed(self):
        assert not signature_allowed(
            KeyStatus.ACTIVE, signed_at="2026-01-01T00:00:00Z", revoked_at=None  # type: ignore[arg-type]
        )

    def test_keyword_only(self):
        with pytest.raises(TypeError):
            signature_allowed(KeyStatus.ACTIVE, self.before, None)  # type: ignore[misc]


def test_reason_mapping():
    assert key_status_for_reason("key_rotation") is KeyStatus.ROTATED
    assert key_status_for_reason(RevocationReason.KEY_COMPROMISE) is KeyStatus.COMPROMISED
    assert key_status_for_reason("agent_decommissioned") is KeyStatus.DECOMMISSIONED
    with pytest.raises(ValueError):
        key_status_for_reason("oops")


# ---------------------------------------------------------------------------
# InMemoryKeyStatusResolver
# ---------------------------------------------------------------------------


def _resolver(pk: bytes, *args, kids=("kid-1",), agent=AGENT, **kwargs):
    r = InMemoryKeyStatusResolver(*args, **kwargs)
    for kid in kids:
        assert r.mark_active(agent, kid, public_key=pk)
    return r


def _revoke(r, body, signer_kid="kid-1", **kwargs):
    return r.add_revocation(body, body.revoked_at_datetime(), signer_kid=signer_kid, **kwargs)


def _other_signer() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TestResolver:
    def test_satisfies_protocol(self):
        assert isinstance(InMemoryKeyStatusResolver(), KeyStatusResolver)

    def test_unknown_by_default(self):
        r = InMemoryKeyStatusResolver()
        assert r.key_status(AGENT, "kid-1") is KeyStatus.UNKNOWN
        assert r.record(AGENT, "kid-1") is None

    def test_malformed_lookup_is_unknown(self):
        r = InMemoryKeyStatusResolver()
        r.mark_active(AGENT, "kid-1")
        assert r.key_status(AGENT, "kid 1") is KeyStatus.UNKNOWN
        assert r.key_status("agent://bad\nhost", "kid-1") is KeyStatus.UNKNOWN
        assert r.key_status(None, "kid-1") is KeyStatus.UNKNOWN  # type: ignore[arg-type]
        assert r.key_status(AGENT, None) is KeyStatus.UNKNOWN  # type: ignore[arg-type]

    def test_mark_active(self):
        r = InMemoryKeyStatusResolver()
        assert r.mark_active(AGENT, "kid-1")
        assert r.key_status(AGENT, "kid-1") is KeyStatus.ACTIVE
        assert r.mark_active(AGENT, "kid-1")
        assert len(r) == 1

    @pytest.mark.parametrize("pk", [b"", b"\x00" * 31, "x" * 32])
    def test_mark_active_rejects_bad_public_key(self, pk):
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver().mark_active(AGENT, "kid-1", public_key=pk)

    def test_mark_active_rejects_malformed(self):
        r = InMemoryKeyStatusResolver()
        with pytest.raises(ValueError):
            r.mark_active(AGENT, "")
        with pytest.raises(ValueError):
            r.mark_active("", "kid")

    @pytest.mark.parametrize("reason, status", [
        ("key_compromise", KeyStatus.COMPROMISED),
        ("key_rotation", KeyStatus.ROTATED),
        ("agent_decommissioned", KeyStatus.DECOMMISSIONED),
    ])
    def test_add_revocation(self, signer, reason, status):
        sk, pk = signer
        r = _resolver(pk)
        body = _signed(sk, reason=reason)
        assert _revoke(r, body) is status
        assert r.key_status(AGENT, "kid-1") is status
        assert r.record(AGENT, "kid-1") == KeyStatusRecord(status, T0)
        assert len(r) == 1

    def test_compromise_ignores_compromised_at_and_backdating(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, compromised_at="2026-04-01T00:00:00Z"))
        rec = r.record(AGENT, "kid-1")
        assert rec is not None
        # A thief back-dates to before both compromised_at and revoked_at.
        assert not signature_allowed(
            rec.status, signed_at=datetime(2020, 1, 1, tzinfo=UTC), revoked_at=rec.revoked_at
        )

    def test_rotation_keeps_earlier_signatures(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, reason="key_rotation"))
        rec = r.record(AGENT, "kid-1")
        assert rec is not None
        assert signature_allowed(rec.status, signed_at=T0 - timedelta(hours=1),
                                 revoked_at=rec.revoked_at)
        assert not signature_allowed(rec.status, signed_at=T0 + timedelta(hours=1),
                                     revoked_at=rec.revoked_at)

    def test_unsigned_revocation_rejected(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        body = _signed(sk).model_copy(update={"signature": "AAAA"})
        with pytest.raises(ValueError, match="signature"):
            _revoke(r, body)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.ACTIVE

    def test_tampered_reason_rejected(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        with pytest.raises(ValueError):
            _revoke(r, _signed(sk).model_copy(update={"reason": "key_rotation"}))

    # -- the signing key must be the revoked agent's own --------------------

    def test_key_from_another_agent_rejected(self, signer):
        """A peer's own valid key cannot revoke someone else's key."""
        sk, pk = signer
        mallory_sk, mallory_pk = _other_signer()
        r = _resolver(pk)
        r.mark_active("agent://mallory.example.com", "kid-1", public_key=mallory_pk)
        body = _signed(mallory_sk)  # names victim's agent_id, signed by mallory
        with pytest.raises(ValueError):
            _revoke(r, body)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.ACTIVE

    def test_unrecorded_signing_key_rejected(self, signer):
        sk, _ = signer
        r = InMemoryKeyStatusResolver()
        r.mark_active(AGENT, "kid-1")  # no key material recorded
        with pytest.raises(ValueError, match="no recorded public key"):
            _revoke(r, _signed(sk))
        assert r.key_status(AGENT, "kid-1") is KeyStatus.ACTIVE

    def test_wrong_key_material_rejected(self, signer):
        sk, _ = signer
        _, other_pk = _other_signer()
        r = _resolver(other_pk)
        with pytest.raises(ValueError, match="signature"):
            _revoke(r, _signed(sk))

    def test_sibling_key_may_revoke(self, signer):
        sk, pk = signer
        sibling_sk, sibling_pk = _other_signer()
        r = _resolver(pk)
        r.mark_active(AGENT, "kid-2", public_key=sibling_pk)
        assert _revoke(r, _signed(sibling_sk), signer_kid="kid-2") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "kid-2") is KeyStatus.ACTIVE

    def test_compromised_key_cannot_revoke_siblings(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _, sibling_pk = _other_signer()
        r.mark_active(AGENT, "kid-2", public_key=sibling_pk)
        _revoke(r, _signed(sk))  # kid-1 revokes itself
        with pytest.raises(ValueError):
            _revoke(r, _signed(sk, revoked_key_id="kid-2"))
        with pytest.raises(ValueError, match="itself revoked"):
            _revoke(r, _signed(sk, revoked_key_id="kid-2"),
                    key_lookup=lambda agent, kid: pk)
        assert r.key_status(AGENT, "kid-2") is KeyStatus.ACTIVE

    def test_revoked_key_can_repeat_its_own_revocation(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, reason="key_rotation"))
        assert _revoke(r, _signed(sk)) is KeyStatus.COMPROMISED

    def test_key_lookup_is_called_with_the_revoked_agent(self, signer):
        sk, pk = signer
        seen = []

        def lookup(agent_id, kid):
            seen.append((agent_id, kid))
            return pk

        r = InMemoryKeyStatusResolver()
        r.mark_active(AGENT, "kid-1")
        assert _revoke(r, _signed(sk), key_lookup=lookup) is KeyStatus.COMPROMISED
        assert seen == [(AGENT, "kid-1")]

    @pytest.mark.parametrize("result", [None, b"short", "x" * 32])
    def test_key_lookup_bad_result(self, signer, result):
        sk, _ = signer
        with pytest.raises(ValueError):
            _revoke(InMemoryKeyStatusResolver(), _signed(sk),
                    key_lookup=lambda agent, kid: result)

    def test_key_lookup_exception_rejects(self, signer):
        sk, _ = signer

        def boom(agent, kid):
            raise RuntimeError("network")

        with pytest.raises(ValueError):
            _revoke(InMemoryKeyStatusResolver(), _signed(sk), key_lookup=boom)

    # -- input validation ---------------------------------------------------

    @pytest.mark.parametrize("bad", [
        datetime(2026, 4, 9, 14, 30),            # naive
        T0 + timedelta(seconds=1),               # mismatch
        "2026-04-09T14:30:00Z",                  # not a datetime
    ])
    def test_bad_revoked_at_dt(self, signer, bad):
        sk, pk = signer
        body = _signed(sk)
        with pytest.raises(ValueError):
            _resolver(pk).add_revocation(body, bad, signer_kid="kid-1")

    def test_equivalent_revoked_at_dt_accepted(self, signer):
        sk, pk = signer
        body = _signed(sk)
        plus2 = timezone(timedelta(hours=2))
        r = _resolver(pk)
        r.add_revocation(body, T0.astimezone(plus2), signer_kid="kid-1")
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_non_body_rejected(self, signer):
        _, pk = signer
        with pytest.raises(ValueError):
            _resolver(pk).add_revocation(
                {"agent_id": AGENT}, T0, signer_kid="kid-1")  # type: ignore[arg-type]

    # -- no downgrades ------------------------------------------------------

    def test_no_downgrade_via_mark_active(self, signer):
        sk, pk = signer
        for reason in ("key_compromise", "key_rotation", "agent_decommissioned"):
            r = _resolver(pk)
            status = _revoke(r, _signed(sk, reason=reason))
            assert r.mark_active(AGENT, "kid-1", public_key=pk) is False
            assert r.key_status(AGENT, "kid-1") is status

    def test_no_downgrade_compromise_to_rotation(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk))
        rot = _signed(sk, reason="key_rotation", revoked_at="2026-05-01T00:00:00Z")
        assert _revoke(r, rot) is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_rotation_upgraded_to_compromise(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, reason="key_rotation"))
        _revoke(r, _signed(sk, revoked_at="2026-05-01T00:00:00Z"))
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_decommission_upgraded_to_compromise_not_back(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, reason="agent_decommissioned"))
        _revoke(r, _signed(sk))
        _revoke(r, _signed(sk, reason="agent_decommissioned"))
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED
        assert len(r) == 1

    def test_two_rotations_keep_earliest(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk, reason="key_rotation", revoked_at="2026-05-01T00:00:00Z"))
        _revoke(r, _signed(sk, reason="key_rotation"))
        _revoke(r, _signed(sk, reason="key_rotation", revoked_at="2026-05-01T00:00:00Z"))
        assert r.record(AGENT, "kid-1") == KeyStatusRecord(KeyStatus.ROTATED, T0)

    # -- agent id spellings -------------------------------------------------

    def test_agent_id_spellings_share_one_record(self, signer):
        sk, pk = signer
        r = _resolver(pk, agent="agent://Bücher.Example")
        _revoke(r, _signed(sk, agent_id="agent://Bücher.Example"))
        for spelling in ("agent://xn--bcher-kva.example", "AGENT://BÜCHER.example",
                         "agent://bücher.example", "agent://bücher.example:443",
                         "agent://bücher.example:8443", "agent://b%C3%BCcher.example"):
            assert r.key_status(spelling, "kid-1") is KeyStatus.COMPROMISED, spelling
            assert r.mark_active(spelling, "kid-1") is False

    @pytest.mark.parametrize("spelling", [
        "agent://victim.example.com.",
        "agent://victim.example.com/",
        "agent://victim.example.com/x",
        "agent://victim.example.com%2F",
        "agent://victim.example.com?x",
        "agent://victim.example.com#x",
        "agent://victim.example.com\\",
        "agent://sales@victim.example.com.",
    ])
    def test_ambiguous_spellings_refused(self, signer, spelling):
        """Spellings DNS folds together must not dodge a revocation."""
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk))
        with pytest.raises(ValueError):
            canonical_agent_id(spelling)
        assert r.key_status(spelling, "kid-1") is KeyStatus.UNKNOWN
        check = delegation_key_check(r, unknown_is_active=True)
        assert check(spelling, "kid-1", T0) is False
        assert check(AGENT, "kid-1", T0) is False

    def test_slug_registry_normalised(self):
        assert canonical_agent_id("agent://Sales@Bücher.example") == \
            canonical_agent_id("agent://sales@xn--bcher-kva.example")

    def test_port_dropped(self):
        assert canonical_agent_id("agent://h.example:8443") == "agent://h.example"

    def test_kid_is_case_sensitive(self, signer):
        sk, pk = signer
        r = _resolver(pk)
        _revoke(r, _signed(sk))
        assert r.key_status(AGENT, "KID-1") is KeyStatus.UNKNOWN

    # -- bounds -------------------------------------------------------------

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10"])
    def test_bad_bounds(self, bad):
        for kwargs in ({"max_revocations": bad}, {"max_unsolicited": bad},
                       {"max_revocations_per_agent": bad}):
            with pytest.raises(ValueError):
                InMemoryKeyStatusResolver(**kwargs)
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver(bad)

    def test_lru_evicts_active(self, signer):
        r = InMemoryKeyStatusResolver(3)
        for kid in ("a", "b", "c"):
            assert r.mark_active(AGENT, kid)
        r.key_status(AGENT, "a")  # touch: "b" is now least recently used
        assert r.mark_active(AGENT, "d")
        assert r.key_status(AGENT, "b") is KeyStatus.UNKNOWN
        assert r.key_status(AGENT, "a") is KeyStatus.ACTIVE
        assert r.key_status(AGENT, "d") is KeyStatus.ACTIVE

    def test_active_to_revoked_does_not_grow(self, signer):
        sk, pk = signer
        r = _resolver(pk, 1)
        _revoke(r, _signed(sk))
        assert len(r) == 1
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_revocations_do_not_block_active_keys(self, signer):
        """The reported flood: revocations can never stop mark_active."""
        r = InMemoryKeyStatusResolver(4, max_revocations=4, max_unsolicited=4)
        for n in range(20):
            sk, pk = _other_signer()
            agent = f"agent://attacker{n}.example"
            r.mark_active(agent, "kid-1", public_key=pk)
            _revoke(r, _signed(sk, agent_id=agent))
        assert r.mark_active(AGENT, "fresh") is True
        assert r.key_status(AGENT, "fresh") is KeyStatus.ACTIVE

    def test_victim_compromise_never_raises_when_full(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(8, max_revocations=4, max_unsolicited=4)
        for n in range(10):
            a_sk, a_pk = _other_signer()
            agent = f"agent://attacker{n}.example"
            r.mark_active(agent, "kid-1", public_key=a_pk)
            _revoke(r, _signed(a_sk, agent_id=agent))
        assert r.mark_active(AGENT, "kid-1", public_key=pk)
        assert _revoke(r, _signed(sk)) is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED
        assert len(r) <= 8 + 4 + 4

    def test_rotated_evicted_before_compromised(self, signer):
        r = InMemoryKeyStatusResolver(max_revocations=2)
        keys = {}
        for kid, reason in (("c", "key_compromise"), ("r", "key_rotation"),
                            ("x", "key_compromise")):
            sk, pk = _other_signer()
            keys[kid] = sk
            r.mark_active(AGENT, kid, public_key=pk)
            _revoke(r, _signed(sk, revoked_key_id=kid, reason=reason), signer_kid=kid)
        assert r.key_status(AGENT, "r") is KeyStatus.UNKNOWN
        assert r.key_status(AGENT, "c") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "x") is KeyStatus.COMPROMISED

    def test_unsolicited_pool_is_lru(self, signer):
        r = InMemoryKeyStatusResolver(max_unsolicited=2)
        sk, pk = _other_signer()
        for kid in ("u1", "u2", "u3"):
            body = _signed(sk, revoked_key_id=kid)
            r.add_revocation(body, body.revoked_at_datetime(), signer_kid=kid,
                             key_lookup=lambda agent, k: pk)
        assert r.key_status(AGENT, "u1") is KeyStatus.UNKNOWN
        assert r.key_status(AGENT, "u2") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "u3") is KeyStatus.COMPROMISED
        assert r.mark_active(AGENT, "u3") is False
        assert len(r) == 2

    def test_per_agent_flood_collapses_to_tombstone(self, signer):
        r = InMemoryKeyStatusResolver(max_revocations_per_agent=3)
        r.mark_active("agent://bystander.example.com", "kid-1")
        for i in range(3):
            sk, pk = _other_signer()
            r.mark_active(AGENT, f"k{i}", public_key=pk)
            assert _revoke(r, _signed(sk, revoked_key_id=f"k{i}", reason="key_rotation"),
                           signer_kid=f"k{i}") is KeyStatus.ROTATED
        sk, pk = _other_signer()
        r.mark_active(AGENT, "k3", public_key=pk)
        assert _revoke(r, _signed(sk, revoked_key_id="k3", reason="key_rotation"),
                       signer_kid="k3") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "k0") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "never-seen") is KeyStatus.COMPROMISED
        assert r.mark_active(AGENT, "fresh") is False
        assert r.key_status("agent://bystander.example.com", "kid-1") is KeyStatus.ACTIVE
        assert len(r) == 2  # bystander + tombstone

    def test_thread_safety_smoke(self, signer):
        r = InMemoryKeyStatusResolver(50)

        def worker(n: int) -> None:
            for i in range(200):
                r.mark_active(AGENT, f"t{n}-{i}")
                r.key_status(AGENT, f"t{n}-{i // 2}")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(r) <= 50


def test_exports():
    import ampro
    import ampro.security as sec

    for name in ("KeyStatus", "KeyStatusResolver", "InMemoryKeyStatusResolver",
                 "signature_allowed", "KeyStatusRecord"):
        assert name in ampro.__all__ and name in sec.__all__
        assert getattr(ampro, name) is getattr(sec, name)
