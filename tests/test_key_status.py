"""Key compromise vs rotation semantics (WIRE-BINDING 12.12.1).

Covers the strict RFC 3339 timestamps and ``compromised_at`` on
``key.revocation``, :func:`signature_allowed`, and the bounded
:class:`InMemoryKeyStatusResolver` (authenticated ingest only, no
downgrades, never evicting revocations).
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
    KeyStatusStoreFullError,
    RevocationReason,
    canonical_agent_id,
    canonical_revocation_bytes,
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

    def test_mark_active(self):
        r = InMemoryKeyStatusResolver()
        assert r.mark_active(AGENT, "kid-1")
        assert r.key_status(AGENT, "kid-1") is KeyStatus.ACTIVE
        assert r.mark_active(AGENT, "kid-1")
        assert len(r) == 1

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
        r = InMemoryKeyStatusResolver()
        r.mark_active(AGENT, "kid-1")
        body = _signed(sk, reason=reason)
        assert r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk) is status
        assert r.key_status(AGENT, "kid-1") is status
        assert r.record(AGENT, "kid-1") == KeyStatusRecord(status, T0)
        assert len(r) == 1

    def test_compromise_ignores_compromised_at_and_backdating(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk, compromised_at="2026-04-01T00:00:00Z")
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        rec = r.record(AGENT, "kid-1")
        assert rec is not None
        # A thief back-dates to before both compromised_at and revoked_at.
        assert not signature_allowed(
            rec.status, signed_at=datetime(2020, 1, 1, tzinfo=UTC), revoked_at=rec.revoked_at
        )

    def test_rotation_keeps_earlier_signatures(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk, reason="key_rotation")
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        rec = r.record(AGENT, "kid-1")
        assert rec is not None
        assert signature_allowed(rec.status, signed_at=T0 - timedelta(hours=1),
                                 revoked_at=rec.revoked_at)
        assert not signature_allowed(rec.status, signed_at=T0 + timedelta(hours=1),
                                     revoked_at=rec.revoked_at)

    def test_unsigned_revocation_rejected(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk).model_copy(update={"signature": "AAAA"})
        with pytest.raises(ValueError, match="signature"):
            r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.UNKNOWN

    def test_wrong_key_rejected(self, signer):
        sk, _ = signer
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        r = InMemoryKeyStatusResolver()
        body = _signed(sk)
        with pytest.raises(ValueError):
            r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=other)

    def test_tampered_reason_rejected(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk).model_copy(update={"reason": "key_rotation"})
        with pytest.raises(ValueError):
            r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)

    @pytest.mark.parametrize("bad", [
        datetime(2026, 4, 9, 14, 30),            # naive
        T0 + timedelta(seconds=1),               # mismatch
        "2026-04-09T14:30:00Z",                  # not a datetime
    ])
    def test_bad_revoked_at_dt(self, signer, bad):
        sk, pk = signer
        body = _signed(sk)
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver().add_revocation(body, bad, public_key_bytes=pk)

    def test_equivalent_revoked_at_dt_accepted(self, signer):
        sk, pk = signer
        body = _signed(sk)
        plus2 = timezone(timedelta(hours=2))
        r = InMemoryKeyStatusResolver()
        r.add_revocation(body, T0.astimezone(plus2), public_key_bytes=pk)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    @pytest.mark.parametrize("pk", [b"", b"\x00" * 31, "x" * 32, None])
    def test_bad_public_key(self, signer, pk):
        sk, _ = signer
        body = _signed(sk)
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver().add_revocation(
                body, body.revoked_at_datetime(), public_key_bytes=pk)

    def test_non_body_rejected(self, signer):
        _, pk = signer
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver().add_revocation(
                {"agent_id": AGENT}, T0, public_key_bytes=pk)  # type: ignore[arg-type]

    def test_no_downgrade_via_mark_active(self, signer):
        sk, pk = signer
        for reason in ("key_compromise", "key_rotation", "agent_decommissioned"):
            r = InMemoryKeyStatusResolver()
            body = _signed(sk, reason=reason)
            status = r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
            assert r.mark_active(AGENT, "kid-1") is False
            assert r.key_status(AGENT, "kid-1") is status

    def test_no_downgrade_compromise_to_rotation(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        comp = _signed(sk)
        rot = _signed(sk, reason="key_rotation", revoked_at="2026-05-01T00:00:00Z")
        r.add_revocation(comp, comp.revoked_at_datetime(), public_key_bytes=pk)
        assert r.add_revocation(rot, rot.revoked_at_datetime(),
                                public_key_bytes=pk) is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_rotation_upgraded_to_compromise(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        rot = _signed(sk, reason="key_rotation")
        comp = _signed(sk, revoked_at="2026-05-01T00:00:00Z")
        r.add_revocation(rot, rot.revoked_at_datetime(), public_key_bytes=pk)
        r.add_revocation(comp, comp.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_decommission_upgraded_to_compromise_not_back(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        dec = _signed(sk, reason="agent_decommissioned")
        comp = _signed(sk)
        r.add_revocation(dec, dec.revoked_at_datetime(), public_key_bytes=pk)
        r.add_revocation(comp, comp.revoked_at_datetime(), public_key_bytes=pk)
        r.add_revocation(dec, dec.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_two_rotations_keep_earliest(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        late = _signed(sk, reason="key_rotation", revoked_at="2026-05-01T00:00:00Z")
        early = _signed(sk, reason="key_rotation")
        r.add_revocation(late, late.revoked_at_datetime(), public_key_bytes=pk)
        r.add_revocation(early, early.revoked_at_datetime(), public_key_bytes=pk)
        r.add_revocation(late, late.revoked_at_datetime(), public_key_bytes=pk)
        rec = r.record(AGENT, "kid-1")
        assert rec == KeyStatusRecord(KeyStatus.ROTATED, T0)

    def test_agent_id_spellings_share_one_record(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk, agent_id="agent://Bücher.Example")
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        for spelling in ("agent://xn--bcher-kva.example", "AGENT://BÜCHER.example",
                         "agent://bücher.example"):
            assert r.key_status(spelling, "kid-1") is KeyStatus.COMPROMISED, spelling
            assert r.mark_active(spelling, "kid-1") is False

    def test_slug_registry_normalised(self):
        assert canonical_agent_id("agent://Sales@Bücher.example") == \
            canonical_agent_id("agent://sales@xn--bcher-kva.example")

    def test_kid_is_case_sensitive(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver()
        body = _signed(sk)
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "KID-1") is KeyStatus.UNKNOWN

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10"])
    def test_bad_bounds(self, bad):
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver(bad)
        with pytest.raises(ValueError):
            InMemoryKeyStatusResolver(max_revocations_per_agent=bad)

    def test_lru_evicts_active_only(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(3)
        body = _signed(sk)
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        assert r.mark_active(AGENT, "a")
        assert r.mark_active(AGENT, "b")
        r.key_status(AGENT, "a")  # touch: "b" is now least recently used
        assert r.mark_active(AGENT, "c")
        assert len(r) == 3
        assert r.key_status(AGENT, "b") is KeyStatus.UNKNOWN
        assert r.key_status(AGENT, "a") is KeyStatus.ACTIVE
        assert r.key_status(AGENT, "c") is KeyStatus.ACTIVE
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_compromised_never_evicted(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(2)
        for kid in ("k1", "k2"):
            b = _signed(sk, revoked_key_id=kid)
            r.add_revocation(b, b.revoked_at_datetime(), public_key_bytes=pk)
        # Full of revocations: an ACTIVE mark is refused (stays UNKNOWN) ...
        assert r.mark_active(AGENT, "k3") is False
        assert r.key_status(AGENT, "k3") is KeyStatus.UNKNOWN
        # ... and a new revocation raises instead of being dropped.
        b3 = _signed(sk, revoked_key_id="k3")
        with pytest.raises(KeyStatusStoreFullError):
            r.add_revocation(b3, b3.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "k1") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "k2") is KeyStatus.COMPROMISED

    def test_revocation_evicts_active_to_make_room(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(1)
        r.mark_active(AGENT, "other")
        body = _signed(sk)
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED
        assert r.key_status(AGENT, "other") is KeyStatus.UNKNOWN

    def test_active_to_revoked_does_not_grow(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(1)
        r.mark_active(AGENT, "kid-1")
        body = _signed(sk)
        r.add_revocation(body, body.revoked_at_datetime(), public_key_bytes=pk)
        assert len(r) == 1
        assert r.key_status(AGENT, "kid-1") is KeyStatus.COMPROMISED

    def test_per_agent_flood_collapses_to_tombstone(self, signer):
        sk, pk = signer
        r = InMemoryKeyStatusResolver(max_revocations_per_agent=3)
        r.mark_active("agent://bystander.example.com", "kid-1")
        for i in range(3):
            b = _signed(sk, revoked_key_id=f"k{i}", reason="key_rotation")
            assert r.add_revocation(b, b.revoked_at_datetime(),
                                    public_key_bytes=pk) is KeyStatus.ROTATED
        b = _signed(sk, revoked_key_id="k3", reason="key_rotation")
        assert r.add_revocation(b, b.revoked_at_datetime(),
                                public_key_bytes=pk) is KeyStatus.COMPROMISED
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
                 "signature_allowed", "KeyStatusStoreFullError", "KeyStatusRecord"):
        assert name in ampro.__all__ and name in sec.__all__
        assert getattr(ampro, name) is getattr(sec, name)
