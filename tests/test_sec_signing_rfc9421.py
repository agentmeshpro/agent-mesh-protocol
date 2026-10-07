"""Regression tests for RFC 9421 verification hardening.

Covers:
  * nonce recorded only AFTER the signature verifies (forged requests can
    neither burn a legitimate nonce nor fill the replay cache);
  * nonces keyed by (keyid, nonce);
  * a full NonceTracker evicts instead of denying everyone;
  * content-digest must be covered and match when a non-empty body is sent;
  * malformed base64 in ``Signature`` returns False instead of raising;
  * a covered header that is missing fails verification;
  * ``@authority`` excludes userinfo and default ports and is lowercased.
"""
from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ampro.security.nonce_tracker import NonceTracker
from ampro.security.rfc9421 import (
    create_signature_base,
    sign_request,
    verify_request,
)

URL = "https://a.example.com/x"


def _keypair() -> tuple[Ed25519PrivateKey, bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, priv_bytes, pub_bytes


def _signed(priv_bytes: bytes, *, nonce: str, key_id: str = "k1",
            body: bytes | None = b"{}") -> dict[str, str]:
    headers: dict[str, str] = {"content-type": "application/json"}
    headers.update(sign_request(priv_bytes, key_id, "POST", URL, headers,
                                body=body, nonce=nonce))
    return headers


class TestNonceRecordedAfterVerification:
    def test_forged_request_does_not_burn_nonce(self) -> None:
        _, priv, pub = _keypair()
        tracker = NonceTracker()
        nonce = secrets.token_hex(8)
        good = _signed(priv, nonce=nonce)

        # Attacker copies the Signature-Input (same nonce) but cannot sign.
        forged = dict(good)
        forged["Signature"] = "sig1=:" + base64.b64encode(b"\x00" * 64).decode() + ":"
        assert verify_request(pub, "POST", URL, forged, body=b"{}",
                              nonce_tracker=tracker) is False

        # The legitimate request must still verify.
        assert verify_request(pub, "POST", URL, good, body=b"{}",
                              nonce_tracker=tracker) is True
        assert verify_request(pub, "POST", URL, good, body=b"{}",
                              nonce_tracker=tracker) is False

    def test_forged_requests_do_not_fill_tracker(self) -> None:
        _, priv, pub = _keypair()
        tracker = NonceTracker(max_size=5)
        for _ in range(20):
            forged = _signed(priv, nonce=secrets.token_hex(8))
            forged["Signature"] = "sig1=:" + base64.b64encode(b"\x01" * 64).decode() + ":"
            assert verify_request(pub, "POST", URL, forged, body=b"{}",
                                  nonce_tracker=tracker) is False
        assert tracker.seen_count() == 0
        good = _signed(priv, nonce=secrets.token_hex(8))
        assert verify_request(pub, "POST", URL, good, body=b"{}",
                              nonce_tracker=tracker) is True

    def test_nonce_scoped_per_keyid(self) -> None:
        _, priv_a, pub_a = _keypair()
        _, priv_b, pub_b = _keypair()
        tracker = NonceTracker()
        nonce = "shared-nonce"
        a = _signed(priv_a, nonce=nonce, key_id="alice")
        b = _signed(priv_b, nonce=nonce, key_id="bob")
        assert verify_request(pub_a, "POST", URL, a, body=b"{}", nonce_tracker=tracker)
        assert verify_request(pub_b, "POST", URL, b, body=b"{}", nonce_tracker=tracker)


class TestNonceTrackerFull:
    def test_full_tracker_evicts_oldest_instead_of_denying(self) -> None:
        tracker = NonceTracker(max_size=3)
        for n in ("a", "b", "c"):
            assert tracker.is_replay(n) is False
        # Full of fresh entries: new nonce is still accepted.
        assert tracker.is_replay("d") is False
        assert tracker.seen_count() == 3
        # Most recent entries are retained.
        assert tracker.is_replay("d") is True
        assert tracker.is_replay("c") is True


class TestContentDigestRequired:
    def test_body_without_covered_digest_rejected(self) -> None:
        _, priv, pub = _keypair()
        headers: dict[str, str] = {"content-type": "application/json"}
        # Sign WITHOUT a body -> content-digest not covered.
        headers.update(sign_request(priv, "k1", "POST", URL, headers,
                                    nonce=secrets.token_hex(8)))
        assert verify_request(pub, "POST", URL, headers,
                              body=b'{"evil": true}') is False

    def test_mismatched_digest_rejected(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8), body=b"{}")
        assert verify_request(pub, "POST", URL, headers, body=b"{ }") is False

    def test_empty_body_without_digest_ok(self) -> None:
        _, priv, pub = _keypair()
        headers: dict[str, str] = {}
        headers.update(sign_request(priv, "k1", "GET", URL, headers,
                                    nonce=secrets.token_hex(8)))
        assert verify_request(pub, "GET", URL, headers, body=b"") is True
        headers2: dict[str, str] = {}
        headers2.update(sign_request(priv, "k1", "GET", URL, headers2,
                                     nonce=secrets.token_hex(8)))
        assert verify_request(pub, "GET", URL, headers2) is True


class TestMalformedInput:
    def test_bad_base64_returns_false(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8))
        for bad in ("sig1=:A:", "sig1=:AAAAA:", "sig1=:====:"):
            h = dict(headers)
            h["Signature"] = bad
            assert verify_request(pub, "POST", URL, h, body=b"{}") is False

    def test_newline_url_returns_false(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8))
        assert verify_request(pub, "POST", URL + "\n", headers, body=b"{}") is False

    def test_bad_port_returns_false(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8))
        assert verify_request(pub, "POST", "https://a.example.com:99999/x",
                              headers, body=b"{}") is False


class TestMissingCoveredHeader:
    def test_missing_covered_header_fails(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8))
        # content-type was covered; dropping it must fail, not become "".
        del headers["content-type"]
        assert verify_request(pub, "POST", URL, headers, body=b"{}") is False

    def test_absent_header_not_equivalent_to_empty(self) -> None:
        """A signature over ``x-h: ""`` must not verify when x-h is absent."""
        import time

        priv, _, pub = _keypair()
        created = int(time.time())
        nonce = secrets.token_hex(8)
        covered = ["@method", "@target-uri", "x-h"]
        base = create_signature_base("GET", URL, {"x-h": ""}, covered,
                                     created=created, keyid="k1", nonce=nonce)
        sig = base64.b64encode(priv.sign(base.encode())).decode()
        headers = {
            "Signature": f"sig1=:{sig}:",
            "Signature-Input": (
                f'sig1=("@method" "@target-uri" "x-h");created={created};'
                f'keyid="k1";alg="ed25519";nonce="{nonce}"'
            ),
        }
        assert verify_request(pub, "GET", URL, headers) is False
        headers["x-h"] = ""
        assert verify_request(pub, "GET", URL, headers) is True

    def test_signer_cannot_cover_absent_header(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            create_signature_base("GET", URL, {}, ["x-missing"], created=1)


class TestAuthority:
    def _authority(self, url: str) -> str:
        base = create_signature_base("GET", url, {}, ["@authority"], created=1)
        return base.splitlines()[0]

    def test_userinfo_excluded(self) -> None:
        assert self._authority("https://user:pw@A.Example.com/x") == '"@authority": a.example.com'

    def test_default_port_removed(self) -> None:
        assert self._authority("https://a.example.com:443/x") == '"@authority": a.example.com'
        assert self._authority("http://a.example.com:80/x") == '"@authority": a.example.com'

    def test_non_default_port_kept(self) -> None:
        assert self._authority("https://a.example.com:8443/x") == '"@authority": a.example.com:8443'

    def test_ipv6(self) -> None:
        assert self._authority("https://[::1]:8443/x") == '"@authority": [::1]:8443'

    def test_userinfo_does_not_change_verification(self) -> None:
        _, priv, pub = _keypair()
        headers = _signed(priv, nonce=secrets.token_hex(8))
        assert verify_request(pub, "POST", "https://a.example.com/x", headers,
                              body=b"{}") is True


def test_signature_must_cover_method_and_target():
    """A signature that omits @method/@target-uri could be replayed on another route."""
    import base64
    import time

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ampro.security.nonce_tracker import NonceTracker
    from ampro.security.rfc9421 import create_signature_base, verify_request

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    created = int(time.time())
    url = "https://a.example/agent/message"
    headers = {"content-type": "application/json"}
    base = create_signature_base(
        "POST", url, headers, ["content-type"], created=created, keyid="k1", nonce="n-1",
    )
    sig = base64.b64encode(sk.sign(base.encode())).decode()
    headers["Signature-Input"] = (
        f'sig1=("content-type");created={created};keyid="k1";alg="ed25519";nonce="n-1"'
    )
    headers["Signature"] = f"sig1=:{sig}:"
    assert not verify_request(pk, "POST", url, headers, None, nonce_tracker=NonceTracker())
