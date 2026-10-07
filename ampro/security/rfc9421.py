"""
Agent Protocol -- RFC 9421 HTTP Message Signatures.

Implements HTTP message signing and verification using Ed25519,
following RFC 9421 (HTTP Message Signatures) conventions.

Covered components: @method, @target-uri, @authority,
content-digest, content-type.

NOTE: This file must NOT import any app.* modules outside
protocol siblings -- it is protocol-pure.
"""

# ─── Reference implementation, not production-wired ────────────────
# This module is part of the AMP protocol surface and is validated by
# the test suite against the normative spec at
# `docs/WIRE-BINDING.md`. It has no first-party runtime caller as of
# ampro v0.3.0; downstream implementers may depend on it directly, or
# provide their own implementation conforming to the same contract.
#
# RFC 9421 (HTTP Message Signatures) canonicalisation primitives.
# Higher-level authentication wrappers live in
# `ampro.identity.auth_methods`; this module is the underlying
# canonicaliser. Keep in sync with the normative RFC, not with any
# caller.
# ───────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:
    from ampro.security.nonce_tracker import NonceTracker

# Default freshness window for ``created`` in signed requests. A verifier
# rejects signatures whose ``created`` is older — or further in the future —
# than this many seconds. Callers that need to relax or tighten the window
# pass ``max_age_seconds`` to :func:`verify_request`; passing ``None``
# disables the check (fixture-only usage).
DEFAULT_MAX_SIGNATURE_AGE_SECONDS = 300

# Algorithms this RFC 9421 implementation can verify. The signed signature
# base embeds ``alg``; verifiers MUST reject anything outside this set so
# that future multi-algorithm verifiers cannot be tricked into
# algorithm-confusion (e.g. accepting an Ed25519 signature while the
# Signature-Input claims RSA).
_SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"ed25519"})

# Process-wide default replay cache. Used by ``verify_request`` when the
# caller does not pass an explicit ``nonce_tracker``. The previous default
# (``None``) silently disabled replay protection — fail-open in the API
# surface. With this module-level default, any signature carrying a nonce
# is automatically replay-checked even when the caller forgets.
_DEFAULT_NONCE_TRACKER: NonceTracker | None = None


def _get_default_nonce_tracker() -> NonceTracker:
    """Lazily instantiate the module-level default NonceTracker."""
    global _DEFAULT_NONCE_TRACKER
    if _DEFAULT_NONCE_TRACKER is None:
        from ampro.security.nonce_tracker import NonceTracker as _NT
        _DEFAULT_NONCE_TRACKER = _NT()
    return _DEFAULT_NONCE_TRACKER

# ---------------------------------------------------------------------------
# Content-Digest helper
# ---------------------------------------------------------------------------


def _content_digest_sha256(body: bytes) -> str:
    """
    Compute Content-Digest header value per RFC 9530.

    Returns:
        String in format ``sha-256=:<base64>:``
    """
    digest = hashlib.sha256(body).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return f"sha-256=:{b64}:"


# ---------------------------------------------------------------------------
# Signature base construction
# ---------------------------------------------------------------------------

# Derived components start with "@"
_DERIVED_COMPONENTS = {"@method", "@target-uri", "@authority"}

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _authority(url: str) -> str:
    """Return the ``@authority`` value per RFC 9421 §2.2.3.

    ``host[:port]`` — lowercased, userinfo stripped, and the port omitted
    when it is the default for the scheme. Raises ``ValueError`` for an
    invalid port.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if ":" in host:  # IPv6 literal — urlparse strips the brackets
        host = f"[{host}]"
    port = parsed.port  # raises ValueError when out of range
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme.lower()):
        return f"{host}:{port}"
    return host


def create_signature_base(
    method: str,
    url: str,
    headers: dict[str, str],
    covered_components: list[str],
    *,
    created: int | None = None,
    keyid: str = "",
    nonce: str | None = None,
) -> str:
    """
    Build the signature base string per RFC 9421 Section 2.5.

    Each covered component occupies its own line in the format::

        "<component>": <value>

    The final line is the ``@signature-params`` pseudo-component
    containing the ordered list of covered components plus metadata.

    Args:
        method: HTTP method (GET, POST, ...).
        url: Full request URL.
        headers: HTTP headers (case-insensitive lookup).
        covered_components: Ordered list of component identifiers
            (e.g. ``["@method", "@target-uri", "content-type"]``).
        created: Unix timestamp; defaults to ``int(time.time())``.
        keyid: Key identifier to embed in signature params.

    Returns:
        The signature base string ready for signing.
    """
    # Reject all forms of newlines and line separators
    if "\n" in url or "\r" in url:
        raise ValueError("URL must not contain newline characters")
    if "%0a" in url.lower() or "%0d" in url.lower():
        raise ValueError("URL must not contain encoded newline characters")
    if "\u2028" in url or "\u2029" in url:
        raise ValueError("URL must not contain Unicode line separators")
    if "\x00" in url:
        raise ValueError("URL must not contain null bytes")

    if created is None:
        created = int(time.time())

    # Case-insensitive header lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}

    lines: list[str] = []
    for comp in covered_components:
        if comp == "@method":
            lines.append(f'"@method": {method.upper()}')
        elif comp == "@target-uri":
            lines.append(f'"@target-uri": {url}')
        elif comp == "@authority":
            lines.append(f'"@authority": {_authority(url)}')
        else:
            # Regular header field. RFC 9421 §2.5: a covered component that
            # is absent from the message MUST cause signing/verification to
            # fail — treating it as "" would let an attacker strip a header
            # whose signed value was empty (or drop one entirely).
            key = comp.lower()
            if key not in lower_headers:
                raise ValueError(f"covered component {comp!r} is not present")
            lines.append(f'"{comp}": {lower_headers[key]}')

    # Build @signature-params
    comp_list = " ".join(f'"{c}"' for c in covered_components)
    sig_params = f"({comp_list});created={created};keyid=\"{keyid}\";alg=\"ed25519\""
    if nonce is not None:
        sig_params += f';nonce="{nonce}"'
    lines.append(f'"@signature-params": {sig_params}')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_request(
    private_key_bytes: bytes,
    key_id: str,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    *,
    nonce: str | None = None,
) -> dict[str, str]:
    """
    Sign an HTTP request per RFC 9421.

    If *body* is provided, a ``content-digest`` header value is computed
    and included in the covered components automatically.

    Args:
        private_key_bytes: Raw 32-byte Ed25519 private key.
        key_id: Key identifier (embedded in Signature-Input).
        method: HTTP method.
        url: Full request URL.
        headers: Mutable dict of HTTP headers (``content-digest`` is
            added when *body* is present).
        body: Optional request body bytes.
        nonce: Optional per-request nonce. When supplied it is bound
            into the signature base via the ``nonce`` signature-input
            parameter (RFC 9421 §2.3) so verifiers that track nonces
            can detect replays.

    Returns:
        Dict with ``Signature`` and ``Signature-Input`` header values
        to merge into the outgoing request headers.
    """
    # Determine covered components
    covered: list[str] = ["@method", "@target-uri", "@authority"]

    # If body is present, compute content-digest and add to headers
    if body is not None:
        digest_value = _content_digest_sha256(body)
        headers["content-digest"] = digest_value
        covered.append("content-digest")

    # Include content-type if present in headers
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if "content-type" in lower_headers:
        covered.append("content-type")

    created = int(time.time())

    sig_base = create_signature_base(
        method=method,
        url=url,
        headers=headers,
        covered_components=covered,
        created=created,
        keyid=key_id,
        nonce=nonce,
    )

    # Sign with Ed25519
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature_bytes = private_key.sign(sig_base.encode("utf-8"))
    sig_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Build Signature-Input
    comp_list = " ".join(f'"{c}"' for c in covered)
    sig_input = f'sig1=({comp_list});created={created};keyid="{key_id}";alg="ed25519"'
    if nonce is not None:
        sig_input += f';nonce="{nonce}"'

    return {
        "Signature": f"sig1=:{sig_b64}:",
        "Signature-Input": sig_input,
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

# Pattern to parse Signature-Input value.
# ``nonce`` is optional (RFC 9421 §2.3 — MAY be present) and, when present,
# may appear before or after alg; we grab it with a separate search below
# rather than trying to order every parameter in one anchored pattern.
_SIG_INPUT_RE = re.compile(
    r"sig1=\((?P<components>[^)]*)\)"
    r";created=(?P<created>\d+)"
    r';keyid="(?P<keyid>[^"]*)"'
    r';alg="(?P<alg>[^"]*)"'
)
_SIG_INPUT_NONCE_RE = re.compile(r';nonce="(?P<nonce>[^"]+)"')


def verify_request(
    public_key_bytes: bytes,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    *,
    max_age_seconds: int | None = DEFAULT_MAX_SIGNATURE_AGE_SECONDS,
    nonce_tracker: NonceTracker | None = None,
) -> bool:
    """
    Verify an RFC 9421 signed HTTP request.

    Parses ``Signature-Input`` to determine the covered components,
    reconstructs the signature base, and verifies the Ed25519 signature.

    If a non-empty *body* is provided, ``content-digest`` MUST be among
    the covered components and MUST match the body; otherwise the request
    is rejected. A covered header that is absent fails verification.
    Malformed input always yields ``False`` (never raises).

    Freshness and replay:
      * When ``max_age_seconds`` is not ``None`` the verifier rejects any
        signature whose ``created`` timestamp is older than, or more than
        ``max_age_seconds`` in the future of, the current wall clock.
        Passing ``None`` disables the check (fixture-only usage).
      * The signature **must** carry a ``nonce`` parameter (unless
        ``max_age_seconds`` is ``None``). After the signature verifies, the
        ``(keyid, nonce)`` pair is recorded in ``nonce_tracker`` (or a
        process-wide default) and reuse causes rejection.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key.
        method: HTTP method.
        url: Full request URL.
        headers: HTTP headers (must include ``Signature``,
            ``Signature-Input``, and any covered header fields).
        body: Optional request body bytes.
        max_age_seconds: Freshness window for ``created``. Default 300s.
            Pass ``None`` to skip the freshness check.
        nonce_tracker: Optional replay cache. When supplied, the
            signature must carry a ``nonce`` parameter and each nonce
            may be seen only once.

    Returns:
        True if the signature is valid, False otherwise.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    sig_input_raw = lower_headers.get("signature-input", "")
    sig_raw = lower_headers.get("signature", "")

    if not sig_input_raw or not sig_raw:
        return False

    # Parse Signature-Input
    match = _SIG_INPUT_RE.match(sig_input_raw)
    if not match:
        return False

    components_str = match.group("components")
    created = int(match.group("created"))
    keyid = match.group("keyid")
    alg = match.group("alg")

    # Algorithm allow-list. Reject any signature whose declared alg is not
    # one this implementation can actually verify. Without this check, a
    # multi-algorithm verifier (future) could be tricked into accepting an
    # Ed25519 signature while the input claims RSA — classic alg confusion.
    if alg not in _SUPPORTED_ALGORITHMS:
        return False

    nonce_match = _SIG_INPUT_NONCE_RE.search(sig_input_raw)
    nonce = nonce_match.group("nonce") if nonce_match else None

    # Freshness window — reject stale or far-future signatures before
    # doing any crypto work.
    if max_age_seconds is not None:
        skew = abs(int(time.time()) - created)
        if skew > max_age_seconds:
            return False

    # A signature with no nonce parameter cannot be replay-protected.
    # Reject unless caller has explicitly disabled replay checks by
    # passing ``max_age_seconds=None`` (fixture-only usage).
    if nonce is None and max_age_seconds is not None:
        return False

    # Parse covered components: "comp1" "comp2" ...
    covered = re.findall(r'"([^"]+)"', components_str)

    # The signature must bind the request line and the target, otherwise a
    # signature captured on one route or agent could be replayed on another.
    if not {"@method", "@target-uri", "@authority"} <= set(covered):
        return False

    # Body integrity. A non-empty body is only authenticated when
    # ``content-digest`` is covered by the signature AND matches the body;
    # otherwise an attacker could swap the body of a signed request.
    if body:
        if "content-digest" not in covered:
            return False
        expected_digest = _content_digest_sha256(body)
        actual_digest = lower_headers.get("content-digest", "")
        if actual_digest != expected_digest:
            return False
    elif body is not None and "content-digest" in covered:
        if lower_headers.get("content-digest", "") != _content_digest_sha256(body):
            return False

    # Extract signature bytes: sig1=:<base64>:
    sig_match = re.fullmatch(r"sig1=:([A-Za-z0-9+/=]+):", sig_raw.strip())
    if not sig_match:
        return False
    try:
        sig_bytes = base64.b64decode(sig_match.group(1), validate=True)
    except (binascii.Error, ValueError):
        return False

    # Reconstruct signature base and verify. Any malformed input (bad URL,
    # missing covered header, invalid port) yields False — never raises.
    try:
        sig_base = create_signature_base(
            method=method,
            url=url,
            headers=headers,
            covered_components=covered,
            created=created,
            keyid=keyid,
            nonce=nonce,
        )
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(sig_bytes, sig_base.encode("utf-8"))
    except Exception:
        return False

    # Replay cache — consulted only AFTER the signature verified, so a
    # forged request can neither burn a legitimate request's nonce nor
    # fill the cache. Nonces are scoped per keyid. Verifiers replay-check
    # every signature that carries a nonce, using either the
    # caller-supplied tracker or a module-level default.
    if nonce is not None:
        effective_tracker = (
            nonce_tracker if nonce_tracker is not None else _get_default_nonce_tracker()
        )
        if effective_tracker.is_replay(json.dumps([keyid, nonce])):
            return False

    return True
