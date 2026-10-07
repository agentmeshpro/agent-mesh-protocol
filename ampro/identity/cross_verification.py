"""
Agent Protocol — Identifier Cross-Verification.

Verifies that each identifier in an agent's identifiers array
resolves back to the same endpoint and same public key.

Spec ref: Section 3.2
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
from typing import Any

from ampro.core.addressing import AddressType, parse_agent_uri
from ampro.transport.attachment import validate_attachment_url

logger = logging.getLogger(__name__)


# Module-level policy flag. When True, any call to
# :func:`cross_verify_identifiers` that returns at least one unverified
# identifier MUST raise :class:`CrossVerificationRequiredError` instead
# of silently returning False. Default is False to preserve current
# permissive behaviour; platforms opt in via
# :func:`register_cross_verification_policy`.
REQUIRE_CROSS_VERIFICATION: bool = False


class CrossVerificationRequiredError(Exception):
    """Raised when cross-verification is mandatory but failed.

    Triggered only when :data:`REQUIRE_CROSS_VERIFICATION` is True and the
    verification call returned any unverified identifier.
    """

    def __init__(self, failed_identifiers: list[str]):
        self.failed_identifiers = failed_identifiers
        super().__init__(
            "Cross-verification policy requires all identifiers to verify; "
            f"failed: {failed_identifiers}"
        )


def register_cross_verification_policy(required: bool) -> None:
    """Set the module-level policy flag.

    Platforms that require strict cross-verification (e.g. for external
    trust-tier agents) call this once at startup with ``required=True``.
    """
    global REQUIRE_CROSS_VERIFICATION
    REQUIRE_CROSS_VERIFICATION = bool(required)


class VerificationResult:
    """Result of cross-verifying an identifier."""

    def __init__(self, identifier: str, verified: bool, reason: str = ""):
        self.identifier = identifier
        self.verified = verified
        self.reason = reason


def _decode_expected_key(value: str) -> bytes:
    """Decode a base64 (standard or url-safe, padding optional) public key."""
    value = value.strip()
    padded = value + "=" * (-len(value) % 4)
    if "-" in value or "_" in value:
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded, validate=True)


def _verify_did_key(
    identifier: str, did: str, expected_public_key: str | None,
) -> VerificationResult:
    """did:key embeds its Ed25519 key — compare it to the expected key."""
    from ampro.trust.resolver import did_key_to_public_key

    try:
        did_key_bytes = did_key_to_public_key(did)
    except ValueError as exc:
        return VerificationResult(identifier, False, f"Invalid did:key: {exc}")
    if not expected_public_key:
        return VerificationResult(
            identifier, False, "No expected public key to compare did:key against",
        )
    try:
        expected_bytes = _decode_expected_key(expected_public_key)
    except (binascii.Error, ValueError) as exc:
        return VerificationResult(identifier, False, f"Invalid expected public key: {exc}")
    if not hmac.compare_digest(did_key_bytes, expected_bytes):
        return VerificationResult(identifier, False, "Public key mismatch for did:key")
    return VerificationResult(identifier, True, "did:key public key matches")


async def cross_verify_identifiers(
    identifiers: list[str],
    expected_endpoint: str,
    expected_public_key: str | None = None,
    fetch_agent_json: Any = None,
) -> list[VerificationResult]:
    """
    Cross-verify each identifier resolves to the same endpoint and key.

    For each identifier:
    - HOST type: would fetch agent.json from host and compare endpoint + key
    - SLUG type: would resolve via registry and compare
    - DID type: did:key — the embedded Ed25519 key must equal
      ``expected_public_key``; other DID methods are unsupported (unverified)

    Args:
        identifiers: List of agent:// URIs to verify
        expected_endpoint: The endpoint we expect all to resolve to
        expected_public_key: The public key we expect (base64)
        fetch_agent_json: Optional async callable to fetch agent.json (for testing)

    Returns:
        List of VerificationResult for each identifier
    """
    results: list[VerificationResult] = []

    for identifier in identifiers:
        try:
            addr = parse_agent_uri(identifier)
        except ValueError as e:
            results.append(VerificationResult(
                identifier=identifier,
                verified=False,
                reason=f"Invalid URI: {e}",
            ))
            continue

        if addr.address_type == AddressType.DID:
            # DID verification: the key IS the identifier.
            # did:key embeds the Ed25519 key — compare to expected_public_key.
            # did:web would need DID resolution (not supported).
            if addr.did and addr.did.startswith("did:key:"):
                results.append(_verify_did_key(identifier, addr.did, expected_public_key))
            else:
                # did:web requires resolution — not yet implemented
                results.append(VerificationResult(
                    identifier=identifier,
                    verified=False,
                    reason="did:web resolution not yet implemented",
                ))
            continue

        if addr.address_type == AddressType.HOST:
            # Would fetch https://{host}/.well-known/agent.json
            # and compare endpoint + public key
            if fetch_agent_json:
                try:
                    url = addr.agent_json_url()
                    if not validate_attachment_url(url):
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason=f"Unsafe URL blocked by SSRF check: {url}",
                        ))
                        continue
                    remote_json = await fetch_agent_json(url)
                    if remote_json is None:
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason="Could not fetch agent.json",
                        ))
                        continue

                    remote_endpoint = remote_json.get("endpoint", "")
                    if remote_endpoint != expected_endpoint:
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason=f"Endpoint mismatch: expected {expected_endpoint}, got {remote_endpoint}",
                        ))
                        continue

                    results.append(VerificationResult(
                        identifier=identifier,
                        verified=True,
                        reason="Endpoint matches",
                    ))
                except Exception as e:
                    results.append(VerificationResult(
                        identifier=identifier,
                        verified=False,
                        reason=f"Fetch failed: {e}",
                    ))
            else:
                # No fetcher provided — cannot verify
                results.append(VerificationResult(
                    identifier=identifier,
                    verified=False,
                    reason="No fetch function provided for HOST verification",
                ))
            continue

        if addr.address_type == AddressType.SLUG:
            # Would resolve via registry and compare
            if fetch_agent_json:
                try:
                    registry_url = addr.registry_resolve_url()
                    if not validate_attachment_url(registry_url):
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason=f"Unsafe registry URL blocked by SSRF check: {registry_url}",
                        ))
                        continue
                    remote_data = await fetch_agent_json(registry_url)
                    if remote_data is None:
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason="Registry resolution failed",
                        ))
                        continue

                    remote_endpoint = remote_data.get("endpoint", "")
                    if remote_endpoint != expected_endpoint:
                        results.append(VerificationResult(
                            identifier=identifier,
                            verified=False,
                            reason=f"Endpoint mismatch: expected {expected_endpoint}, got {remote_endpoint}",
                        ))
                        continue

                    results.append(VerificationResult(
                        identifier=identifier,
                        verified=True,
                        reason="Registry resolution matches",
                    ))
                except Exception as e:
                    results.append(VerificationResult(
                        identifier=identifier,
                        verified=False,
                        reason=f"Registry fetch failed: {e}",
                    ))
            else:
                results.append(VerificationResult(
                    identifier=identifier,
                    verified=False,
                    reason="No fetch function provided for SLUG verification",
                ))
            continue

    if REQUIRE_CROSS_VERIFICATION:
        failed = [r.identifier for r in results if not r.verified]
        if failed:
            raise CrossVerificationRequiredError(failed)

    return results


def check_all_verified(results: list[VerificationResult]) -> bool:
    """Check if all identifiers passed verification."""
    return all(r.verified for r in results)


def get_failed_identifiers(results: list[VerificationResult]) -> list[str]:
    """Get list of identifiers that failed verification."""
    return [r.identifier for r in results if not r.verified]
