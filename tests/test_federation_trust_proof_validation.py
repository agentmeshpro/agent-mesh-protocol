"""C12: Federation trust_proof verification tests.

Validates that:
1. Empty trust_proof raises ValidationError
2. Too-short trust_proof raises ValidationError
3. Valid-length trust_proof passes field validation
4. verify_federation_trust_proof returns False for garbage input
"""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

# A valid base64 string of 88 chars (decodes to 64 bytes — Ed25519 sig size)
_VALID_B64_PROOF = base64.b64encode(b"A" * 64).decode()  # 88 chars, valid base64


class TestTrustProofFieldValidation:
    """Field-level validation on RegistryFederationRequest.trust_proof."""

    def test_empty_trust_proof_rejected(self):
        """Empty string must be rejected by the field validator."""
        from ampro import RegistryFederationRequest

        with pytest.raises(ValidationError) as exc_info:
            RegistryFederationRequest(
                registry_id="agent://registry.example.com",
                capabilities=["resolve"],
                trust_proof="",
            )
        errors = exc_info.value.errors()
        assert any("trust_proof" in str(e) for e in errors)

    def test_too_short_trust_proof_rejected(self):
        """trust_proof shorter than 64 chars must be rejected."""
        from ampro import RegistryFederationRequest

        short_proof = "a" * 63  # One char below minimum
        with pytest.raises(ValidationError) as exc_info:
            RegistryFederationRequest(
                registry_id="agent://registry.example.com",
                capabilities=["resolve"],
                trust_proof=short_proof,
            )
        errors = exc_info.value.errors()
        assert any("trust_proof" in str(e) for e in errors)

    def test_valid_length_trust_proof_accepted(self):
        """trust_proof of 64+ chars passes field validation."""
        from ampro import RegistryFederationRequest

        req = RegistryFederationRequest(
            registry_id="agent://registry.example.com",
            capabilities=["resolve", "search"],
            trust_proof=_VALID_B64_PROOF,
        )
        assert req.trust_proof == _VALID_B64_PROOF
        assert len(req.trust_proof) >= 64


class TestVerifyFederationTrustProof:
    """Module-level verify_federation_trust_proof() function."""

    def test_garbage_input_returns_false(self):
        """Non-base64 garbage that passes the 64-char minimum
        should still return False from verify_federation_trust_proof."""
        from ampro import RegistryFederationRequest, verify_federation_trust_proof

        # Use a string that is 64+ chars but is NOT valid base64
        # (contains characters outside base64 alphabet)
        garbage_proof = "!" * 64 + "@@##$$%%^^&&**(())"  # 82 chars, not base64
        # We need to bypass the field validator for construction since it
        # only checks length, not base64-ness. The garbage passes length check.
        req = RegistryFederationRequest(
            registry_id="agent://registry.example.com",
            capabilities=["resolve"],
            trust_proof=garbage_proof,
        )

        result = verify_federation_trust_proof(req)
        assert result is False

    def test_valid_base64_proof_without_resolver_returns_false(self):
        """A properly-formed base64 proof MUST NOT pass without a registered
        resolver. The previous behaviour accepted any 64+ char base64 string
        as a "trust proof", which let any attacker establish federation.
        Real verification requires the host to register a
        FederationTrustProofResolver."""
        from ampro import RegistryFederationRequest, verify_federation_trust_proof

        req = RegistryFederationRequest(
            registry_id="agent://registry.example.com",
            capabilities=["resolve", "search"],
            trust_proof=_VALID_B64_PROOF,
        )

        result = verify_federation_trust_proof(req)
        assert result is False  # fail-closed without resolver

    def test_valid_signature_with_resolver_returns_true(self):
        """A real Ed25519 signature, verified through a registered resolver,
        is the only path that returns True."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ampro import RegistryFederationRequest, verify_federation_trust_proof
        from ampro.registry.federation import register_federation_trust_proof_resolver

        sk = Ed25519PrivateKey.generate()
        pk_bytes = sk.public_key().public_bytes_raw()

        registry_id = "agent://registry.example.com"
        capabilities = ["resolve", "search"]
        canonical = (
            registry_id.encode("utf-8")
            + b"\x00"
            + b"\x1f".join(sorted(c.encode("utf-8") for c in capabilities))
        )
        sig = sk.sign(canonical)
        sig_b64 = base64.b64encode(sig).decode()

        register_federation_trust_proof_resolver(lambda rid: pk_bytes if rid == registry_id else None)

        req = RegistryFederationRequest(
            registry_id=registry_id,
            capabilities=capabilities,
            trust_proof=sig_b64,
        )

        assert verify_federation_trust_proof(req) is True

        # Reset to no-resolver state for following tests
        register_federation_trust_proof_resolver(lambda rid: None)
