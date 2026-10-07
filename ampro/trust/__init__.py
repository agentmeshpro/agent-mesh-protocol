"""Trust tiers, scoring, resolution, and proofs."""

from ampro.trust.proof import TrustProofBody
from ampro.trust.resolver import (
    ALLOWED_JWT_ALGS,
    DID_PROOF_MAX_LIFETIME_SECONDS,
    did_key_to_public_key,
    register_api_key,
    register_api_key_store,
    resolve_trust_tier,
    unregister_api_key,
    validate_jwt_algorithm,
)
from ampro.trust.score import (
    TrustFactor,
    TrustPolicy,
    TrustScore,
    calculate_trust_score,
    score_to_policy,
)
from ampro.trust.tiers import CLOCK_SKEW_SECONDS, TrustConfig, TrustTier
from ampro.trust.upgrade import TrustUpgradeRequestBody, TrustUpgradeResponseBody

__all__ = [
    # Tiers
    "TrustTier", "TrustConfig", "CLOCK_SKEW_SECONDS",
    # Scoring
    "TrustFactor", "TrustScore", "TrustPolicy",
    "calculate_trust_score", "score_to_policy",
    # Resolution
    "resolve_trust_tier",
    "validate_jwt_algorithm",
    "ALLOWED_JWT_ALGS",
    "register_api_key", "unregister_api_key", "register_api_key_store",
    "did_key_to_public_key", "DID_PROOF_MAX_LIFETIME_SECONDS",
    # Upgrade
    "TrustUpgradeRequestBody", "TrustUpgradeResponseBody",
    # Proof
    "TrustProofBody",
]
