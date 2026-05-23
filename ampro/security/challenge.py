"""
Agent Protocol — Anti-Abuse Challenge.

Challenge-response mechanism for public-facing agents. When a sender
appears suspicious or is making first contact, the receiver can issue
a challenge that must be solved before the conversation proceeds.

The protocol defines the challenge flow (body types). The specific
challenge algorithms (proof-of-work, CAPTCHA, etc.) are implementation
guidance, not protocol.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Minimum PoW difficulty accepted by the default validator. Lower difficulty
# is a no-op challenge — anything below this is rejected outright so that a
# buggy or attacker-influenced issuer cannot ship a 0-bit "challenge".
MIN_POW_DIFFICULTY = 8


class ChallengeReason(str, Enum):
    """Why a challenge was issued."""

    FIRST_CONTACT = "first_contact"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    TRUST_UPGRADE = "trust_upgrade"


class ChallengeType(str, Enum):
    """Canonical challenge types with built-in solution validators.

    Implementations MAY extend by registering new types via
    :func:`register_challenge_validator`. Unregistered types fall back to
    a string-equality check against ``parameters['expected_solution']``
    when present.
    """

    PROOF_OF_WORK = "proof_of_work"
    SHARED_SECRET = "shared_secret"
    ECHO = "echo"
    CAPTCHA = "captcha"


class TaskChallengeBody(BaseModel):
    """body.type = 'task.challenge' — Issue a challenge to the sender."""

    challenge_id: str = Field(description="Unique challenge identifier")
    challenge_type: str = Field(
        description="Challenge type (extensible, e.g. 'proof_of_work', 'captcha')",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Challenge-type-specific parameters",
    )
    expires_at: str = Field(description="ISO-8601 expiration timestamp")
    reason: str = Field(description="Why this challenge was issued")

    model_config = {"extra": "ignore"}


class TaskChallengeResponseBody(BaseModel):
    """body.type = 'task.challenge_response' — Respond to a challenge."""

    challenge_id: str = Field(description="Challenge ID being responded to")
    solution: str = Field(description="The computed answer to the challenge")

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Per-type solution validators
# ---------------------------------------------------------------------------


ChallengeValidator = Callable[[TaskChallengeBody, TaskChallengeResponseBody], bool]


def _validate_proof_of_work(
    challenge: TaskChallengeBody, response: TaskChallengeResponseBody
) -> bool:
    """SHA-256(challenge_id || solution) must have N leading zero bits.

    ``parameters['difficulty']`` carries the required leading-zero-bit count.
    The solution is a hex string.
    """
    try:
        difficulty = int(challenge.parameters.get("difficulty", 0))
    except (TypeError, ValueError):
        return False
    if difficulty < MIN_POW_DIFFICULTY:
        # Reject trivially-easy or zero-difficulty challenges. A challenge
        # with difficulty < MIN_POW_DIFFICULTY is functionally a no-op and
        # MUST NOT be accepted by the default validator.
        return False
    try:
        _ = bytes.fromhex(response.solution)
    except ValueError:
        return False
    digest = hashlib.sha256(
        (challenge.challenge_id + response.solution).encode("utf-8")
    ).digest()
    # Count leading zero bits of the digest
    leading = 0
    for byte in digest:
        if byte == 0:
            leading += 8
            continue
        # count leading zeros in this byte
        mask = 0x80
        while mask and not (byte & mask):
            leading += 1
            mask >>= 1
        break
    return leading >= difficulty


def _validate_shared_secret(
    challenge: TaskChallengeBody, response: TaskChallengeResponseBody
) -> bool:
    """Solution equals a pre-shared secret carried in parameters."""
    expected = challenge.parameters.get("expected_solution")
    if not isinstance(expected, str):
        return False
    # Use hmac-style constant-time compare
    import hmac as _hmac

    return _hmac.compare_digest(expected, response.solution)


def _validate_echo(
    challenge: TaskChallengeBody, response: TaskChallengeResponseBody
) -> bool:
    """Solution must echo parameters['echo']."""
    expected = challenge.parameters.get("echo")
    return isinstance(expected, str) and expected == response.solution


def _validate_captcha(
    challenge: TaskChallengeBody, response: TaskChallengeResponseBody
) -> bool:
    """CAPTCHA validation requires a platform-provided solver.

    The default validator FAILS CLOSED — it always returns False. Platforms
    that need real CAPTCHA verification MUST register a validator via
    :func:`register_challenge_validator` that consults their CAPTCHA backend
    (hCaptcha, Turnstile, reCAPTCHA, etc.). The previous default accepted
    ``parameters['expected_solution']`` via string-equality, which meant the
    answer travelled inside the challenge — trivially bypassable.
    """
    logger.warning(
        "captcha challenge failed: no platform validator registered. "
        "Call register_challenge_validator('captcha', <real_validator>)."
    )
    return False


_VALIDATORS: dict[str, ChallengeValidator] = {
    ChallengeType.PROOF_OF_WORK.value: _validate_proof_of_work,
    ChallengeType.SHARED_SECRET.value: _validate_shared_secret,
    ChallengeType.ECHO.value: _validate_echo,
    ChallengeType.CAPTCHA.value: _validate_captcha,
}


def register_challenge_validator(
    challenge_type: str, validator: ChallengeValidator
) -> None:
    """Register or override a validator for a given challenge_type string."""
    _VALIDATORS[challenge_type] = validator


def _is_expired(expires_at: str) -> bool:
    """Return True when *expires_at* is a parseable timestamp strictly in the past."""
    try:
        raw = expires_at.replace("Z", "+00:00") if expires_at.endswith("Z") else expires_at
        ts = datetime.fromisoformat(raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        # Unparseable expiry is treated as expired (fail-closed).
        return True
    return ts < datetime.now(timezone.utc)


def validate_challenge_solution(
    challenge: TaskChallengeBody, response: TaskChallengeResponseBody
) -> bool:
    """Dispatch to the per-type validator and return pass/fail.

    Enforces, in order:
      1. ``response.challenge_id == challenge.challenge_id``
      2. ``challenge.expires_at`` is in the future (fail-closed on unparseable)
      3. A validator is registered for ``challenge.challenge_type``
      4. The validator returns True

    Unknown challenge types and expired challenges return False. The
    expiry check used to be the caller's responsibility — silently
    fail-open if the caller forgot. It now runs unconditionally inside
    the dispatcher.
    """
    if challenge.challenge_id != response.challenge_id:
        return False
    if _is_expired(challenge.expires_at):
        return False
    validator = _VALIDATORS.get(challenge.challenge_type)
    if validator is None:
        return False
    try:
        return bool(validator(challenge, response))
    except Exception:
        return False
