"""
Agent Protocol — Handshake Body Types & State Machine.

Implements the session handshake lifecycle for the Agent Mesh Protocol:
  1. Client sends session.init with proposed capabilities, nonce and an
     ephemeral X25519 public key (``client_ephemeral_key``)
  2. Server replies with session.established (negotiated capabilities,
     server nonce, confirm_nonce and its own ``server_ephemeral_key``)
  3. Both sides derive the binding key via X25519 + HKDF-SHA256; the key
     is never transmitted. Client sends session.confirm (binding proof +
     confirm_nonce echo); the server verifies it with
     :func:`server_verify_confirm`.
  4. Session transitions to ACTIVE

Once active, sessions support ping/pong keepalive, pause/resume, and close.

The HandshakeStateMachine enforces valid state transitions and raises
ValueError on illegal moves.

Security notes:
  - The binding key is derived independently by both peers from an
    ephemeral X25519 exchange (see ``ampro.session.binding``) and is
    NEVER sent on the wire. ``SessionEstablishedBody.binding_token`` is a
    deprecated legacy field; servers MUST NOT populate it and clients
    ignore it.
  - Verification of ``binding_proof`` is mandatory: a server that cannot
    verify it (no ephemeral key from the client, bad proof) rejects the
    handshake with :class:`SessionBindingError`.
  - ``confirm_nonce`` provides replay protection for the session.confirm
    step. The server issues a single-use nonce in session.established;
    the client echoes it in session.confirm. The HandshakeStateMachine
    tracks issued and consumed nonces and raises SessionReplayError on
    any replay or unknown nonce.

PURE — zero platform-specific imports. Only pydantic, stdlib and cryptography.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import BaseModel, Field

from ampro.errors import SessionError
from ampro.session.binding import (
    SessionBinding,
    compute_binding_proof,
    derive_session_binding_key,
    generate_ephemeral_keypair,
    verify_binding_proof,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SessionReplayError(SessionError):
    """Raised when a confirm_nonce is replayed or was never issued.

    This indicates either a replay attack on the session.confirm message
    or a programming error where the nonce was not properly generated via
    the HandshakeStateMachine.
    """


class SessionBindingError(SessionError):
    """Raised when session binding cannot be established or verified.

    Examples: the peer did not supply an ephemeral key, the
    ``binding_proof`` does not verify, or the confirm refers to a
    different session.
    """


class HandshakeTimeoutError(SessionError):
    """Raised when the handshake does not complete within the configured window.

    Handshakes are bounded operations — a peer that goes silent mid-way
    must not leave the state machine stuck in INIT_SENT / ESTABLISHED
    forever. The default timeout is 30 seconds; customise via
    :class:`HandshakeStateMachine`'s ``timeout_seconds`` constructor arg.
    """


# ---------------------------------------------------------------------------
# Handshake state enum
# ---------------------------------------------------------------------------


class HandshakeState(str, Enum):
    """States in the session handshake lifecycle."""

    IDLE = "idle"
    INIT_SENT = "init_sent"
    INIT_RECEIVED = "init_received"
    ESTABLISHED = "established"
    CONFIRMED = "confirmed"
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Session init / teardown body types
# ---------------------------------------------------------------------------


class SessionInitBody(BaseModel):
    """body.type = 'session.init' — Propose a new session with capabilities."""

    proposed_capabilities: list[str] = Field(
        description="Capabilities the client wants to negotiate (e.g. messaging, tools, streaming)",
    )
    proposed_version: str = Field(
        description="Protocol version the client proposes (e.g. 1.0.0)",
    )
    client_nonce: str = Field(
        description=(
            "Random 256-bit hex string for replay protection. "
            "MUST be cryptographically random and globally unique. "
            "Use secrets.token_hex(32) or equivalent."
        ),
    )
    conversation_id: str | None = Field(
        default=None,
        description="Optional conversation ID to resume or bind to",
    )
    previous_session_id: str | None = Field(
        default=None,
        description="Previous session ID for session resumption",
    )
    client_ephemeral_key: str | None = Field(
        default=None,
        description=(
            "Client ephemeral X25519 public key (32 bytes, base64url, no "
            "padding) for binding-key agreement. Required by servers that "
            "bind sessions (server_accept_init rejects an init without it)."
        ),
    )

    model_config = {"extra": "ignore"}


class SessionEstablishedBody(BaseModel):
    """body.type = 'session.established' — Server accepts the session."""

    session_id: str = Field(
        description="Unique session identifier assigned by the server",
    )
    negotiated_capabilities: list[str] = Field(
        description="Intersection of proposed and supported capabilities",
    )
    negotiated_version: str = Field(
        description="Protocol version both sides agreed on",
    )
    trust_tier: str = Field(
        description="Trust tier granted to the client. Must be one of: internal, owner, verified, external",
    )
    trust_score: int = Field(
        description="Numeric trust score from 0-1000",
    )
    session_ttl_seconds: int = Field(
        default=3600,
        description="Session time-to-live in seconds",
    )
    server_nonce: str = Field(
        description="Server-side 256-bit hex nonce for binding proof",
    )
    server_ephemeral_key: str | None = Field(
        default=None,
        description=(
            "Server ephemeral X25519 public key (32 bytes, base64url, no "
            "padding). Clients MUST refuse a session.established without it."
        ),
    )
    binding_token: str | None = Field(
        default=None,
        description=(
            "DEPRECATED — legacy field that carried the binding secret in "
            "the clear. Servers MUST NOT send it; clients MUST ignore it. "
            "The binding key is derived via X25519 key agreement instead."
        ),
    )
    confirm_nonce: str = Field(
        description=(
            "Single-use nonce for replay protection of session.confirm. "
            "Generated by the server via HandshakeStateMachine.issue_confirm_nonce(). "
            "The client MUST echo this value in its SessionConfirmBody."
        ),
    )
    resumed: bool = Field(
        default=False,
        description="Whether the previous session was successfully resumed",
    )

    model_config = {"extra": "ignore"}


class SessionConfirmBody(BaseModel):
    """body.type = 'session.confirm' — Client proves it holds the binding token."""

    session_id: str = Field(
        description="Session ID from the session.established message",
    )
    binding_proof: str = Field(
        description=(
            "HMAC-SHA256 under the derived binding key over the handshake "
            "transcript (see ampro.session.binding.compute_binding_proof)"
        ),
    )
    confirm_nonce: str = Field(
        description=(
            "Echo of the confirm_nonce from session.established. "
            "The server validates this via HandshakeStateMachine.consume_confirm_nonce() "
            "and raises SessionReplayError if replayed or unknown."
        ),
    )

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Keepalive body types
# ---------------------------------------------------------------------------


class SessionPingBody(BaseModel):
    """body.type = 'session.ping' — Keepalive ping."""

    session_id: str = Field(
        description="Session ID to keep alive",
    )
    timestamp: str = Field(
        description="ISO-8601 timestamp of the ping",
    )

    model_config = {"extra": "ignore"}


class SessionPongBody(BaseModel):
    """body.type = 'session.pong' — Keepalive pong response."""

    session_id: str = Field(
        description="Session ID being kept alive",
    )
    timestamp: str = Field(
        description="ISO-8601 timestamp of the pong",
    )
    active_tasks: int = Field(
        default=0,
        description="Number of tasks currently active in this session",
    )

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Pause / resume / close body types
# ---------------------------------------------------------------------------


class SessionPauseBody(BaseModel):
    """body.type = 'session.pause' — Temporarily suspend the session.

    The ``resume_token`` SHOULD be created via :func:`create_resume_token`
    which embeds session_id, binding_token, and optional context into a
    structured, optionally HMAC-signed token. This ensures the binding
    state survives process restarts and can be verified on resume.
    """

    session_id: str = Field(
        description="Session ID to pause",
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable reason for pausing",
    )
    resume_token: str | None = Field(
        default=None,
        description="Token required to resume this session",
    )

    model_config = {"extra": "ignore"}


class SessionResumeBody(BaseModel):
    """body.type = 'session.resume' — Resume a paused session."""

    session_id: str = Field(
        description="Session ID to resume",
    )
    resume_token: str | None = Field(
        default=None,
        description="Token provided during pause, if one was issued",
    )

    model_config = {"extra": "ignore"}


class SessionCloseBody(BaseModel):
    """body.type = 'session.close' — Gracefully close the session."""

    session_id: str = Field(
        description="Session ID to close",
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable reason for closing",
    )

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Resume token helpers
# ---------------------------------------------------------------------------


_TOKEN_VERSION_SIGNED = "v1s"
_TOKEN_VERSION_UNSIGNED = "v1u"

# Cap on resume token length. Tokens encode session_id + binding_token plus
# small session context; a token over 64KiB is a DoS attempt or a misuse.
_MAX_RESUME_TOKEN_BYTES = 65_536

# Default maximum age of a resume token (seconds). Override per call via
# ``parse_resume_token(..., max_age_seconds=...)``.
DEFAULT_RESUME_TOKEN_MAX_AGE_SECONDS: float = 3600.0

# Tolerance for resume tokens whose created_at lies slightly in the future
# (clock skew between processes sharing the HMAC key).
_RESUME_TOKEN_FUTURE_SKEW = timedelta(seconds=30)


def create_resume_token(
    session_id: str,
    binding_token: str,
    session_context: dict | None = None,
    key: bytes | None = None,
) -> str:
    """Create a structured resume token that preserves binding state.

    The token encodes session_id, binding_token, and optional context
    into a base64 payload. When *key* is provided the payload is
    HMAC-SHA256 signed and the signature is appended (format:
    ``base64(payload).base64(sig)``).

    Args:
        session_id: The session being paused.
        binding_token: The binding token from the handshake.
        session_context: Optional dict of additional state to persist.
        key: Optional HMAC-SHA256 key. When ``None`` the token is
            unsigned (suitable for testing / dev).

    Returns:
        A resume token string.
    """
    # Embed a version tag inside the payload so the parser can detect whether
    # the token was created as signed or unsigned. Without this an attacker
    # who strips the ``.signature`` suffix from a signed token can present
    # the payload to a verifier as if it were always unsigned.
    payload = {
        "v": _TOKEN_VERSION_SIGNED if key is not None else _TOKEN_VERSION_UNSIGNED,
        "session_id": session_id,
        "binding_token": binding_token,
        "context": session_context,
        "created_at": datetime.now(UTC).isoformat(),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")

    if key is not None:
        sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii")
        return f"{payload_b64}.{sig_b64}"

    return payload_b64


_ALLOW_UNSIGNED_RESUME_TOKENS = False


def allow_unsigned_resume_tokens(allow: bool) -> None:
    """Opt-in to accepting unsigned resume tokens.

    Production callers SHOULD always sign resume tokens — an unsigned token
    is fundamentally just an encoded session_id+binding_token blob. The
    parser rejects unsigned tokens by default; tests and local-dev callers
    can enable acceptance explicitly via this toggle.
    """
    global _ALLOW_UNSIGNED_RESUME_TOKENS
    _ALLOW_UNSIGNED_RESUME_TOKENS = allow


def parse_resume_token(
    token: str,
    key: bytes | None = None,
    *,
    max_age_seconds: float = DEFAULT_RESUME_TOKEN_MAX_AGE_SECONDS,
) -> dict:
    """Parse and verify a resume token.

    Security contract:

      * If the token contains a ``.`` separator it is treated as a SIGNED
        token and MUST be verified with *key*. Calling with ``key=None`` on
        a signed-shaped token raises :class:`ValueError` so an attacker
        cannot strip the signature and present the payload to a caller
        that forgot to pass the key.
      * If the token has no ``.`` separator it is an UNSIGNED token and is
        accepted only when *key* is also ``None``. Mixing signed/unsigned
        forms is rejected.

      * Tokens expire: ``created_at`` (embedded and covered by the HMAC)
        MUST be a tz-aware ISO-8601 timestamp no older than
        *max_age_seconds* and not in the future (beyond 30s skew).

    Args:
        token: The resume token string produced by :func:`create_resume_token`.
        key: HMAC-SHA256 key, required for signed tokens.
        max_age_seconds: Maximum token age (default 1 hour). Must be > 0.

    Returns:
        Parsed dict with ``session_id``, ``binding_token``, ``context``,
        and ``created_at`` keys.

    Raises:
        ValueError: If the token is malformed, signed format without a key,
            unsigned format with a key, the signature does not match, or
            the token is expired / missing a valid ``created_at``.
    """
    if not max_age_seconds or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive number")
    if len(token) > _MAX_RESUME_TOKEN_BYTES:
        raise ValueError(
            f"resume token exceeds {_MAX_RESUME_TOKEN_BYTES} byte cap"
        )
    looks_signed = "." in token

    if looks_signed and key is None:
        raise ValueError(
            "Refusing to parse signed-shaped token without a key — "
            "supply the HMAC key. Stripping the signature is not allowed."
        )
    if not looks_signed and key is not None:
        raise ValueError(
            "Token has no signature but a key was provided — "
            "unsigned tokens are not accepted under key validation."
        )
    if not looks_signed and key is None and not _ALLOW_UNSIGNED_RESUME_TOKENS:
        # Block the "rewrite v=unsigned, strip the .sig, present as unsigned"
        # attack. Once a token is created as signed, an attacker can rewrite
        # any in-payload version field; the ONLY trustworthy indicator of
        # signedness is HMAC verification. So unsigned tokens are rejected
        # by default, opt-in only via allow_unsigned_resume_tokens(True).
        raise ValueError(
            "Unsigned resume tokens are rejected by default. Either supply "
            "an HMAC key when creating + parsing, or call "
            "allow_unsigned_resume_tokens(True) at startup."
        )

    if key is not None:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError("Signed token must contain exactly one '.' separator")
        payload_b64, sig_b64 = parts
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            sig_bytes = base64.urlsafe_b64decode(sig_b64)
        except Exception as exc:
            raise ValueError(f"Invalid base64 in token: {exc}") from exc
        expected_sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(sig_bytes, expected_sig):
            raise ValueError("HMAC signature verification failed")
    else:
        try:
            payload_bytes = base64.urlsafe_b64decode(token)
        except Exception as exc:
            raise ValueError(f"Invalid base64 in token: {exc}") from exc

    try:
        data = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in token payload: {exc}") from exc

    for required in ("session_id", "binding_token"):
        if required not in data:
            raise ValueError(f"Token payload missing required field: {required}")

    # Cross-check the embedded version against the parse path. If the
    # payload declares itself signed but we got here via the unsigned
    # branch, the signature was stripped by an attacker.
    version = data.get("v")
    if version == _TOKEN_VERSION_SIGNED and key is None:
        raise ValueError(
            "Token payload declares v=signed but was parsed without a key "
            "— signature appears to have been stripped"
        )
    if version == _TOKEN_VERSION_UNSIGNED and key is not None:
        raise ValueError(
            "Token payload declares v=unsigned but a verification key was "
            "supplied — refusing inconsistent token"
        )

    created_raw = data.get("created_at")
    if not isinstance(created_raw, str):
        raise ValueError("Token payload missing created_at")
    try:
        created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Token created_at is not ISO-8601: {exc}") from exc
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("Token created_at must be timezone-aware")
    now = datetime.now(UTC)
    if created_at > now + _RESUME_TOKEN_FUTURE_SKEW:
        raise ValueError("Token created_at is in the future")
    if now - created_at > timedelta(seconds=max_age_seconds):
        raise ValueError(
            f"Resume token expired (older than {max_age_seconds:g}s)"
        )

    return data


# ---------------------------------------------------------------------------
# Handshake state machine
# ---------------------------------------------------------------------------

# Transition table: (current_state, event) → next_state
_TRANSITIONS: dict[tuple[HandshakeState, str], HandshakeState] = {
    # Initiating
    (HandshakeState.IDLE, "send_init"): HandshakeState.INIT_SENT,
    (HandshakeState.IDLE, "receive_init"): HandshakeState.INIT_RECEIVED,
    # Establishing
    (HandshakeState.INIT_SENT, "receive_established"): HandshakeState.ESTABLISHED,
    (HandshakeState.INIT_RECEIVED, "send_established"): HandshakeState.ESTABLISHED,
    # Confirming
    (HandshakeState.ESTABLISHED, "receive_confirm"): HandshakeState.CONFIRMED,
    (HandshakeState.ESTABLISHED, "send_confirm"): HandshakeState.CONFIRMED,
    # Activating
    (HandshakeState.CONFIRMED, "activate"): HandshakeState.ACTIVE,
    # Pause / resume
    (HandshakeState.ACTIVE, "pause"): HandshakeState.PAUSED,
    (HandshakeState.PAUSED, "resume"): HandshakeState.ACTIVE,
    # Closing (from multiple states)
    (HandshakeState.ACTIVE, "close"): HandshakeState.CLOSED,
    (HandshakeState.PAUSED, "close"): HandshakeState.CLOSED,
    (HandshakeState.ESTABLISHED, "close"): HandshakeState.CLOSED,
    (HandshakeState.CONFIRMED, "close"): HandshakeState.CLOSED,
}


class HandshakeStateMachine:
    """Enforces valid state transitions for the session handshake lifecycle.

    Usage:
        sm = HandshakeStateMachine()
        sm.transition("send_init")       # IDLE → INIT_SENT
        sm.transition("receive_established")  # INIT_SENT → ESTABLISHED
        sm.transition("send_confirm")    # ESTABLISHED → CONFIRMED
        sm.transition("activate")        # CONFIRMED → ACTIVE

        sm.transition("invalid_event")   # raises ValueError

    Note: This state machine uses threading.Lock for thread safety.
    In async contexts, ensure transitions are not called from the
    event loop thread, or use asyncio.Lock instead.
    """

    DEFAULT_TIMEOUT_SECONDS: float = 30.0
    # Maximum issued nonces tracked per state machine. A handshake legitimately
    # issues exactly one, so this is purely a defence against buggy or
    # malicious callers spamming ``issue_confirm_nonce`` without ever
    # consuming. Bounded to prevent unbounded memory growth.
    MAX_ISSUED_NONCES: int = 16

    def __init__(self, timeout_seconds: float | None = None) -> None:
        self._state = HandshakeState.IDLE
        self._lock = threading.Lock()
        # Track (nonce, issued_at_monotonic) so we can age out stale issuances.
        self._issued_confirm_nonces: dict[str, float] = {}
        self._consumed_confirm_nonces: set[str] = set()
        self._timeout_seconds: float = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.DEFAULT_TIMEOUT_SECONDS
        )
        # The handshake clock starts at the first transition out of IDLE
        # (send_init / receive_init), not at construction — a state machine
        # may legitimately be created ahead of time.
        self._started_at: float | None = None

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    # ------------------------------------------------------------------
    # Confirm-nonce replay protection
    # ------------------------------------------------------------------

    def issue_confirm_nonce(self) -> str:
        """Generate a single-use confirm nonce and track it as issued.

        Bounded by ``MAX_ISSUED_NONCES`` and aged out by the handshake
        timeout window: stale nonces older than ``timeout_seconds`` are
        evicted on each call. A handshake state machine that has hit the
        cap raises :class:`RuntimeError` rather than silently growing.
        """
        nonce = secrets.token_hex(16)
        now = time.monotonic()
        with self._lock:
            # Age out anything past the handshake timeout — those nonces
            # can never legitimately be consumed.
            cutoff = now - self._timeout_seconds
            self._issued_confirm_nonces = {
                n: t for n, t in self._issued_confirm_nonces.items() if t >= cutoff
            }
            if len(self._issued_confirm_nonces) >= self.MAX_ISSUED_NONCES:
                raise RuntimeError(
                    f"HandshakeStateMachine: {self.MAX_ISSUED_NONCES} unconsumed "
                    f"confirm nonces — caller is leaking. Refusing to issue more."
                )
            self._issued_confirm_nonces[nonce] = now
        return nonce

    def consume_confirm_nonce(self, nonce: str) -> bool:
        """Validate and consume a confirm nonce echoed by the client.

        Called by the server when processing a ``SessionConfirmBody``.
        The nonce must have been previously issued and must not have been
        consumed already.

        Args:
            nonce: The confirm_nonce value from the client's session.confirm.

        Returns:
            True if the nonce was valid and successfully consumed.

        Raises:
            SessionReplayError: If the nonce was already consumed (replay)
                or was never issued (unknown nonce).
        """
        with self._lock:
            if nonce in self._consumed_confirm_nonces:
                raise SessionReplayError(
                    f"Replay detected: confirm_nonce '{nonce}' has already been consumed"
                )
            if nonce not in self._issued_confirm_nonces:
                raise SessionReplayError(
                    f"Unknown confirm_nonce '{nonce}' — was never issued by this state machine"
                )
            self._issued_confirm_nonces.pop(nonce, None)
            self._consumed_confirm_nonces.add(nonce)
            return True

    @property
    def state(self) -> HandshakeState:
        """Current state of the handshake."""
        with self._lock:
            return self._state

    def transition(self, event: str) -> HandshakeState:
        """Attempt a state transition triggered by *event*.

        Thread-safe: uses a lock to prevent concurrent state mutations.

        Args:
            event: The transition event name (e.g., "send_init", "close").

        Returns:
            The new HandshakeState after a successful transition.

        Raises:
            ValueError: If the event is not valid for the current state.
        """
        with self._lock:
            # Timeout only applies while the handshake is still negotiating.
            # Once ACTIVE / PAUSED / CLOSED the session has its own TTL.
            if self._started_at is None:
                if self._state == HandshakeState.IDLE:
                    self._started_at = time.monotonic()
            elif self._state not in (
                HandshakeState.ACTIVE,
                HandshakeState.PAUSED,
                HandshakeState.CLOSED,
            ):
                elapsed = time.monotonic() - self._started_at
                if elapsed > self._timeout_seconds:
                    raise HandshakeTimeoutError(
                        f"Handshake timed out after {elapsed:.2f}s "
                        f"(limit {self._timeout_seconds}s) in state "
                        f"'{self._state.value}'"
                    )
            key = (self._state, event)
            next_state = _TRANSITIONS.get(key)
            if next_state is None:
                raise ValueError(
                    f"Invalid transition: event '{event}' is not allowed "
                    f"in state '{self._state.value}'"
                )
            self._state = next_state
            return self._state


# ---------------------------------------------------------------------------
# Handshake helpers (key agreement + mandatory proof verification)
# ---------------------------------------------------------------------------


@dataclass
class ClientHandshakeState:
    """Client-side secrets held between session.init and session.established."""

    client_nonce: str
    client_public_key: str
    private_key: X25519PrivateKey


def client_start_handshake(
    proposed_capabilities: list[str],
    proposed_version: str,
    state_machine: HandshakeStateMachine | None = None,
    *,
    conversation_id: str | None = None,
    previous_session_id: str | None = None,
) -> tuple[SessionInitBody, ClientHandshakeState]:
    """Build a ``session.init`` body with a fresh nonce and ephemeral key.

    Transitions *state_machine* (if given) via ``send_init``.
    """
    private_key, public_key = generate_ephemeral_keypair()
    client_nonce = secrets.token_hex(32)
    body = SessionInitBody(
        proposed_capabilities=proposed_capabilities,
        proposed_version=proposed_version,
        client_nonce=client_nonce,
        conversation_id=conversation_id,
        previous_session_id=previous_session_id,
        client_ephemeral_key=public_key,
    )
    if state_machine is not None:
        state_machine.transition("send_init")
    return body, ClientHandshakeState(client_nonce, public_key, private_key)


def server_accept_init(
    init: SessionInitBody,
    state_machine: HandshakeStateMachine,
    *,
    session_id: str,
    negotiated_capabilities: list[str],
    negotiated_version: str,
    trust_tier: str,
    trust_score: int,
    session_ttl_seconds: int = 3600,
) -> tuple[SessionEstablishedBody, SessionBinding]:
    """Server side of phase 2: derive the binding key, build session.established.

    Transitions *state_machine* ``receive_init`` -> ``send_established`` and
    issues a single-use confirm nonce. The returned :class:`SessionBinding`
    holds the derived key and transcript values; keep it server-side and
    pass it to :func:`server_verify_confirm`. The established body does
    NOT contain the binding key.

    Raises:
        SessionBindingError: If the init lacks a valid ``client_ephemeral_key``.
    """
    if not init.client_ephemeral_key:
        raise SessionBindingError(
            "session.init has no client_ephemeral_key — binding key agreement "
            "is mandatory"
        )
    state_machine.transition("receive_init")
    private_key, server_public = generate_ephemeral_keypair()
    server_nonce = secrets.token_hex(32)
    try:
        key = derive_session_binding_key(
            private_key,
            init.client_ephemeral_key,
            session_id=session_id,
            client_nonce=init.client_nonce,
            server_nonce=server_nonce,
            client_public_key=init.client_ephemeral_key,
            server_public_key=server_public,
        )
    except ValueError as exc:
        raise SessionBindingError(f"key agreement failed: {exc}") from exc
    confirm_nonce = state_machine.issue_confirm_nonce()
    body = SessionEstablishedBody(
        session_id=session_id,
        negotiated_capabilities=negotiated_capabilities,
        negotiated_version=negotiated_version,
        trust_tier=trust_tier,
        trust_score=trust_score,
        session_ttl_seconds=session_ttl_seconds,
        server_nonce=server_nonce,
        server_ephemeral_key=server_public,
        confirm_nonce=confirm_nonce,
    )
    binding = SessionBinding(
        session_id=session_id,
        binding_token=key,
        client_nonce=init.client_nonce,
        server_nonce=server_nonce,
        client_public_key=init.client_ephemeral_key,
        server_public_key=server_public,
        confirm_nonce=confirm_nonce,
    )
    state_machine.transition("send_established")
    return body, binding


def client_finish_handshake(
    state: ClientHandshakeState,
    established: SessionEstablishedBody,
    state_machine: HandshakeStateMachine | None = None,
) -> tuple[SessionConfirmBody, SessionBinding]:
    """Client side of phase 3: derive the key and build session.confirm.

    Any ``binding_token`` in *established* is ignored. Transitions
    *state_machine* (if given) ``receive_established`` -> ``send_confirm``.

    Raises:
        SessionBindingError: If the server did not perform key agreement
            (no ``server_ephemeral_key``) or the key is invalid.
    """
    if not established.server_ephemeral_key:
        raise SessionBindingError(
            "session.established has no server_ephemeral_key — refusing "
            "unbound / legacy cleartext-token session"
        )
    if state_machine is not None:
        state_machine.transition("receive_established")
    try:
        key = derive_session_binding_key(
            state.private_key,
            established.server_ephemeral_key,
            session_id=established.session_id,
            client_nonce=state.client_nonce,
            server_nonce=established.server_nonce,
            client_public_key=state.client_public_key,
            server_public_key=established.server_ephemeral_key,
        )
    except ValueError as exc:
        raise SessionBindingError(f"key agreement failed: {exc}") from exc
    binding = SessionBinding(
        session_id=established.session_id,
        binding_token=key,
        client_nonce=state.client_nonce,
        server_nonce=established.server_nonce,
        client_public_key=state.client_public_key,
        server_public_key=established.server_ephemeral_key,
        confirm_nonce=established.confirm_nonce,
    )
    proof = compute_binding_proof(
        key,
        session_id=binding.session_id,
        client_nonce=binding.client_nonce,
        server_nonce=binding.server_nonce,
        confirm_nonce=binding.confirm_nonce,
        client_public_key=binding.client_public_key,
        server_public_key=binding.server_public_key,
    )
    confirm = SessionConfirmBody(
        session_id=binding.session_id,
        binding_proof=proof,
        confirm_nonce=binding.confirm_nonce,
    )
    if state_machine is not None:
        state_machine.transition("send_confirm")
    return confirm, binding


def server_verify_confirm(
    confirm: SessionConfirmBody,
    binding: SessionBinding,
    state_machine: HandshakeStateMachine,
) -> bool:
    """Verify a client's session.confirm (mandatory for bound sessions).

    Checks, in order: session_id and confirm_nonce match the binding,
    ``binding_proof`` verifies (constant time), then consumes the confirm
    nonce (replay protection) and transitions ``receive_confirm``.

    Returns:
        True on success.

    Raises:
        SessionBindingError: On session mismatch or invalid proof.
        SessionReplayError: If the confirm nonce was already consumed or
            never issued.
    """
    if not binding.binding_token or not binding.server_public_key:
        raise SessionBindingError("binding has no derived key")
    if not hmac.compare_digest(
        confirm.session_id.encode("utf-8"), binding.session_id.encode("utf-8")
    ):
        raise SessionBindingError("session.confirm session_id mismatch")
    if not hmac.compare_digest(
        confirm.confirm_nonce.encode("utf-8"), binding.confirm_nonce.encode("utf-8")
    ):
        raise SessionBindingError("session.confirm confirm_nonce mismatch")
    if not verify_binding_proof(
        binding.binding_token,
        confirm.binding_proof,
        session_id=binding.session_id,
        client_nonce=binding.client_nonce,
        server_nonce=binding.server_nonce,
        confirm_nonce=binding.confirm_nonce,
        client_public_key=binding.client_public_key,
        server_public_key=binding.server_public_key,
    ):
        raise SessionBindingError("binding_proof verification failed")
    state_machine.consume_confirm_nonce(confirm.confirm_nonce)
    state_machine.transition("receive_confirm")
    return True
