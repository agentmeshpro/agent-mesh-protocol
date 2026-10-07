"""
AMP Client SDK — Session management with 3-phase handshake.

Implements the full session lifecycle:
  1. Client sends ``session.init`` with ``client_nonce`` and an ephemeral
     X25519 public key (``client_ephemeral_key``)
  2. Server replies ``session.established`` with ``server_nonce``,
     ``confirm_nonce`` and ``server_ephemeral_key``; both sides derive the
     binding key via X25519 + HKDF (the key is never transmitted)
  3. Client sends ``session.confirm`` with ``binding_proof`` and the echoed
     ``confirm_nonce``
  4. Session is ACTIVE — all subsequent messages include binding headers
     whose HMAC covers the message body

Usage::

    from ampro.client import connect

    async with await connect("agent://weather.example.com") as session:
        reply = await session.send({"q": "forecast"})
        print(reply.body)
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

from ampro.client.core import _post_message, _resolve_endpoint
from ampro.core.envelope import AgentMessage
from ampro.session.binding import create_message_binding
from ampro.session.handshake import (
    SessionEstablishedBody,
    client_finish_handshake,
    client_start_handshake,
)


class Session:
    """An active AMP session with automatic message binding.

    Obtained via :func:`connect`.  Use as an async context manager::

        async with await connect("agent://target.example.com") as s:
            reply = await s.send({"hello": "world"})
    """

    def __init__(
        self,
        *,
        endpoint: str,
        target_uri: str,
        sender: str,
        session_id: str,
        binding_token: str,
    ) -> None:
        self._endpoint = endpoint
        self._target_uri = target_uri
        self._sender = sender
        self.session_id = session_id
        self._binding_token = binding_token

    async def send(
        self,
        body: dict[str, Any],
        body_type: str = "message",
        headers: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> AgentMessage:
        """Send a message within this session.

        Automatically attaches ``Session-Id`` and ``Session-Binding``
        headers with a per-message HMAC proof.

        Args:
            body: Message body (dict).
            body_type: AMP body type (default ``"message"``).
            headers: Additional AMP headers.
            timeout: HTTP timeout in seconds.

        Returns:
            The response ``AgentMessage``.
        """
        msg_headers: dict[str, Any] = {"Session-Id": self.session_id}
        if headers:
            msg_headers.update(headers)

        msg = AgentMessage(
            sender=self._sender,
            recipient=self._target_uri,
            body_type=body_type,
            headers=msg_headers,
            body=body,
        )

        # Compute per-message binding proof (covers the wire-form body)
        binding_proof = create_message_binding(
            self.session_id,
            msg.id,
            self._binding_token,
            body=msg.model_dump(mode="json")["body"],
        )

        return await _post_message(
            self._endpoint,
            msg,
            timeout=timeout,
            extra_headers={"Session-Binding": binding_proof},
        )

    async def close(self) -> None:
        """Gracefully close the session by sending ``session.close``."""
        msg = AgentMessage(
            sender=self._sender,
            recipient=self._target_uri,
            body_type="session.close",
            headers={"Session-Id": self.session_id},
            body={"session_id": self.session_id, "reason": "client_close"},
        )
        binding_proof = create_message_binding(
            self.session_id,
            msg.id,
            self._binding_token,
            body=msg.model_dump(mode="json")["body"],
        )
        await _post_message(
            self._endpoint,
            msg,
            extra_headers={"Session-Binding": binding_proof},
        )

    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            await self.close()
        except Exception:
            # Best-effort close — don't mask the original exception
            pass


async def connect(
    to: str,
    sender: str | None = None,
) -> Session:
    """Establish a session via the 3-phase AMP handshake.

    1. Sends ``session.init`` with a random ``client_nonce`` and an
       ephemeral X25519 public key.
    2. Receives ``session.established`` with ``server_nonce``,
       ``session_id``, ``confirm_nonce`` and ``server_ephemeral_key``;
       derives the binding key locally (never sent on the wire). A
       response without ``server_ephemeral_key`` is refused.
    3. Sends ``session.confirm`` with ``binding_proof`` (HMAC over the
       handshake transcript) and the echoed ``confirm_nonce``.

    Args:
        to: Agent URI of the target agent.
        sender: Agent URI of the sender (defaults to ``"anonymous"``).

    Returns:
        An active ``Session`` ready for communication.

    Raises:
        AmpProtocolError: If any handshake step fails.
        ValueError: If the URI cannot be resolved or the server
            returns an unexpected / malformed body.
        SessionBindingError: If the server did not perform key agreement.
    """
    endpoint = await _resolve_endpoint(to)
    sender_uri = sender or "anonymous"

    # Phase 1: session.init (with ephemeral key)
    init_body, client_state = client_start_handshake(["messaging"], "1.0.0")
    init_msg = AgentMessage(
        sender=sender_uri,
        recipient=to,
        body_type="session.init",
        body=init_body.model_dump(mode="json", exclude_none=True),
    )
    established_msg = await _post_message(endpoint, init_msg)

    # Validate the response
    if established_msg.body_type != "session.established":
        raise ValueError(
            f"Expected session.established, got {established_msg.body_type}"
        )

    body = established_msg.body
    if not isinstance(body, dict):
        raise ValueError("session.established body must be a dict")
    try:
        established = SessionEstablishedBody.model_validate(body)
    except Exception as exc:
        raise ValueError(f"malformed session.established: {exc}") from exc

    # Phase 2/3: derive key locally, compute proof, echo confirm_nonce
    confirm_body, binding = client_finish_handshake(client_state, established)

    confirm_msg = AgentMessage(
        sender=sender_uri,
        recipient=to,
        body_type="session.confirm",
        headers={"Session-Id": binding.session_id},
        body=confirm_body.model_dump(mode="json"),
    )
    await _post_message(endpoint, confirm_msg)

    return Session(
        endpoint=endpoint,
        target_uri=to,
        sender=sender_uri,
        session_id=binding.session_id,
        binding_token=binding.binding_token,
    )
