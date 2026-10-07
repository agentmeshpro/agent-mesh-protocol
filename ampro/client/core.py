"""
AMP Client SDK — Internal HTTP Transport.

NOT public API.  All public functions in send / discover / stream / session
delegate to these helpers for HTTP communication.

Handles:
  - agent:// URI resolution to HTTPS endpoints via /.well-known/agent.json
  - POST /agent/message with AgentMessage envelope
  - Error mapping from HTTP responses to AmpProtocolError
  - SSRF protection: every outbound request is checked with
    :mod:`ampro.security.ssrf` (scheme, internal hostnames, every resolved
    address) and the connection is pinned to the checked addresses so DNS
    rebinding cannot redirect it.  Pass ``allow_private=True`` to the public
    helpers to reach loopback / private addresses during local development.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ampro import __version__ as _AMPRO_VERSION
from ampro.client.errors import AmpProtocolError
from ampro.core.addressing import AddressType, parse_agent_uri
from ampro.core.envelope import AgentMessage
from ampro.security.ssrf import pinned_async_transport, validate_url_async
from ampro.transport.limits import read_capped
from ampro.wire.config import DEFAULTS
from ampro.wire.errors import ProblemDetail

logger = logging.getLogger("ampro.client")

# Header sent on all AMP client requests.
_USER_AGENT = f"ampro-client/{_AMPRO_VERSION}"


async def _guarded_client(
    url: str,
    *,
    allow_private: bool = False,
    max_response_bytes: int | None = None,
) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` that may only talk to *url*'s host.

    With *max_response_bytes*, every (non-streamed) response body is read
    through :func:`~ampro.transport.limits.read_capped` and the read is
    aborted with ``ResponseTooLarge`` once it exceeds the cap.  Leave it
    ``None`` for clients used with ``client.stream(...)`` (SSE), which bound
    their reads themselves.

    The host is resolved once; every resolved address must be public
    (unless *allow_private*), and the client's transport dials only those
    addresses.  Redirects are not followed and environment proxies are
    ignored (a proxy would re-resolve the name and defeat pinning).

    Raises:
        SSRFError: (a ``ValueError``) if the URL is not allowed.
    """
    validated = await validate_url_async(url, allow_private=allow_private)
    hooks: dict[str, list[Any]] = {}
    if max_response_bytes is not None:
        cap = max_response_bytes

        async def _cap_body(response: httpx.Response) -> None:
            # Runs before httpx reads the body; reading it here, capped,
            # leaves nothing for the unbounded default read to do.
            await read_capped(response, cap)

        hooks["response"] = [_cap_body]
    return httpx.AsyncClient(
        transport=pinned_async_transport(validated),
        follow_redirects=False,
        trust_env=False,
        event_hooks=hooks,
    )


async def _resolve_endpoint(uri: str) -> str:
    """Resolve an ``agent://`` URI to an HTTPS base URL.

    Currently supports HOST form only (e.g. ``agent://weather.example.com``).
    Slug and DID resolution are future work.

    Returns:
        The HTTPS base URL (e.g. ``https://weather.example.com``).

    Raises:
        ValueError: If the URI uses an unsupported address form (slug or DID).
    """
    addr = parse_agent_uri(uri)

    if addr.address_type == AddressType.HOST:
        return f"https://{addr.host}"

    if addr.address_type == AddressType.SLUG:
        raise ValueError(
            f"Slug-based addressing ({uri}) requires registry resolution "
            f"which is not yet implemented in the client SDK."
        )

    if addr.address_type == AddressType.DID:
        raise ValueError(
            f"DID-based addressing ({uri}) requires DID resolution "
            f"which is not yet implemented in the client SDK."
        )

    raise ValueError(f"Unknown address type: {addr.address_type}")


def _raise_for_problem(response: httpx.Response) -> None:
    """Parse a non-2xx response as RFC 7807 ProblemDetail and raise.

    If the response body cannot be parsed as ProblemDetail, a generic
    AmpProtocolError is raised with the status code and raw body.
    """
    try:
        data = response.json()
        problem = ProblemDetail.model_validate(data)
    except Exception:
        problem = ProblemDetail(
            type="urn:amp:error:unknown",
            title=f"HTTP {response.status_code}",
            status=response.status_code,
            detail=response.text[:512] if response.text else None,
        )
    raise AmpProtocolError(problem)


async def _post_message(
    endpoint: str,
    msg: AgentMessage,
    *,
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    allow_private: bool = False,
    max_response_bytes: int | None = None,
) -> AgentMessage:
    """POST an AgentMessage to ``/agent/message`` and return the response.

    Args:
        endpoint: HTTPS base URL of the target agent.
        msg: The message envelope to send.
        timeout: Request timeout in seconds.
        extra_headers: Additional HTTP headers (e.g. Session-Binding).
        allow_private: Permit loopback/private targets (local development).
        max_response_bytes: Response body cap (default
            ``WireConfig.max_response_bytes``); the read is aborted beyond it.

    Returns:
        The response parsed as an AgentMessage.

    Raises:
        AmpProtocolError: If the server returns a non-2xx response.
        SSRFError: If the endpoint is not a permitted outbound target.
        ResponseTooLarge: If the response exceeds the size cap.
    """
    url = f"{endpoint}/agent/message"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
    }
    if extra_headers:
        headers.update(extra_headers)

    payload = msg.model_dump(mode="json")

    cap = max_response_bytes or DEFAULTS.max_response_bytes
    async with await _guarded_client(
        url, allow_private=allow_private, max_response_bytes=cap,
    ) as client:
        response = await client.post(
            url,
            json=payload,
            headers=headers,
            timeout=timeout,
        )

    if response.status_code >= 400:
        _raise_for_problem(response)

    return AgentMessage.model_validate(response.json())


async def _get_json(
    url: str,
    *,
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    allow_private: bool = False,
    max_response_bytes: int | None = None,
) -> dict[str, Any]:
    """GET a URL and return parsed JSON.

    Raises:
        AmpProtocolError: If the server returns a non-2xx response.
        SSRFError: If the URL is not a permitted outbound target.
        ResponseTooLarge: If the response exceeds the size cap
            (``max_response_bytes``, default ``WireConfig.max_response_bytes``).
    """
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    cap = max_response_bytes or DEFAULTS.max_response_bytes
    async with await _guarded_client(
        url, allow_private=allow_private, max_response_bytes=cap,
    ) as client:
        response = await client.get(url, headers=headers, timeout=timeout)

    if response.status_code >= 400:
        _raise_for_problem(response)

    return response.json()
