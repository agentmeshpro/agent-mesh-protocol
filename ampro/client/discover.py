"""
AMP Client SDK — discover().

Fetch an agent's ``/.well-known/agent.json`` to learn its capabilities,
trust configuration, and endpoint details.  Like ``httpx.get()`` but
parses the result into a typed ``AgentJson``.

Usage::

    from ampro.client import discover

    info = await discover("agent://weather.example.com")
    print(info.protocol_version)
    print(info.capabilities)
    print(info.endpoint)
"""

from __future__ import annotations

from ampro.agent.schema import AgentJson
from ampro.client.core import _get_json
from ampro.core.addressing import AddressType, parse_agent_uri


async def discover(
    uri: str, timeout: float = 30.0, *, allow_private: bool = False,
) -> AgentJson:
    """Fetch an agent's capabilities via ``/.well-known/agent.json``.

    Args:
        uri: Agent URI (e.g. ``agent://weather.example.com``).
            Currently only HOST-form URIs are supported.
        timeout: HTTP timeout in seconds (default 30).
        allow_private: Allow the agent host to resolve to a loopback,
            private or otherwise internal address.  Off by default (SSRF
            protection); set ``True`` only for local development.

    Returns:
        Parsed ``AgentJson`` describing the agent's identity,
        capabilities, constraints, and security configuration.

    Raises:
        AmpProtocolError: If the server returns a non-2xx response.
        ValueError: If the URI uses an unsupported address form.
        SSRFError: (subclass of ``ValueError``) if the host is internal
            and ``allow_private`` is False.
    """
    addr = parse_agent_uri(uri)

    if addr.address_type != AddressType.HOST:
        raise ValueError(
            f"discover() currently requires HOST-form URIs, got {addr.address_type.value}: {uri}"
        )

    url = f"https://{addr.host}/.well-known/agent.json"
    data = await _get_json(url, timeout=timeout, allow_private=allow_private)
    return AgentJson.model_validate(data)
