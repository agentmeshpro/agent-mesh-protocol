"""Personal-agent registration (PACT §3.1).

The Provider keeps, per personal agent: ``issuer`` (exact ``iss``),
``jwks_uri`` (HTTPS), ``audience`` (opaque, the value the PA puts in ``aud``)
and ``enabled``.  :class:`PersonalAgentRegistry` is the lookup seam;
:class:`InMemoryPersonalAgentRegistry` is a bounded default that also
implements the optional *open* policy — accept any issuer that publishes a
JWKS through OIDC discovery at ``{iss}/.well-known/openid-configuration``.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from ampro.interop.pact.jwks import FetchError, JSONFetcher
from ampro.interop.pact.stores import BoundedTTLMap, Clock

logger = logging.getLogger("ampro.interop.pact.registry")

MAX_ISSUER_LEN = 512


@dataclass(frozen=True)
class PersonalAgentRegistration:
    """One registered personal agent.

    ``jwks`` may hold a static JWKS instead of (or as a seed for)
    ``jwks_uri`` — useful for tests and air-gapped deployments.
    ``audience`` of ``None`` means "the Provider's default audience".
    """

    issuer: str
    jwks_uri: str | None = None
    audience: str | None = None
    enabled: bool = True
    name: str | None = None
    jwks: dict[str, Any] | None = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not self.issuer or len(self.issuer) > MAX_ISSUER_LEN:
            raise ValueError("issuer must be a non-empty string")
        if self.jwks_uri is None and self.jwks is None:
            raise ValueError("a registration needs jwks_uri or jwks")


@runtime_checkable
class PersonalAgentRegistry(Protocol):
    async def lookup(self, issuer: str) -> PersonalAgentRegistration | None:
        """The registration for exactly *issuer*, or ``None`` (unknown)."""


def _https_issuer(issuer: str) -> bool:
    parts = urlsplit(issuer)
    return (
        parts.scheme == "https" and bool(parts.hostname) and not parts.query
        and not parts.fragment and not parts.username and not parts.password
    )


class InMemoryPersonalAgentRegistry:
    """Allow-list registry with an optional open (OIDC discovery) mode.

    Args:
        registrations: initial allow-list.
        open_mode: accept unknown ``https`` issuers whose OIDC discovery
            document names a ``jwks_uri``.  Explicitly disabled issuers stay
            rejected.  Discovered issuers get the default audience.
        fetcher: network seam for discovery (required for ``open_mode``).
        max_discovered: bound on cached discovery results.
        discovery_ttl: seconds a discovery result (positive or negative) is kept.
    """

    def __init__(
        self,
        registrations: list[PersonalAgentRegistration] | tuple[PersonalAgentRegistration, ...] = (),
        *,
        open_mode: bool = False,
        fetcher: JSONFetcher | None = None,
        max_registrations: int = 10_000,
        max_discovered: int = 10_000,
        discovery_ttl: float = 3600.0,
        clock: Clock = time.time,
    ) -> None:
        self._regs: dict[str, PersonalAgentRegistration] = {}
        self.max_registrations = max_registrations
        for reg in registrations:
            self.register(reg)
        self.open_mode = open_mode
        self._fetcher = fetcher
        self._discovered = BoundedTTLMap(max_discovered, discovery_ttl, clock)
        if open_mode and fetcher is None:
            from ampro.interop.pact.jwks import HttpsJSONFetcher

            self._fetcher = HttpsJSONFetcher()

    def register(self, registration: PersonalAgentRegistration) -> None:
        if registration.issuer not in self._regs and len(self._regs) >= self.max_registrations:
            raise ValueError("registry is full")
        self._regs[registration.issuer] = registration

    def set_enabled(self, issuer: str, enabled: bool) -> None:
        reg = self._regs[issuer]
        self._regs[issuer] = PersonalAgentRegistration(
            issuer=reg.issuer, jwks_uri=reg.jwks_uri, audience=reg.audience,
            enabled=enabled, name=reg.name, jwks=reg.jwks,
        )

    def remove(self, issuer: str) -> None:
        self._regs.pop(issuer, None)

    async def lookup(self, issuer: str) -> PersonalAgentRegistration | None:
        reg = self._regs.get(issuer)
        if reg is not None or not self.open_mode:
            return reg
        if not isinstance(issuer, str) or len(issuer) > MAX_ISSUER_LEN or not _https_issuer(issuer):
            return None
        cached = self._discovered.get(issuer)
        if cached is not None:
            return cached or None
        found = await self._discover(issuer)
        self._discovered.set(issuer, found or False)
        return found

    async def _discover(self, issuer: str) -> PersonalAgentRegistration | None:
        assert self._fetcher is not None
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        try:
            doc = await self._fetcher.fetch_json(url)
        except FetchError as exc:
            logger.info("pact.registry.discovery_failed", extra={"issuer": issuer, "reason": str(exc)})
            return None
        if not isinstance(doc, dict) or doc.get("issuer") != issuer:
            return None
        jwks_uri = doc.get("jwks_uri")
        if not isinstance(jwks_uri, str) or urlsplit(jwks_uri).scheme != "https":
            return None
        return PersonalAgentRegistration(issuer=issuer, jwks_uri=jwks_uri, name=None)


__all__ = [
    "InMemoryPersonalAgentRegistry",
    "PersonalAgentRegistration",
    "PersonalAgentRegistry",
]
