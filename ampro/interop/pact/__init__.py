"""PACT — Personal Agent Consent & Trust, on A2A 1.0 (HTTP+JSON).

Provider side
-------------
* :class:`PACTProvider` — multi-Brand host (a ``ProtocolAdapter``) serving
  ``{public_url}/a2a/{brandId}`` for the **Identity** profile (§2–4, §6) and,
  per Brand, the **Delegated** profile (§5).
* :class:`PAJwtAuthenticator`, :class:`InMemoryPersonalAgentRegistry` —
  personal-agent JWT verification against registered JWKS.
* :class:`Brand`, :class:`Scope`, :class:`BrandLogin`, :class:`JWTBrandLogin`.
* :class:`ProviderKeySet` — signing keys for delegation tokens and receipts.
* Handler API: :func:`requires_scopes`, :func:`ensure_scopes`,
  :func:`record_action`, :func:`current_delegation`,
  :func:`close_conversation`.

Personal-agent side
-------------------
* :class:`PASigner`, :class:`PACTClient`, :func:`verify_receipt`.

Requires ``pip install 'ampro[pact]'`` (PyJWT with crypto) at runtime.
"""
from __future__ import annotations

from ampro.interop.a2a import AuthRequired
from ampro.interop.pact.auth import PAIdentity, PAJwtAuthenticator, principal_id
from ampro.interop.pact.brand import Brand, BrandLogin, BrandUser, JWTBrandLogin, Scope
from ampro.interop.pact.card import build_pact_card
from ampro.interop.pact.client import (
    BrandSession,
    OAuthError,
    PACTClient,
    PACTClientError,
    PASigner,
    ReceiptError,
    Reply,
    verify_receipt,
)
from ampro.interop.pact.delegation import DelegationServer, OAuthURLs
from ampro.interop.pact.jwks import HttpsJSONFetcher, JSONFetcher, JWKSCache
from ampro.interop.pact.keys import ProviderKeySet
from ampro.interop.pact.provider import PACTProvider
from ampro.interop.pact.registry import (
    InMemoryPersonalAgentRegistry,
    PersonalAgentRegistration,
    PersonalAgentRegistry,
)
from ampro.interop.pact.scopes import (
    Delegation,
    close_conversation,
    current_delegation,
    current_turn,
    ensure_scopes,
    record_action,
    requires_scopes,
    use_scopes,
)
from ampro.interop.pact.stores import DelegationStores, InMemoryContextStore

__all__ = [
    "AuthRequired",
    "Brand",
    "BrandLogin",
    "BrandSession",
    "BrandUser",
    "Delegation",
    "DelegationServer",
    "DelegationStores",
    "HttpsJSONFetcher",
    "InMemoryContextStore",
    "InMemoryPersonalAgentRegistry",
    "JSONFetcher",
    "JWKSCache",
    "JWTBrandLogin",
    "OAuthError",
    "OAuthURLs",
    "PACTClient",
    "PACTClientError",
    "PACTProvider",
    "PAIdentity",
    "PAJwtAuthenticator",
    "PASigner",
    "PersonalAgentRegistration",
    "PersonalAgentRegistry",
    "ProviderKeySet",
    "ReceiptError",
    "Reply",
    "Scope",
    "build_pact_card",
    "close_conversation",
    "current_delegation",
    "current_turn",
    "ensure_scopes",
    "principal_id",
    "record_action",
    "requires_scopes",
    "use_scopes",
    "verify_receipt",
]
