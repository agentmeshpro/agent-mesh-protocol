"""PACT Agent Card (§2.1, §5.1)."""
from __future__ import annotations

from typing import Any

from ampro.interop.pact.brand import Brand
from ampro.interop.pact.delegation import OAuthURLs

DEFAULT_SCHEME = "paJwt"
DELEGATION_SCHEME = "userDelegation"


def _skill(skill: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": str(skill["id"]),
        "name": str(skill.get("name") or skill["id"]),
        "description": str(skill.get("description") or ""),
        "tags": [str(t) for t in skill.get("tags") or []],
    }
    if skill.get("examples"):
        out["examples"] = [str(e) for e in skill["examples"]]
    return out


def build_pact_card(
    brand: Brand,
    *,
    interface_url: str,
    provider_url: str,
    provider_name: str,
    identity_scheme: str = DEFAULT_SCHEME,
    delegation: bool | None = None,
) -> dict[str, Any]:
    """The card for *brand*: one HTTP+JSON 1.0 interface, the PA-JWT scheme
    alone in one requirement, plus the device-code scheme when delegating."""
    delegation = brand.delegation_enabled if delegation is None else delegation
    schemes: dict[str, Any] = {
        identity_scheme: {"httpAuthSecurityScheme": {
            "scheme": "Bearer", "bearerFormat": "JWT",
            "description": "JWT signed by a registered personal agent; aud is the audience "
                           "the provider assigned at registration",
        }},
    }
    requirements: list[dict[str, Any]] = [{"schemes": {identity_scheme: {"list": []}}}]
    if delegation:
        urls = OAuthURLs.for_interface(interface_url)
        schemes[DELEGATION_SCHEME] = {"oauth2SecurityScheme": {
            "description": f"Act on the User's {brand.name} account within the scopes they approve",
            "flows": {"deviceCode": {
                "deviceAuthorizationUrl": urls.device_authorization,
                "tokenUrl": urls.token,
                "scopes": {s.id: s.description for s in brand.scopes},
            }},
            "oauth2MetadataUrl": urls.metadata,
        }}
        requirements.append({"schemes": {identity_scheme: {"list": []},
                                         DELEGATION_SCHEME: {"list": []}}})
    return {
        "name": brand.name,
        "description": brand.description or brand.name,
        "supportedInterfaces": [
            {"url": interface_url, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
        ],
        "provider": {"organization": provider_name, "url": provider_url},
        "version": brand.version,
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
        "securitySchemes": schemes,
        "securityRequirements": requirements,
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [_skill(s) for s in brand.skills],
    }


__all__ = ["DEFAULT_SCHEME", "DELEGATION_SCHEME", "build_pact_card"]
