"""
AMP Wire Binding -- naming rules for third-party extensions.

Third parties extend AMP without forking it (``docs/EXTENSIONS.md``): they
define body types, headers, error types, stream events and extension URIs
in a namespace they control.  These helpers check those names, so that
extension authors, the spec generator and receivers apply the same rules.

PURE -- stdlib only.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

#: First labels of body types and stream events reserved for AMP itself.
RESERVED_NAMESPACES: frozenset[str] = frozenset({
    "agent", "amp", "audit", "data", "encryption", "erasure", "identity", "key",
    "message", "notification", "registry", "session", "stream", "task", "tool", "trust",
})

#: Header prefix reserved for AMP-defined extension headers.
RESERVED_HEADER_PREFIX = "x-amp-"

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
# Reverse-DNS: at least three labels; the last segment may use underscores.
_REVERSE_DNS = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+\.[a-z0-9][a-z0-9_-]*$")
# Experimental / private: x-<vendor>.<name>[.<name>...]
_EXPERIMENTAL = re.compile(rf"^x-{_LABEL}(?:\.[a-z0-9][a-z0-9_-]*)+$")
_HEADER = re.compile(r"^X-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$")
_ERROR_URN = re.compile(r"^urn:[a-z0-9][a-z0-9.-]*:error:[a-z0-9][a-z0-9-]*$")


def _https_uri(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and not parts.fragment


def extension_name_error(name: str) -> str | None:
    """Why *name* is not a valid extension body type / event type, or ``None``.

    Valid forms:

    * reverse-DNS of a domain the author controls: ``com.acme.order_confirmation``
    * experimental or private: ``x-acme.order_confirmation``
    * an absolute ``https`` URI the author controls:
      ``https://acme.example/amp/order-confirmation/v1``
    """
    if not name or name != name.strip():
        return "empty or padded name"
    if name.startswith("https://"):
        return None if _https_uri(name) else "malformed https URI"
    if name.startswith("x-"):
        return None if _EXPERIMENTAL.match(name) else "expected x-<vendor>.<name>"
    if not _REVERSE_DNS.match(name):
        return "expected reverse-DNS (com.example.name), x-<vendor>.<name> or an https URI"
    if name.split(".", 1)[0] in RESERVED_NAMESPACES:
        return f"namespace {name.split('.', 1)[0]!r} is reserved for AMP"
    return None


def is_extension_name(name: str) -> bool:
    """True if *name* is a well-formed third-party body type or event type."""
    return extension_name_error(name) is None


def extension_header_error(name: str) -> str | None:
    """Why *name* is not a valid third-party header, or ``None``.

    Third-party headers use ``X-<Vendor>-<Name>`` (WIRE-BINDING 18.2) and
    MUST NOT use the reserved ``X-AMP-`` prefix.
    """
    if not _HEADER.match(name):
        return "expected X-<Vendor>-<Name>"
    if name.lower().startswith(RESERVED_HEADER_PREFIX):
        return "the X-AMP- prefix is reserved for AMP"
    return None


def extension_error_type_error(urn: str) -> str | None:
    """Why *urn* is not a valid third-party problem type, or ``None``.

    Form: ``urn:<reverse-domain>:error:<name>`` (WIRE-BINDING 7.1.2).
    """
    if not _ERROR_URN.match(urn):
        return "expected urn:<reverse-domain>:error:<name>"
    if urn.startswith("urn:amp:"):
        return "urn:amp: is reserved for AMP"
    return None


def extension_uri_error(uri: str) -> str | None:
    """Why *uri* is not a valid extension URI, or ``None``.

    Extension URIs are absolute ``https`` URIs under a domain the author
    controls, SHOULD end in a version segment (``/v1``), and SHOULD
    resolve to the extension's specification.
    """
    return None if _https_uri(uri) else "expected an absolute https URI without fragment"
