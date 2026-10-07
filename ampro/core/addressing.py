"""
Agent Protocol — agent:// URI Addressing.

Parses agent:// URIs into structured addresses with three forms:
  - Direct host:    agent://bakery.example.com
  - Registry slug:  agent://sales@example.com
  - DID:            agent://did:web:example.com

This module is PURE — no platform-specific imports.
Designed for extraction as part of `pip install agent-protocol`.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from enum import Enum
from urllib.parse import unquote

from pydantic import BaseModel, Field

SCHEME = "agent"

# Control characters and percent-encoded control characters that MUST NOT
# appear in an agent:// authority (defense against smuggling / log injection).
_DANGEROUS_PERCENT_ENCODED = ("%00", "%0a", "%0A", "%0d", "%0D", "%09")


class AddressType(str, Enum):
    HOST = "host"
    SLUG = "slug"
    DID = "did"


class AgentAddress(BaseModel):
    raw: str = Field(description="Original URI string")
    address_type: AddressType
    host: str | None = None
    port: int | None = None
    slug: str | None = None
    registry: str | None = None
    did: str | None = None

    model_config = {"extra": "ignore"}

    def to_uri(self) -> str:
        if self.address_type == AddressType.DID:
            return f"agent://{self.did}"
        if self.address_type == AddressType.SLUG:
            return f"agent://{self.slug}@{self.registry}"
        if self.host and ":" in self.host:
            # IPv6 literal — re-bracket
            host_part = f"[{self.host}]"
        else:
            host_part = self.host or ""
        if self.port is not None:
            return f"agent://{host_part}:{self.port}"
        return f"agent://{host_part}"

    def agent_json_url(self) -> str:
        if self.address_type != AddressType.HOST:
            raise ValueError(f"agent_json_url() requires HOST address, got {self.address_type}")
        return f"https://{self.host}/.well-known/agent.json"

    def registry_resolve_url(self) -> str:
        """Build the registry resolution URL for a SLUG address.

        The returned URL is validated against SSRF (via
        ``validate_attachment_url``) before being returned. Callers may still
        validate again if they accept user-supplied registries.
        """
        if self.address_type != AddressType.SLUG:
            raise ValueError(
                f"registry_resolve_url() requires SLUG address, got {self.address_type}"
            )
        url = f"https://{self.registry}/agent/resolve/{self.slug}"
        # SSRF guard — enforces the docstring contract.
        try:
            from ampro.transport.attachment import validate_attachment_url
        except ImportError:
            return url
        if not validate_attachment_url(url):
            raise ValueError(
                f"registry_resolve_url() rejected URL (SSRF guard): {url!r}"
            )
        return url


def _normalize_host(host: str) -> str:
    """NFKC-normalize and IDNA-encode a hostname for shape comparison.

    This converts Unicode hostnames to their ASCII Compatible Encoding (ACE)
    form. We only NORMALIZE — we do not reject unknown labels.
    """
    normalized = unicodedata.normalize("NFKC", host)
    try:
        # .encode("idna") enforces IDNA label-shape rules only (length etc.)
        ace = normalized.encode("idna").decode("ascii")
        return ace
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"hostname IDNA normalization failed for {host!r}: {exc}"
        ) from exc


def parse_agent_uri(uri: str) -> AgentAddress:
    if not uri.startswith("agent://"):
        raise ValueError(f"Agent URI must start with agent://, got: {uri!r}")
    authority = uri[len("agent://"):]
    if not authority:
        raise ValueError("Agent URI has empty authority")

    # Reject dangerous percent-encoded control sequences before decoding.
    for bad in _DANGEROUS_PERCENT_ENCODED:
        if bad in authority:
            raise ValueError(
                f"Agent URI authority contains forbidden percent-encoded "
                f"control character {bad!r}: {uri!r}"
            )
    # Reject raw control characters in the authority.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in authority):
        raise ValueError(
            f"Agent URI authority contains raw control character: {uri!r}"
        )

    # Decode percent-encoding (matching validate_attachment_url semantics).
    authority = unquote(authority)

    # IPv6 literal in brackets — must come before did: check and before
    # the ':' port-split (because IPv6 contains colons).
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ValueError(f"Agent URI with '[' missing closing ']': {uri!r}")
        ipv6_literal = authority[1:end]
        try:
            ipaddress.ip_address(ipv6_literal)
        except ValueError as exc:
            raise ValueError(
                f"Agent URI has invalid IPv6 literal {ipv6_literal!r}: {exc}"
            ) from exc
        port: int | None = None
        remainder = authority[end + 1:]
        if remainder:
            if not remainder.startswith(":"):
                raise ValueError(
                    f"Agent URI has trailing characters after IPv6 bracket: {uri!r}"
                )
            port_str = remainder[1:]
            if not port_str.isdigit():
                raise ValueError(f"Agent URI has non-numeric port: {uri!r}")
            port = int(port_str)
            if port > 65535:
                raise ValueError(f"Agent URI port out of range: {port}")
        return AgentAddress(
            raw=uri,
            address_type=AddressType.HOST,
            host=ipv6_literal,
            port=port,
        )

    if "did:" in authority:
        return AgentAddress(raw=uri, address_type=AddressType.DID, did=authority)

    if "@" in authority:
        # rsplit handles did:web:foo@registry.example.com (method-specific-id
        # may contain '@'), though did: was already handled above. This also
        # defends against "slug@a@b" — see multi-'@' check below.
        slug, registry = authority.rsplit("@", 1)
        if "@" in slug:
            raise ValueError(
                "malformed agent URI: multiple '@' not allowed in slug or registry"
            )
        if not slug or not registry:
            raise ValueError(f"Invalid slug@registry format: {authority!r}")
        return AgentAddress(
            raw=uri, address_type=AddressType.SLUG, slug=slug, registry=registry
        )

    # Host form — possibly with :port.
    host = authority
    port = None
    if ":" in authority:
        host_part, _, port_str = authority.rpartition(":")
        if port_str.isdigit():
            port_value = int(port_str)
            if port_value > 65535:
                raise ValueError(f"Agent URI port out of range: {port_value}")
            host = host_part
            port = port_value
        # else: leave host/port unseparated — odd shapes fall through to
        # IDNA validation below which will raise.

    if not host:
        raise ValueError(f"Agent URI has empty host: {uri!r}")

    # NFKC + IDNA shape-check for Unicode/ASCII hostnames.
    host = _normalize_host(host)

    return AgentAddress(
        raw=uri, address_type=AddressType.HOST, host=host, port=port
    )


# ---------------------------------------------------------------------------
# Foreign identifiers (agent.json ``foreign_identifiers``, WIRE-BINDING E.4)
# ---------------------------------------------------------------------------
#
# Other ecosystems name the same agent differently: an MCP client ID
# metadata document URL, a ``did:web`` / ``did:wba`` DID (ANP), a Web Bot
# Auth ``Signature-Agent`` key directory URL.  These helpers only check
# and canonicalise the *syntax*; a foreign identifier never confers trust
# by itself (see :func:`ampro.identity.link.verified_foreign_aliases`).

#: Upper bound on a foreign https identifier, after normalisation.
MAX_FOREIGN_URL_LENGTH = 2048
#: Upper bound on a foreign DID.
MAX_FOREIGN_DID_LENGTH = 512
#: DID methods accepted as foreign identifiers.
FOREIGN_DID_METHODS = frozenset({"key", "web", "wba"})

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
# RFC 3986 pchar minus pct-encoded, plus "/".
_PATH_CHARS = _UNRESERVED | frozenset("!$&'()*+,;=:@/")
_HEX = frozenset("0123456789abcdefABCDEF")
_LDH_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DID_KEY_ED25519 = re.compile(r"^z6Mk[" + _BASE58 + r"]{40,50}$")
_DID_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def _canonical_dns_host(host: str, what: str) -> str:
    """NFKC + IDNA a hostname and enforce LDH shape; IP literals refused."""
    if not host:
        raise ValueError(f"{what} has an empty host")
    if host.endswith("."):
        raise ValueError(f"{what} host must not end with '.'")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError(f"{what} host must be a DNS name, not an IP literal")
    ace = _normalize_host(host).lower()
    if len(ace) > 253:
        raise ValueError(f"{what} host is longer than 253 characters")
    labels = ace.split(".")
    if len(labels) < 2:
        raise ValueError(f"{what} host must be a fully-qualified domain name")
    for label in labels:
        if not _LDH_LABEL.match(label):
            raise ValueError(f"{what} host has an invalid label {label!r}")
    if labels[-1].isdigit():
        raise ValueError(f"{what} host must not end in a numeric label")
    return ace


def _normalise_percent(segment: str, what: str) -> str:
    """RFC 3986 6.2.2 percent-normalisation of a path.

    Escapes of unreserved characters are decoded, other escapes get
    upper-case hex, and escaped control characters, ``/``, ``\\`` and
    ``%`` are refused (they could smuggle a different path through a
    decoder).
    """
    out: list[str] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "%":
            pair = segment[i + 1:i + 3]
            if len(pair) != 2 or not set(pair) <= _HEX:
                raise ValueError(f"{what} has a malformed percent-escape")
            code = int(pair, 16)
            if code < 0x20 or code == 0x7F or chr(code) in "/\\%":
                raise ValueError(f"{what} has a forbidden percent-escaped character")
            decoded = chr(code)
            out.append(decoded if decoded in _UNRESERVED else "%" + pair.upper())
            i += 3
            continue
        if ch not in _PATH_CHARS:
            raise ValueError(f"{what} contains a forbidden character {ch!r}")
        out.append(ch)
        i += 1
    return "".join(out)


def normalize_foreign_https_id(value: str) -> str:
    """Validate and canonicalise an ``https://`` foreign identifier.

    Used for MCP client ID metadata document URLs and Web Bot Auth
    ``Signature-Agent`` key directories.  Rules (all fail closed):

    * scheme ``https`` only (``http`` and everything else refused);
    * no userinfo, no fragment, no query, no backslashes, no whitespace
      or control characters, ASCII only outside the host;
    * host: NFKC + IDNA to its A-label form (as :func:`parse_agent_uri`),
      lowercased, LDH labels, fully qualified, no IP literals, no
      trailing dot, no percent-encoding;
    * port 1..65535, ``:443`` dropped;
    * path percent-normalised (RFC 3986 6.2.2), empty path becomes ``/``,
      dot segments refused;
    * at most :data:`MAX_FOREIGN_URL_LENGTH` characters before and after.
    """
    if not isinstance(value, str):
        raise ValueError("foreign identifier must be a string")
    what = "foreign https identifier"
    if not value or len(value) > MAX_FOREIGN_URL_LENGTH:
        raise ValueError(f"{what} must be 1..{MAX_FOREIGN_URL_LENGTH} characters")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{what} contains whitespace or control characters")
    if "\\" in value:
        raise ValueError(f"{what} contains a backslash")
    scheme, sep, rest = value.partition("://")
    if not sep or scheme.lower() != "https":
        raise ValueError(f"{what} must use the https scheme")
    if "#" in rest:
        raise ValueError(f"{what} must not have a fragment")
    if "?" in rest:
        raise ValueError(f"{what} must not have a query")
    authority, slash, path = rest.partition("/")
    path = slash + path
    if "@" in authority:
        raise ValueError(f"{what} must not carry userinfo")
    if "%" in authority:
        raise ValueError(f"{what} host must not be percent-encoded")
    if authority.startswith("["):
        raise ValueError(f"{what} host must be a DNS name, not an IP literal")
    host, colon, port_str = authority.rpartition(":") if ":" in authority else (authority, "", "")
    port: int | None = None
    if colon:
        if not port_str.isascii() or not port_str.isdigit() or len(port_str) > 5:
            raise ValueError(f"{what} has an invalid port")
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError(f"{what} port out of range")
    host = _canonical_dns_host(host, what)
    if not path.isascii():
        raise ValueError(f"{what} path must be ASCII (percent-encode it)")
    path = _normalise_percent(path or "/", what)
    if any(seg in (".", "..") for seg in path.split("/")):
        raise ValueError(f"{what} path must not contain dot segments")
    netloc = host if port in (None, 443) else f"{host}:{port}"
    result = f"https://{netloc}{path}"
    if len(result) > MAX_FOREIGN_URL_LENGTH:
        raise ValueError(f"{what} is longer than {MAX_FOREIGN_URL_LENGTH} characters")
    return result


def normalize_foreign_did(value: str) -> str:
    """Validate and canonicalise a foreign DID (``did:key``, ``did:web``, ``did:wba``).

    * Only the methods in :data:`FOREIGN_DID_METHODS` are accepted; the
      method name must be lowercase.
    * A bare DID only: no DID-URL path, query or fragment.
    * ``did:key``: an Ed25519 multibase key (``z6Mk`` + base58btc).
    * ``did:web`` / ``did:wba``: the first segment is a DNS name
      (lowercased, LDH, fully qualified, no IP literals), optionally with
      a ``%3A``-encoded port; further ``:``-separated path segments use
      ``[A-Za-z0-9._-]`` only.
    * At most :data:`MAX_FOREIGN_DID_LENGTH` characters, ASCII only.
    """
    if not isinstance(value, str):
        raise ValueError("foreign DID must be a string")
    if not value or len(value) > MAX_FOREIGN_DID_LENGTH or not value.isascii():
        raise ValueError(f"foreign DID must be 1..{MAX_FOREIGN_DID_LENGTH} ASCII characters")
    if any(ch in value for ch in "/?#") or any(ch.isspace() for ch in value):
        raise ValueError("foreign DID must be a bare DID (no path, query or fragment)")
    parts = value.split(":")
    if len(parts) < 3 or parts[0] != "did":
        raise ValueError("foreign DID must look like did:<method>:<id>")
    method = parts[1]
    if method not in FOREIGN_DID_METHODS:
        raise ValueError(
            f"DID method {method!r} not allowed; expected one of {sorted(FOREIGN_DID_METHODS)}"
        )
    if method == "key":
        if len(parts) != 3 or not _DID_KEY_ED25519.match(parts[2]):
            raise ValueError("did:key must be an Ed25519 multibase key (z6Mk...)")
        return value
    domain, pct, port_str = parts[2].partition("%3A")
    if not pct:
        domain, pct, port_str = parts[2].partition("%3a")
    if "%" in domain:
        raise ValueError(f"did:{method} domain must not be percent-encoded")
    domain = _canonical_dns_host(domain, f"did:{method}")
    host_part = domain
    if pct:
        if not port_str.isdigit() or len(port_str) > 5 or not 1 <= int(port_str) <= 65535:
            raise ValueError(f"did:{method} has an invalid port")
        host_part = f"{domain}%3A{int(port_str)}"
    segments = parts[3:]
    for seg in segments:
        if not _DID_SEGMENT.match(seg) or seg in (".", ".."):
            raise ValueError(f"did:{method} has an invalid path segment {seg!r}")
    return ":".join(["did", method, host_part, *segments])


def normalize_shorthand(value: str, default_registry: str) -> str:
    if value.startswith("agent://"):
        return value
    if value.startswith("@"):
        slug = value[1:]
        if not default_registry:
            raise ValueError(f"Cannot normalize bare slug {value!r} without a default registry")
        return f"agent://{slug}@{default_registry}"
    if value.startswith("https://"):
        host = value[len("https://"):].rstrip("/")
        return f"agent://{host}"
    if value.startswith("http://"):
        host = value[len("http://"):].rstrip("/")
        return f"agent://{host}"
    if "." in value:
        return f"agent://{value}"
    if not default_registry:
        raise ValueError(f"Cannot normalize bare slug {value!r} without a default registry")
    return f"agent://{value}@{default_registry}"
