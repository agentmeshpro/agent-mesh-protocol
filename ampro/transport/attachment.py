"""
Agent Protocol — Binary Attachment Types.

Attachments are URL-referenced, not embedded. SHA-256 for integrity.

This module is PURE — no platform-specific imports.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from ampro.security.ssrf import is_url_safe_static


class Attachment(BaseModel):
    """A binary attachment referenced by URL."""

    name: str = Field(description="Filename")
    url: str = Field(description="HTTPS download URL")
    content_type: str = Field(description="MIME type")
    size_bytes: int = Field(ge=0, description="File size in bytes")
    sha256: str = Field(description="SHA-256 hash for integrity")

    model_config = {"extra": "ignore"}

    @field_validator("url")
    @classmethod
    def url_must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("Attachment URL must be HTTPS")
        return v


def validate_attachment_url(url: str) -> bool:
    """SSRF protection — returns True if URL is safe to fetch.

    Delegates to :func:`ampro.security.ssrf.is_url_safe_static`, which
    rejects (without any network I/O):

    - non-HTTPS schemes and URLs carrying userinfo
    - internal hostnames: ``localhost``, ``*.localhost``, ``*.internal``
      (incl. ``metadata.google.internal``), ``*.local`` … and their
      trailing-dot variants
    - literal IPs that are private, loopback, link-local, multicast,
      reserved, unspecified or CGNAT (``100.64.0.0/10``), in every
      ``inet_aton`` spelling (``0x7f.1``, ``2130706433``, ``0177.0.0.1``)
    - IPv6 loopback / link-local (incl. zone IDs), IPv4-mapped/compatible,
      6to4, Teredo and NAT64 addresses
    - percent-encoded hostnames

    This is a *static* check: a public hostname whose DNS points at an
    internal address passes.  Code that actually fetches the URL must call
    :func:`ampro.security.ssrf.validate_url` and connect to the pinned
    addresses (see :func:`ampro.security.ssrf.pinned_async_transport`).
    """
    return is_url_safe_static(url)
