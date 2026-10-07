"""
Agent Protocol — Protocol Versioning.

Tracks supported protocol versions, validates client version requests,
and formats HTTP Sunset headers per RFC 7231.

This module is PURE — no platform-specific imports (app.*, etc.).
Designed for extraction as part of `pip install ampro`.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)


# All protocol versions this server can speak.
SUPPORTED_VERSIONS: list[str] = ["1.0.0", "0.1.0"]

# The version returned when the client does not specify one.
CURRENT_VERSION: str = "1.0.0"

# SemVer 2.0.0 shape check — MAJOR.MINOR.PATCH with optional
# pre-release (``-x.y``) and build metadata (``+x.y``).
_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$"
)


def _major(version: str) -> int:
    return int(version.split(".", 1)[0])


def _best_for_major(major: int) -> str | None:
    """Highest supported version sharing *major*, or None."""
    candidates = [v for v in SUPPORTED_VERSIONS if _major(v) == major]
    if not candidates:
        return None
    return max(candidates, key=lambda v: tuple(int(p) for p in v.split("-")[0].split("+")[0].split(".")))


def check_version(requested: str | None) -> str:
    """
    Validate a client-requested protocol version.

    Per PROTOCOL-CONTRACTS, receivers MUST NOT reject based on version
    alone unless the MAJOR component differs. A well-formed version whose
    MAJOR matches a supported version is accepted; the return value is
    the version this implementation will actually speak (the request
    itself when it is exactly supported, otherwise the highest supported
    version with the same MAJOR).

    Args:
        requested: The version string from the ``Accept-Version`` header,
                   or ``None`` if the client did not specify one.

    Returns:
        A supported version string (``CURRENT_VERSION`` when *requested* is None).

    Raises:
        ValueError: If *requested* is malformed (not SemVer) or its MAJOR
                    component matches no supported version.
    """
    if requested is None:
        return CURRENT_VERSION
    if not _SEMVER_RE.match(requested):
        raise ValueError(
            f"Malformed protocol version '{requested}'. "
            f"Expected SemVer (e.g. '1.0.0', '1.0.0-beta', '1.0.0+build.1')."
        )
    if requested in SUPPORTED_VERSIONS:
        return requested
    best = _best_for_major(_major(requested))
    if best is None:
        raise ValueError(
            f"Unsupported protocol version '{requested}' (MAJOR differs). "
            f"Supported: {', '.join(SUPPORTED_VERSIONS)}"
        )
    if requested != best:
        logger.info("[versioning] peer requested %s; speaking %s", requested, best)
    return best


def format_sunset_header(deprecated_at: datetime) -> str:
    """
    Format a ``Sunset`` response header value per RFC 7231.

    The format is the HTTP-date (IMF-fixdate) production:
        ``Sun, 06 Nov 1994 08:49:37 GMT``

    Args:
        deprecated_at: The deprecation timestamp (will be treated as UTC).

    Returns:
        An RFC 7231 HTTP-date string.
    """
    # strftime %a/%b are locale-independent in CPython for the en_US names
    # used by HTTP-date, but we format explicitly to be safe.
    _DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    _MONTHS = [
        "", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]

    day_name = _DAYS[deprecated_at.weekday()]
    month_name = _MONTHS[deprecated_at.month]

    return (
        f"{day_name}, {deprecated_at.day:02d} {month_name} "
        f"{deprecated_at.year:04d} {deprecated_at.hour:02d}:"
        f"{deprecated_at.minute:02d}:{deprecated_at.second:02d} GMT"
    )


def negotiate_version(
    accept_version: str | None,
    fallback_version: str | None = None,
) -> str:
    """
    Negotiate protocol version from Accept-Version preference list.

    The client sends comma-separated versions in preference order.
    Server picks the highest version it supports from the list.
    Returns CURRENT_VERSION if accept_version is None.

    If no requested version is supported and ``fallback_version`` is
    given, logs a WARNING and returns the fallback (graceful degrade).
    Otherwise raises ValueError.
    """
    if accept_version is None:
        return CURRENT_VERSION

    requested = [v.strip() for v in accept_version.split(",") if v.strip()]
    if not requested:
        return CURRENT_VERSION

    for version in requested:
        if version in SUPPORTED_VERSIONS:
            return version

    # No exact match: accept the first same-MAJOR preference (contract:
    # never reject unless MAJOR differs).
    for version in requested:
        if _SEMVER_RE.match(version):
            best = _best_for_major(_major(version))
            if best is not None:
                return best

    if fallback_version is not None:
        logger.warning(
            "[versioning] no supported version in %s — falling back to %s",
            requested,
            fallback_version,
        )
        return fallback_version

    raise ValueError(
        f"No supported version in requested list {requested}. "
        f"Supported: {SUPPORTED_VERSIONS}"
    )
