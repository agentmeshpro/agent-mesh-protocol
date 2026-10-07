"""
Agent Protocol — Callback URL Delivery.

Delivers task results to caller-specified callback URLs with retry.
Uses the same AgentMessage envelope for delivery.

Spec ref: Section 5.5
- Verify callback URL reachability before accepting
- Retry: 3 attempts, exponential backoff (1s, 5s, 25s)
- SSRF validation on callback URLs, with DNS pinning (no rebinding)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ampro.security.ssrf import (
    SSRFError,
    is_url_safe_static,
    pinned_async_transport,
    validate_url_async,
)

logger = logging.getLogger(__name__)

RETRY_DELAYS = [1, 5, 25]  # seconds


def validate_callback_url(url: str) -> bool:
    """
    Validate a callback URL for safety (static check, no DNS).

    Must be HTTPS + pass the shared SSRF checks in
    :mod:`ampro.security.ssrf`.  :func:`deliver_callback` additionally
    resolves the host and pins the connection to the checked addresses.
    """
    return is_url_safe_static(url)


async def deliver_callback(
    callback_url: str,
    message: dict[str, Any],
    max_retries: int = 3,
) -> bool:
    """
    Deliver a message to a callback URL with retry.

    Returns True if delivery succeeded, False if all retries failed.

    SSRF / DNS-rebinding protection: the hostname is resolved exactly once
    and every resolved address must be publicly routable.  All requests
    (HEAD check + POST attempts) are then made through a transport that
    dials only those pinned addresses, while the ``Host`` header and TLS
    SNI / certificate verification still use the original hostname.
    Redirects are not followed and environment proxies are ignored.
    """
    import httpx

    try:
        validated = await validate_url_async(callback_url)
    except SSRFError as exc:
        logger.warning("Callback URL failed validation: %s (%s)", callback_url, exc)
        return False

    transport = pinned_async_transport(validated)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        # HEAD reachability check (spec Section 5.5)
        try:
            # Responses are opened as streams and closed without reading
            # the body: a callback target cannot make us buffer anything.
            async with client.stream("HEAD", callback_url) as head_resp:
                head_status = head_resp.status_code
            if head_status >= 300:
                logger.warning(
                    "Callback URL HEAD check failed: %s → %d",
                    callback_url, head_status,
                )
                return False
        except Exception as exc:
            logger.warning("Callback URL unreachable: %s → %s", callback_url, exc)
            return False

        for attempt in range(max_retries):
            try:
                async with client.stream(
                    "POST",
                    callback_url,
                    json=message,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    status = resp.status_code
                if status in (200, 201, 202, 204):
                    logger.info("Callback delivered to %s (attempt %d)", callback_url, attempt + 1)
                    return True
                logger.warning(
                    "Callback to %s returned %d (attempt %d)",
                    callback_url, status, attempt + 1,
                )
            except Exception as exc:
                logger.warning(
                    "Callback to %s failed (attempt %d): %s",
                    callback_url, attempt + 1, exc,
                )

            if attempt < max_retries - 1:
                delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
                await asyncio.sleep(delay)

    logger.error("Callback delivery to %s failed after %d attempts", callback_url, max_retries)
    return False
