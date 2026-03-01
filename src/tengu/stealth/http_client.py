"""Stealth HTTP client factory — creates httpx clients with proxy and UA rotation."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


def create_stealth_client(
    proxy_url: str | None = None,
    user_agent: str | None = None,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx AsyncClient configured for stealth operation.

    Args:
        proxy_url: SOCKS5/HTTP proxy URL (e.g. socks5://127.0.0.1:9050)
        user_agent: User-Agent string to use (rotated if None)
        timeout: Request timeout in seconds

    Returns:
        Configured httpx.AsyncClient
    """
    headers: dict[str, str] = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    client_kwargs: dict = {
        "timeout": timeout,
        "headers": headers,
        "follow_redirects": follow_redirects,
    }

    if proxy_url:
        client_kwargs["proxy"] = proxy_url
        logger.debug("Stealth client created with proxy", proxy=proxy_url)

    return httpx.AsyncClient(**client_kwargs, **kwargs)
