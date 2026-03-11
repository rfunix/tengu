"""Check Tor connectivity and exit node information."""

from __future__ import annotations

import httpx
import structlog

from tengu.stealth import get_stealth_layer

logger = structlog.get_logger(__name__)


async def tor_check() -> dict:
    """Check Tor connectivity and retrieve exit node IP and country.

    Returns:
        Dictionary with tor_connected, exit_ip, exit_country, real_ip fields.
    """
    stealth = get_stealth_layer()

    # Check real IP first (without any proxy)
    real_ip = "unknown"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get("https://api.ipify.org?format=json")
            real_ip = resp.json().get("ip", "unknown")
    except (httpx.RequestError, TimeoutError):
        pass

    # Check Tor exit IP
    exit_ip = None
    exit_country = None
    tor_connected = False

    proxy_url = "socks5://127.0.0.1:9050"  # Tor default
    if stealth.proxy_url:
        proxy_url = stealth.proxy_url

    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=15) as client:
            resp = await client.get("https://check.torproject.org/api/ip")
            data = resp.json()
            exit_ip = data.get("IP")
            tor_connected = data.get("IsTor", False)
    except (httpx.RequestError, TimeoutError) as exc:
        logger.warning("Tor check failed", error=str(exc))

    return {
        "tor_connected": tor_connected,
        "exit_ip": exit_ip,
        "exit_country": exit_country,
        "real_ip": real_ip,
        "proxy_url": proxy_url,
    }
