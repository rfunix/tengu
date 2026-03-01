"""Validate a proxy — latency, anonymity level, exit IP."""

from __future__ import annotations

import time

import httpx
import structlog

logger = structlog.get_logger(__name__)

_ALLOWED_SCHEMES = ("socks5://", "socks4://", "http://", "https://")


async def proxy_check(proxy_url: str) -> dict:
    """Validate a proxy server: check reachability, latency, exit IP and anonymity level.

    Args:
        proxy_url: Proxy URL (e.g. socks5://127.0.0.1:9050 or http://proxy:3128)

    Returns:
        Dictionary with reachable, latency_ms, exit_ip, anonymity_level, supports_https.
    """
    if not any(proxy_url.startswith(s) for s in _ALLOWED_SCHEMES):
        return {
            "proxy_url": proxy_url,
            "reachable": False,
            "latency_ms": None,
            "exit_ip": None,
            "anonymity_level": None,
            "supports_https": False,
            "country": None,
            "error": (f"Invalid proxy scheme. Must start with: {', '.join(_ALLOWED_SCHEMES)}"),
        }

    start = time.monotonic()
    exit_ip = None
    reachable = False
    supports_https = False
    anonymity_level = None

    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=15) as client:
            # Test HTTP connectivity
            resp = await client.get("http://httpbin.org/ip")
            if resp.status_code == 200:
                reachable = True
                exit_ip = resp.json().get("origin", "").split(",")[0].strip()

                # Check for proxy-revealing headers to classify anonymity level
                resp2 = await client.get("http://httpbin.org/headers")
                headers = resp2.json().get("headers", {})

                proxy_reveal_headers = ["X-Forwarded-For", "Via", "X-Proxy-Id"]
                if any(h in headers for h in proxy_reveal_headers):
                    anonymity_level = "transparent"
                else:
                    anonymity_level = "anonymous"

            # Test HTTPS connectivity
            try:
                resp_https = await client.get("https://httpbin.org/ip")
                supports_https = resp_https.status_code == 200
                if supports_https and anonymity_level == "anonymous":
                    anonymity_level = "elite"
            except Exception:
                pass

    except Exception as exc:
        logger.warning("Proxy check failed", proxy=proxy_url, error=str(exc))

    latency_ms = (time.monotonic() - start) * 1000 if reachable else None

    return {
        "proxy_url": proxy_url,
        "reachable": reachable,
        "latency_ms": round(latency_ms, 1) if latency_ms else None,
        "exit_ip": exit_ip,
        "anonymity_level": anonymity_level,
        "supports_https": supports_https,
        "country": None,  # Would require GeoIP lookup
    }
