"""DNS privacy — DNS-over-HTTPS resolver (RFC 8484)."""

from __future__ import annotations

import httpx
import structlog

logger = structlog.get_logger(__name__)


async def resolve_doh(
    hostname: str,
    doh_url: str,
    record_type: str = "A",
) -> list[str]:
    """Resolve hostname using DNS-over-HTTPS (RFC 8484).

    Args:
        hostname: The hostname to resolve.
        doh_url: The DNS-over-HTTPS resolver URL.
        record_type: DNS record type (A, AAAA, MX, TXT, etc.).

    Returns:
        List of resolved IP addresses or record values.
    """
    params = {"name": hostname, "type": record_type}
    headers = {"Accept": "application/dns-json"}

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.get(doh_url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            answers = data.get("Answer", [])
            # Type 1 = A (IPv4), Type 28 = AAAA (IPv6)
            return [answer["data"] for answer in answers if answer.get("type") in (1, 28)]
        except Exception as exc:
            logger.warning(
                "DoH resolution failed",
                hostname=hostname,
                doh_url=doh_url,
                error=str(exc),
            )
            return []
