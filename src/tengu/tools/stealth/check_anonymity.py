"""Check anonymity level — IP exposure, DNS leak, proxy headers."""

from __future__ import annotations

import socket

import httpx
import structlog

from tengu.stealth import get_stealth_layer

logger = structlog.get_logger(__name__)


async def check_anonymity() -> dict:
    """Check current anonymity level — IP exposure, DNS leaks, proxy headers.

    Returns:
        Dictionary with real_ip_exposed, dns_leak_detected, anonymity_level,
        and recommendations.
    """
    stealth = get_stealth_layer()

    detected_ip = "unknown"
    tor_exit_node = False
    dns_servers: list[str] = []
    real_ip_exposed = True

    try:
        if stealth.enabled and stealth.proxy_url:
            client_kwargs: dict = {"proxy": stealth.proxy_url}
        else:
            client_kwargs = {}

        async with httpx.AsyncClient(timeout=15, **client_kwargs) as client:
            try:
                resp = await client.get("https://check.torproject.org/api/ip")
                data = resp.json()
                detected_ip = data.get("IP", "unknown")
                tor_exit_node = data.get("IsTor", False)
            except Exception:
                pass
    except Exception:
        pass

    # DNS leak check — use well-known hostnames that return the resolver's IP
    dns_check_hosts = ["whoami.akamai.net", "myip.opendns.com"]
    for host in dns_check_hosts:
        try:
            result = socket.getaddrinfo(host, None)
            if result:
                dns_servers.append(result[0][4][0])
        except Exception:
            pass

    # DNS leak heuristic: if we resolved via Tor but system DNS is still local
    dns_leak_detected = bool(dns_servers) and not tor_exit_node

    # Anonymity level heuristic
    if tor_exit_node and not dns_leak_detected:
        anonymity_level = "high"
        real_ip_exposed = False
    elif stealth.enabled and stealth.proxy_url:
        anonymity_level = "medium"
        real_ip_exposed = False
    elif not tor_exit_node and not stealth.enabled:
        anonymity_level = "none"
        real_ip_exposed = True
    else:
        anonymity_level = "low"

    recommendations: list[str] = []
    if not tor_exit_node:
        recommendations.append(
            "Enable Tor for high anonymity "
            "(set stealth.enabled = true, stealth.proxy.enabled = true in tengu.toml)"
        )
    if dns_leak_detected:
        recommendations.append(
            "DNS leak detected. Set stealth.dns.method = 'doh' or 'tor' in tengu.toml"
        )
    if not stealth.enabled:
        recommendations.append("Enable stealth mode in tengu.toml: [stealth] enabled = true")

    return {
        "real_ip_exposed": real_ip_exposed,
        "detected_ip": detected_ip,
        "tor_exit_node": tor_exit_node,
        "dns_leak_detected": dns_leak_detected,
        "dns_servers_detected": dns_servers,
        "anonymity_level": anonymity_level,
        "recommendations": recommendations,
    }
