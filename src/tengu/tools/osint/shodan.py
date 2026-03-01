"""Shodan API integration for host lookup and search."""

from __future__ import annotations

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_free_text, sanitize_target

logger = structlog.get_logger(__name__)


async def shodan_lookup(
    ctx: Context,
    target: str,
    query_type: str = "host",
    query: str = "",
    limit: int = 20,
) -> dict:
    """Query Shodan for exposed services, vulnerabilities, and device information.

    Args:
        target: IP address or domain to look up (for host queries).
        query_type: Query type — host (single IP lookup), search (Shodan search query).
        query: Shodan search query string (for search mode, e.g. "apache country:BR").
        limit: Maximum number of search results to return.

    Returns:
        Host information, open ports, detected vulnerabilities, and banner data.

    Note:
        - Requires TENGU_SHODAN_API_KEY environment variable or shodan_api_key in tengu.toml.
        - Passive OSINT — queries Shodan's database, does NOT interact with target directly.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "query_type": query_type}

    target = sanitize_target(target)
    if query_type not in ("host", "search"):
        query_type = "host"

    api_key = cfg.osint.shodan_api_key
    if not api_key:
        return {
            "tool": "shodan",
            "error": "Shodan API key not configured. Set TENGU_SHODAN_API_KEY env var or osint.shodan_api_key in tengu.toml.",
        }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("shodan", target, str(exc))
        raise

    await ctx.report_progress(0, 3, f"Querying Shodan for {target}...")

    try:
        import httpx

        headers = {"Accept": "application/json"}

        async with httpx.AsyncClient(timeout=30) as client:
            if query_type == "host":
                url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                await ctx.report_progress(3, 3, "Shodan lookup complete")
                await audit.log_tool_call("shodan", target, params, result="completed")

                ports = data.get("ports", [])
                vulns = data.get("vulns", [])

                return {
                    "tool": "shodan",
                    "query_type": "host",
                    "target": target,
                    "ip": data.get("ip_str"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "asn": data.get("asn"),
                    "os": data.get("os"),
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                    "ports": ports,
                    "tags": data.get("tags", []),
                    "vulnerabilities": list(vulns) if isinstance(vulns, (list, dict)) else [],
                    "last_update": data.get("last_update"),
                    "services_count": len(data.get("data", [])),
                }

            else:
                safe_query = sanitize_free_text(query or target, field="query", max_length=200)
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={safe_query}&limit={limit}"
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                matches = data.get("matches", [])
                results = []
                for m in matches[:limit]:
                    results.append(
                        {
                            "ip": m.get("ip_str"),
                            "port": m.get("port"),
                            "org": m.get("org"),
                            "country": m.get("location", {}).get("country_name"),
                            "hostnames": m.get("hostnames", []),
                            "product": m.get("product"),
                            "version": m.get("version"),
                            "cpe": m.get("cpe", []),
                        }
                    )

                await ctx.report_progress(3, 3, "Shodan search complete")
                await audit.log_tool_call("shodan", target, params, result="completed")

                return {
                    "tool": "shodan",
                    "query_type": "search",
                    "query": safe_query,
                    "total_results": data.get("total", 0),
                    "results_returned": len(results),
                    "results": results,
                }

    except ImportError:
        return {"tool": "shodan", "error": "httpx not installed. Run: uv pip install httpx"}
    except Exception as exc:
        await audit.log_tool_call("shodan", target, params, result="failed", error=str(exc))
        return {"tool": "shodan", "error": str(exc)}
