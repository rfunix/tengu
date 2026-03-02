"""dnstwist typosquatting and phishing domain detection tool wrapper."""

from __future__ import annotations

import json
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


def _parse_dnstwist_output(output: str) -> list[dict]:
    """Parse dnstwist JSON array output into a list of domain records."""
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            return [
                {
                    "fuzzer": item.get("fuzzer", ""),
                    "domain": item.get("domain", ""),
                    "dns_a": item.get("dns_a", []),
                    "dns_mx": item.get("dns_mx", []),
                    "registered": bool(item.get("dns_a") or item.get("dns_mx")),
                }
                for item in data
            ]
    except (json.JSONDecodeError, TypeError):
        pass
    return []


async def dnstwist_scan(
    ctx: Context,
    domain: str,
    threads: int = 10,
    registered_only: bool = True,
    check_mx: bool = False,
    timeout: int | None = None,
) -> dict:
    """Detect typosquatting and phishing domains using dnstwist.

    Generates permutations of a domain name (homoglyphs, additions, deletions,
    substitutions) and checks which ones are registered, helping identify
    potential phishing or brand abuse domains.

    Args:
        domain: Target domain to check (e.g. "example.com").
        threads: Number of DNS query threads (default 10).
        registered_only: Only return registered/live domains (default True).
        check_mx: Check MX records to identify phishing-ready domains.
        timeout: Override scan timeout in seconds.

    Returns:
        List of suspicious domain permutations with registration status.

    Note:
        - Target domain must be in tengu.toml [targets].allowed_hosts.
        - Passive OSINT — only sends DNS queries, no HTTP requests.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {
        "domain": domain,
        "threads": threads,
        "registered_only": registered_only,
        "check_mx": check_mx,
    }

    domain = sanitize_target(domain)
    threads = max(1, min(threads, 50))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("dnstwist", domain, str(exc))
        raise

    tool_path = resolve_tool_path("dnstwist")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "--format", "json",
        "--threads", str(threads),
        domain,
    ]
    if registered_only:
        args.append("--registered")
    if check_mx:
        args.append("--mxcheck")

    await ctx.report_progress(0, 100, f"Starting dnstwist scan on {domain}...")

    async with rate_limited("dnstwist"):
        start = time.monotonic()
        await audit.log_tool_call("dnstwist", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("dnstwist", domain, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing dnstwist results...")
    results = _parse_dnstwist_output(stdout)

    await ctx.report_progress(100, 100, "dnstwist scan complete")
    await audit.log_tool_call(
        "dnstwist", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "dnstwist",
        "domain": domain,
        "threads": threads,
        "registered_only": registered_only,
        "duration_seconds": round(duration, 2),
        "suspicious_domains_count": len(results),
        "suspicious_domains": results,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }
