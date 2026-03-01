"""DNSRecon DNS enumeration tool wrapper."""

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
from tengu.security.sanitizer import sanitize_domain

logger = structlog.get_logger(__name__)


async def dnsrecon_scan(
    ctx: Context,
    domain: str,
    scan_type: str = "std",
    timeout: int | None = None,
) -> dict:
    """Perform DNS reconnaissance using DNSRecon.

    Supports zone transfers, DNS brute-force, PTR lookups, and standard record enumeration.

    Args:
        domain: Target domain to enumerate.
        scan_type: Scan type — std (standard records), brt (brute-force), axfr (zone transfer),
                   rvl (reverse lookup), goo (Google enumeration).
        timeout: Override default timeout in seconds.

    Returns:
        DNS records, zone transfer results, and raw output.

    Note:
        - Zone transfer (axfr) may fail if target nameservers are properly configured.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"domain": domain, "scan_type": scan_type}

    domain = sanitize_domain(domain)
    if scan_type not in ("std", "brt", "axfr", "rvl", "goo", "srv"):
        scan_type = "std"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("dnsrecon", domain, str(exc))
        raise

    tool_path = resolve_tool_path("dnsrecon")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, "-d", domain, "-t", scan_type, "-j", "/dev/stdout"]

    await ctx.report_progress(0, 100, f"Starting dnsrecon on {domain} ({scan_type})...")

    async with rate_limited("dnsrecon"):
        start = time.monotonic()
        await audit.log_tool_call("dnsrecon", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("dnsrecon", domain, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing dnsrecon results...")

    records = []
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            records = data
    except (json.JSONDecodeError, ValueError):
        # Parse plain text fallback
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[*]") and not line.startswith("[+]"):
                records.append({"raw": line})

    await ctx.report_progress(100, 100, "DNSRecon complete")
    await audit.log_tool_call(
        "dnsrecon", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "dnsrecon",
        "domain": domain,
        "scan_type": scan_type,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "records_found": len(records),
        "records": records,
        "raw_output": stdout,
        "errors": stderr if returncode != 0 else None,
    }
