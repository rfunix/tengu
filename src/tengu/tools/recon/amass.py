"""Amass subdomain enumeration and attack surface mapping."""

from __future__ import annotations

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


async def amass_enum(
    ctx: Context,
    domain: str,
    mode: str = "passive",
    timeout: int | None = None,
) -> dict:
    """Enumerate subdomains and map attack surface using Amass.

    Args:
        domain: Target domain to enumerate (e.g. example.com).
        mode: Enumeration mode — passive (no direct interaction), active (DNS brute-force + zone walk).
        timeout: Override default scan timeout in seconds.

    Returns:
        Structured results with discovered subdomains, IPs, and ASN info.

    Note:
        - Active mode sends DNS queries directly to target's nameservers.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"domain": domain, "mode": mode}

    domain = sanitize_domain(domain)
    if mode not in ("passive", "active"):
        mode = "passive"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("amass", domain, str(exc))
        raise

    tool_path = resolve_tool_path("amass")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, "enum", "-d", domain]
    if mode == "passive":
        args.append("-passive")

    await ctx.report_progress(0, 100, f"Starting amass enumeration on {domain}...")

    async with rate_limited("amass"):
        start = time.monotonic()
        await audit.log_tool_call("amass", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("amass", domain, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing amass results...")

    subdomains = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            # Amass outputs: subdomain
            parts = line.split()
            if parts:
                sub = parts[0].lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.append(sub)

    subdomains = sorted(set(subdomains))

    await ctx.report_progress(100, 100, "Amass complete")
    await audit.log_tool_call(
        "amass", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "amass",
        "domain": domain,
        "mode": mode,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "subdomains_found": len(subdomains),
        "subdomains": subdomains,
        "raw_output": stdout,
        "errors": stderr if returncode != 0 else None,
    }
