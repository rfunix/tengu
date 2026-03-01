"""Subfinder passive subdomain enumeration tool wrapper."""

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


async def subfinder_enum(
    ctx: Context,
    domain: str,
    sources: list[str] | None = None,
    timeout: int | None = None,
) -> dict:
    """Enumerate subdomains passively using Subfinder.

    Queries multiple passive sources (certificate transparency logs, DNS
    datasets, APIs) to discover subdomains without directly probing the target.

    Args:
        domain: Target domain (e.g. "example.com").
        sources: Optional list of specific sources to query
                 (e.g. ["crtsh", "hackertarget", "censys"]).
                 Leave empty to use all configured sources.
        timeout: Override default timeout in seconds.

    Returns:
        List of discovered subdomains with metadata.

    Note:
        - Passive enumeration only — does not send requests to the target domain.
        - Some sources require API keys configured in ~/.config/subfinder/config.yaml.
        - Target domain must match an entry in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"domain": domain, "sources": sources}

    # Validate domain format
    domain = sanitize_domain(domain)

    # Check allowlist (use base domain)
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("subfinder", domain, str(exc))
        raise

    tool_path = resolve_tool_path("subfinder", cfg.tools.paths.subfinder)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, "-d", domain, "-silent", "-json"]

    if sources:
        # Sanitize source names — only alphanumeric and hyphens
        safe_sources = ",".join(s for s in sources if all(c.isalnum() or c == "-" for c in s))
        if safe_sources:
            args.extend(["-sources", safe_sources])

    # Stealth: inject --proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("subfinder", args)

    await ctx.report_progress(0, 100, f"Enumerating subdomains for {domain}...")

    async with rate_limited("subfinder"):
        start = time.monotonic()
        await audit.log_tool_call("subfinder", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("subfinder", domain, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Processing subdomain results...")

    subdomains = _parse_subfinder_output(stdout)

    await ctx.report_progress(100, 100, "Enumeration complete")
    await audit.log_tool_call(
        "subfinder", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "subfinder",
        "domain": domain,
        "count": len(subdomains),
        "subdomains": subdomains,
        "duration_seconds": round(duration, 2),
    }


def _parse_subfinder_output(output: str) -> list[str]:
    """Parse subfinder output (one subdomain per line, possibly JSON)."""
    import json

    subdomains: list[str] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON format first
        try:
            data = json.loads(line)
            host = data.get("host", "")
            if host:
                subdomains.append(host)
            continue
        except json.JSONDecodeError:
            pass

        # Plain text format
        if "." in line and not line.startswith("#"):
            subdomains.append(line)

    return sorted(set(subdomains))
