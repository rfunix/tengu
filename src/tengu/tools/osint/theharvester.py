"""theHarvester OSINT tool wrapper — emails, subdomains, hosts from public sources."""

from __future__ import annotations

import re
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


async def theharvester_scan(
    ctx: Context,
    domain: str,
    sources: str = "bing,certspotter,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r",
    limit: int = 500,
    timeout: int | None = None,
) -> dict:
    """Gather OSINT data (emails, subdomains, IPs) using theHarvester.

    Queries multiple public data sources without directly interacting with the target.

    Args:
        domain: Target domain to investigate.
        sources: Comma-separated data sources. Available: bing, google, crtsh, certspotter,
                 dnsdumpster, hackertarget, rapiddns, sublist3r, shodan (needs API key).
        limit: Maximum number of results per source.
        timeout: Override default timeout in seconds.

    Returns:
        Emails, subdomains, IP addresses, and hosts discovered from OSINT sources.

    Note:
        - Passive OSINT — does NOT interact directly with the target.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"domain": domain, "sources": sources, "limit": limit}

    domain = sanitize_domain(domain)
    limit = max(1, min(limit, 2000))

    # Sanitize sources — only alphanumeric, commas, underscores, hyphens
    safe_sources = re.sub(r"[^a-zA-Z0-9,_-]", "", sources)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("theHarvester", domain, str(exc))
        raise

    tool_path = resolve_tool_path("theHarvester")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-d",
        domain,
        "-b",
        safe_sources,
        "-l",
        str(limit),
    ]

    await ctx.report_progress(0, 100, f"Starting theHarvester OSINT on {domain}...")

    async with rate_limited("theHarvester"):
        start = time.monotonic()
        await audit.log_tool_call("theHarvester", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(
                "theHarvester", domain, params, result="failed", error=str(exc)
            )
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing theHarvester results...")

    emails: list[str] = []
    subdomains: list[str] = []
    ips: list[str] = []
    hosts: list[str] = []

    # Parse text output
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    section = None
    for line in stdout.splitlines():
        line = line.strip()
        if "[*] Emails found:" in line:
            section = "emails"
        elif "[*] Hosts found:" in line or "[*] IPs found:" in line:
            section = "hosts"
        elif line.startswith("[*]"):
            section = None
        elif section == "emails" and line:
            if email_pattern.match(line):
                emails.append(line.lower())
        elif section == "hosts" and line:
            if ip_pattern.match(line):
                ips.append(line)
            elif "." in line:
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.append(line.lower())
                hosts.append(line)

    # Also scan full output for emails and IPs
    for match in email_pattern.finditer(stdout):
        e = match.group().lower()
        if e not in emails:
            emails.append(e)

    await ctx.report_progress(100, 100, "theHarvester complete")
    await audit.log_tool_call(
        "theHarvester", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "theHarvester",
        "domain": domain,
        "sources": safe_sources,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "emails_found": len(emails),
        "emails": sorted(set(emails)),
        "subdomains_found": len(subdomains),
        "subdomains": sorted(set(subdomains)),
        "ips_found": len(ips),
        "ips": sorted(set(ips)),
        "hosts": sorted(set(hosts)),
        "raw_output": stdout,
    }
