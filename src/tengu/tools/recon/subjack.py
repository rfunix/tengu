"""Subjack subdomain takeover detection tool wrapper."""

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


async def subjack_check(
    ctx: Context,
    domain: str,
    subdomains_file: str = "",
    threads: int = 20,
    timeout: int | None = None,
) -> dict:
    """Check for subdomain takeover vulnerabilities using Subjack.

    Identifies dangling DNS records pointing to unclaimed third-party services
    (GitHub Pages, S3, Heroku, Netlify, Azure, etc.).

    Args:
        domain: Target domain to check (e.g. example.com).
        subdomains_file: Path to file with subdomain list (one per line).
                         If not provided, uses common wordlist.
        threads: Number of concurrent threads (default 20, max 100).
        timeout: Override default timeout in seconds.

    Returns:
        List of potentially vulnerable subdomains with CNAME targets and service names.

    Note:
        - A finding means the CNAME points to an unclaimed resource.
        - Manual verification required before claiming/reporting.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"domain": domain, "threads": threads}

    domain = sanitize_domain(domain)
    threads = max(1, min(threads, 100))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("subjack", domain, str(exc))
        raise

    tool_path = resolve_tool_path("subjack")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Use provided wordlist or default
    if subdomains_file:
        from tengu.security.sanitizer import sanitize_wordlist_path

        wordlist_arg = sanitize_wordlist_path(subdomains_file)
    else:
        wordlist_arg = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

    args = [
        tool_path,
        "-w",
        wordlist_arg,
        "-t",
        str(threads),
        "-o",
        "/dev/stdout",
        "-ssl",
        "-a",
        "-timeout",
        "10",
    ]

    await ctx.report_progress(0, 100, f"Starting Subjack takeover check on {domain}...")

    async with rate_limited("subjack"):
        start = time.monotonic()
        await audit.log_tool_call("subjack", domain, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("subjack", domain, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Subjack results...")

    vulnerable: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[Vulnerable]" in line or "VULNERABLE" in line.upper():
            vulnerable.append({"subdomain": line, "status": "vulnerable"})

    await ctx.report_progress(100, 100, "Subjack complete")
    await audit.log_tool_call(
        "subjack", domain, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "subjack",
        "domain": domain,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "vulnerable_count": len(vulnerable),
        "vulnerable_subdomains": vulnerable,
        "raw_output": stdout,
        "errors": stderr if returncode != 0 else None,
    }
