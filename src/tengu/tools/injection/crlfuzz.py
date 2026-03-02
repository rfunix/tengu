"""CRLFuzz CRLF injection scanning tool wrapper."""

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
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def crlfuzz_scan(
    ctx: Context,
    url: str,
    threads: int = 25,
    timeout: int | None = None,
) -> dict:
    """Scan a URL for CRLF injection vulnerabilities using CRLFuzz.

    CRLF injection (HTTP Response Splitting) allows attackers to inject
    arbitrary HTTP headers or split HTTP responses, potentially leading to
    XSS, cache poisoning, or session fixation.

    Args:
        url: Target URL to scan (e.g. "https://example.com/redirect?url=test").
        threads: Number of concurrent threads (default 25, max 50).
        timeout: Override scan timeout in seconds.

    Returns:
        CRLF injection scan results with vulnerable URLs and evidence.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "threads": threads}

    url = sanitize_url(url)
    threads = max(1, min(threads, 50))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("crlfuzz", url, str(exc))
        raise

    tool_path = resolve_tool_path("crlfuzz")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, "-u", url, "-t", str(threads), "-s"]

    # Stealth: inject proxy manually (crlfuzz uses -p flag, not in inject_proxy_flags)
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args.extend(["-p", stealth.proxy_url])

    await ctx.report_progress(0, 100, f"Starting CRLFuzz scan on {url}...")

    async with rate_limited("crlfuzz"):
        start = time.monotonic()
        await audit.log_tool_call("crlfuzz", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("crlfuzz", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing CRLFuzz results...")

    findings = _parse_crlfuzz_output(stdout)

    await ctx.report_progress(100, 100, "CRLF injection scan complete")
    await audit.log_tool_call("crlfuzz", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "crlfuzz",
        "url": url,
        "threads": threads,
        "duration_seconds": round(duration, 2),
        "vulnerable": findings["vulnerable"],
        "vulnerable_urls": findings["vulnerable_urls"],
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_crlfuzz_output(output: str) -> dict:
    """Parse CRLFuzz stdout for vulnerable URLs."""
    vulnerable_urls = []

    for line in output.splitlines():
        line = line.strip()
        if line and ("VULN" in line or "[+]" in line or "vulnerable" in line.lower()):
            vulnerable_urls.append(line)

    return {"vulnerable": len(vulnerable_urls) > 0, "vulnerable_urls": vulnerable_urls}
