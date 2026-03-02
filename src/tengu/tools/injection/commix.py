"""Commix OS command injection testing tool wrapper.

IMPORTANT: Commix is a highly intrusive tool. Its use requires explicit
authorization from the target owner.
"""

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
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def commix_scan(
    ctx: Context,
    url: str,
    method: str = "GET",
    data: str = "",
    level: int = 1,
    timeout: int | None = None,
) -> dict:
    """Test a URL for OS command injection vulnerabilities using Commix.

    Commix (command injection exploiter) automates the detection of OS command
    injection flaws in web applications. Requires explicit authorization.

    Args:
        url: Target URL to test (e.g. "https://example.com/ping?host=test").
        method: HTTP method: GET or POST.
        data: POST data string (e.g. "param=value").
        level: Detection level (1-3). Default: 1.
        timeout: Override scan timeout in seconds.

    Returns:
        Command injection test results with vulnerable parameters and evidence.

    Note:
        - This tool requires explicit authorization from the target owner.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "method": method, "level": level}

    url = sanitize_url(url)
    method = method.upper()
    if method not in ("GET", "POST"):
        method = "GET"

    level = max(1, min(level, 3))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("commix", url, str(exc))
        raise

    tool_path = resolve_tool_path("commix")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, "-u", url, "--batch", "--output-dir=/tmp/commix_tengu"]

    if level > 1:
        args.extend([f"--level={level}"])

    safe_data = ""
    if data:
        safe_data = re.sub(r"[;&|`$<>()\{\}]", "", data)

    if method == "POST" and safe_data:
        args.extend(["--data", safe_data])
    elif method == "POST":
        args.extend(["--method", "POST"])

    # Stealth: inject --proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("commix", args)

    await ctx.report_progress(0, 100, f"Starting Commix scan on {url}...")

    async with rate_limited("commix"):
        start = time.monotonic()
        await audit.log_tool_call("commix", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("commix", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Commix results...")

    findings = _parse_commix_output(stdout)

    await ctx.report_progress(100, 100, "Command injection test complete")
    await audit.log_tool_call("commix", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "commix",
        "url": url,
        "method": method,
        "level": level,
        "duration_seconds": round(duration, 2),
        "vulnerable": findings["vulnerable"],
        "evidence": findings["evidence"],
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_commix_output(output: str) -> dict:
    """Parse Commix stdout for key findings."""
    evidence = []
    vulnerable = False

    for line in output.splitlines():
        is_positive = "[+]" in line
        is_negative = "[-]" in line
        line_lower = line.lower()
        has_vuln_keyword = "vulnerable" in line_lower or "injectable" in line_lower
        has_injection_keyword = "injection" in line_lower and not is_negative

        if is_positive or has_vuln_keyword or has_injection_keyword:
            evidence.append(line.strip())
            if is_positive or has_vuln_keyword or has_injection_keyword:
                vulnerable = True

    return {"vulnerable": vulnerable, "evidence": evidence[:20]}
