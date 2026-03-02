"""WafW00f WAF detection tool wrapper."""

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
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


def _parse_wafw00f_output(output: str) -> dict:
    """Parse wafw00f text output and extract WAF detection results."""
    detected = []
    no_waf = False
    for line in output.splitlines():
        line_lower = line.lower()
        if "is behind" in line_lower or ("waf" in line_lower and "detected" in line_lower):
            detected.append(line.strip())
        if "no waf detected" in line_lower or "generic detection" in line_lower:
            no_waf = True
    return {
        "waf_detected": len(detected) > 0 and not no_waf,
        "detections": detected,
    }


async def wafw00f_scan(
    ctx: Context,
    target: str,
    detect_all: bool = False,
    timeout: int | None = None,
) -> dict:
    """Detect Web Application Firewalls (WAF) protecting a target using WafW00f.

    Identifies WAF products (Cloudflare, AWS WAF, ModSecurity, etc.) before
    active scanning to avoid false negatives and detection.

    Args:
        target: Target URL to check (e.g. "https://example.com").
        detect_all: If True, try to detect all WAFs instead of stopping at first match.
        timeout: Override scan timeout in seconds.

    Returns:
        WAF detection results with product names, confidence, and detection evidence.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Run this before active scans to understand defensive posture.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "detect_all": detect_all}

    target = sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("wafw00f", target, str(exc))
        raise

    tool_path = resolve_tool_path("wafw00f")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [tool_path, target]
    if detect_all:
        args.append("-a")

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("wafw00f", args)

    await ctx.report_progress(0, 100, f"Starting wafw00f scan on {target}...")

    async with rate_limited("wafw00f"):
        start = time.monotonic()
        await audit.log_tool_call("wafw00f", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("wafw00f", target, params, result="failed", error=str(exc))
            raise
        duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "WafW00f scan complete")
    await audit.log_tool_call(
        "wafw00f", target, params, result="completed", duration_seconds=duration
    )

    findings = _parse_wafw00f_output(stdout)

    return {
        "tool": "wafw00f",
        "target": target,
        "duration_seconds": round(duration, 2),
        "waf_detected": findings["waf_detected"],
        "detections": findings["detections"],
        "raw_output": stdout,
    }
