"""XSS testing using Dalfox tool wrapper."""

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
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def xss_scan(
    ctx: Context,
    url: str,
    parameter: str = "",
    cookie: str = "",
    header: str = "",
    method: str = "GET",
    data: str = "",
    timeout: int | None = None,
) -> dict:
    """Test for Cross-Site Scripting (XSS) vulnerabilities using Dalfox.

    Dalfox is a powerful XSS scanner that detects reflected, stored, and
    DOM-based XSS vulnerabilities using pattern analysis and DOM parsing.

    Args:
        url: Target URL to test (e.g. "https://example.com/search?q=test").
        parameter: Specific parameter to focus testing on.
                   If empty, tests all parameters found in the URL.
        cookie: Session cookie for authenticated testing
                (e.g. "session=abc123; csrf_token=xyz").
        header: Additional HTTP header (e.g. "Authorization: Bearer token").
        method: HTTP method to use: GET or POST. Default: GET.
        data: POST body data for testing POST endpoints
              (e.g. "q=FUZZ&other=value" — use FUZZ as the injection placeholder,
               or leave as plain value and dalfox will find injection points).
        timeout: Override scan timeout in seconds.

    Returns:
        XSS test results with vulnerable parameters, payload types, and evidence.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "parameter": parameter, "method": method}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("dalfox", url, str(exc))
        raise

    tool_path = resolve_tool_path("dalfox", cfg.tools.paths.dalfox)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "url",
        url,
        "--format",
        "json",
        "--no-color",
        "--silence",
    ]

    if parameter:
        import re

        safe_param = re.sub(r"[^a-zA-Z0-9_\-\[\]]", "", parameter)
        if safe_param:
            args.extend(["-p", safe_param])

    if cookie:
        # Cookie validation — remove dangerous chars
        import re

        safe_cookie = re.sub(r"[\r\n<>]", "", cookie)
        if safe_cookie:
            args.extend(["--cookie", safe_cookie])

    if header:
        import re

        safe_header = re.sub(r"[\r\n]", "", header)
        if safe_header:
            args.extend(["-H", safe_header])

    if method.upper() == "POST" or data:
        import re

        safe_data = re.sub(r"[\r\n;&|`$<>()\{\}\\\"']", "", data) if data else ""
        if safe_data:
            args.extend(["--data", safe_data])

    await ctx.report_progress(0, 100, f"Starting XSS scan on {url}...")

    async with rate_limited("dalfox"):
        start = time.monotonic()
        await audit.log_tool_call("dalfox", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("dalfox", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing XSS results...")

    findings = _parse_dalfox_output(stdout)

    await ctx.report_progress(100, 100, "XSS scan complete")
    await audit.log_tool_call("dalfox", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "dalfox",
        "url": url,
        "duration_seconds": round(duration, 2),
        "vulnerable": len(findings) > 0,
        "findings_count": len(findings),
        "findings": findings,
        "remediation": (
            "Encode all user-supplied data before rendering in HTML context. "
            "Implement a strict Content-Security-Policy. "
            "Use modern framework auto-escaping features."
        )
        if findings
        else None,
    }


def _parse_dalfox_output(output: str) -> list[dict]:
    """Parse Dalfox JSON output."""
    findings = []

    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                findings.append(
                    {
                        "type": item.get("type", ""),
                        "parameter": item.get("param", ""),
                        "payload": item.get("payload", ""),
                        "evidence": item.get("evidence", ""),
                        "poc": item.get("poc", ""),
                    }
                )
        elif isinstance(data, dict):
            findings.append(data)
        return findings
    except (json.JSONDecodeError, TypeError):
        pass

    # Fall back to line parsing for non-JSON output
    for line in output.splitlines():
        if "[V]" in line or "POC" in line.upper():
            findings.append({"message": line.strip(), "type": "xss"})

    return findings
