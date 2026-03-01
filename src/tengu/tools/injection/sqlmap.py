"""SQLMap SQL injection testing tool wrapper.

IMPORTANT: SQLMap is a highly intrusive tool. Its use requires explicit
authorization. Level > 2 and risk > 2 should trigger human confirmation.
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


async def sqlmap_scan(
    ctx: Context,  # type: ignore[type-arg]
    url: str,
    method: str = "GET",
    data: str = "",
    parameter: str = "",
    level: int = 1,
    risk: int = 1,
    dbms: str = "",
    batch: bool = True,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Test a URL for SQL injection vulnerabilities using SQLMap.

    SQLMap automates the detection and exploitation of SQL injection flaws.
    This tool requires explicit authorization — SQL injection testing
    can cause database errors and potential data exposure.

    Args:
        url: Target URL to test (e.g. "https://example.com/search?q=test").
        method: HTTP method: GET or POST.
        data: POST data string (e.g. "username=admin&password=test").
        parameter: Specific parameter to test (e.g. "q" or "username").
                   If empty, tests all parameters.
        level: Detection aggressiveness level (1-5). Default: 1 (safe).
               Levels 3+ significantly increase request count.
        risk: Risk of tests (1-3). Default: 1 (safe).
              Risk 2+ includes boolean-based tests; Risk 3 includes heavy OR-based tests.
        dbms: Force specific DBMS (e.g. "mysql", "postgresql", "mssql").
              Leave empty for auto-detection.
        batch: Run in non-interactive batch mode (recommended: True).
        timeout: Override scan timeout in seconds.

    Returns:
        SQL injection test results including vulnerable parameters and DBMS info.

    Note:
        - Level > 2 or Risk > 2 requires careful consideration — may cause errors.
        - Target must be in tengu.toml [targets].allowed_hosts.
        - This tool requires explicit human authorization for exploitation.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "method": method, "level": level, "risk": risk}

    url = sanitize_url(url)
    method = method.upper()
    if method not in ("GET", "POST", "PUT", "DELETE"):
        method = "GET"

    # Clamp level and risk to safe defaults
    level = max(1, min(level, 5))
    risk = max(1, min(risk, 3))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("sqlmap", url, str(exc))
        raise

    tool_path = resolve_tool_path("sqlmap", cfg.tools.paths.sqlmap)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        url,
        "--method",
        method,
        f"--level={level}",
        f"--risk={risk}",
        "--output-dir=/tmp/sqlmap_tengu",
        "--answers=quit=N,crack=N",
        "--no-logging",
    ]

    if batch:
        args.append("--batch")

    if data:
        # Sanitize POST data — remove any shell metacharacters
        safe_data = re.sub(r"[;&|`$<>()\{\}]", "", data)
        args.extend(["--data", safe_data])

    if parameter:
        safe_param = re.sub(r"[^a-zA-Z0-9_\-\[\]]", "", parameter)
        if safe_param:
            args.extend(["-p", safe_param])

    if dbms:
        safe_dbms = re.sub(r"[^a-zA-Z0-9]", "", dbms).lower()
        if safe_dbms in {"mysql", "postgresql", "mssql", "oracle", "sqlite", "access", "db2"}:
            args.extend(["--dbms", safe_dbms])

    # Human confirmation annotation for destructive levels
    if level > 2 or risk > 2:
        logger.warning(
            "SQLMap running with elevated level/risk — requires explicit authorization",
            level=level,
            risk=risk,
            url=url,
        )

    # Stealth: inject --proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("sqlmap", args)

    await ctx.report_progress(0, 100, f"Starting SQLMap test on {url}...")

    async with rate_limited("sqlmap"):
        start = time.monotonic()
        await audit.log_tool_call("sqlmap", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("sqlmap", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing SQLMap results...")

    findings = _parse_sqlmap_output(stdout)

    await ctx.report_progress(100, 100, "SQL injection test complete")
    await audit.log_tool_call("sqlmap", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "sqlmap",
        "url": url,
        "method": method,
        "duration_seconds": round(duration, 2),
        "vulnerable": len(findings.get("vulnerable_params", [])) > 0,
        "vulnerable_parameters": findings.get("vulnerable_params", []),
        "dbms": findings.get("dbms"),
        "injection_types": findings.get("injection_types", []),
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_sqlmap_output(output: str) -> dict:  # type: ignore[type-arg]
    """Parse SQLMap stdout for key findings."""
    result: dict[str, object] = {
        "vulnerable_params": [],
        "dbms": None,
        "injection_types": [],
    }

    vulnerable_params: list[str] = []
    injection_types: list[str] = []
    dbms: str | None = None

    for line in output.splitlines():
        # Parameter vulnerability
        m = re.search(r"parameter '(.+?)' is vulnerable", line, re.IGNORECASE)
        if m:
            param = m.group(1)
            if param not in vulnerable_params:
                vulnerable_params.append(param)

        # DBMS detection
        m = re.search(r"back-end DBMS: (.+)", line, re.IGNORECASE)
        if m:
            dbms = m.group(1).strip()

        # Injection type
        m = re.search(r"Type: (.+)", line, re.IGNORECASE)
        if m:
            itype = m.group(1).strip()
            if itype not in injection_types:
                injection_types.append(itype)

    result["vulnerable_params"] = vulnerable_params
    result["dbms"] = dbms
    result["injection_types"] = injection_types
    return result
