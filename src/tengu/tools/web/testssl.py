"""testssl.sh SSL/TLS analysis tool wrapper."""

from __future__ import annotations

import json
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


async def testssl_check(
    ctx: Context,
    host: str,
    port: int = 443,
    severity_threshold: str = "LOW",
    timeout: int | None = None,
) -> dict:
    """Comprehensive SSL/TLS analysis using testssl.sh.

    Complements sslyze with additional checks including BEAST, BREACH, CRIME,
    LUCKY13, POODLE, HEARTBLEED, CCS injection, ROBOT, and more.

    Args:
        host: Target hostname or IP address.
        port: Target port (default 443).
        severity_threshold: Minimum severity to report — INFO, LOW, MEDIUM, HIGH, CRITICAL.
        timeout: Override default timeout in seconds.

    Returns:
        SSL/TLS findings including protocol support, cipher strength, and known vulnerabilities.

    Note:
        - testssl.sh executable or testssl must be in PATH.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"host": host, "port": port}

    host = sanitize_target(host)
    port = max(1, min(port, 65535))
    if severity_threshold not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        severity_threshold = "LOW"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(host)
    except Exception as exc:
        await audit.log_target_blocked("testssl", host, str(exc))
        raise

    # Try testssl.sh first, then testssl
    tool_path = None
    import shutil

    for name in ("testssl.sh", "testssl"):
        path = shutil.which(name)
        if path:
            tool_path = path
            break

    if tool_path is None:
        from tengu.exceptions import ToolNotFoundError

        raise ToolNotFoundError("testssl.sh")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "--jsonfile=/dev/stdout",
        "--severity",
        severity_threshold,
        "--quiet",
        "--color",
        "0",
        f"{host}:{port}",
    ]

    await ctx.report_progress(0, 100, f"Starting testssl.sh on {host}:{port}...")

    async with rate_limited("testssl"):
        start = time.monotonic()
        await audit.log_tool_call("testssl", host, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("testssl", host, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing testssl results...")

    findings: list[dict] = []
    supported_protocols: list[str] = []
    vulnerabilities: list[dict] = []

    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            for item in data:
                finding = {
                    "id": item.get("id"),
                    "severity": item.get("severity"),
                    "finding": item.get("finding"),
                    "cve": item.get("cve"),
                }
                findings.append(finding)

                # Categorize
                item_id = item.get("id", "")
                if "protocol" in item_id.lower():
                    if "offered" in item.get("finding", "").lower():
                        supported_protocols.append(item_id)
                elif item.get("severity") in ("HIGH", "CRITICAL", "MEDIUM"):
                    vulnerabilities.append(finding)
    except (json.JSONDecodeError, KeyError):
        pass

    await ctx.report_progress(100, 100, "testssl.sh complete")
    await audit.log_tool_call(
        "testssl", host, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "testssl",
        "host": host,
        "port": port,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "findings_count": len(findings),
        "vulnerabilities_count": len(vulnerabilities),
        "supported_protocols": supported_protocols,
        "vulnerabilities": vulnerabilities,
        "all_findings": findings,
        "raw_output": stdout,
    }
