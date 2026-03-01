"""Nikto web server scanner tool wrapper."""

from __future__ import annotations

import json
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


async def nikto_scan(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    tuning: str = "x6",
    ssl: bool = False,
    port: int | None = None,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Scan a web server for vulnerabilities using Nikto.

    Nikto checks for outdated server software, dangerous files/programs,
    default credentials, and server misconfigurations.

    Args:
        target: URL or host to scan.
        tuning: Nikto tuning options to control scan types:
                0=File Upload, 1=Interesting File, 2=Misconfiguration,
                3=Information Disclosure, 4=Injection, 5=Remote File Retrieval,
                6=Denial of Service, 7=Remote File Retrieval (server),
                8=Command Execution, 9=SQL Injection, a=Authentication Bypass,
                b=Software Identification, c=Remote Source Inclusion, x=Reverse Tuning.
                Default "x6" = everything except DoS.
        ssl: Force SSL mode.
        port: Target port (auto-detected from URL if not specified).
        timeout: Override scan timeout in seconds.

    Returns:
        List of vulnerability findings with descriptions and references.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "tuning": tuning, "ssl": ssl, "port": port}

    target = sanitize_url(target)

    # Validate tuning string — only valid tuning chars allowed
    if not re.match(r"^[0-9a-cx]+$", tuning.lower()):
        tuning = "x6"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nikto", target, str(exc))
        raise

    tool_path = resolve_tool_path("nikto", cfg.tools.paths.nikto)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-h",
        target,
        "-Tuning",
        tuning,
        "-Format",
        "json",
        "-output",
        "/dev/stdout",
        "-nointeractive",
    ]

    if ssl:
        args.append("-ssl")

    if port is not None and 1 <= port <= 65535:
        args.extend(["-port", str(port)])

    # Stealth: inject -useproxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("nikto", args)

    await ctx.report_progress(0, 100, f"Starting Nikto scan on {target}...")

    async with rate_limited("nikto"):
        start = time.monotonic()
        await audit.log_tool_call("nikto", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("nikto", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Nikto results...")

    findings = _parse_nikto_output(stdout)

    await ctx.report_progress(100, 100, "Scan complete")
    await audit.log_tool_call(
        "nikto", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "nikto",
        "target": target,
        "duration_seconds": round(duration, 2),
        "findings_count": len(findings),
        "findings": findings,
        "raw_output": stdout[:5000],
    }


def _parse_nikto_output(output: str) -> list[dict]:  # type: ignore[type-arg]
    """Parse Nikto JSON output."""
    findings = []

    try:
        data = json.loads(output)
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            findings.append(
                {
                    "id": vuln.get("id", ""),
                    "osvdb": vuln.get("OSVDB", ""),
                    "method": vuln.get("method", ""),
                    "url": vuln.get("url", ""),
                    "message": vuln.get("msg", ""),
                    "references": vuln.get("references", {}).get("url", []),
                }
            )
        return findings
    except (json.JSONDecodeError, KeyError):
        pass

    # Fall back to text parsing
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("+ ") and len(line) > 2:
            findings.append(
                {
                    "message": line[2:],
                    "id": "",
                    "url": "",
                    "method": "",
                }
            )

    return findings
