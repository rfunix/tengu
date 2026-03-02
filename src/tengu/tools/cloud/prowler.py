"""Prowler cloud security audit tool wrapper."""

from __future__ import annotations

import re
import time
from pathlib import Path

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited

logger = structlog.get_logger(__name__)

_VALID_PROVIDERS = ("aws", "azure", "gcp")


def _parse_prowler_output(output: str) -> dict:
    """Parse prowler stdout for FAIL/PASS/WARNING/ERROR counts."""
    counts: dict[str, int] = {"FAIL": 0, "PASS": 0, "WARNING": 0, "ERROR": 0}
    findings: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        for status in ("FAIL", "PASS", "WARNING", "ERROR"):
            if f" {status} " in line or line.startswith(status):
                counts[status] += 1
                if status in ("FAIL", "ERROR") and len(findings) < 20:
                    findings.append(line)
                break
    return {"counts": counts, "critical_findings": findings}


async def prowler_scan(
    ctx: Context,
    provider: str,
    profile: str = "",
    project: str = "",
    subscription: str = "",
    report_dir: str = "/tmp/prowler-report",
    timeout: int | None = None,
) -> dict:
    """Perform a cloud security audit using Prowler.

    Prowler checks cloud provider configurations against security best practices
    and compliance frameworks (CIS, NIST, SOC2, ISO 27001, etc.).

    Args:
        provider: Cloud provider to audit — aws, azure, gcp.
        profile: AWS named profile (for aws provider). Uses default credentials if empty.
        project: GCP project ID (for gcp provider).
        subscription: Azure subscription ID (for azure provider).
        report_dir: Directory to write Prowler reports.
        timeout: Override scan timeout in seconds.

    Returns:
        Summary of cloud security findings by severity.

    Note:
        - Requires cloud provider credentials configured in the environment.
        - Long-running — cloud audits typically take 5-30 minutes.
    """
    cfg = get_config()
    audit = get_audit_logger()

    safe_provider = re.sub(r"[^a-z]", "", provider.lower())
    if safe_provider not in _VALID_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}. Use aws, azure, or gcp.")

    safe_profile = re.sub(r"[^a-zA-Z0-9_\-]", "", profile) if profile else ""
    safe_project = re.sub(r"[^a-zA-Z0-9_\-]", "", project) if project else ""
    safe_subscription = re.sub(r"[^a-zA-Z0-9_\-]", "", subscription) if subscription else ""
    safe_report_dir = re.sub(r"[^a-zA-Z0-9/_\-]", "", report_dir) or "/tmp/prowler-report"

    params: dict[str, object] = {
        "provider": safe_provider,
        "profile": safe_profile,
        "project": safe_project,
        "subscription": safe_subscription,
        "report_dir": safe_report_dir,
    }

    Path(safe_report_dir).mkdir(parents=True, exist_ok=True)

    tool_path = resolve_tool_path("prowler")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        safe_provider,
        "-M", "json",
        "-z",
        "-q",
        "-o", safe_report_dir,
    ]
    if safe_provider == "aws" and safe_profile:
        args.extend(["-p", safe_profile])
    if safe_provider == "gcp" and safe_project:
        args.extend(["--project-id", safe_project])
    if safe_provider == "azure" and safe_subscription:
        args.extend(["--subscription-id", safe_subscription])

    await ctx.report_progress(0, 100, f"Starting prowler {safe_provider} audit...")

    async with rate_limited("prowler"):
        start = time.monotonic()
        await audit.log_tool_call("prowler", safe_provider, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("prowler", safe_provider, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing prowler results...")
    parsed = _parse_prowler_output(stdout)

    await ctx.report_progress(100, 100, "Prowler audit complete")
    await audit.log_tool_call(
        "prowler", safe_provider, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "prowler",
        "provider": safe_provider,
        "report_dir": safe_report_dir,
        "duration_seconds": round(duration, 2),
        "findings_summary": parsed["counts"],
        "critical_findings": parsed["critical_findings"],
        "raw_output_excerpt": stdout[-5000:] if len(stdout) > 5000 else stdout,
    }
