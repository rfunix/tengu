"""ScoutSuite cloud security auditing tool wrapper."""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_free_text

logger = structlog.get_logger(__name__)

_VALID_PROVIDERS = {"aws", "azure", "gcp", "alibaba"}


async def scoutsuite_scan(
    ctx: Context,
    provider: str,
    profile: str = "",
    project: str = "",
    subscription: str = "",
    report_dir: str = "/tmp/scoutsuite-report",
    timeout: int | None = None,
) -> dict:
    """Perform a cloud security audit using ScoutSuite.

    Args:
        provider: Cloud provider to audit — aws, azure, gcp, alibaba.
        profile: AWS named profile (for aws provider). Uses default credentials if empty.
        project: GCP project ID (for gcp provider).
        subscription: Azure subscription ID (for azure provider).
        report_dir: Directory to write the ScoutSuite report to.
        timeout: Override default timeout.

    Returns:
        Summary of cloud security findings by service and severity from the ScoutSuite report.

    Note:
        - Requires cloud provider credentials configured in the environment (AWS_PROFILE,
          GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_ID, etc.).
        - ScoutSuite writes its full report to report_dir/scoutsuite-report/.
        - Long-running tool — cloud audits typically take 5-30 minutes depending on account size.
    """
    cfg = get_config()
    audit = get_audit_logger()

    # Validate and sanitize provider
    provider = provider.strip().lower()
    if provider not in _VALID_PROVIDERS:
        return {
            "tool": "scoutsuite",
            "error": f"Invalid provider '{provider}'. Must be one of: {', '.join(sorted(_VALID_PROVIDERS))}",
        }

    # Sanitize optional identifier fields
    safe_profile = sanitize_free_text(profile, field="profile", max_length=128) if profile else ""
    safe_project = sanitize_free_text(project, field="project", max_length=256) if project else ""
    safe_subscription = (
        sanitize_free_text(subscription, field="subscription", max_length=256)
        if subscription
        else ""
    )
    safe_report_dir = (
        sanitize_free_text(report_dir, field="report_dir", max_length=512)
        if report_dir
        else "/tmp/scoutsuite-report"
    )

    params: dict[str, object] = {
        "provider": provider,
        "profile": safe_profile,
        "project": safe_project,
        "subscription": safe_subscription,
        "report_dir": safe_report_dir,
    }

    tool_path = resolve_tool_path("scout")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [
        tool_path,
        provider,
        "--no-browser",
        "--report-dir",
        safe_report_dir,
    ]

    # Provider-specific arguments
    if provider == "aws" and safe_profile:
        args.extend(["--profile", safe_profile])
    elif provider == "gcp" and safe_project:
        args.extend(["--project", safe_project])
    elif provider == "azure" and safe_subscription:
        args.extend(["--subscription", safe_subscription])

    await ctx.report_progress(0, 100, f"Starting ScoutSuite {provider.upper()} audit...")

    async with rate_limited("scoutsuite"):
        start = time.monotonic()
        await audit.log_tool_call("scout", provider, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("scout", provider, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing ScoutSuite report...")

    # Attempt to parse the JSON report written to disk
    report_summary = _parse_scoutsuite_report(safe_report_dir)

    await ctx.report_progress(100, 100, "ScoutSuite audit complete")
    await audit.log_tool_call(
        "scout", provider, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "scoutsuite",
        "provider": provider,
        "report_dir": safe_report_dir,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "summary": report_summary,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_scoutsuite_report(report_dir: str) -> dict:
    """Parse the ScoutSuite JSON results file from disk."""
    result: dict[str, object] = {
        "parsed": False,
        "services": {},
        "total_flagged_items": 0,
        "top_findings": [],
    }

    # ScoutSuite writes results to <report_dir>/scoutsuite-report/scoutsuite_results.json
    results_path = Path(report_dir) / "scoutsuite-report" / "scoutsuite_results.json"

    if not results_path.exists():
        logger.warning("ScoutSuite results file not found", path=str(results_path))
        result["error"] = f"Results file not found at {results_path}"
        return result

    try:
        with results_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse ScoutSuite results", error=str(exc))
        result["error"] = f"Failed to parse results: {exc}"
        return result

    result["parsed"] = True
    services_data = data.get("services", {})
    service_summaries: dict[str, object] = {}
    top_findings: list[dict] = []
    total_flagged = 0

    for service_name, service_data in services_data.items():
        if not isinstance(service_data, dict):
            continue

        findings = service_data.get("findings", {})
        if not isinstance(findings, dict):
            continue

        flagged_count = 0
        high_severity: list[str] = []

        for finding_key, finding_data in findings.items():
            if not isinstance(finding_data, dict):
                continue

            flagged = finding_data.get("flagged_items", 0) or 0
            if flagged > 0:
                flagged_count += flagged
                level = finding_data.get("level", "unknown")
                description = finding_data.get("description", finding_key)

                if level in ("danger", "warning"):
                    high_severity.append(f"{service_name}: {description} ({flagged} flagged)")
                    top_findings.append(
                        {
                            "service": service_name,
                            "finding": finding_key,
                            "description": description,
                            "flagged_items": flagged,
                            "severity": "high" if level == "danger" else "medium",
                        }
                    )

        if flagged_count > 0:
            service_summaries[service_name] = {
                "flagged_items": flagged_count,
                "high_severity_findings": high_severity[:5],
            }
            total_flagged += flagged_count

    # Sort top findings by flagged items descending
    top_findings_sorted = sorted(
        top_findings, key=lambda x: x.get("flagged_items", 0), reverse=True
    )

    result["services"] = service_summaries
    result["total_flagged_items"] = total_flagged
    result["top_findings"] = top_findings_sorted[:20]

    return result
