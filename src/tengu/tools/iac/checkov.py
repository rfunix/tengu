"""Checkov IaC security scanner wrapper — Terraform, Kubernetes, Docker, CloudFormation."""

from __future__ import annotations

import json
import re
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_wordlist_path

logger = structlog.get_logger(__name__)


async def checkov_scan(
    ctx: Context,
    path: str,
    framework: str = "all",
    check_ids: str = "",
    skip_check_ids: str = "",
    timeout: int | None = None,
) -> dict:
    """Scan Infrastructure as Code for security misconfigurations using Checkov.

    Supports Terraform, Kubernetes, Dockerfile, CloudFormation, ARM, Bicep,
    GitHub Actions, and more.

    Args:
        path: Path to IaC directory or file to scan.
        framework: Framework type — all, terraform, kubernetes, dockerfile, cloudformation,
                   arm, bicep, github_actions, helm, kustomize.
        check_ids: Comma-separated check IDs to run (e.g. "CKV_AWS_1,CKV_AWS_2").
        skip_check_ids: Comma-separated check IDs to skip.
        timeout: Override default timeout in seconds.

    Returns:
        Security findings grouped by severity with resource IDs, check names, and remediation.

    Note:
        - Scans local files only — no network access required.
        - No allowlist check needed (local path, not a network target).
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"path": path, "framework": framework}

    # Sanitize path (local only)
    path = sanitize_wordlist_path(path)

    valid_frameworks = {
        "all",
        "terraform",
        "kubernetes",
        "dockerfile",
        "cloudformation",
        "arm",
        "bicep",
        "github_actions",
        "helm",
        "kustomize",
    }
    if framework not in valid_frameworks:
        framework = "all"

    safe_checks = re.sub(r"[^a-zA-Z0-9_,]", "", check_ids)
    safe_skips = re.sub(r"[^a-zA-Z0-9_,]", "", skip_check_ids)

    tool_path = resolve_tool_path("checkov")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-d",
        path,
        "--output",
        "json",
        "--quiet",
        "--compact",
    ]

    if framework != "all":
        args.extend(["--framework", framework])
    if safe_checks:
        args.extend(["--check", safe_checks])
    if safe_skips:
        args.extend(["--skip-check", safe_skips])

    await ctx.report_progress(0, 100, f"Starting Checkov scan on {path}...")

    async with rate_limited("checkov"):
        start = time.monotonic()
        await audit.log_tool_call("checkov", path, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("checkov", path, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Checkov results...")

    passed = 0
    failed = 0
    findings: list[dict] = []

    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            results = data.get("results", data)
        elif isinstance(data, list):
            results = {"failed_checks": data}
        else:
            results = {}

        passed = len(results.get("passed_checks", []))

        for check in results.get("failed_checks", []):
            failed += 1
            findings.append(
                {
                    "check_id": check.get("check_id"),
                    "check_type": check.get("check_type"),
                    "resource": check.get("resource"),
                    "file": check.get("repo_file_path"),
                    "line_range": check.get("file_line_range"),
                    "severity": check.get("severity", "MEDIUM"),
                    "guideline": check.get("guideline"),
                }
            )

    except (json.JSONDecodeError, KeyError, AttributeError):
        pass

    await ctx.report_progress(100, 100, "Checkov scan complete")
    await audit.log_tool_call(
        "checkov", path, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "checkov",
        "path": path,
        "framework": framework,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "passed": passed,
        "failed": failed,
        "findings": findings,
        "raw_output": stdout,
    }
