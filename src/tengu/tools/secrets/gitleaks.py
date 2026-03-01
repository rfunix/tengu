"""Gitleaks secret scanning tool wrapper."""

from __future__ import annotations

import json
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

_VALID_SCAN_TYPES = {"detect", "protect", "dir"}
_VALID_REPORT_FORMATS = {"json", "csv", "sarif"}


async def gitleaks_scan(
    ctx: Context,
    target: str,
    scan_type: str = "detect",
    report_format: str = "json",
    timeout: int | None = None,
) -> dict:
    """Scan a repository or directory for secrets and credentials using Gitleaks.

    Args:
        target: Local path to a Git repository or directory to scan.
        scan_type: Scan mode — detect (full repo history), protect (pre-commit staged changes),
                   dir (scan directory without git history).
        report_format: Output format — json, csv, sarif.
        timeout: Override default timeout.

    Returns:
        List of secret findings with rule ID, file, commit, description, and partially-redacted secret.

    Note:
        - Target path must be under an allowed directory (/usr/share, /opt, $HOME, /tmp).
        - Use detect for comprehensive historical scans.
        - Use protect as a pre-commit hook to catch secrets before they are committed.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {
        "target": target,
        "scan_type": scan_type,
        "report_format": report_format,
    }

    # Validate scan_type
    scan_type = scan_type.strip().lower()
    if scan_type not in _VALID_SCAN_TYPES:
        return {
            "tool": "gitleaks",
            "error": f"Invalid scan_type '{scan_type}'. Must be one of: {', '.join(sorted(_VALID_SCAN_TYPES))}",
        }

    # Validate report_format
    report_format = report_format.strip().lower()
    if report_format not in _VALID_REPORT_FORMATS:
        report_format = "json"

    # Sanitize target path
    target = sanitize_wordlist_path(target)

    tool_path = resolve_tool_path("gitleaks")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [
        tool_path,
        scan_type,
        "--source",
        target,
        "--report-format",
        report_format,
        "--report-path",
        "/dev/stdout",
        "--exit-code",
        "0",
    ]

    await ctx.report_progress(0, 100, f"Starting Gitleaks {scan_type} scan on {target}...")

    async with rate_limited("gitleaks"):
        start = time.monotonic()
        await audit.log_tool_call("gitleaks", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("gitleaks", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Gitleaks results...")

    findings = _parse_gitleaks_output(stdout, report_format)

    await ctx.report_progress(100, 100, "Gitleaks scan complete")
    await audit.log_tool_call(
        "gitleaks", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "gitleaks",
        "target": target,
        "scan_type": scan_type,
        "report_format": report_format,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "secrets_found": len(findings),
        "findings": findings,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_gitleaks_output(output: str, report_format: str) -> list[dict]:
    """Parse Gitleaks output into structured findings."""
    findings: list[dict] = []

    if not output.strip():
        return findings

    if report_format == "json":
        try:
            raw_findings = json.loads(output)
            if not isinstance(raw_findings, list):
                return findings
        except json.JSONDecodeError:
            logger.warning("Failed to parse Gitleaks JSON output")
            return findings

        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            secret_raw = item.get("Secret", item.get("secret", ""))
            redacted = _redact_secret(str(secret_raw))

            findings.append(
                {
                    "rule": item.get("RuleID", item.get("ruleID", "unknown")),
                    "description": item.get("Description", item.get("description", "")),
                    "file": item.get("File", item.get("file", "")),
                    "line": item.get("StartLine", item.get("startLine", 0)),
                    "commit": item.get("Commit", item.get("commit", "")),
                    "author": item.get("Author", item.get("author", "")),
                    "date": item.get("Date", item.get("date", "")),
                    "match": item.get("Match", item.get("match", "")),
                    "secret_redacted": redacted,
                    "severity": "high",
                }
            )

    return findings


def _redact_secret(value: str, visible_chars: int = 4) -> str:
    """Partially redact a secret value for safe display."""
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    prefix = value[:visible_chars]
    suffix = value[-visible_chars:]
    masked = "*" * min(len(value) - visible_chars * 2, 16)
    return f"{prefix}{masked}{suffix}"
