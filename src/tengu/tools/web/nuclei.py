"""Nuclei vulnerability scanner tool wrapper."""

from __future__ import annotations

import json
import time
from typing import Literal

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_severity, sanitize_url

logger = structlog.get_logger(__name__)

Severity = Literal["info", "low", "medium", "high", "critical"]


async def nuclei_scan(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    templates: list[str] | None = None,
    severity: list[Severity] | None = None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
    rate_limit: int = 150,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Scan a target for vulnerabilities using Nuclei template engine.

    Nuclei uses YAML templates to detect vulnerabilities, misconfigurations,
    exposed panels, CVEs, and more across web applications and network services.

    Args:
        target: URL or host to scan (e.g. "https://example.com").
        templates: Specific template paths or directories to use
                   (e.g. ["cves/", "misconfiguration/", "exposures/"]).
                   Defaults to all community templates.
        severity: Filter by severity levels. Defaults to configured levels
                  (medium, high, critical).
        tags: Filter templates by tags (e.g. ["sqli", "xss", "oast"]).
        exclude_tags: Tags to exclude (e.g. ["dos", "fuzz"]).
        rate_limit: Maximum requests per second. Default: 150.
        timeout: Override scan timeout in seconds.

    Returns:
        List of findings with template ID, name, severity, matched URL, and evidence.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {
        "target": target,
        "templates": templates,
        "severity": severity,
        "tags": tags,
    }

    target = sanitize_url(target)

    effective_severity = severity or cfg.tools.defaults.nuclei_severity
    effective_severity = sanitize_severity(effective_severity)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nuclei", target, str(exc))
        raise

    tool_path = resolve_tool_path("nuclei", cfg.tools.paths.nuclei)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        target,
        "-json",
        "-silent",
        "-severity",
        ",".join(effective_severity),
        "-rate-limit",
        str(max(1, min(rate_limit, 1000))),
    ]

    if templates:
        import re

        safe_templates = [t for t in templates if re.match(r"^[a-zA-Z0-9_\-/\.]+$", t)]
        for tmpl in safe_templates:
            args.extend(["-t", tmpl])

    if tags:
        import re

        safe_tags = [t for t in tags if re.match(r"^[a-zA-Z0-9_\-]+$", t)]
        if safe_tags:
            args.extend(["-tags", ",".join(safe_tags)])

    if exclude_tags:
        import re

        safe_exclude = [t for t in exclude_tags if re.match(r"^[a-zA-Z0-9_\-]+$", t)]
        if safe_exclude:
            args.extend(["-etags", ",".join(safe_exclude)])

    # Stealth: inject -proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("nuclei", args)

    await ctx.report_progress(0, 100, f"Starting Nuclei scan on {target}...")

    async with rate_limited("nuclei"):
        start = time.monotonic()
        await audit.log_tool_call("nuclei", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("nuclei", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Nuclei results...")

    findings = _parse_nuclei_output(stdout)

    await ctx.report_progress(100, 100, "Scan complete")
    await audit.log_tool_call(
        "nuclei", target, params, result="completed", duration_seconds=duration
    )

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "tool": "nuclei",
        "target": target,
        "duration_seconds": round(duration, 2),
        "findings_count": len(findings),
        "severity_breakdown": severity_counts,
        "findings": findings,
    }


def _parse_nuclei_output(output: str) -> list[dict]:  # type: ignore[type-arg]
    """Parse Nuclei JSONL output into structured findings."""
    findings = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            finding = {
                "template_id": data.get("template-id", ""),
                "template_name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "description": info.get("description", ""),
                "matched_url": data.get("matched-at", data.get("host", "")),
                "type": data.get("type", ""),
                "extracted_results": data.get("extracted-results", []),
                "curl_command": data.get("curl-command", ""),
                "cve_ids": info.get("classification", {}).get("cve-id", []),
                "cwe_ids": info.get("classification", {}).get("cwe-id", []),
                "cvss_score": info.get("classification", {}).get("cvss-score"),
                "tags": info.get("tags", []),
                "references": info.get("reference", []),
                "timestamp": data.get("timestamp", ""),
            }
            findings.append(finding)
        except json.JSONDecodeError:
            continue

    return findings
