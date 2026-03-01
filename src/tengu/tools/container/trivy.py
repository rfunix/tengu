"""Trivy container and filesystem vulnerability scanner tool wrapper."""

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

_VALID_SCAN_TYPES = {"image", "fs", "repo", "config", "sbom"}
_VALID_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Docker image names: alphanumeric, colon, slash, dot, hyphen, at-sign (for digests)
_DOCKER_IMAGE_PATTERN = re.compile(r"^[a-zA-Z0-9:/_.\-@]+$")


def _sanitize_docker_image(value: str) -> str:
    """Validate a Docker image name or tag."""
    from tengu.exceptions import InvalidInputError

    value = value.strip()
    if not value:
        raise InvalidInputError("target", value, "docker image name cannot be empty")
    if len(value) > 512:
        raise InvalidInputError("target", value, "docker image name too long")
    if not _DOCKER_IMAGE_PATTERN.match(value):
        raise InvalidInputError(
            "target",
            value,
            "docker image name contains forbidden characters (allowed: alphanumeric :/_.-@)",
        )
    return value


async def trivy_scan(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    scan_type: str = "image",
    severity: str = "HIGH,CRITICAL",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Scan container images, filesystems, or repositories for vulnerabilities using Trivy.

    Args:
        target: Docker image name (for image), local path (for fs/config/sbom), or repo URL (for repo).
        scan_type: Scan target type — image (Docker image), fs (filesystem), repo (git repo),
                   config (IaC misconfigurations), sbom (SBOM analysis).
        severity: Comma-separated severity filter (e.g. "HIGH,CRITICAL" or "MEDIUM,HIGH,CRITICAL").
        timeout: Override default timeout.

    Returns:
        Structured vulnerability report with total counts by severity and top findings.

    Note:
        - For image scans, the image must be pullable or already present locally.
        - Severity filter accepts: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "scan_type": scan_type, "severity": severity}

    # Validate scan_type
    scan_type = scan_type.strip().lower()
    if scan_type not in _VALID_SCAN_TYPES:
        return {
            "tool": "trivy",
            "error": f"Invalid scan_type '{scan_type}'. Must be one of: {', '.join(sorted(_VALID_SCAN_TYPES))}",
        }

    # Sanitize severity filter
    severity_parts = [s.strip().upper() for s in severity.split(",")]
    safe_severity_parts = [s for s in severity_parts if s in _VALID_SEVERITIES]
    if not safe_severity_parts:
        safe_severity_parts = ["HIGH", "CRITICAL"]
    safe_severity = ",".join(safe_severity_parts)

    # Sanitize target based on scan_type
    if scan_type == "image":
        target = _sanitize_docker_image(target)
    elif scan_type == "repo":
        from tengu.security.sanitizer import sanitize_url

        target = sanitize_url(target)
    else:
        # fs, config, sbom — local path
        target = sanitize_wordlist_path(target)

    tool_path = resolve_tool_path("trivy")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [
        tool_path,
        scan_type,
        "--format",
        "json",
        "--severity",
        safe_severity,
        "--no-progress",
        target,
    ]

    await ctx.report_progress(0, 100, f"Starting Trivy {scan_type} scan on {target}...")

    async with rate_limited("trivy"):
        start = time.monotonic()
        await audit.log_tool_call("trivy", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("trivy", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Trivy results...")

    parsed = _parse_trivy_output(stdout)

    await ctx.report_progress(100, 100, "Trivy scan complete")
    await audit.log_tool_call(
        "trivy", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "trivy",
        "target": target,
        "scan_type": scan_type,
        "severity_filter": safe_severity,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "total_vulnerabilities": parsed["total"],
        "severity_counts": parsed["severity_counts"],
        "results": parsed["results"],
        "top_vulnerabilities": parsed["top_vulns"],
        "raw_output_excerpt": stdout[-4000:] if len(stdout) > 4000 else stdout,
    }


def _parse_trivy_output(output: str) -> dict:  # type: ignore[type-arg]
    """Parse Trivy JSON output into structured results."""
    result: dict[str, object] = {
        "total": 0,
        "severity_counts": {"UNKNOWN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "results": [],
        "top_vulns": [],
    }

    if not output.strip():
        return result

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Trivy JSON output")
        return result

    raw_results = data.get("Results", [])
    all_vulns: list[dict] = []  # type: ignore[type-arg]
    structured_results: list[dict] = []  # type: ignore[type-arg]

    severity_counts: dict[str, int] = {
        "UNKNOWN": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for scan_result in raw_results:
        if not isinstance(scan_result, dict):
            continue

        scan_target = scan_result.get("Target", "")
        vuln_class = scan_result.get("Class", "")
        vuln_type = scan_result.get("Type", "")
        vulnerabilities = scan_result.get("Vulnerabilities", []) or []

        result_entry: dict[str, object] = {
            "target": scan_target,
            "class": vuln_class,
            "type": vuln_type,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": [],
        }

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev not in severity_counts:
                sev = "UNKNOWN"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Extract CVSS score
            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source_data in cvss_data.values():
                if isinstance(source_data, dict):
                    v3 = source_data.get("V3Score") or source_data.get("v3Score")
                    if v3 is not None:
                        cvss_score = float(v3)
                        break

            structured_vuln: dict[str, object] = {
                "id": vuln.get("VulnerabilityID", ""),
                "package": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": sev,
                "cvss_score": cvss_score,
                "description": vuln.get("Description", "")[:500],
                "references": (vuln.get("References", []) or [])[:3],
            }

            result_entry["vulnerabilities"].append(structured_vuln)  # type: ignore[union-attr]
            all_vulns.append(structured_vuln)

        structured_results.append(result_entry)

    # Sort all vulns by severity and CVSS for top-N list
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulns_sorted = sorted(
        all_vulns,
        key=lambda v: (
            _sev_order.get(str(v.get("severity", "UNKNOWN")), 4),
            -(v.get("cvss_score") or 0),
        ),
    )

    result["total"] = len(all_vulns)
    result["severity_counts"] = severity_counts
    result["results"] = structured_results
    result["top_vulns"] = all_vulns_sorted[:20]

    return result
