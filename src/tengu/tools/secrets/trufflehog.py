"""TruffleHog secret scanning tool wrapper."""

from __future__ import annotations

import json
import time
import urllib.parse

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_free_text, sanitize_url, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

_VALID_SCAN_TYPES = {"git", "filesystem", "github"}


async def trufflehog_scan(
    ctx: Context,
    target: str,
    scan_type: str = "git",
    branch: str = "",
    timeout: int | None = None,
) -> dict:
    """Scan for leaked secrets and credentials using TruffleHog.

    Args:
        target: Git repository URL (for git/github mode) or local directory path (for filesystem mode).
        scan_type: Scan type — git (repo URL), filesystem (local path), github (GitHub org/user).
        branch: Branch to scan (optional, defaults to all branches).
        timeout: Override default timeout.

    Returns:
        List of secret findings with detector type, verification status, and source location.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "scan_type": scan_type, "branch": branch}

    # Validate scan_type
    scan_type = scan_type.strip().lower()
    if scan_type not in _VALID_SCAN_TYPES:
        return {
            "tool": "trufflehog",
            "error": f"Invalid scan_type '{scan_type}'. Must be one of: {', '.join(sorted(_VALID_SCAN_TYPES))}",
        }

    # Sanitize inputs based on scan type
    if scan_type in ("git", "github"):
        if target.startswith(("https://", "http://")):
            target = sanitize_url(target)
        elif target.startswith("git@"):
            # SSH git URL — validate format only (no shell metacharacters)
            import re

            if re.search(r"[;&|`$<>()\{\}\[\]!\\\'\"\r\n\s]", target):
                from tengu.exceptions import InvalidInputError

                raise InvalidInputError(
                    "target", target, "SSH git URL contains forbidden characters"
                )
        else:
            # GitHub org/user slug or similar — treat as free text
            target = sanitize_free_text(target, field="target", max_length=200)

        # Allowlist check — extract domain from git URL for http/https
        if target.startswith(("https://", "http://")):
            parsed = urllib.parse.urlparse(target)
            allowlist = make_allowlist_from_config()
            try:
                allowlist.check(parsed.netloc)
            except Exception as exc:
                await audit.log_target_blocked("trufflehog", target, str(exc))
                raise
    else:
        # filesystem mode — validate as a local path
        target = sanitize_wordlist_path(target)

    # Sanitize optional branch name
    safe_branch = ""
    if branch:
        safe_branch = sanitize_free_text(branch, field="branch", max_length=200)

    tool_path = resolve_tool_path("trufflehog")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [tool_path, scan_type, target, "--json", "--no-update"]

    if safe_branch:
        args.extend(["--branch", safe_branch])

    await ctx.report_progress(0, 100, f"Starting TruffleHog {scan_type} scan on {target}...")

    async with rate_limited("trufflehog"):
        start = time.monotonic()
        await audit.log_tool_call("trufflehog", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("trufflehog", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing TruffleHog results...")

    findings = _parse_trufflehog_output(stdout)

    await ctx.report_progress(100, 100, "TruffleHog scan complete")
    await audit.log_tool_call(
        "trufflehog", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "trufflehog",
        "target": target,
        "scan_type": scan_type,
        "branch": safe_branch or "all",
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "secrets_found": len(findings),
        "verified_count": sum(1 for f in findings if f.get("verified")),
        "findings": findings,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_trufflehog_output(output: str) -> list[dict]:
    """Parse TruffleHog JSON-lines output into structured findings."""
    findings: list[dict] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Extract relevant fields from the TruffleHog JSON schema
        detector = entry.get("DetectorName", entry.get("detectorName", "unknown"))
        verified = bool(entry.get("Verified", entry.get("verified", False)))
        raw = entry.get("Raw", entry.get("raw", ""))

        # Source metadata varies by scan type
        source_meta = entry.get("SourceMetadata", entry.get("sourceMetadata", {}))
        source_data = source_meta.get("Data", source_meta.get("data", {}))

        # Flatten source info — could be Git, Filesystem, GitHub, etc.
        source_info: dict[str, object] = {}
        for key, val in source_data.items():
            if isinstance(val, dict):
                source_info.update(val)
            else:
                source_info[key] = val

        # Redact the raw secret value partially for safety
        redacted_raw = _redact_secret(str(raw))

        findings.append(
            {
                "detector": detector,
                "verified": verified,
                "severity": "high" if verified else "info",
                "description": f"Detected {detector} credential{'(verified)' if verified else '(unverified)'}",
                "source": source_info,
                "secret_redacted": redacted_raw,
                "raw_entry": entry,
            }
        )

    return findings


def _redact_secret(value: str, visible_chars: int = 6) -> str:
    """Partially redact a secret value for safe logging."""
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    prefix = value[:visible_chars]
    suffix = value[-visible_chars:]
    masked = "*" * min(len(value) - visible_chars * 2, 20)
    return f"{prefix}{masked}{suffix}"
