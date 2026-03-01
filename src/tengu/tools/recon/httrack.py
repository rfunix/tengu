"""HTTrack website mirror tool wrapper for offline analysis and forensics."""

from __future__ import annotations

import re
import time
from pathlib import Path

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

_MAX_DEPTH = 5
_MAX_SIZE_MB = 500

# Patterns indicating interesting content worth noting in results
_INTERESTING_PATTERNS: list[tuple[str, str]] = [
    (r"api[_-]?key\s*[=:]\s*['\"]?\w+", "potential API key"),
    (r"(?i)(secret|token|password)\s*[=:]\s*['\"]?\w+", "potential credential"),
    (r"TODO|FIXME|HACK|XXX", "development note"),
    (r"<!--.*?(debug|internal|staging|test).*?-->", "HTML comment with env hint"),
    (
        r"https?://(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)",
        "internal URL reference",
    ),
]


def _sanitize_output_dir(output_dir: str) -> str:
    """Strip dangerous characters; enforce /tmp/ or /home/ prefix."""
    safe = re.sub(r"[^a-zA-Z0-9/_\-.]", "", output_dir)
    if not safe.startswith(("/tmp/", "/home/")):
        return "/tmp/httrack"
    return safe


def _count_files_by_type(base: Path) -> dict[str, int]:
    """Recursively count downloaded files grouped by extension."""
    counts: dict[str, int] = {}
    if not base.is_dir():
        return counts
    for f in base.rglob("*"):
        if f.is_file():
            ext = f.suffix.lstrip(".").lower() or "other"
            counts[ext] = counts.get(ext, 0) + 1
    return counts


def _find_interesting(base: Path) -> list[str]:
    """Scan HTML and JS files for interesting patterns."""
    findings: list[str] = []
    found_labels: set[str] = set()

    if not base.is_dir():
        return findings

    for f in base.rglob("*"):
        if f.suffix.lower() not in (".html", ".htm", ".js", ".json", ".xml", ".txt"):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern, label in _INTERESTING_PATTERNS:
            if label not in found_labels and re.search(pattern, content, re.IGNORECASE):
                found_labels.add(label)
                findings.append(f"Found {label} in {f.name}")
    return findings


def _dir_size_mb(base: Path) -> float:
    """Return total size of directory tree in megabytes."""
    if not base.is_dir():
        return 0.0
    total = sum(f.stat().st_size for f in base.rglob("*") if f.is_file())
    return round(total / (1024 * 1024), 2)


async def httrack_mirror(
    ctx: Context,
    target: str,
    depth: int = 2,
    output_dir: str = "/tmp/httrack",
    max_size: int = 100,
    include_assets: bool = True,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]  # FastMCP cannot serialize generic dict
    """Mirror a website locally for offline analysis using HTTrack.

    Downloads the full website (HTML, JS, CSS, images) to a local directory,
    preserving structure for offline inspection. Useful for:
    - Forensic snapshots of a target's web surface
    - Offline search for hardcoded secrets, API keys, dev comments
    - Mapping application structure without active interaction

    Args:
        target: URL of the site to mirror (e.g. http://example.com).
        depth: Crawl depth (1–5). Default 2. Capped at 5 to prevent runaway crawls.
        output_dir: Local directory to save the mirror (default /tmp/httrack).
        max_size: Maximum download size in MB (default 100, max 500).
        include_assets: Whether to download CSS/JS/images (default True).
        timeout: Override default scan timeout in seconds.

    Returns:
        Mirror results with download stats, file type breakdown, and interesting findings.

    Note:
        - HTTrack must be installed on the system (apt install httrack / brew install httrack).
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Set depth=1 for a shallow mirror of the top-level page only.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {
        "target": target,
        "depth": depth,
        "output_dir": output_dir,
        "max_size": max_size,
        "include_assets": include_assets,
    }

    # Sanitize inputs
    target = sanitize_url(target)

    # Clamp depth and max_size to safe maximums
    depth = max(1, min(depth, _MAX_DEPTH))
    max_size = max(1, min(max_size, _MAX_SIZE_MB))

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("httrack", target, str(exc))
        raise

    safe_dir = _sanitize_output_dir(output_dir)

    tool_path = resolve_tool_path("httrack")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Convert MB to bytes for httrack's -M flag
    max_size_bytes = max_size * 1024 * 1024

    args: list[str] = [
        tool_path,
        target,
        "-O",
        safe_dir,
        f"-r{depth}",
        f"-M{max_size_bytes}",
        "-%v",  # verbose progress
        "--quiet",  # suppress interactive prompts
    ]

    if not include_assets:
        # Exclude images, CSS, audio, video
        args += [
            "-*.png",
            "-*.jpg",
            "-*.jpeg",
            "-*.gif",
            "-*.css",
            "-*.ico",
            "-*.mp4",
            "-*.mp3",
            "-*.svg",
            "-*.woff",
            "-*.woff2",
        ]

    await ctx.report_progress(0, 100, f"Starting HTTrack mirror of {target} (depth={depth})...")

    async with rate_limited("httrack"):
        start = time.monotonic()
        await audit.log_tool_call("httrack", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("httrack", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "HTTrack complete, analysing results...")

    # Post-processing
    mirror_path = Path(safe_dir)
    file_types = _count_files_by_type(mirror_path)
    total_files = sum(file_types.values())
    total_size = _dir_size_mb(mirror_path)
    interesting = _find_interesting(mirror_path)

    await audit.log_tool_call(
        "httrack", target, params, result="completed", duration_seconds=duration
    )
    await ctx.report_progress(100, 100, "Mirror and analysis complete")

    return {
        "tool": "httrack",
        "target": target,
        "output_dir": safe_dir,
        "depth": depth,
        "max_size_mb": max_size,
        "include_assets": include_assets,
        "pages_downloaded": file_types.get("html", 0) + file_types.get("htm", 0),
        "total_files": total_files,
        "total_size_mb": total_size,
        "duration_seconds": round(duration, 2),
        "file_types": file_types,
        "interesting_findings": interesting,
        "command": " ".join(args),
        "raw_output": stdout,
    }
