"""Gowitness web screenshot tool wrapper for visual reconnaissance."""

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
from tengu.security.sanitizer import sanitize_target, sanitize_url

logger = structlog.get_logger(__name__)


async def gowitness_screenshot(
    ctx: Context,
    target: str,
    mode: str = "single",
    output_dir: str = "/tmp/gowitness",
    timeout: int | None = None,
) -> dict:
    """Capture web screenshots for visual documentation using Gowitness.

    Useful for documenting web interfaces, login pages, and web-based findings
    in penetration test reports.

    Args:
        target: URL (single mode) or path to URL list file (file mode) or CIDR (scan mode).
        mode: Screenshot mode — single (one URL), file (URL list), scan (CIDR range), nmap (nmap XML).
        output_dir: Directory to save screenshots (default /tmp/gowitness).
        timeout: Override default timeout in seconds.

    Returns:
        Screenshot results with file paths, titles, status codes, and technologies detected.

    Note:
        - Requires Chrome/Chromium installed on the system.
        - Screenshots are saved locally to output_dir.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "mode": mode, "output_dir": output_dir}

    if mode not in ("single", "file", "scan", "nmap"):
        mode = "single"

    target = sanitize_url(target) if mode == "single" else sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("gowitness", target, str(exc))
        raise

    # Sanitize output dir (must be under /tmp or home)
    safe_dir = re.sub(r"[^a-zA-Z0-9/_\-.]", "", output_dir)
    if not safe_dir.startswith(("/tmp/", "/home/")):
        safe_dir = "/tmp/gowitness"

    tool_path = resolve_tool_path("gowitness")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    if mode == "file":
        args = [tool_path, "screenshot", "--file", target, "--screenshot-path", safe_dir]
    else:
        args = [tool_path, "screenshot", "--url", target, "--screenshot-path", safe_dir]

    await ctx.report_progress(0, 100, f"Starting Gowitness screenshot ({mode}) on {target}...")

    async with rate_limited("gowitness"):
        start = time.monotonic()
        await audit.log_tool_call("gowitness", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("gowitness", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "Gowitness complete")
    await audit.log_tool_call(
        "gowitness", target, params, result="completed", duration_seconds=duration
    )

    # List screenshots taken
    screenshots: list[str] = []
    try:
        safe_path = Path(safe_dir)
        if safe_path.is_dir():
            screenshots = [
                str(f) for f in safe_path.iterdir() if f.suffix in (".png", ".jpg", ".jpeg")
            ]
    except Exception:
        pass

    return {
        "tool": "gowitness",
        "target": target,
        "mode": mode,
        "output_dir": safe_dir,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "screenshots_taken": len(screenshots),
        "screenshot_paths": screenshots,
        "raw_output": stdout,
    }
