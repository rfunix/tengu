"""Feroxbuster recursive content discovery tool wrapper."""

from __future__ import annotations

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
from tengu.security.sanitizer import sanitize_target, sanitize_wordlist_path

logger = structlog.get_logger(__name__)


def _parse_feroxbuster_output(output: str) -> list[dict]:
    """Parse feroxbuster plain text output into structured findings."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Try to parse status lines: "200      GET      1l      2w      3c https://..."
        parts = line.split()
        if parts and parts[0].isdigit():
            finding: dict[str, object] = {"line": line}
            try:
                finding["status"] = int(parts[0])
                # Find URL (starts with http)
                for part in parts:
                    if part.startswith("http"):
                        finding["url"] = part
                        break
            except (ValueError, IndexError):
                pass
            findings.append(finding)
    return findings


async def feroxbuster_scan(
    ctx: Context,
    target: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    threads: int = 50,
    depth: int = 4,
    timeout: int | None = None,
) -> dict:
    """Perform recursive content discovery using Feroxbuster.

    Unlike Gobuster or FFuf, Feroxbuster recursively discovers directories,
    automatically crawling into discovered paths to find nested content.

    Args:
        target: Target URL to scan (e.g. "https://example.com").
        wordlist: Path to wordlist file.
        extensions: Comma-separated file extensions (e.g. "php,html,txt").
        threads: Number of concurrent threads (default 50, max 100).
        depth: Maximum recursion depth (default 4, max 10).
        timeout: Override scan timeout in seconds.

    Returns:
        Discovered URLs with status codes, content lengths, and word counts.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Feroxbuster recurses by default — use depth to control scope.
    """
    cfg = get_config()
    audit = get_audit_logger()

    threads = max(1, min(threads, 100))
    depth = max(1, min(depth, 10))

    params: dict[str, object] = {
        "target": target,
        "wordlist": wordlist,
        "threads": threads,
        "depth": depth,
    }

    target = sanitize_target(target)
    wordlist = sanitize_wordlist_path(wordlist)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("feroxbuster", target, str(exc))
        raise

    tool_path = resolve_tool_path("feroxbuster")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        target,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "-d",
        str(depth),
        "--no-state",
        "-q",
    ]

    if extensions:
        safe_ext = re.sub(r"[^a-zA-Z0-9,.]", "", extensions)
        if safe_ext:
            args.extend(["-x", safe_ext])

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("feroxbuster", args)

    await ctx.report_progress(0, 100, f"Starting feroxbuster scan on {target}...")

    async with rate_limited("feroxbuster"):
        start = time.monotonic()
        await audit.log_tool_call("feroxbuster", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(
                "feroxbuster", target, params, result="failed", error=str(exc)
            )
            raise
        duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "Feroxbuster scan complete")
    await audit.log_tool_call(
        "feroxbuster", target, params, result="completed", duration_seconds=duration
    )

    findings = _parse_feroxbuster_output(stdout)

    return {
        "tool": "feroxbuster",
        "target": target,
        "wordlist": wordlist,
        "threads": threads,
        "depth": depth,
        "duration_seconds": round(duration, 2),
        "findings_count": len(findings),
        "findings": findings,
        "raw_output": stdout[-5000:] if len(stdout) > 5000 else stdout,
    }
