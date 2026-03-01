"""Gobuster directory, file, and vhost brute-force tool wrapper."""

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


async def gobuster_scan(
    ctx: Context,
    target: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    threads: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    timeout: int | None = None,
) -> dict:
    """Brute-force directories, files, and virtual hosts using Gobuster.

    Args:
        target: Target URL (e.g. https://example.com).
        mode: Gobuster mode — dir (directory/file), vhost (virtual hosts), dns (subdomains).
        wordlist: Path to wordlist file.
        extensions: Comma-separated file extensions to check (e.g. "php,html,txt").
        threads: Number of concurrent threads (default 10, max 50).
        status_codes: Comma-separated HTTP status codes to show (default: 200,204,301,302,307,401,403).
        timeout: Override default timeout in seconds.

    Returns:
        Discovered paths/vhosts with status codes and content lengths.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Rate limiting applies — use threads <= 10 for stealth.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "mode": mode, "wordlist": wordlist}

    target = sanitize_target(target)
    wordlist = sanitize_wordlist_path(wordlist)
    if mode not in ("dir", "vhost", "dns", "fuzz"):
        mode = "dir"
    threads = max(1, min(threads, 50))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("gobuster", target, str(exc))
        raise

    tool_path = resolve_tool_path("gobuster")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        mode,
        "-u",
        target,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "--no-error",
    ]

    if mode == "dir":
        args.extend(["-s", status_codes])
        if extensions:
            safe_ext = re.sub(r"[^a-zA-Z0-9,.]", "", extensions)
            if safe_ext:
                args.extend(["-x", safe_ext])

    await ctx.report_progress(0, 100, f"Starting gobuster {mode} on {target}...")

    async with rate_limited("gobuster"):
        start = time.monotonic()
        await audit.log_tool_call("gobuster", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("gobuster", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing gobuster results...")

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("=") and not line.startswith("["):
            findings.append(line)

    await ctx.report_progress(100, 100, "Gobuster complete")
    await audit.log_tool_call(
        "gobuster", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "gobuster",
        "target": target,
        "mode": mode,
        "wordlist": wordlist,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "findings_count": len(findings),
        "findings": findings,
        "raw_output": stdout,
        "errors": stderr if returncode != 0 else None,
    }
