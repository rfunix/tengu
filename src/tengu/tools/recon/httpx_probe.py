"""ProjectDiscovery httpx HTTP probing tool wrapper."""

from __future__ import annotations

import json
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


def _parse_httpx_output(output: str) -> list[dict]:
    """Parse ProjectDiscovery httpx JSON output (one JSON object per line)."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(
                {
                    "url": data.get("url", ""),
                    "status_code": data.get("status-code", data.get("status_code")),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                }
            )
        except (json.JSONDecodeError, KeyError):
            # Plain text line (non-JSON output)
            if line.startswith("http"):
                results.append(
                    {"url": line, "status_code": None, "title": "", "technologies": []}
                )
    return results


async def httpx_probe(
    ctx: Context,
    target: str,
    threads: int = 50,
    detect_tech: bool = True,
    timeout: int | None = None,
) -> dict:
    """Probe HTTP services on a host or URL list using ProjectDiscovery httpx.

    httpx performs fast HTTP probing with optional technology detection,
    status code enumeration, and title extraction. Useful for quickly
    triaging large host lists after subdomain enumeration.

    Args:
        target: Target URL or host to probe (e.g. "https://example.com").
        threads: Number of concurrent threads (default 50, max 200).
        detect_tech: Enable technology detection (default True).
        timeout: Override scan timeout in seconds.

    Returns:
        HTTP probe results with status codes, titles, and detected technologies.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Uses ProjectDiscovery httpx CLI tool (not the Python httpx library).
    """
    cfg = get_config()
    audit = get_audit_logger()

    threads = max(1, min(threads, 200))

    params: dict[str, object] = {
        "target": target,
        "threads": threads,
        "detect_tech": detect_tech,
    }

    target = sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("httpx", target, str(exc))
        raise

    tool_path = resolve_tool_path("httpx")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        target,
        "-status-code",
        "-title",
        "-threads",
        str(threads),
        "-silent",
        "-json",
    ]

    if detect_tech:
        args.append("-tech-detect")

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args.extend(["-http-proxy", stealth.proxy_url])

    await ctx.report_progress(0, 100, f"Starting httpx probe on {target}...")

    async with rate_limited("httpx"):
        start = time.monotonic()
        await audit.log_tool_call("httpx", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("httpx", target, params, result="failed", error=str(exc))
            raise
        duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "httpx probe complete")
    await audit.log_tool_call(
        "httpx", target, params, result="completed", duration_seconds=duration
    )

    results = _parse_httpx_output(stdout)

    return {
        "tool": "httpx",
        "target": target,
        "threads": threads,
        "duration_seconds": round(duration, 2),
        "probes_count": len(results),
        "results": results,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }
