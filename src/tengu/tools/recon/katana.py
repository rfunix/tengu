"""Katana web crawler tool wrapper."""

from __future__ import annotations

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


def _parse_katana_output(output: str) -> list[str]:
    """Parse katana output, extracting discovered URLs (one per line)."""
    urls = []
    for line in output.splitlines():
        line = line.strip()
        if line and (line.startswith("http://") or line.startswith("https://")):
            urls.append(line)
    return list(set(urls))  # deduplicate


async def katana_crawl(
    ctx: Context,
    target: str,
    depth: int = 3,
    concurrency: int = 10,
    js_crawl: bool = False,
    timeout: int | None = None,
) -> dict:
    """Crawl a web application to discover endpoints and URLs using Katana.

    Katana is a modern, fast web crawler by ProjectDiscovery that supports
    JavaScript rendering, form submission, and scope-aware crawling.

    Args:
        target: Target URL to crawl (e.g. "https://example.com").
        depth: Maximum crawl depth (default 3, max 10).
        concurrency: Number of concurrent requests (default 10, max 50).
        js_crawl: Enable JavaScript crawling for SPA applications.
        timeout: Override scan timeout in seconds.

    Returns:
        Discovered URLs, endpoints, and technology indicators.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()

    depth = max(1, min(depth, 10))
    concurrency = max(1, min(concurrency, 50))

    params: dict[str, object] = {
        "target": target,
        "depth": depth,
        "concurrency": concurrency,
        "js_crawl": js_crawl,
    }

    target = sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("katana", target, str(exc))
        raise

    tool_path = resolve_tool_path("katana")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        target,
        "-d",
        str(depth),
        "-c",
        str(concurrency),
        "-silent",
    ]

    if js_crawl:
        args.append("-jc")

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args.extend(["-proxy", stealth.proxy_url])

    await ctx.report_progress(0, 100, f"Starting katana crawl on {target}...")

    async with rate_limited("katana"):
        start = time.monotonic()
        await audit.log_tool_call("katana", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("katana", target, params, result="failed", error=str(exc))
            raise
        duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "Katana crawl complete")
    await audit.log_tool_call(
        "katana", target, params, result="completed", duration_seconds=duration
    )

    urls = _parse_katana_output(stdout)

    return {
        "tool": "katana",
        "target": target,
        "depth": depth,
        "concurrency": concurrency,
        "js_crawl": js_crawl,
        "duration_seconds": round(duration, 2),
        "urls_found": len(urls),
        "urls": urls,
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }
