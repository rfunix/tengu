"""CeWL custom wordlist generator from web page content."""

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


async def cewl_generate(
    ctx: Context,
    url: str,
    depth: int = 2,
    min_word_length: int = 6,
    include_emails: bool = False,
    output_file: str = "/tmp/cewl_wordlist.txt",
    timeout: int | None = None,
) -> dict:
    """Generate a custom wordlist by crawling a website with CeWL.

    CeWL spiders a target website and collects unique words from the content,
    creating organization-specific wordlists for password attacks.

    Args:
        url: Target URL to crawl.
        depth: Spider depth (default 2, max 5).
        min_word_length: Minimum word length to include (default 6).
        include_emails: Also extract email addresses from the site.
        output_file: Path to save the generated wordlist.
        timeout: Override default timeout in seconds.

    Returns:
        Path to generated wordlist, word count, and sample words.

    Note:
        - Be cautious with depth — higher values generate more traffic.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"url": url, "depth": depth, "min_word_length": min_word_length}

    url = sanitize_url(url)
    depth = max(1, min(depth, 5))
    min_word_length = max(3, min(min_word_length, 20))

    safe_output = re.sub(r"[^a-zA-Z0-9/_\-.]", "", output_file)
    if not safe_output.startswith("/tmp/"):
        safe_output = "/tmp/cewl_wordlist.txt"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("cewl", url, str(exc))
        raise

    tool_path = resolve_tool_path("cewl")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-d",
        str(depth),
        "-m",
        str(min_word_length),
        "-w",
        safe_output,
        url,
    ]

    if include_emails:
        args.append("--email")

    await ctx.report_progress(0, 100, f"Starting CeWL crawl on {url}...")

    async with rate_limited("cewl"):
        start = time.monotonic()
        await audit.log_tool_call("cewl", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("cewl", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Reading generated wordlist...")

    words: list[str] = []
    try:
        words = [w.strip() for w in Path(safe_output).read_text().splitlines() if w.strip()]
    except Exception:
        words = [line for line in stdout.splitlines() if line.strip()]

    await ctx.report_progress(100, 100, "CeWL complete")
    await audit.log_tool_call("cewl", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "cewl",
        "url": url,
        "depth": depth,
        "min_word_length": min_word_length,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "words_generated": len(words),
        "wordlist_path": safe_output,
        "sample_words": words[:20],
    }
