"""FFUF directory/endpoint fuzzer tool wrapper."""

import json
import re
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
from tengu.security.sanitizer import sanitize_url, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

HTTPMethod = Literal["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]


async def ffuf_fuzz(
    ctx: Context,
    url: str,
    wordlist: str | None = None,
    method: Literal["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] = "GET",
    filter_codes: list[int] | None = None,
    match_codes: list[int] | None = None,
    extensions: list[str] | None = None,
    threads: int = 40,
    rate: int = 0,
    headers: dict[str, str] | None = None,
    timeout: int | None = None,
) -> dict:
    """Fuzz directories, files, and endpoints using FFUF.

    Uses a wordlist to discover hidden files, directories, APIs, and endpoints
    that are not linked from the application's public pages.

    The URL must contain the placeholder 'FUZZ' where substitution occurs.
    If 'FUZZ' is not in the URL, it is automatically appended to the path.

    Args:
        url: Target URL with optional FUZZ placeholder
             (e.g. "https://example.com/FUZZ" or "https://example.com/api/FUZZ.php").
        wordlist: Path to wordlist file. Defaults to the configured default.
        method: HTTP method to use.
        filter_codes: HTTP response codes to exclude from results
                      (e.g. [404, 403] to hide not-found and forbidden).
        match_codes: Only show responses with these codes (e.g. [200, 301, 302]).
        extensions: File extensions to append to each word
                    (e.g. [".php", ".html", ".bak"]).
        threads: Number of concurrent threads. Default: 40.
        rate: Requests per second limit (0 = unlimited).
        headers: Additional HTTP headers (e.g. {"Cookie": "session=abc123"}).
        timeout: Override scan timeout in seconds.

    Returns:
        Discovered paths/endpoints with response codes, sizes, and redirect targets.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "method": method, "extensions": extensions}

    url = sanitize_url(url)

    # Auto-add FUZZ marker if missing
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    effective_wordlist = wordlist or cfg.tools.defaults.wordlist_path
    effective_wordlist = sanitize_wordlist_path(effective_wordlist)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("ffuf", url, str(exc))
        raise

    tool_path = resolve_tool_path("ffuf", cfg.tools.paths.ffuf)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        url,
        "-w",
        effective_wordlist,
        "-X",
        method,
        "-json",
        "-t",
        str(max(1, min(threads, 200))),
        "-noninteractive",
    ]

    if rate > 0:
        args.extend(["-rate", str(rate)])

    if filter_codes:
        codes = [str(c) for c in filter_codes if 100 <= c <= 599]
        if codes:
            args.extend(["-fc", ",".join(codes)])

    if match_codes:
        codes = [str(c) for c in match_codes if 100 <= c <= 599]
        if codes:
            args.extend(["-mc", ",".join(codes)])

    if extensions:
        # Sanitize extensions — only alphanumeric and dots
        safe_exts = [
            e if e.startswith(".") else f".{e}"
            for e in extensions
            if re.match(r"^\.?[a-zA-Z0-9]{1,10}$", e)
        ]
        if safe_exts:
            args.extend(["-e", ",".join(safe_exts)])

    if headers:
        for key, value in headers.items():
            # Sanitize header names (no CRLF injection)
            safe_key = re.sub(r"[^\w\-]", "", key)
            safe_value = value.replace("\r", "").replace("\n", "")
            if safe_key:
                args.extend(["-H", f"{safe_key}: {safe_value}"])

    # Stealth: inject -x proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("ffuf", args)

    await ctx.report_progress(0, 100, f"Starting FFUF fuzzing on {url}...")

    async with rate_limited("ffuf"):
        start = time.monotonic()
        await audit.log_tool_call("ffuf", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("ffuf", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing FFUF results...")

    results = _parse_ffuf_output(stdout)

    await ctx.report_progress(100, 100, "Fuzzing complete")
    await audit.log_tool_call("ffuf", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "ffuf",
        "url": url,
        "wordlist": effective_wordlist,
        "method": method,
        "duration_seconds": round(duration, 2),
        "results_count": len(results),
        "results": results,
    }


def _parse_ffuf_output(output: str) -> list[dict]:
    """Parse FFUF JSON output."""
    results = []

    try:
        data = json.loads(output)
        for entry in data.get("results", []):
            results.append(
                {
                    "url": entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "length": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "lines": entry.get("lines", 0),
                    "redirect_location": entry.get("redirectlocation", ""),
                    "input": entry.get("input", {}).get("FUZZ", ""),
                }
            )
    except (json.JSONDecodeError, KeyError):
        pass

    return results
