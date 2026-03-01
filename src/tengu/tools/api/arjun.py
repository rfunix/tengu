"""Arjun HTTP parameter discovery tool wrapper."""

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
from tengu.security.sanitizer import sanitize_url, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

_VALID_METHODS = {"GET", "POST", "JSON", "XML"}


async def arjun_discover(
    ctx: Context,
    url: str,
    method: str = "GET",
    wordlist: str = "",
    timeout: int | None = None,
) -> dict:
    """Discover hidden HTTP parameters in web endpoints using Arjun.

    Args:
        url: Target URL to test for hidden parameters.
        method: HTTP method to use — GET, POST, JSON, XML.
        wordlist: Path to a custom parameter wordlist file (optional).
        timeout: Override default timeout.

    Returns:
        List of discovered parameters, the method used, and the tested URL.

    Note:
        - Target URL must be in tengu.toml [targets].allowed_hosts.
        - Arjun sends many requests — use with care on rate-limited endpoints.
        - JSON and XML modes test parameters in the request body.
    """
    cfg = get_config()
    audit = get_audit_logger()

    # Sanitize inputs
    url = sanitize_url(url)
    method = method.strip().upper()
    if method not in _VALID_METHODS:
        method = "GET"

    params: dict[str, object] = {"url": url, "method": method, "wordlist": wordlist}

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("arjun", url, str(exc))
        raise

    # Sanitize optional wordlist path
    safe_wordlist = ""
    if wordlist:
        safe_wordlist = sanitize_wordlist_path(wordlist)

    tool_path = resolve_tool_path("arjun")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [
        tool_path,
        "-u",
        url,
        "-m",
        method,
        "--stable",
        "-oJ",
        "/dev/stdout",
    ]

    if safe_wordlist:
        args.extend(["-w", safe_wordlist])

    await ctx.report_progress(0, 100, f"Starting Arjun parameter discovery on {url} [{method}]...")

    async with rate_limited("arjun"):
        start = time.monotonic()
        await audit.log_tool_call("arjun", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("arjun", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Arjun results...")

    discovered_params = _parse_arjun_output(stdout)

    await ctx.report_progress(100, 100, "Arjun parameter discovery complete")
    await audit.log_tool_call("arjun", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "arjun",
        "url": url,
        "method": method,
        "wordlist": safe_wordlist or "arjun-default",
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "parameters_found": len(discovered_params),
        "parameters": discovered_params,
        "raw_output_excerpt": stdout[-2000:] if len(stdout) > 2000 else stdout,
    }


def _parse_arjun_output(output: str) -> list[str]:
    """Parse Arjun JSON output to extract discovered parameters."""
    parameters: list[str] = []

    if not output.strip():
        return parameters

    # Arjun outputs JSON — may be a dict with an "arjun" key or nested structure
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        # Fall back to line-by-line search for parameter names
        import re

        for line in output.splitlines():
            m = re.search(r'"([a-zA-Z0-9_\-]+)"\s*:', line)
            if m:
                param = m.group(1)
                if param not in ("arjun", "url", "method") and param not in parameters:
                    parameters.append(param)
        return parameters

    # Handle various Arjun output formats
    if isinstance(data, dict):
        # Format: {"arjun": ["param1", "param2"]}
        if "arjun" in data and isinstance(data["arjun"], list):
            parameters = [str(p) for p in data["arjun"]]
        # Format: {"url": {..., "params": [...]}}
        else:
            for _key, val in data.items():
                if isinstance(val, dict):
                    params = val.get("params", val.get("parameters", []))
                    if isinstance(params, list):
                        parameters.extend(str(p) for p in params)
                elif isinstance(val, list):
                    parameters.extend(str(p) for p in val)
    elif isinstance(data, list):
        parameters = [str(p) for p in data]

    return list(dict.fromkeys(parameters))  # deduplicate preserving order
