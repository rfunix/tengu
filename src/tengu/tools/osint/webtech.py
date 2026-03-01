"""WhatWeb web technology fingerprinting tool wrapper."""

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
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def whatweb_scan(
    ctx: Context,
    target: str,
    aggression: int = 1,
    timeout: int | None = None,
) -> dict:
    """Detect web technologies, CMS, frameworks, and WAF using WhatWeb.

    Args:
        target: Target URL to fingerprint (e.g. https://example.com).
        aggression: Aggression level 1-4 (1=passive/stealthy, 3=aggressive, 4=heavy).
        timeout: Override default timeout in seconds.

    Returns:
        Detected technologies, plugins, versions, and confidence levels.

    Note:
        - Aggression level 1 sends a single request (safe for production).
        - Aggression 3+ sends many requests and may trigger WAF/IDS alerts.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "aggression": aggression}

    target = sanitize_url(target)
    aggression = max(1, min(aggression, 4))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("whatweb", target, str(exc))
        raise

    tool_path = resolve_tool_path("whatweb")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        f"--aggression={aggression}",
        "--log-json=-",
        "--no-errors",
        target,
    ]

    await ctx.report_progress(0, 100, f"Starting WhatWeb fingerprinting on {target}...")

    async with rate_limited("whatweb"):
        start = time.monotonic()
        await audit.log_tool_call("whatweb", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("whatweb", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing WhatWeb results...")

    plugins = []
    detected_url = target
    http_status = None

    try:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            if isinstance(data, list) and data:
                entry = data[0]
                detected_url = entry.get("target", target)
                http_status = entry.get("http_status")
                plugin_data = entry.get("plugins", {})
                for plugin_name, plugin_info in plugin_data.items():
                    versions = plugin_info.get("version", [])
                    string = plugin_info.get("string", [])
                    plugins.append(
                        {
                            "name": plugin_name,
                            "version": versions[0] if versions else None,
                            "detail": string[0] if string else None,
                        }
                    )
    except (json.JSONDecodeError, KeyError, IndexError):
        # Fallback: parse plain text output
        for line in stdout.splitlines():
            if "[" in line and "]" in line:
                plugins.append({"name": line.strip(), "version": None, "detail": None})

    await ctx.report_progress(100, 100, "WhatWeb complete")
    await audit.log_tool_call(
        "whatweb", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "whatweb",
        "target": detected_url,
        "http_status": http_status,
        "aggression": aggression,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "plugins_found": len(plugins),
        "technologies": plugins,
        "raw_output": stdout,
    }
