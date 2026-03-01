"""WPScan WordPress vulnerability scanner wrapper."""

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


async def wpscan_scan(
    ctx: Context,
    url: str,
    enumerate: str = "vp,vt,u",
    api_token: str = "",
    threads: int = 5,
    timeout: int | None = None,
) -> dict:
    """Scan a WordPress site for vulnerabilities, plugins, themes, and users using WPScan.

    Args:
        url: WordPress site URL (e.g. https://example.com).
        enumerate: Enumeration options — vp (vulnerable plugins), vt (vulnerable themes),
                   u (users), ap (all plugins), at (all themes), cb (config backups), dbe (db exports).
        api_token: WPScan API token for vulnerability database lookups (optional but recommended).
        threads: Number of concurrent threads (default 5, max 20).
        timeout: Override default timeout in seconds.

    Returns:
        WordPress version, vulnerable plugins/themes, user enumeration, and security issues.

    Note:
        - Free WPScan API token at https://wpscan.com provides 75 daily requests.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"url": url, "enumerate": enumerate}

    url = sanitize_url(url)
    import re

    safe_enumerate = re.sub(r"[^a-z,]", "", enumerate.lower())
    threads = max(1, min(threads, 20))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("wpscan", url, str(exc))
        raise

    tool_path = resolve_tool_path("wpscan")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "--url",
        url,
        "--enumerate",
        safe_enumerate,
        "--threads",
        str(threads),
        "--format",
        "json",
        "--no-update",
    ]

    if api_token:
        args.extend(["--api-token", api_token])

    await ctx.report_progress(0, 100, f"Starting WPScan on {url}...")

    async with rate_limited("wpscan"):
        start = time.monotonic()
        await audit.log_tool_call("wpscan", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("wpscan", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing WPScan results...")

    wp_version = None
    plugins: list[dict] = []
    themes: list[dict] = []
    users: list[str] = []
    vulnerabilities: list[dict] = []

    try:
        data = json.loads(stdout)

        version_data = data.get("version", {})
        if version_data:
            wp_version = version_data.get("number")

        for slug, plugin_data in data.get("plugins", {}).items():
            p = {"slug": slug, "version": plugin_data.get("version")}
            vulns = plugin_data.get("vulnerabilities", [])
            if vulns:
                p["vulnerabilities"] = vulns
                vulnerabilities.extend(vulns)
            plugins.append(p)

        for slug, theme_data in data.get("themes", {}).items():
            t = {"slug": slug, "version": theme_data.get("version")}
            vulns = theme_data.get("vulnerabilities", [])
            if vulns:
                t["vulnerabilities"] = vulns
                vulnerabilities.extend(vulns)
            themes.append(t)

        for uid, user_data in data.get("users", {}).items():
            users.append(user_data.get("username", uid))

    except (json.JSONDecodeError, KeyError, AttributeError):
        pass

    await ctx.report_progress(100, 100, "WPScan complete")
    await audit.log_tool_call("wpscan", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "wpscan",
        "url": url,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "wordpress_version": wp_version,
        "plugins_found": len(plugins),
        "themes_found": len(themes),
        "users_found": len(users),
        "vulnerabilities_found": len(vulnerabilities),
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "vulnerabilities": vulnerabilities,
        "raw_output": stdout,
    }
