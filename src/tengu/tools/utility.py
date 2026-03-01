"""Utility MCP tools: check_tools and validate_target."""

from __future__ import annotations

from fastmcp import Context

from tengu.executor.registry import check_all
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.sanitizer import sanitize_target
from tengu.types import ToolsCheckResult


async def check_tools(ctx: Context) -> dict:  # type: ignore[type-arg]
    """Check which external pentesting tools are installed and available.

    Returns a catalog of all supported tools with their installation status,
    paths, and versions. Useful for diagnosing missing dependencies before
    starting a pentest engagement.
    """
    await ctx.report_progress(0, 1, "Scanning system for installed tools...")
    result: ToolsCheckResult = await check_all(verbose=False)
    await ctx.report_progress(1, 1, "Done")

    return {
        "summary": {
            "total": result.total,
            "available": result.available,
            "missing": result.missing,
        },
        "tools": [
            {
                "name": t.name,
                "category": t.category,
                "available": t.available,
                "path": t.path,
                "version": t.version,
            }
            for t in result.tools
        ],
        "missing_tools": [t.name for t in result.tools if not t.available],
        "install_hint": (
            "Run 'make install-tools' or './scripts/install-tools.sh --all' "
            "to install missing tools."
        )
        if result.missing > 0
        else None,
    }


async def validate_target(ctx: Context, target: str) -> dict:  # type: ignore[type-arg]
    """Validate whether a target is allowed for scanning.

    Checks the target against:
    1. Input validation (IP, hostname, CIDR, URL format)
    2. The configured allowlist (tengu.toml [targets].allowed_hosts)
    3. The blocklist (tengu.toml [targets].blocked_hosts + built-in defaults)

    Returns validation status and any restrictions that apply.
    """
    result: dict[str, object] = {"target": target, "valid": False, "allowed": False, "reason": ""}

    # Step 1: Sanitize input format
    try:
        sanitized = sanitize_target(target)
        result["sanitized"] = sanitized
        result["valid"] = True
    except Exception as exc:
        result["reason"] = str(exc)
        return result

    # Step 2: Check allowlist
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(sanitized)
        result["allowed"] = True
        result["reason"] = "Target is allowed and ready for scanning."
    except Exception as exc:
        result["allowed"] = False
        result["reason"] = str(exc)

    return result
