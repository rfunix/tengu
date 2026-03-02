"""smbmap SMB share enumeration tool wrapper."""

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
from tengu.security.sanitizer import sanitize_domain, sanitize_free_text, sanitize_target

logger = structlog.get_logger(__name__)

# smbmap permission tokens recognised in output
_SHARE_PERMISSIONS = frozenset(
    [
        "READ ONLY",
        "READ, WRITE",
        "READ/WRITE",
        "NO ACCESS",
        "WRITE ONLY",
    ]
)


async def smbmap_scan(
    ctx: Context,
    target: str,
    domain: str = "WORKGROUP",
    username: str = "",
    password: str = "",
    hashes: str = "",
    recursive: bool = False,
    share: str = "",
    timeout: int | None = None,
) -> dict:
    """Enumerate SMB shares and permissions using smbmap.

    smbmap lists available SMB shares on a target host with their access
    permissions (READ/WRITE/NO ACCESS) for the provided credentials.
    Optionally performs recursive listing of share contents.

    Args:
        target: Target IP address or hostname.
        domain: Domain name (default "WORKGROUP" for local).
        username: Username for authentication (empty for null session).
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT).
        recursive: Recursively list share contents.
        share: Specific share to list recursively.
        timeout: Override scan timeout in seconds.

    Returns:
        SMB shares with access permissions and optional file listing.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)
    domain = sanitize_domain(domain) if domain else "WORKGROUP"
    safe_username = (
        sanitize_free_text(username, field="username", max_length=256) if username else ""
    )
    safe_password = (
        sanitize_free_text(password, field="password", max_length=512) if password else ""
    )
    safe_hashes = sanitize_free_text(hashes, field="hashes", max_length=128) if hashes else ""
    safe_share = re.sub(r"[^a-zA-Z0-9_$\-]", "", share)[:64] if share else ""

    # Audit params — redact credentials
    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
        "recursive": recursive,
        "share": safe_share,
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("smbmap", target, str(exc))
        raise

    tool_path_str = resolve_tool_path("smbmap")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Build args — list only, never shell=True
    args: list[str] = [
        tool_path_str,
        "-H", target,
        "-d", domain,
        "--no-banner",
    ]
    if safe_username:
        args.extend(["-u", safe_username])
    if safe_hashes:
        # Pass NTLM hash directly — smbmap accepts LM:NT format via -p
        args.extend(["-p", safe_hashes])
    elif safe_password:
        args.extend(["-p", safe_password])
    if recursive and safe_share:
        args.extend(["-r", safe_share, "--depth", "3"])
    elif recursive:
        args.extend(["-R"])

    await ctx.report_progress(0, 100, f"Starting smbmap enumeration on {target}...")

    async with rate_limited("smbmap"):
        start = time.monotonic()
        await audit.log_tool_call("smbmap", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("smbmap", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing smbmap results...")

    parsed = _parse_smbmap_output(stdout)

    await ctx.report_progress(100, 100, "smbmap enumeration complete")
    await audit.log_tool_call(
        "smbmap", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "smbmap",
        "target": target,
        "domain": domain,
        "duration_seconds": round(duration, 2),
        "shares_count": len(parsed["shares"]),
        "shares": parsed["shares"],
        "errors": stderr if returncode != 0 else None,
        "raw_output": stdout,
    }


def _parse_smbmap_output(output: str) -> dict:
    """Parse smbmap output into a list of share entries with permissions."""
    shares: list[dict[str, str]] = []

    for line in output.splitlines():
        line = line.strip()
        # Skip empty lines, smbmap status prefixes, and separator lines
        if not line or line.startswith("[") or line.startswith("=") or line.startswith("-"):
            continue

        # smbmap tabular format uses 2+ spaces as column separator:
        # ADMIN$    NO ACCESS       Remote Admin
        parts = re.split(r"\s{2,}", line)
        if len(parts) >= 2:
            share_name = parts[0].strip()
            permissions = parts[1].strip() if len(parts) > 1 else ""
            comment = parts[2].strip() if len(parts) > 2 else ""

            if share_name and permissions and permissions.upper() in _SHARE_PERMISSIONS:
                shares.append(
                    {
                        "name": share_name,
                        "permissions": permissions,
                        "comment": comment,
                    }
                )

    return {"shares": shares}
