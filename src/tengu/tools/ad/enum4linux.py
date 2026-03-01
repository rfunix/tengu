"""Enum4linux-ng Active Directory / SMB enumeration tool wrapper."""

from __future__ import annotations

import json
import shutil
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_free_text, sanitize_target

logger = structlog.get_logger(__name__)


async def enum4linux_scan(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    username: str = "",
    password: str = "",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Enumerate SMB/NetBIOS information using enum4linux-ng.

    Args:
        target: Target IP or hostname running SMB (port 139/445).
        username: Optional username for authenticated enumeration.
        password: Optional password (will be redacted in logs).
        timeout: Override default timeout.

    Returns:
        Users, groups, shares, and password policy from the target.

    Note:
        - Requires SMB access (port 139 or 445).
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)

    # Sanitize credentials — redact password from audit logs
    safe_username = (
        sanitize_free_text(username, field="username", max_length=256) if username else ""
    )
    safe_password = (
        sanitize_free_text(password, field="password", max_length=256) if password else ""
    )

    # Audit params with redacted password
    params: dict[str, object] = {
        "target": target,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("enum4linux", target, str(exc))
        raise

    # Prefer enum4linux-ng, fall back to enum4linux
    tool_path: str
    tool_name: str
    if shutil.which("enum4linux-ng"):
        tool_name = "enum4linux-ng"
        tool_path = resolve_tool_path("enum4linux-ng")
    else:
        tool_name = "enum4linux"
        tool_path = resolve_tool_path("enum4linux")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [tool_path, "-A", "-oJ", "/dev/stdout", target]

    if safe_username:
        args.extend(["-u", safe_username, "-p", safe_password])

    await ctx.report_progress(0, 100, f"Starting {tool_name} enumeration on {target}...")

    async with rate_limited("enum4linux-ng"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing enum4linux results...")

    parsed = _parse_enum4linux_output(stdout)

    await ctx.report_progress(100, 100, "Enum4linux enumeration complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "authenticated": bool(safe_username),
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "users": parsed.get("users", []),
        "groups": parsed.get("groups", []),
        "shares": parsed.get("shares", []),
        "password_policy": parsed.get("password_policy", {}),
        "os_info": parsed.get("os_info", {}),
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_enum4linux_output(output: str) -> dict:  # type: ignore[type-arg]
    """Parse enum4linux-ng JSON output into structured data."""
    result: dict[str, object] = {
        "users": [],
        "groups": [],
        "shares": [],
        "password_policy": {},
        "os_info": {},
    }

    if not output.strip():
        return result

    # Try JSON first (enum4linux-ng -oJ outputs JSON)
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        # Fall back to text parsing for classic enum4linux
        return _parse_enum4linux_text(output)

    # enum4linux-ng JSON structure
    users: list[dict] = []  # type: ignore[type-arg]
    groups: list[dict] = []  # type: ignore[type-arg]
    shares: list[dict] = []  # type: ignore[type-arg]
    password_policy: dict[str, object] = {}
    os_info: dict[str, object] = {}

    # Users
    users_data = data.get("users", {})
    if isinstance(users_data, dict):
        for uid, user_info in users_data.items():
            if isinstance(user_info, dict):
                users.append(
                    {
                        "rid": uid,
                        "username": user_info.get("username", ""),
                        "full_name": user_info.get("fullname", ""),
                        "description": user_info.get("description", ""),
                        "flags": user_info.get("acb_text", ""),
                    }
                )
    elif isinstance(users_data, list):
        for user_info in users_data:
            if isinstance(user_info, dict):
                users.append(
                    {
                        "username": user_info.get("username", user_info.get("name", "")),
                        "rid": user_info.get("rid", ""),
                        "description": user_info.get("description", ""),
                    }
                )

    # Groups
    groups_data = data.get("groups", {})
    if isinstance(groups_data, dict):
        for gid, group_info in groups_data.items():
            if isinstance(group_info, dict):
                groups.append(
                    {
                        "rid": gid,
                        "name": group_info.get("groupname", group_info.get("name", "")),
                        "members": group_info.get("members", []),
                    }
                )

    # Shares
    shares_data = data.get("shares", {})
    if isinstance(shares_data, dict):
        for share_name, share_info in shares_data.items():
            entry: dict[str, object] = {"name": share_name}
            if isinstance(share_info, dict):
                entry["type"] = share_info.get("type", "")
                entry["comment"] = share_info.get("comment", "")
                entry["access"] = share_info.get("access", "")
            shares.append(entry)

    # Password policy
    pol_data = data.get("password_policy", {})
    if isinstance(pol_data, dict):
        password_policy = {
            "min_length": pol_data.get("min_password_length", pol_data.get("MinPasswordLength")),
            "lockout_threshold": pol_data.get(
                "account_lockout_threshold", pol_data.get("LockoutThreshold")
            ),
            "lockout_duration": pol_data.get(
                "account_lockout_duration", pol_data.get("LockoutDuration")
            ),
            "password_history": pol_data.get(
                "password_history_length", pol_data.get("PasswordHistoryLength")
            ),
            "complexity": pol_data.get("password_properties", pol_data.get("PasswordComplexity")),
        }

    # OS info
    os_data = data.get("smb_info", data.get("os_info", {}))
    if isinstance(os_data, dict):
        os_info = {
            "os": os_data.get("os", os_data.get("Operating System", "")),
            "build": os_data.get("build", os_data.get("OS Build", "")),
            "domain": os_data.get("workgroup", os_data.get("Domain", "")),
            "smb_signing": os_data.get("smb_signing", ""),
        }

    result["users"] = users
    result["groups"] = groups
    result["shares"] = shares
    result["password_policy"] = password_policy
    result["os_info"] = os_info
    return result


def _parse_enum4linux_text(output: str) -> dict:  # type: ignore[type-arg]
    """Fall-back parser for classic enum4linux text output."""
    import re

    users: list[dict] = []  # type: ignore[type-arg]
    shares: list[dict] = []  # type: ignore[type-arg]
    groups: list[dict] = []  # type: ignore[type-arg]

    for line in output.splitlines():
        # Users: user:[name] rid:[RID]
        m = re.search(r"user:\[(.+?)\]\s+rid:\[(.+?)\]", line, re.IGNORECASE)
        if m:
            users.append({"username": m.group(1), "rid": m.group(2)})

        # Shares: Sharename   Type    Comment
        m = re.match(r"\s{4}(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line, re.IGNORECASE)
        if m:
            shares.append({"name": m.group(1), "type": m.group(2), "comment": m.group(3).strip()})

        # Groups: group:[name] rid:[RID]
        m = re.search(r"group:\[(.+?)\]\s+rid:\[(.+?)\]", line, re.IGNORECASE)
        if m:
            groups.append({"name": m.group(1), "rid": m.group(2)})

    return {
        "users": users,
        "groups": groups,
        "shares": shares,
        "password_policy": {},
        "os_info": {},
    }
