"""NetExec (nxc) / CrackMapExec network enumeration and AD tool wrapper.

IMPORTANT: This tool can perform credential spraying and authenticated enumeration.
Requires explicit written authorization from the target system owner.
"""

from __future__ import annotations

import re
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

_SUPPORTED_PROTOCOLS = {"smb", "ldap", "winrm", "ssh", "rdp", "ftp", "mssql", "wmi"}

# Module names: only alphanumeric, underscore, hyphen
_MODULE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")


async def nxc_enum(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    domain: str = "",
    modules: list[str] | None = None,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Enumerate network services and AD using NetExec (successor to CrackMapExec).

    Args:
        target: Target IP, hostname, or CIDR range.
        protocol: Protocol to use — smb, ldap, winrm, ssh, rdp, ftp, mssql, wmi.
        username: Username for authentication (optional).
        password: Password for authentication (redacted in logs).
        domain: Active Directory domain name.
        modules: List of NetExec modules to run (e.g. ["spider_plus", "enum_av"]).
        timeout: Override default timeout.

    Returns:
        Authentication results, discovered hosts, shares, users, and module output.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)
    protocol = protocol.strip().lower()

    if protocol not in _SUPPORTED_PROTOCOLS:
        return {
            "tool": "nxc",
            "error": f"Unsupported protocol '{protocol}'. Supported: {', '.join(sorted(_SUPPORTED_PROTOCOLS))}",
        }

    safe_username = (
        sanitize_free_text(username, field="username", max_length=256) if username else ""
    )
    safe_password = (
        sanitize_free_text(password, field="password", max_length=256) if password else ""
    )
    safe_domain = sanitize_free_text(domain, field="domain", max_length=256) if domain else ""

    # Sanitize module names
    safe_modules: list[str] = []
    if modules:
        for mod in modules:
            mod = mod.strip()
            if _MODULE_NAME_PATTERN.match(mod):
                safe_modules.append(mod)
            else:
                logger.warning("Skipping invalid module name", module=mod)

    # Audit params — redact password
    params: dict[str, object] = {
        "target": target,
        "protocol": protocol,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "domain": safe_domain,
        "modules": safe_modules,
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nxc", target, str(exc))
        raise

    # Prefer nxc (NetExec), fall back to crackmapexec
    tool_name: str
    tool_path: str
    if shutil.which("nxc"):
        tool_name = "nxc"
        tool_path = resolve_tool_path("nxc")
    else:
        tool_name = "crackmapexec"
        tool_path = resolve_tool_path("crackmapexec")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args: list[str] = [tool_path, protocol, target]

    if safe_username:
        args.extend(["-u", safe_username, "-p", safe_password])

    if safe_domain:
        args.extend(["-d", safe_domain])

    for module in safe_modules:
        args.extend(["-M", module])

    await ctx.report_progress(
        0, 100, f"Starting {tool_name} {protocol.upper()} enumeration on {target}..."
    )

    async with rate_limited("nxc"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, f"Parsing {tool_name} results...")

    parsed = _parse_nxc_output(stdout)

    await ctx.report_progress(100, 100, f"{tool_name} enumeration complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "protocol": protocol,
        "domain": safe_domain,
        "authenticated": bool(safe_username),
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "authentication_status": parsed.get("auth_status", "unknown"),
        "hosts_found": parsed.get("hosts", []),
        "shares": parsed.get("shares", []),
        "users": parsed.get("users", []),
        "success_lines": parsed.get("success_lines", []),
        "info_lines": parsed.get("info_lines", []),
        "module_output": parsed.get("module_output", []),
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_nxc_output(output: str) -> dict:  # type: ignore[type-arg]
    """Parse NetExec/CrackMapExec line-based output into structured data."""
    hosts: list[str] = []
    shares: list[dict] = []  # type: ignore[type-arg]
    users: list[str] = []
    success_lines: list[str] = []
    info_lines: list[str] = []
    module_output: list[str] = []
    auth_status = "unknown"

    for line in output.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Authentication success marker
        if "[+]" in line_stripped:
            success_lines.append(line_stripped)
            if "Pwn3d!" in line_stripped or "pwned" in line_stripped.lower():
                auth_status = "admin_access"
            elif auth_status == "unknown":
                auth_status = "authenticated"

        # Authentication failure marker
        elif "[-]" in line_stripped:
            if auth_status == "unknown":
                auth_status = "authentication_failed"

        # Info marker
        elif "[*]" in line_stripped:
            info_lines.append(line_stripped)

        # Module output
        if "[MODULE]" in line_stripped or line_stripped.startswith("[+]["):
            module_output.append(line_stripped)

        # Host detection — IP with service info
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line_stripped)
        if ip_match:
            ip = ip_match.group(1)
            if ip not in hosts:
                hosts.append(ip)

        # Share enumeration
        share_match = re.search(
            r"SHARE\s+(\S+)\s+(READ|WRITE|NO ACCESS|READ,WRITE)", line_stripped, re.IGNORECASE
        )
        if share_match:
            shares.append(
                {
                    "name": share_match.group(1),
                    "access": share_match.group(2),
                }
            )

        # User enumeration
        user_match = re.search(r"User:\s+(\S+)", line_stripped, re.IGNORECASE)
        if user_match:
            username = user_match.group(1)
            if username not in users:
                users.append(username)

    return {
        "auth_status": auth_status,
        "hosts": hosts,
        "shares": shares,
        "users": users,
        "success_lines": success_lines,
        "info_lines": info_lines,
        "module_output": module_output,
    }
