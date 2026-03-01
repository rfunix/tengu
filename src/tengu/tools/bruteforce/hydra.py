"""Hydra network service brute force tool wrapper.

IMPORTANT: This is a destructive tool. Requires explicit authorization.
Account lockouts, IDS alerts, and network disruption may result.
"""

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
from tengu.security.sanitizer import sanitize_target, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

_SUPPORTED_SERVICES = {
    "ssh",
    "ftp",
    "http-get",
    "http-post-form",
    "https-get",
    "https-post-form",
    "smb",
    "rdp",
    "telnet",
    "mysql",
    "mssql",
    "postgresql",
    "smtp",
    "pop3",
    "imap",
    "ldap",
    "vnc",
    "snmp",
    "redis",
    "mongodb",
}


async def hydra_attack(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    service: str,
    userlist: str,
    passlist: str,
    port: int | None = None,
    threads: int = 16,
    stop_on_success: bool = True,
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Perform a credential brute force attack using Hydra.

    WARNING: This is a destructive operation that may trigger account lockouts,
    IDS/IPS alerts, and log entries on the target system. Only use with
    explicit written authorization from the target system owner.

    Args:
        target: Target IP or hostname.
        service: Service protocol to attack (e.g. "ssh", "ftp", "http-post-form").
        userlist: Path to username list file.
        passlist: Path to password list file.
        port: Override default port for the service.
        threads: Number of parallel attack threads (default: 16, max: 64).
        stop_on_success: Stop after finding the first valid credential pair.
        timeout: Override scan timeout in seconds.

    Returns:
        List of discovered valid credentials.

    Note:
        - Requires explicit human authorization before execution.
        - Consider rate limiting to avoid lockouts.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "service": service, "threads": threads}

    target = sanitize_target(target)
    service = service.lower().strip()

    if service not in _SUPPORTED_SERVICES:
        return {
            "tool": "hydra",
            "error": f"Unsupported service '{service}'. Supported: {', '.join(sorted(_SUPPORTED_SERVICES))}",
        }

    userlist = sanitize_wordlist_path(userlist)
    passlist = sanitize_wordlist_path(passlist)
    threads = max(1, min(threads, 64))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("hydra", target, str(exc))
        raise

    tool_path = resolve_tool_path("hydra", cfg.tools.paths.hydra)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        target,
        service,
        "-L",
        userlist,
        "-P",
        passlist,
        "-t",
        str(threads),
    ]

    if stop_on_success:
        args.append("-f")

    if port and 1 <= port <= 65535:
        args.extend(["-s", str(port)])

    # Output format for easier parsing
    args.extend(["-o", "/dev/stdout"])

    await ctx.report_progress(0, 100, f"Starting Hydra attack on {target} ({service})...")

    async with rate_limited("hydra"):
        start = time.monotonic()
        await audit.log_tool_call("hydra", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("hydra", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    credentials = _parse_hydra_output(stdout)

    await ctx.report_progress(100, 100, "Brute force attack complete")
    await audit.log_tool_call(
        "hydra", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "hydra",
        "target": target,
        "service": service,
        "duration_seconds": round(duration, 2),
        "valid_credentials_found": len(credentials),
        "credentials": credentials,
        "raw_output_excerpt": stdout[-2000:],
    }


def _parse_hydra_output(output: str) -> list[dict]:  # type: ignore[type-arg]
    """Parse Hydra output for valid credentials."""
    credentials = []

    for line in output.splitlines():
        # Pattern: [service][host:port] login: USER password: PASS
        m = re.search(
            r"\[.+?\]\s+login:\s+(\S+)\s+password:\s+(\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            credentials.append(
                {
                    "username": m.group(1),
                    "password": m.group(2),
                    "raw_line": line.strip(),
                }
            )

    return credentials
