"""snmpwalk SNMP enumeration tool wrapper."""

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
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)

_VALID_VERSIONS = ("1", "2c", "3")


def _parse_snmpwalk_output(output: str) -> dict:
    """Parse snmpwalk output into OID entries and system information dict."""
    entries = []
    sys_info: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Error"):
            continue
        if "sysDescr" in line or ".1.3.6.1.2.1.1.1" in line:
            sys_info["description"] = line.split("=", 1)[-1].strip()
        elif "sysName" in line or ".1.3.6.1.2.1.1.5" in line:
            sys_info["name"] = line.split("=", 1)[-1].strip()
        elif "sysLocation" in line or ".1.3.6.1.2.1.1.6" in line:
            sys_info["location"] = line.split("=", 1)[-1].strip()
        if "=" in line:
            entries.append(line)
    return {"entries": entries[:200], "sys_info": sys_info}


async def snmpwalk_scan(
    ctx: Context,
    target: str,
    community: str = "public",
    version: str = "2c",
    oid: str = ".",
    timeout: int | None = None,
) -> dict:
    """Enumerate SNMP information from a network device using snmpwalk.

    SNMP (Simple Network Management Protocol) exposes device configuration,
    interface info, routing tables, and system information on routers,
    switches, printers, and other network devices.

    Args:
        target: Target IP address or hostname.
        community: SNMP community string (default "public").
        version: SNMP version — "1", "2c" (default), or "3".
        oid: OID to walk (default "." for entire MIB).
        timeout: Override scan timeout in seconds.

    Returns:
        SNMP walk results with OID-value pairs and system information.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - SNMP version 3 requires additional authentication parameters.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)
    safe_community = re.sub(r"[^a-zA-Z0-9_\-@#!]", "", community)[:64] or "public"
    if version not in _VALID_VERSIONS:
        version = "2c"
    safe_oid = re.sub(r"[^0-9.]", "", oid) or "."

    params: dict[str, object] = {
        "target": target,
        "community": safe_community,
        "version": version,
        "oid": safe_oid,
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("snmpwalk", target, str(exc))
        raise

    tool_path = resolve_tool_path("snmpwalk")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-v", version,
        "-c", safe_community,
        "-O", "n",
        "-r", "1",
        target,
        safe_oid,
    ]

    await ctx.report_progress(0, 100, f"Starting snmpwalk on {target}...")

    async with rate_limited("snmpwalk"):
        start = time.monotonic()
        await audit.log_tool_call("snmpwalk", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("snmpwalk", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing snmpwalk results...")
    parsed = _parse_snmpwalk_output(stdout)

    await ctx.report_progress(100, 100, "snmpwalk complete")
    await audit.log_tool_call(
        "snmpwalk", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "snmpwalk",
        "target": target,
        "community": safe_community,
        "version": version,
        "oid": safe_oid,
        "duration_seconds": round(duration, 2),
        "entries_count": len(parsed["entries"]),
        "entries": parsed["entries"],
        "sys_info": parsed["sys_info"],
        "errors": stderr if returncode != 0 else None,
    }
