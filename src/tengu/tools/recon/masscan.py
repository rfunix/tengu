"""Masscan high-speed port scanner tool wrapper."""

from __future__ import annotations

import json
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
from tengu.security.sanitizer import sanitize_port_spec, sanitize_target

logger = structlog.get_logger(__name__)


async def masscan_scan(
    ctx: Context,
    target: str,
    ports: str = "1-1024",
    rate: int = 1000,
    timeout: int | None = None,
) -> dict:
    """Scan a network range for open ports at high speed using Masscan.

    Masscan is significantly faster than Nmap for large networks but produces
    less detailed results (no service detection). Ideal for initial port
    discovery across large IP ranges.

    Args:
        target: IP address, hostname, or CIDR range (e.g. "192.168.1.0/24").
        ports: Port specification (e.g. "80", "22-443", "22,80,443").
        rate: Packets per second. Keep low (< 10000) for stealth.
              Warning: High rates may trigger IDS/IPS alerts or crash routers.
        timeout: Override default scan timeout in seconds.

    Returns:
        Structured results with discovered open ports per host.

    Note:
        - Masscan requires root/sudo privileges to send raw packets.
        - Use lower rates (100-1000) for stability and stealth.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "ports": ports, "rate": rate}

    # Input validation
    target = sanitize_target(target)
    ports = sanitize_port_spec(ports)

    # Clamp rate to safe limits
    rate = max(1, min(rate, 100_000))

    # Target allowlist
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("masscan", target, str(exc))
        raise

    tool_path = resolve_tool_path("masscan", cfg.tools.paths.masscan)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        target,
        "-p",
        ports,
        "--rate",
        str(rate),
        "--output-format",
        "json",
        "--output-filename",
        "-",  # stdout
        "--wait",
        "3",  # wait 3s after last packet
    ]

    await ctx.report_progress(0, 100, f"Starting masscan on {target} at {rate} pps...")

    async with rate_limited("masscan"):
        start = time.monotonic()
        await audit.log_tool_call("masscan", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("masscan", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing masscan results...")

    results = _parse_masscan_json(stdout)

    await ctx.report_progress(100, 100, "Scan complete")
    await audit.log_tool_call(
        "masscan", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "masscan",
        "target": target,
        "command": " ".join(args),
        "rate_pps": rate,
        "duration_seconds": round(duration, 2),
        "open_ports_count": len(results),
        "results": results,
    }


def _parse_masscan_json(output: str) -> list[dict[str, object]]:
    """Parse masscan JSON output."""
    results: list[dict[str, object]] = []
    output = output.strip()

    if not output:
        return results

    # Masscan JSON sometimes has trailing commas — fix it
    if output.startswith("[") and not output.endswith("]"):
        output = output.rstrip(",\n ") + "\n]"

    try:
        data = json.loads(output)
        for entry in data:
            ip = entry.get("ip", "")
            for port_info in entry.get("ports", []):
                results.append(
                    {
                        "ip": ip,
                        "port": port_info.get("port"),
                        "protocol": port_info.get("proto", "tcp"),
                        "status": port_info.get("status", "open"),
                    }
                )
    except json.JSONDecodeError:
        # Fall back to line-by-line parsing
        for line in output.splitlines():
            m = re.match(r"Discovered open port (\d+)/(\w+) on (.+)", line)
            if m:
                results.append(
                    {
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "ip": m.group(3).strip(),
                        "status": "open",
                    }
                )

    return results
