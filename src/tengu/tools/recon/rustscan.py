"""RustScan ultra-fast port scanner tool wrapper."""

from __future__ import annotations

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


def _parse_rustscan_output(output: str) -> dict:
    """Parse RustScan output to extract open port numbers."""
    open_ports: list[int] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Open ") and ":" in line:
            try:
                port = int(line.split(":")[-1])
                if port not in open_ports:
                    open_ports.append(port)
            except ValueError:
                pass
        elif "/tcp" in line.lower() and "open" in line.lower():
            try:
                port = int(line.split("/")[0])
                if port not in open_ports:
                    open_ports.append(port)
            except ValueError:
                pass
    return {"open_ports": sorted(open_ports)}


async def rustscan_scan(
    ctx: Context,
    target: str,
    ports: str = "1-65535",
    batch_size: int = 1500,
    timeout: int | None = None,
) -> dict:
    """Perform ultra-fast port scanning using RustScan.

    RustScan can scan all 65535 ports in seconds by using async I/O,
    then passes discovered open ports to Nmap for service detection.

    Args:
        target: Target IP address or hostname.
        ports: Port specification (e.g. "80,443" or "1-65535").
        batch_size: Number of ports to scan per batch (default 1500, max 65535).
        timeout: Override scan timeout in seconds.

    Returns:
        Discovered open ports and basic service information.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - High batch_size values may trigger IDS/IPS alerts.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)
    safe_ports = sanitize_port_spec(ports)
    batch_size = max(100, min(batch_size, 65535))

    params: dict[str, object] = {
        "target": target,
        "ports": safe_ports,
        "batch_size": batch_size,
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("rustscan", target, str(exc))
        raise

    tool_path = resolve_tool_path("rustscan")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-a", target,
        "-p", safe_ports,
        "-b", str(batch_size),
        "--accessible",
        "--no-config",
    ]

    await ctx.report_progress(0, 100, f"Starting rustscan on {target}...")

    async with rate_limited("rustscan"):
        start = time.monotonic()
        await audit.log_tool_call("rustscan", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("rustscan", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing rustscan results...")
    parsed = _parse_rustscan_output(stdout)

    await ctx.report_progress(100, 100, "rustscan complete")
    await audit.log_tool_call(
        "rustscan", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "rustscan",
        "target": target,
        "ports": safe_ports,
        "batch_size": batch_size,
        "duration_seconds": round(duration, 2),
        "open_ports_count": len(parsed["open_ports"]),
        "open_ports": parsed["open_ports"],
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }
