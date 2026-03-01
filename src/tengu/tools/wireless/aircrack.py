"""Aircrack-ng wireless network scanner (passive mode only)."""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from pathlib import Path

import structlog
from fastmcp import Context

from tengu.executor.registry import resolve_tool_path
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited

logger = structlog.get_logger(__name__)


async def aircrack_scan(
    ctx: Context,
    interface: str = "wlan0",
    scan_time: int = 30,
    timeout: int | None = None,
) -> dict:
    """Passively scan for wireless networks using aircrack-ng suite.

    Uses airodump-ng to passively capture wireless network information
    without transmitting any packets (monitor mode required).

    Args:
        interface: Wireless interface in monitor mode (e.g. wlan0mon, wlan0).
        scan_time: Duration in seconds to capture (default 30).
        timeout: Override default timeout.

    Returns:
        Discovered access points with BSSID, SSID, channel, encryption, and signal strength.

    WARNING:
        - Requires wireless interface in monitor mode: sudo airmon-ng start wlan0
        - Requires root/sudo privileges.
        - Only use on networks you own or have explicit written authorization to test.
        - This tool captures wireless frames — ensure legal authorization first.
        - Target must be a wireless interface, not a remote host.
    """
    audit = get_audit_logger()
    params = {"interface": interface, "scan_time": scan_time}

    # Sanitize interface name — only alphanumeric, underscore, hyphen
    safe_interface = re.sub(r"[^a-zA-Z0-9_\-]", "", interface)
    if not safe_interface:
        safe_interface = "wlan0"

    scan_time = max(5, min(scan_time, 300))

    await audit.log_tool_call("airodump-ng", safe_interface, params, result="started")

    tool_path = resolve_tool_path("airodump-ng")
    output_prefix = "/tmp/tengu_airodump"

    args = [
        tool_path,
        "--write",
        output_prefix,
        "--write-interval",
        "1",
        "--output-format",
        "csv",
        safe_interface,
    ]

    await ctx.report_progress(
        0, 100, f"Scanning wireless networks on {safe_interface} for {scan_time}s..."
    )

    async with rate_limited("airodump-ng"):
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            await asyncio.sleep(scan_time)
            proc.terminate()
            await proc.communicate()
        except Exception as exc:
            await audit.log_tool_call(
                "airodump-ng", safe_interface, params, result="failed", error=str(exc)
            )
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing scan results...")

    access_points: list[dict] = []

    # Parse CSV output file
    csv_file = Path(f"{output_prefix}-01.csv")
    if csv_file.exists():
        try:
            content = csv_file.read_text()
            lines = content.splitlines()
            in_ap_section = True
            for line in lines:
                if not line.strip():
                    in_ap_section = False
                    continue
                if "Station MAC" in line:
                    break
                if in_ap_section and "BSSID" not in line:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 14:
                        access_points.append(
                            {
                                "bssid": parts[0],
                                "first_seen": parts[1],
                                "channel": parts[3],
                                "speed": parts[4],
                                "privacy": parts[5],
                                "cipher": parts[6],
                                "auth": parts[7],
                                "power": parts[8],
                                "beacons": parts[9],
                                "ssid": parts[13] if len(parts) > 13 else "",
                            }
                        )
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                csv_file.unlink()

    await ctx.report_progress(100, 100, "Wireless scan complete")
    await audit.log_tool_call(
        "airodump-ng", safe_interface, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "airodump-ng",
        "interface": safe_interface,
        "scan_duration_seconds": round(duration, 2),
        "networks_found": len(access_points),
        "access_points": access_points,
        "warning": "Passive capture only. Active testing (deauth, WEP cracking) requires separate authorization.",
    }
