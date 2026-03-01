"""Nmap port scanner tool wrapper."""

import re
import time
import xml.etree.ElementTree as ET
from typing import Literal

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_port_spec, sanitize_target
from tengu.types import Host, Port, ScanResult

logger = structlog.get_logger(__name__)

ScanType = Literal["syn", "connect", "udp", "version", "ping", "fast"]

_SCAN_TYPE_FLAGS: dict[ScanType, list[str]] = {
    "syn": ["-sS"],
    "connect": ["-sT"],
    "udp": ["-sU"],
    "version": ["-sV", "-sS"],
    "ping": ["-sn"],
    "fast": ["-F"],
}

_TIMING_FLAGS = {"T0", "T1", "T2", "T3", "T4", "T5"}


async def nmap_scan(
    ctx: Context,
    target: str,
    ports: str = "1-1024",
    scan_type: Literal["syn", "connect", "udp", "version", "ping", "fast"] = "connect",
    timing: str = "T3",
    os_detection: bool = False,
    scripts: str = "",
    timeout: int | None = None,
) -> dict:
    """Scan a target for open ports, services, and versions using Nmap.

    Args:
        target: IP address, hostname, CIDR range, or URL to scan.
        ports: Port specification (e.g. "80", "22-443", "22,80,443", "1-65535").
        scan_type: Scan technique — syn (stealthy), connect (no root), udp,
                   version (service detection), ping (host discovery), fast (top 100).
        timing: Nmap timing template T0 (paranoid) to T5 (insane). Default: T3.
        os_detection: Enable OS fingerprinting (-O). Requires root/sudo.
        scripts: Comma-separated nmap script names (e.g. "http-title,ssl-cert").
        timeout: Override default scan timeout in seconds.

    Returns:
        Structured scan results with hosts, ports, services, and raw nmap output.

    Note:
        - SYN scan (-sS) requires root/sudo privileges.
        - OS detection (-O) requires root/sudo privileges.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "ports": ports, "scan_type": scan_type, "timing": timing}

    # Input validation
    target = sanitize_target(target)
    ports = sanitize_port_spec(ports)

    if timing not in _TIMING_FLAGS:
        timing = "T3"

    # Target allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nmap", target, str(exc))
        raise

    tool_path = resolve_tool_path("nmap", cfg.tools.paths.nmap)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Build argument list (never shell=True)
    args: list[str] = [tool_path]
    args.extend(_SCAN_TYPE_FLAGS.get(scan_type, ["-sT"]))
    args.extend([f"-{timing}", "-p", ports])
    args.extend(["-oX", "-"])  # XML output to stdout

    if os_detection:
        args.append("-O")

    if scripts:
        # Sanitize script names — only alphanumeric, hyphens, commas
        safe_scripts = re.sub(r"[^a-zA-Z0-9\-,_]", "", scripts)
        if safe_scripts:
            args.extend(["--script", safe_scripts])

    args.append(target)

    # Stealth: inject --proxies flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("nmap", args)

    await ctx.report_progress(0, 100, f"Starting nmap scan on {target}...")

    async with rate_limited("nmap"):
        start = time.monotonic()
        await audit.log_tool_call("nmap", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(
                args,
                timeout=effective_timeout,
            )
        except Exception as exc:
            await audit.log_tool_call("nmap", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing nmap results...")

    hosts = _parse_nmap_xml(stdout)

    scan_result = ScanResult(
        tool="nmap",
        target=target,
        command=args,
        hosts=hosts,
        raw_output=stdout,
        duration_seconds=round(duration, 2),
        error=stderr if returncode != 0 else None,
    )

    await ctx.report_progress(100, 100, "Scan complete")
    await audit.log_tool_call("nmap", target, params, result="completed", duration_seconds=duration)

    return {
        "tool": "nmap",
        "target": target,
        "command": " ".join(args),
        "duration_seconds": scan_result.duration_seconds,
        "hosts_found": len(hosts),
        "hosts": [h.model_dump() for h in hosts],
        "open_ports_summary": _summarize_ports(hosts),
        "raw_output": stdout,
    }


def _parse_nmap_xml(xml_output: str) -> list[Host]:
    """Parse nmap XML output into Host objects."""
    hosts: list[Host] = []

    if not xml_output.strip():
        return hosts

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output")
        return hosts

    for host_elem in root.findall("host"):
        # Get IP address
        address = ""
        hostname = None

        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") in ("ipv4", "ipv6"):
                address = addr_elem.get("addr", "")

        # Get hostname
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                hostname = hn.get("name")
                break

        if not address:
            continue

        # Parse ports
        ports: list[Port] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                portid = int(port_elem.get("portid", "0"))
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = None
                version = None
                if service_elem is not None:
                    service = service_elem.get("name")
                    product = service_elem.get("product", "")
                    ver = service_elem.get("version", "")
                    if product or ver:
                        version = f"{product} {ver}".strip()

                if state == "open":
                    ports.append(
                        Port(
                            number=portid,
                            protocol=protocol,
                            state=state,
                            service=service,
                            version=version,
                        )
                    )

        # Get OS detection
        os_name = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")

        # Get host status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        hosts.append(
            Host(
                address=address,
                hostname=hostname,
                os=os_name,
                ports=ports,
                status=status,
            )
        )

    return hosts


def _summarize_ports(hosts: list[Host]) -> list[dict[str, object]]:
    """Create a concise summary of open ports across all hosts."""
    summary = []
    for host in hosts:
        for port in host.ports:
            if port.state == "open":
                summary.append(
                    {
                        "host": host.address,
                        "port": port.number,
                        "protocol": port.protocol,
                        "service": port.service,
                        "version": port.version,
                    }
                )
    return summary
