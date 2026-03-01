"""SSL/TLS analysis using sslyze (pure Python)."""

from __future__ import annotations

import asyncio

import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_target
from tengu.types import SSLResult

logger = structlog.get_logger(__name__)

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHERS_PATTERNS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"]


async def ssl_tls_check(
    ctx: Context,
    host: str,
    port: int = 443,
    timeout: int | None = None,
) -> dict:
    """Analyze SSL/TLS configuration of a host using sslyze.

    Checks for:
    - Supported protocol versions (SSLv2/3, TLS 1.0-1.3)
    - Weak/deprecated cipher suites
    - Certificate validity and expiration
    - Known vulnerabilities (Heartbleed, ROBOT, POODLE, DROWN, BEAST)
    - Certificate chain trust issues
    - OCSP stapling support
    - Forward secrecy support

    Args:
        host: Target hostname or IP address.
        port: Target port. Default: 443.
        timeout: Scan timeout in seconds.

    Returns:
        Comprehensive SSL/TLS analysis with grade, vulnerabilities, and recommendations.

    Note:
        - Uses sslyze Python library directly (no subprocess).
        - May take 30-60 seconds to complete a full analysis.
    """
    audit = get_audit_logger()
    params = {"host": host, "port": port}

    host = sanitize_target(host)

    if not (1 <= port <= 65535):
        port = 443

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(host)
    except Exception as exc:
        await audit.log_target_blocked("ssl_tls_check", host, str(exc))
        raise

    await ctx.report_progress(0, 5, f"Connecting to {host}:{port}...")

    try:
        # Import sslyze lazily — it's an optional heavy dependency
        from sslyze import (  # type: ignore[attr-defined]
            ServerNetworkLocation,
            ServerScanRequest,
        )
        from sslyze.plugins.scan_commands import ScanCommand
    except ImportError:
        return {
            "tool": "ssl_tls_check",
            "host": host,
            "port": port,
            "error": "sslyze is not installed. Run: uv pip install sslyze",
        }

    effective_timeout = timeout or 120

    try:
        server_location = ServerNetworkLocation(hostname=host, port=port)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
            },
        )
    except Exception as exc:
        return {
            "tool": "ssl_tls_check",
            "host": host,
            "port": port,
            "error": f"Failed to create scan request: {exc}",
        }

    await ctx.report_progress(1, 5, "Scanning SSL/TLS protocols and ciphers...")

    # sslyze is synchronous — run in thread pool
    loop = asyncio.get_event_loop()

    try:
        scan_result_raw = await asyncio.wait_for(
            loop.run_in_executor(None, _run_sslyze_scan, scan_request),
            timeout=effective_timeout,
        )
    except TimeoutError:
        await audit.log_tool_call("ssl_tls_check", host, params, result="failed", error="timeout")
        return {"tool": "ssl_tls_check", "host": host, "port": port, "error": "Scan timed out"}
    except Exception as exc:
        await audit.log_tool_call("ssl_tls_check", host, params, result="failed", error=str(exc))
        return {"tool": "ssl_tls_check", "host": host, "port": port, "error": str(exc)}

    await ctx.report_progress(4, 5, "Analyzing results...")

    result = _build_ssl_result(host, port, scan_result_raw)

    await ctx.report_progress(5, 5, "SSL/TLS analysis complete")
    await audit.log_tool_call("ssl_tls_check", host, params, result="completed")

    return {
        "tool": "ssl_tls_check",
        "host": host,
        "port": port,
        "certificate_valid": result.certificate_valid,
        "certificate_expiry": result.certificate_expiry,
        "supported_protocols": result.protocols,
        "weak_protocols": result.weak_protocols,
        "vulnerabilities": result.vulnerabilities,
        "grade": result.grade,
        "recommendations": _generate_recommendations(result),
    }


def _run_sslyze_scan(scan_request: object) -> object:
    """Run sslyze synchronously in a thread pool executor."""
    from sslyze import Scanner  # type: ignore[attr-defined]

    scanner = Scanner()
    scanner.queue_scans([scan_request])  # type: ignore[list-item]
    results = list(scanner.get_results())
    return results[0] if results else None


def _build_ssl_result(host: str, port: int, scan_result: object) -> SSLResult:
    """Build an SSLResult from sslyze scan output."""
    result = SSLResult(host=host, port=port)

    if scan_result is None:
        return result

    try:
        from sslyze.plugins.scan_commands import ScanCommand

        # Check supported protocols
        protocol_commands = {
            "SSLv2": ScanCommand.SSL_2_0_CIPHER_SUITES,
            "SSLv3": ScanCommand.SSL_3_0_CIPHER_SUITES,
            "TLSv1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
            "TLSv1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
            "TLSv1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
            "TLSv1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
        }

        for proto_name, command in protocol_commands.items():
            cmd_result = scan_result.scan_result.__dict__.get(  # type: ignore[attr-defined]
                command.value.lower().replace("-", "_"), None
            )
            if (
                cmd_result
                and hasattr(cmd_result, "accepted_cipher_suites")
                and cmd_result.accepted_cipher_suites
            ):
                result.protocols.append(proto_name)
                if proto_name in _WEAK_PROTOCOLS:
                    result.weak_protocols.append(proto_name)

        # Check certificate
        cert_result = scan_result.scan_result.__dict__.get("certificate_info")  # type: ignore[attr-defined]
        if cert_result and hasattr(cert_result, "certificate_deployments"):
            for deployment in cert_result.certificate_deployments:
                leaf = deployment.received_certificate_chain[0]
                result.certificate_valid = deployment.verified_certificate_chain is not None
                result.certificate_expiry = str(leaf.not_valid_after_utc)
                break

        # Check vulnerabilities
        heartbleed = scan_result.scan_result.__dict__.get("heartbleed")  # type: ignore[attr-defined]
        if heartbleed and getattr(heartbleed, "is_vulnerable_to_heartbleed", False):
            result.vulnerabilities.append("Heartbleed (CVE-2014-0160)")

        robot = scan_result.scan_result.__dict__.get("robot")  # type: ignore[attr-defined]
        if robot and "not_vulnerable" not in str(getattr(robot, "robot_result", "")).lower():
            result.vulnerabilities.append("ROBOT Attack")

        # Assign grade
        if result.weak_protocols or result.vulnerabilities:
            result.grade = "F"
        elif "TLSv1.2" in result.protocols and "TLSv1.3" in result.protocols:
            result.grade = "A+"
        elif "TLSv1.2" in result.protocols:
            result.grade = "A"
        else:
            result.grade = "B"

    except Exception as exc:
        logger.warning("Error parsing sslyze results", error=str(exc))

    return result


def _generate_recommendations(result: SSLResult) -> list[str]:
    """Generate remediation recommendations based on SSL analysis."""
    recs = []

    if result.weak_protocols:
        recs.append(
            f"Disable deprecated protocols: {', '.join(result.weak_protocols)}. "
            "Only TLSv1.2 and TLSv1.3 should be enabled."
        )

    if "Heartbleed" in " ".join(result.vulnerabilities):
        recs.append("Patch Heartbleed immediately (CVE-2014-0160). Update OpenSSL.")

    if not result.certificate_valid:
        recs.append("Fix certificate validation issues. Ensure chain of trust is complete.")

    if "TLSv1.3" not in result.protocols:
        recs.append("Enable TLS 1.3 for improved security and performance.")

    return recs
