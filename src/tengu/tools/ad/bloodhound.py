"""BloodHound data collection tool wrapper for Active Directory attack path analysis.

WARNING: BloodHound collection is a high-visibility AD enumeration technique.
It generates significant LDAP traffic against domain controllers and is detectable
by modern EDR, SIEM solutions, and Windows Event IDs 4662, 4624.
Requires explicit written authorization from the target domain owner.
"""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_domain, sanitize_free_text, sanitize_target

logger = structlog.get_logger(__name__)

_VALID_COLLECTION_METHODS = frozenset(
    ["All", "DCOnly", "Group", "LocalAdmin", "Session", "Trusts", "Default", "Container", "RDP"]
)


async def bloodhound_collect(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    collection_method: str = "Default",
    output_dir: str = "/tmp/bloodhound-tengu",
    timeout: int | None = None,
) -> dict:
    """Collect Active Directory data for BloodHound attack path analysis.

    bloodhound-python enumerates users, groups, computers, GPOs, and trust
    relationships in an AD domain to map attack paths to Domain Admin.

    Args:
        target: Domain Controller IP address.
        domain: Active Directory domain name (e.g. corp.local).
        username: Valid domain username for authentication.
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT).
        collection_method: Data to collect — Default, All, DCOnly, Group, Session.
        output_dir: Directory to write collected JSON/ZIP files.
        timeout: Override scan timeout in seconds.

    Returns:
        Collection summary with file locations and AD object counts.

    WARNING:
        - BloodHound collection is detectable by modern EDR and SIEM solutions.
        - Generates significant LDAP traffic against the domain controller.
        - Requires valid domain credentials.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()

    target = sanitize_target(target)
    domain = sanitize_domain(domain)
    safe_username = sanitize_free_text(username, field="username", max_length=256)
    safe_password = (
        sanitize_free_text(password, field="password", max_length=512) if password else ""
    )
    safe_hashes = sanitize_free_text(hashes, field="hashes", max_length=128) if hashes else ""
    safe_output_dir = re.sub(r"[^a-zA-Z0-9/_\-]", "", output_dir) or "/tmp/bloodhound-tengu"

    # Validate collection method — fall back to Default if unknown
    if collection_method not in _VALID_COLLECTION_METHODS:
        collection_method = "Default"

    # Audit params — redact credentials
    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
        "collection_method": collection_method,
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("bloodhound", target, str(exc))
        raise

    # Prefer bloodhound-python, fall back to bloodhound
    tool_name: str
    tool_path_str: str
    if shutil.which("bloodhound-python"):
        tool_name = "bloodhound-python"
        tool_path_str = resolve_tool_path("bloodhound-python")
    else:
        tool_name = "bloodhound"
        tool_path_str = resolve_tool_path("bloodhound")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Create output directory
    Path(safe_output_dir).mkdir(parents=True, exist_ok=True)

    # Build args — list only, never shell=True
    args: list[str] = [
        tool_path_str,
        "-d", domain,
        "-u", safe_username,
        "-dc", target,
        "-c", collection_method,
        "-o", safe_output_dir,
        "--zip",
        "--dns-tcp",
    ]
    if safe_password:
        args.extend(["-p", safe_password])
    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    logger.warning(
        "BloodHound collection initiated — generates LDAP traffic detectable by domain controllers",
        target=target,
        domain=domain,
        username=safe_username,
        collection_method=collection_method,
    )

    await ctx.report_progress(0, 100, f"Starting BloodHound collection on {domain} DC {target}...")

    async with rate_limited("bloodhound"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing BloodHound collection results...")

    parsed = _parse_bloodhound_output(stdout, safe_output_dir)

    await ctx.report_progress(100, 100, "BloodHound collection complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "collection_method": collection_method,
        "output_dir": safe_output_dir,
        "duration_seconds": round(duration, 2),
        "output_files": parsed["files"],
        "object_counts": parsed["counts"],
        "warning": "BloodHound collection generates LDAP traffic detectable by domain controllers.",
        "raw_output_excerpt": stdout[-4000:] if len(stdout) > 4000 else stdout,
    }


def _parse_bloodhound_output(output: str, output_dir: str) -> dict:
    """Parse bloodhound-python output for file paths and AD object counts."""
    files: list[str] = []
    counts: dict[str, int] = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Detect collected output files
        if ".json" in line or ".zip" in line:
            files.append(line)
        # Parse object counts: "Found 150 users", "Found 30 computers", etc.
        m = re.search(r"Found (\d+) (\w+)", line, re.IGNORECASE)
        if m:
            count, obj_type = int(m.group(1)), m.group(2).lower()
            counts[obj_type] = counts.get(obj_type, 0) + count

    # Also check output directory for actual files produced
    try:
        output_path = Path(output_dir)
        if output_path.exists():
            for f in output_path.iterdir():
                if f.name.endswith((".json", ".zip")) and str(f) not in files:
                    files.append(str(f))
    except Exception:
        pass

    return {"files": files, "counts": counts}
