"""WHOIS lookup using python-whois (pure Python, no subprocess)."""

from __future__ import annotations

import asyncio
from datetime import datetime

import structlog
import whois
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_target
from tengu.types import WhoisResult

logger = structlog.get_logger(__name__)


async def whois_lookup(
    ctx: Context,
    target: str,
) -> dict:
    """Perform a WHOIS lookup for a domain or IP address.

    Queries WHOIS databases to retrieve registration information including
    registrar, creation/expiry dates, nameservers, and contact details.

    Args:
        target: Domain name (e.g. "example.com") or IP address.

    Returns:
        WHOIS registration data including registrar, dates, nameservers, and contacts.

    Note:
        - Uses python-whois library (no subprocess, no shell injection risk).
        - Some registrars rate-limit WHOIS queries — be mindful of frequency.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    audit = get_audit_logger()
    params = {"target": target}

    target = sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("whois_lookup", target, str(exc))
        raise

    await ctx.report_progress(0, 1, f"Querying WHOIS for {target}...")

    # python-whois is synchronous — run in thread pool to avoid blocking
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, lambda: whois.whois(target))
    except Exception as exc:
        await audit.log_tool_call("whois_lookup", target, params, result="failed", error=str(exc))
        return {
            "tool": "whois_lookup",
            "target": target,
            "error": str(exc),
        }

    await ctx.report_progress(1, 1, "WHOIS lookup complete")
    await audit.log_tool_call("whois_lookup", target, params, result="completed")

    def _date_str(value: object) -> str | None:
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, datetime):
            return value.isoformat()
        if value is not None:
            return str(value)
        return None

    def _str_list(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value if v]
        return [str(value)]

    result = WhoisResult(
        target=target,
        registrar=w.registrar if hasattr(w, "registrar") else None,
        creation_date=_date_str(w.creation_date if hasattr(w, "creation_date") else None),
        expiration_date=_date_str(w.expiration_date if hasattr(w, "expiration_date") else None),
        name_servers=_str_list(w.name_servers if hasattr(w, "name_servers") else None),
        status=_str_list(w.status if hasattr(w, "status") else None),
        emails=_str_list(w.emails if hasattr(w, "emails") else None),
        org=w.org if hasattr(w, "org") else None,
        country=w.country if hasattr(w, "country") else None,
        raw=str(w.text) if hasattr(w, "text") else "",
    )

    return {
        "tool": "whois_lookup",
        "target": target,
        "registrar": result.registrar,
        "creation_date": result.creation_date,
        "expiration_date": result.expiration_date,
        "name_servers": result.name_servers,
        "status": result.status,
        "emails": result.emails,
        "org": result.org,
        "country": result.country,
        "raw_excerpt": result.raw[:2000] if result.raw else "",
    }
