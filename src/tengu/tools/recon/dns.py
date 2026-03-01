"""DNS enumeration using dnspython (pure Python, no subprocess)."""

from __future__ import annotations

from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_domain
from tengu.types import DNSRecord, DNSResult

logger = structlog.get_logger(__name__)

RecordType = Literal["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

_ALL_RECORD_TYPES: list[RecordType] = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
    "PTR",
    "SRV",
    "CAA",
]


async def dns_enumerate(
    ctx: Context,  # type: ignore[type-arg]
    domain: str,
    record_types: list[RecordType] | None = None,
    nameserver: str | None = None,
) -> dict:  # type: ignore[type-arg]
    """Query DNS records for a domain.

    Performs DNS lookups for the specified record types using dnspython.
    No external process is spawned — this is a pure-Python DNS client.

    Args:
        domain: Target domain to query (e.g. "example.com").
        record_types: List of DNS record types to query.
                      Defaults to all common types: A, AAAA, MX, NS, TXT, CNAME, SOA.
        nameserver: Optional custom DNS resolver IP (e.g. "8.8.8.8").
                    Defaults to system resolver.

    Returns:
        DNS records grouped by type with values and TTLs.
    """
    audit = get_audit_logger()
    params: dict[str, object] = {"domain": domain, "record_types": record_types}

    domain = sanitize_domain(domain)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(domain)
    except Exception as exc:
        await audit.log_target_blocked("dns_enumerate", domain, str(exc))
        raise

    types_to_query = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    # Validate record type names
    valid_types = set(_ALL_RECORD_TYPES)
    types_to_query = [t.upper() for t in types_to_query if t.upper() in valid_types]

    resolver = dns.asyncresolver.Resolver()
    if nameserver:
        # Validate nameserver is a valid IP
        import ipaddress

        try:
            ipaddress.ip_address(nameserver)
            resolver.nameservers = [nameserver]
        except ValueError:
            logger.warning("Invalid nameserver IP, using system default", nameserver=nameserver)

    await ctx.report_progress(0, len(types_to_query), f"Querying DNS for {domain}...")

    records: list[DNSRecord] = []
    errors: dict[str, str] = {}

    for i, rtype in enumerate(types_to_query):
        await ctx.report_progress(i, len(types_to_query), f"Querying {rtype} records...")
        try:
            answers = await resolver.resolve(domain, rtype)
            for rdata in answers:
                records.append(
                    DNSRecord(
                        name=domain,
                        record_type=rtype,
                        value=str(rdata),
                        ttl=answers.ttl,
                    )
                )
        except dns.resolver.NXDOMAIN:
            errors[rtype] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            pass  # Record type simply doesn't exist
        except dns.exception.Timeout:
            errors[rtype] = "timeout"
        except Exception as exc:
            errors[rtype] = str(exc)

    result = DNSResult(domain=domain, records=records)

    await ctx.report_progress(len(types_to_query), len(types_to_query), "DNS enumeration complete")
    await audit.log_tool_call("dns_enumerate", domain, params, result="completed")

    # Group records by type for easy consumption
    grouped: dict[str, list[str]] = {}
    for record in records:
        grouped.setdefault(record.record_type, []).append(record.value)

    return {
        "tool": "dns_enumerate",
        "domain": domain,
        "records_found": len(records),
        "records_by_type": grouped,
        "errors": errors,
        "all_records": [r.model_dump() for r in result.records],
    }
