"""CVE search and lookup MCP tools."""

from __future__ import annotations

from fastmcp import Context

from tengu.resources.cve import lookup_cve, search_cves
from tengu.security.sanitizer import sanitize_cve_id, sanitize_free_text


async def cve_lookup(
    ctx: Context,  # type: ignore[type-arg]
    cve_id: str,
) -> dict:  # type: ignore[type-arg]
    """Fetch complete details for a specific CVE from NVD and CVE.org.

    Returns CVSS scores (v2/v3.1/v4.0), CWE mappings, affected products,
    references, and cross-references to known exploits.

    Args:
        cve_id: CVE identifier in the format CVE-YYYY-NNNNN (e.g. "CVE-2024-1234").

    Returns:
        Full CVE details including CVSS vector, severity, affected products,
        and exploit availability indicators.
    """
    cve_id = sanitize_cve_id(cve_id)

    await ctx.report_progress(0, 2, f"Looking up {cve_id}...")

    record = await lookup_cve(cve_id)

    await ctx.report_progress(2, 2, "Done")

    if not record:
        return {
            "cve_id": cve_id,
            "found": False,
            "message": f"{cve_id} not found in NVD or CVE.org databases.",
        }

    # Find highest CVSS score
    highest_cvss = max(record.cvss, key=lambda x: x.base_score) if record.cvss else None

    return {
        "cve_id": record.id,
        "found": True,
        "description": record.description,
        "published": record.published,
        "last_modified": record.last_modified,
        "severity": highest_cvss.severity if highest_cvss else "UNKNOWN",
        "cvss_score": highest_cvss.base_score if highest_cvss else None,
        "cvss_vector": highest_cvss.vector_string if highest_cvss else None,
        "all_cvss_metrics": [m.model_dump() for m in record.cvss],
        "cwe_ids": record.cwe_ids,
        "affected_products": record.affected_products[:10],
        "references": record.references[:10],
        "exploit_available": record.exploit_available,
        "metasploit_module": record.metasploit_module,
    }


async def cve_search(
    ctx: Context,  # type: ignore[type-arg]
    keyword: str | None = None,
    cpe_name: str | None = None,
    severity: str | None = None,
    days_back: int | None = None,
    max_results: int = 20,
) -> dict:  # type: ignore[type-arg]
    """Search CVEs by keyword, product, CPE, or severity.

    Queries the NVD database for matching CVEs. Results are cached
    locally for 24 hours to respect API rate limits.

    Args:
        keyword: Search term (e.g. "apache log4j", "OpenSSL", "nginx 1.18").
        cpe_name: CPE 2.3 identifier (e.g. "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*").
        severity: Filter by CVSS severity: LOW, MEDIUM, HIGH, CRITICAL.
        days_back: Only return CVEs published in the last N days.
        max_results: Maximum number of results to return (max: 100).

    Returns:
        List of matching CVEs with severity, CVSS score, and description.
    """
    if not keyword and not cpe_name:
        return {"error": "Provide at least one search parameter: keyword or cpe_name"}

    if keyword:
        keyword = sanitize_free_text(keyword, field="keyword")

    if severity:
        severity = severity.upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = None

    max_results = max(1, min(max_results, 100))

    await ctx.report_progress(0, 3, "Searching CVE database...")

    records = await search_cves(
        keyword=keyword,
        cpe_name=cpe_name,
        days_back=days_back,
        severity=severity,
        results_per_page=max_results,
    )

    await ctx.report_progress(3, 3, "Done")

    return {
        "query": {
            "keyword": keyword,
            "cpe_name": cpe_name,
            "severity": severity,
            "days_back": days_back,
        },
        "total_found": len(records),
        "cves": [
            {
                "id": r.id,
                "description": r.description[:300] + "..."
                if len(r.description) > 300
                else r.description,
                "published": r.published,
                "severity": max((m.severity for m in r.cvss), default="UNKNOWN")
                if r.cvss
                else "UNKNOWN",
                "cvss_score": max((m.base_score for m in r.cvss), default=0.0) if r.cvss else 0.0,
                "cwe_ids": r.cwe_ids,
                "exploit_available": r.exploit_available,
            }
            for r in records
        ],
    }
