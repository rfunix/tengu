"""CVE lookup resources using NVD API v2.0 and CVE.org API.

Architecture:
- Primary source: NVD API (CVSS scores, CWE mappings, references)
- Fallback: CVE.org API (base data without CVSS)
- Cache: SQLite with configurable TTL to respect API rate limits
- Rate limiting: 5 req/30s without API key, 50 req/30s with key
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from datetime import UTC
from pathlib import Path

import httpx
import structlog

from tengu.config import get_config
from tengu.types import CVERecord, CVSSMetrics

logger = structlog.get_logger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ORG_URL = "https://cveawg.mitre.org/api/cve"

# NVD rate limits (requests per 30 seconds)
_RATE_NO_KEY = 5
_RATE_WITH_KEY = 50


class CVECache:
    """SQLite-backed CVE cache with TTL support."""

    def __init__(self, db_path: str) -> None:
        self._path = Path(db_path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_cache (
                    query_key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)
            conn.commit()

    def get_cve(self, cve_id: str, ttl_hours: int = 24) -> dict | None:  # type: ignore[type-arg]
        cutoff = time.time() - ttl_hours * 3600
        with sqlite3.connect(self._path) as conn:
            row = conn.execute(
                "SELECT data FROM cve_cache WHERE cve_id = ? AND cached_at > ?",
                (cve_id.upper(), cutoff),
            ).fetchone()
        if row:
            return json.loads(row[0])  # type: ignore[no-any-return]
        return None

    def set_cve(self, cve_id: str, data: dict) -> None:  # type: ignore[type-arg]
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
                (cve_id.upper(), json.dumps(data), time.time()),
            )
            conn.commit()

    def get_search(self, query_key: str, ttl_hours: int = 24) -> dict | None:  # type: ignore[type-arg]
        cutoff = time.time() - ttl_hours * 3600
        with sqlite3.connect(self._path) as conn:
            row = conn.execute(
                "SELECT data FROM search_cache WHERE query_key = ? AND cached_at > ?",
                (query_key, cutoff),
            ).fetchone()
        if row:
            return json.loads(row[0])  # type: ignore[no-any-return]
        return None

    def set_search(self, query_key: str, data: dict) -> None:  # type: ignore[type-arg]
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO search_cache (query_key, data, cached_at) VALUES (?, ?, ?)",
                (query_key, json.dumps(data), time.time()),
            )
            conn.commit()


_cache: CVECache | None = None
_last_request_time: float = 0.0
_request_lock = asyncio.Lock()


def _get_cache() -> CVECache:
    global _cache
    if _cache is None:
        cfg = get_config()
        _cache = CVECache(cfg.cve.cache_path)
    return _cache


async def _rate_limit_wait(has_api_key: bool) -> None:
    """Respect NVD rate limits between requests."""
    global _last_request_time
    rate = _RATE_WITH_KEY if has_api_key else _RATE_NO_KEY
    min_interval = 30.0 / rate

    async with _request_lock:
        elapsed = time.monotonic() - _last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        _last_request_time = time.monotonic()


def _build_headers(api_key: str) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


async def lookup_cve(cve_id: str) -> CVERecord | None:
    """Fetch complete details for a specific CVE from NVD API.

    Uses local cache to avoid repeated API calls.
    Falls back to CVE.org if NVD is unavailable.
    """
    cfg = get_config()
    cache = _get_cache()

    # Check cache first
    cached = cache.get_cve(cve_id, cfg.cve.cache_ttl_hours)
    if cached:
        logger.debug("CVE cache hit", cve_id=cve_id)
        return CVERecord(**cached)

    await _rate_limit_wait(bool(cfg.cve.nvd_api_key))

    # Try NVD API
    params = {"cveId": cve_id.upper()}
    headers = _build_headers(cfg.cve.nvd_api_key)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(_NVD_BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        record = _parse_nvd_cve(vulnerabilities[0])
        cache.set_cve(cve_id, record.model_dump(mode="json"))
        return record

    except httpx.HTTPError as exc:
        logger.warning("NVD API failed, trying CVE.org", error=str(exc), cve_id=cve_id)

    # Fallback: CVE.org
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(f"{_CVE_ORG_URL}/{cve_id.upper()}")
            response.raise_for_status()
            data = response.json()

        record = _parse_cveorg(data)
        cache.set_cve(cve_id, record.model_dump(mode="json"))
        return record

    except Exception as exc:
        logger.error("CVE lookup failed on all sources", cve_id=cve_id, error=str(exc))
        return None


async def search_cves(
    keyword: str | None = None,
    cpe_name: str | None = None,
    days_back: int | None = None,
    severity: str | None = None,
    results_per_page: int = 20,
) -> list[CVERecord]:
    """Search CVEs using NVD API with various filters."""
    cfg = get_config()
    cache = _get_cache()

    # Build cache key
    query_key = f"{keyword}:{cpe_name}:{days_back}:{severity}:{results_per_page}"
    cached = cache.get_search(query_key, cfg.cve.cache_ttl_hours)
    if cached:
        return [CVERecord(**r) for r in cached.get("records", [])]

    await _rate_limit_wait(bool(cfg.cve.nvd_api_key))

    params: dict[str, str | int] = {
        "resultsPerPage": min(results_per_page, 100),
        "startIndex": 0,
    }

    if keyword:
        params["keywordSearch"] = keyword

    if cpe_name:
        params["cpeName"] = cpe_name

    if severity:
        params["cvssV3Severity"] = severity.upper()

    if days_back:
        from datetime import datetime, timedelta

        end_date = datetime.now(tz=UTC)
        start_date = end_date - timedelta(days=days_back)
        params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = _build_headers(cfg.cve.nvd_api_key)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(_NVD_BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        records = [_parse_nvd_cve(vuln) for vuln in data.get("vulnerabilities", [])]

        cache.set_search(query_key, {"records": [r.model_dump(mode="json") for r in records]})
        return records

    except Exception as exc:
        logger.error("CVE search failed", error=str(exc))
        return []


def _parse_nvd_cve(vuln_data: dict) -> CVERecord:  # type: ignore[type-arg]
    """Parse NVD API CVE data into a CVERecord."""
    cve = vuln_data.get("cve", {})
    cve_id = cve.get("id", "")

    # Description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # CVSS metrics
    cvss_list: list[CVSSMetrics] = []
    metrics = cve.get("metrics", {})

    for version_key, version_str in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    ]:
        for metric in metrics.get(version_key, []):
            cvss_data = metric.get("cvssData", {})
            cvss_list.append(
                CVSSMetrics(
                    version=version_str,
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=float(cvss_data.get("baseScore", 0.0)),
                    severity=cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN")),
                    exploitability_score=metric.get("exploitabilityScore"),
                    impact_score=metric.get("impactScore"),
                )
            )

    # CWE IDs
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if value and value != "NVD-CWE-Other":
                    cwe_ids.append(value)

    # References
    references = [ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")]

    # Affected products (CPE)
    affected_products: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    affected_products.append(cpe_match.get("criteria", ""))

    return CVERecord(
        id=cve_id,
        description=description,
        published=cve.get("published", ""),
        last_modified=cve.get("lastModified", ""),
        cvss=cvss_list,
        cwe_ids=cwe_ids,
        references=references[:20],
        affected_products=affected_products[:20],
    )


def _parse_cveorg(data: dict) -> CVERecord:  # type: ignore[type-arg]
    """Parse CVE.org API data into a CVERecord (fallback, no CVSS)."""
    cve_meta = data.get("cveMetadata", {})
    cve_id = cve_meta.get("cveId", "")

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    descriptions = cna.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang", "").startswith("en")),
        "No description available.",
    )

    references = [ref.get("url", "") for ref in cna.get("references", []) if ref.get("url")]

    return CVERecord(
        id=cve_id,
        description=description,
        published=cve_meta.get("datePublished", ""),
        last_modified=cve_meta.get("dateUpdated", ""),
        references=references[:20],
    )
