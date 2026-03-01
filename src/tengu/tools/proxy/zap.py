"""OWASP ZAP (Zed Attack Proxy) integration via REST API.

ZAP must be running with its API enabled. Start ZAP with:
    zaproxy -daemon -host 127.0.0.1 -port 8080 -config api.key=YOUR_API_KEY
"""

from __future__ import annotations

import asyncio
import time

import httpx
import structlog
from fastmcp import Context

from tengu.exceptions import ZAPConnectionError
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


def _get_zap_config() -> tuple[str, str]:
    """Return (base_url, api_key) from environment/config."""
    import os

    base_url = os.environ.get("ZAP_BASE_URL", "http://localhost:8080")
    api_key = os.environ.get("ZAP_API_KEY", "")
    return base_url, api_key


async def _zap_request(
    path: str,
    params: dict | None = None,
) -> dict:
    """Make a request to the ZAP REST API."""
    base_url, api_key = _get_zap_config()

    if params is None:
        params = {}
    if api_key:
        params["apikey"] = api_key

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(f"{base_url}{path}", params=params)
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError as exc:
        raise ZAPConnectionError(base_url, "Connection refused — is ZAP running?") from exc
    except httpx.HTTPError as exc:
        raise ZAPConnectionError(base_url, str(exc)) from exc


async def zap_spider(
    ctx: Context,
    url: str,
    max_depth: int = 5,
    wait_for_completion: bool = True,
    timeout: int | None = None,
) -> dict:
    """Spider/crawl a web application using OWASP ZAP.

    Discovers all links and application URLs by crawling the target application.
    This is typically the first step before an active scan.

    Args:
        url: Target URL to start spidering from.
        max_depth: Maximum crawl depth. Default: 5.
        wait_for_completion: Wait for the spider to finish before returning.
        timeout: Override scan timeout in seconds.

    Returns:
        Spider results with discovered URLs and status.

    Note:
        - Requires OWASP ZAP to be running with API enabled.
        - Set ZAP_BASE_URL and ZAP_API_KEY environment variables.
    """
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "max_depth": max_depth}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("zap_spider", url, str(exc))
        raise

    await ctx.report_progress(0, 5, f"Starting ZAP spider on {url}...")

    # Start spider
    try:
        start_result = await _zap_request(
            "/JSON/spider/action/scan/",
            {"url": url, "maxDepth": str(max_depth)},
        )
    except ZAPConnectionError as exc:
        return {"tool": "zap_spider", "error": str(exc)}

    scan_id = start_result.get("scan", "0")

    if not wait_for_completion:
        return {
            "tool": "zap_spider",
            "url": url,
            "scan_id": scan_id,
            "status": "started",
        }

    # Poll until completion
    effective_timeout = timeout or 300
    start = time.monotonic()

    while True:
        if time.monotonic() - start > effective_timeout:
            break

        try:
            status = await _zap_request(
                "/JSON/spider/view/status/",
                {"scanId": scan_id},
            )
            progress = int(status.get("status", "0"))
            await ctx.report_progress(progress, 100, f"Spidering... {progress}%")

            if progress >= 100:
                break
        except Exception:
            pass

        await asyncio.sleep(3)

    # Get results
    try:
        results = await _zap_request(
            "/JSON/spider/view/results/",
            {"scanId": scan_id},
        )
        urls = results.get("results", [])
    except Exception:
        urls = []

    await audit.log_tool_call("zap_spider", url, params, result="completed")

    return {
        "tool": "zap_spider",
        "url": url,
        "urls_discovered": len(urls),
        "urls": urls[:200],  # Cap output size
    }


async def zap_active_scan(
    ctx: Context,
    url: str,
    policy: str = "",
    timeout: int | None = None,
) -> dict:
    """Run an active vulnerability scan using OWASP ZAP.

    Active scanning sends crafted requests to identify vulnerabilities.
    This is an intrusive operation — it will send potentially malicious
    payloads to the target application.

    Args:
        url: Target URL to scan (should be spidered first).
        policy: ZAP scan policy name. Leave empty for the default policy.
        timeout: Override scan timeout in seconds.

    Returns:
        Active scan status with number of alerts found.
    """
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("zap_active_scan", url, str(exc))
        raise

    await ctx.report_progress(0, 5, f"Starting ZAP active scan on {url}...")

    scan_params: dict[str, str] = {"url": url}
    if policy:
        import re

        safe_policy = re.sub(r"[^a-zA-Z0-9 _\-]", "", policy)[:100]
        if safe_policy:
            scan_params["scanPolicyName"] = safe_policy

    try:
        start_result = await _zap_request(
            "/JSON/ascan/action/scan/",
            scan_params,
        )
    except ZAPConnectionError as exc:
        return {"tool": "zap_active_scan", "error": str(exc)}

    scan_id = start_result.get("scan", "0")

    effective_timeout = timeout or 600
    start = time.monotonic()

    while True:
        if time.monotonic() - start > effective_timeout:
            break

        try:
            status = await _zap_request(
                "/JSON/ascan/view/status/",
                {"scanId": scan_id},
            )
            progress = int(status.get("status", "0"))
            await ctx.report_progress(progress, 100, f"Active scanning... {progress}%")

            if progress >= 100:
                break
        except Exception:
            pass

        await asyncio.sleep(5)

    await audit.log_tool_call("zap_active_scan", url, params, result="completed")

    return {
        "tool": "zap_active_scan",
        "url": url,
        "scan_id": scan_id,
        "status": "completed",
        "message": "Use zap_get_alerts to retrieve the discovered vulnerabilities.",
    }


async def zap_get_alerts(
    ctx: Context,
    url: str | None = None,
    risk_level: str | None = None,
    max_alerts: int = 100,
) -> dict:
    """Retrieve vulnerability alerts from OWASP ZAP.

    Fetches the list of vulnerabilities found during active/passive scanning.

    Args:
        url: Filter alerts for a specific URL (optional).
        risk_level: Filter by risk: 'High', 'Medium', 'Low', 'Informational'.
        max_alerts: Maximum number of alerts to return.

    Returns:
        List of ZAP alerts with risk level, description, solution, and evidence.
    """
    await ctx.report_progress(0, 2, "Fetching ZAP alerts...")

    alert_params: dict[str, str | int] = {
        "count": str(max_alerts),
        "start": "0",
    }

    if url:
        try:
            url = sanitize_url(url)
            alert_params["baseurl"] = url
        except Exception:
            pass

    if risk_level:
        valid_risks = {"High", "Medium", "Low", "Informational"}
        if risk_level in valid_risks:
            alert_params["riskid"] = {
                "High": "3",
                "Medium": "2",
                "Low": "1",
                "Informational": "0",
            }.get(risk_level, "")

    try:
        result = await _zap_request("/JSON/alert/view/alerts/", alert_params)
        alerts = result.get("alerts", [])
    except ZAPConnectionError as exc:
        return {"tool": "zap_get_alerts", "error": str(exc)}

    await ctx.report_progress(2, 2, "Done")

    # Structure alerts
    structured = []
    for alert in alerts[:max_alerts]:
        structured.append(
            {
                "alert_id": alert.get("id", ""),
                "name": alert.get("alert", ""),
                "risk": alert.get("risk", ""),
                "confidence": alert.get("confidence", ""),
                "url": alert.get("url", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "cweid": alert.get("cweid", ""),
                "wascid": alert.get("wascid", ""),
                "evidence": alert.get("evidence", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
            }
        )

    # Count by risk
    risk_counts: dict[str, int] = {}
    for alert in structured:
        risk = alert.get("risk", "Unknown")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {
        "tool": "zap_get_alerts",
        "total_alerts": len(structured),
        "risk_summary": risk_counts,
        "alerts": structured,
    }
