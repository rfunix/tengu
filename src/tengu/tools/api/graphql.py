"""GraphQL security checker — pure Python, no subprocess."""

from __future__ import annotations

import time

import httpx
import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)

# Deeply nested query to test depth limit enforcement
_DEPTH_QUERY = """
{
  a { b { c { d { e { f { g { h { i { j { __typename } } } } } } } } } }
}
"""

# Query with a typo to trigger field suggestion leak
_SUGGESTION_QUERY = "{ __typ }"

# Introspection query
_INTROSPECTION_QUERY = "{ __schema { types { name } } }"

# Batch query payload (list of two identical introspection queries)
_BATCH_QUERIES = [
    {"query": _INTROSPECTION_QUERY},
    {"query": "{ __typename }"},
]


async def graphql_security_check(
    ctx: Context,
    url: str,
    check_introspection: bool = True,
    authenticated: bool = False,
    auth_header: str = "",
    timeout: int | None = None,
) -> dict:
    """Perform automated GraphQL security checks using direct HTTP requests.

    Checks performed:
    - Introspection enabled (schema disclosure)
    - Query batching enabled (potential DoS amplification)
    - Depth limit enforcement (unbounded query depth)
    - Field suggestion leak (information disclosure via error messages)

    Args:
        url: GraphQL endpoint URL (e.g. https://example.com/graphql).
        check_introspection: Whether to test for introspection (schema exposure).
        authenticated: If True, include the Authorization header in requests.
        auth_header: Authorization header value (e.g. "Bearer <token>").
        timeout: HTTP request timeout in seconds (not the tool timeout).

    Returns:
        Dict with each check result, overall is_vulnerable flag, and recommendations.

    Note:
        - Target URL must be in tengu.toml [targets].allowed_hosts.
        - No subprocess is used — all checks are pure Python httpx requests.
        - Does not perform mutation or data modification of any kind.
    """
    try:
        import httpx
    except ImportError:
        return {
            "tool": "graphql_security_check",
            "error": "httpx is required. Install with: pip install httpx",
        }

    cfg = get_config()
    audit = get_audit_logger()

    url = sanitize_url(url)

    params: dict[str, object] = {
        "url": url,
        "check_introspection": check_introspection,
        "authenticated": authenticated,
    }

    # Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("graphql_security_check", url, str(exc))
        raise

    # Build headers
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if authenticated and auth_header:
        # Sanitize auth_header — strip newlines and control chars
        safe_auth = "".join(c for c in auth_header if c.isprintable() and c not in ("\r", "\n"))
        headers["Authorization"] = safe_auth

    request_timeout = float(timeout or cfg.tools.defaults.scan_timeout)
    # Cap individual request timeout at 30 s for interactive checks
    request_timeout = min(request_timeout, 30.0)

    await audit.log_tool_call("graphql_security_check", url, params, result="started")
    start = time.monotonic()

    checks: dict[str, dict] = {}
    is_vulnerable = False
    recommendations: list[str] = []

    async with httpx.AsyncClient(
        headers=headers, verify=True, follow_redirects=True, timeout=request_timeout
    ) as client:
        # 1. Introspection check
        if check_introspection:
            await ctx.report_progress(10, 100, "Checking GraphQL introspection...")
            introspection_result = await _check_introspection(client, url)
            checks["introspection"] = introspection_result
            if introspection_result.get("vulnerable"):
                is_vulnerable = True
                recommendations.append(
                    "Disable introspection in production — it exposes the entire schema to attackers. "
                    "Use a schema-aware firewall or set introspection=False in your GraphQL server config."
                )

        # 2. Batching check
        await ctx.report_progress(30, 100, "Checking GraphQL query batching...")
        batching_result = await _check_batching(client, url)
        checks["batching"] = batching_result
        if batching_result.get("vulnerable"):
            is_vulnerable = True
            recommendations.append(
                "Limit or disable query batching to prevent DoS amplification attacks. "
                "Implement query complexity limits and rate limiting per batch."
            )

        # 3. Depth limit check
        await ctx.report_progress(55, 100, "Checking GraphQL query depth limit...")
        depth_result = await _check_depth_limit(client, url)
        checks["depth_limit"] = depth_result
        if depth_result.get("vulnerable"):
            is_vulnerable = True
            recommendations.append(
                "Implement a maximum query depth limit (recommended: 10-15 levels). "
                "Libraries like graphql-depth-limit or graphql-query-complexity can enforce this."
            )

        # 4. Field suggestion check
        await ctx.report_progress(75, 100, "Checking GraphQL field suggestions...")
        suggestion_result = await _check_field_suggestions(client, url)
        checks["field_suggestions"] = suggestion_result
        if suggestion_result.get("vulnerable"):
            recommendations.append(
                "Disable field suggestions in production — they help attackers enumerate field names. "
                "Many GraphQL servers allow disabling suggestions via a configuration flag."
            )

    duration = time.monotonic() - start

    await ctx.report_progress(100, 100, "GraphQL security check complete")
    await audit.log_tool_call(
        "graphql_security_check", url, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "graphql_security_check",
        "url": url,
        "duration_seconds": round(duration, 2),
        "is_vulnerable": is_vulnerable,
        "checks": checks,
        "recommendations": recommendations,
    }


async def _check_introspection(client: httpx.AsyncClient, url: str) -> dict:
    """Test whether introspection is enabled on the GraphQL endpoint."""
    try:
        resp = await client.post(url, json={"query": _INTROSPECTION_QUERY})
        data = resp.json()
        types = data.get("data", {}).get("__schema", {}).get("types", [])
        enabled = isinstance(types, list) and len(types) > 0
        return {
            "vulnerable": enabled,
            "status_code": resp.status_code,
            "description": "Introspection is enabled — full schema is publicly accessible"
            if enabled
            else "Introspection is disabled",
            "severity": "high" if enabled else "info",
            "type_count": len(types) if enabled else 0,
        }
    except Exception as exc:
        return {"vulnerable": False, "error": str(exc), "description": "Introspection check failed"}


async def _check_batching(client: httpx.AsyncClient, url: str) -> dict:
    """Test whether query batching is supported (potential DoS amplification)."""
    try:
        resp = await client.post(url, json=_BATCH_QUERIES)
        data = resp.json()
        # Batching returns a list of results
        batch_supported = isinstance(data, list) and len(data) == len(_BATCH_QUERIES)
        return {
            "vulnerable": batch_supported,
            "status_code": resp.status_code,
            "description": "Query batching is enabled — may allow DoS amplification"
            if batch_supported
            else "Query batching does not appear to be enabled",
            "severity": "medium" if batch_supported else "info",
        }
    except Exception as exc:
        return {"vulnerable": False, "error": str(exc), "description": "Batching check failed"}


async def _check_depth_limit(client: httpx.AsyncClient, url: str) -> dict:
    """Test whether deep nested queries are rejected (no depth limit)."""
    try:
        resp = await client.post(url, json={"query": _DEPTH_QUERY})
        data = resp.json()
        errors = data.get("errors", [])
        # If errors mention depth or complexity, a limit is in place
        depth_error = any(
            "depth" in str(e).lower() or "complex" in str(e).lower() or "limit" in str(e).lower()
            for e in errors
        )
        has_data = data.get("data") is not None
        # Vulnerable if no error and data was returned (query succeeded)
        vulnerable = has_data and not depth_error
        return {
            "vulnerable": vulnerable,
            "status_code": resp.status_code,
            "description": "No query depth limit detected — deeply nested queries succeed"
            if vulnerable
            else "Query depth limit appears to be in place",
            "severity": "high" if vulnerable else "info",
            "depth_tested": 10,
        }
    except Exception as exc:
        return {"vulnerable": False, "error": str(exc), "description": "Depth limit check failed"}


async def _check_field_suggestions(client: httpx.AsyncClient, url: str) -> dict:
    """Test whether the server leaks field name suggestions in error messages."""
    try:
        resp = await client.post(url, json={"query": _SUGGESTION_QUERY})
        data = resp.json()
        errors = data.get("errors", [])
        has_suggestions = any(
            "did you mean" in str(e).lower() or "suggestion" in str(e).lower() for e in errors
        )
        return {
            "vulnerable": has_suggestions,
            "status_code": resp.status_code,
            "description": "Field suggestions enabled — error messages reveal valid field names"
            if has_suggestions
            else "No field suggestions detected in error messages",
            "severity": "low" if has_suggestions else "info",
        }
    except Exception as exc:
        return {
            "vulnerable": False,
            "error": str(exc),
            "description": "Field suggestion check failed",
        }
