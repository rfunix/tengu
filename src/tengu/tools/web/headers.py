"""HTTP security headers analysis using httpx (pure Python)."""

from __future__ import annotations

import httpx
import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url
from tengu.types import HeaderAnalysisResult, SecurityHeader

logger = structlog.get_logger(__name__)

# Security header definitions: name, whether it should be present, and advice
_SECURITY_HEADERS: list[dict[str, object]] = [
    {
        "name": "Strict-Transport-Security",
        "required": True,
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    {
        "name": "Content-Security-Policy",
        "required": True,
        "recommendation": "Define a strict CSP policy to prevent XSS and data injection attacks.",
    },
    {
        "name": "X-Frame-Options",
        "required": True,
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    {
        "name": "X-Content-Type-Options",
        "required": True,
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
    },
    {
        "name": "Referrer-Policy",
        "required": True,
        "recommendation": "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
    },
    {
        "name": "Permissions-Policy",
        "required": True,
        "recommendation": "Add Permissions-Policy to restrict access to browser features.",
    },
    {
        "name": "X-XSS-Protection",
        "required": False,
        "recommendation": "Deprecated in modern browsers. Use CSP instead.",
    },
    {
        "name": "Cache-Control",
        "required": False,
        "recommendation": "Set appropriate caching directives for sensitive pages.",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "required": True,
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate the browsing context.",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "required": True,
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' to protect resources.",
    },
]

# Headers that should NOT be present (information disclosure)
_INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
]


async def analyze_headers(
    ctx: Context,
    url: str,
    follow_redirects: bool = True,
    timeout_seconds: int = 30,
) -> dict:
    """Analyze HTTP security headers for a web application.

    Checks for the presence and correctness of critical security headers
    and flags information disclosure headers that should be removed.

    Args:
        url: Target URL to analyze.
        follow_redirects: Follow HTTP redirects to the final destination.
        timeout_seconds: HTTP request timeout in seconds.

    Returns:
        Security header analysis with scores, grades, and recommendations.

    Note:
        - Uses httpx directly (no subprocess). Pure Python implementation.
        - Performs a single GET request to the target URL.
    """
    audit = get_audit_logger()
    params = {"url": url}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("analyze_headers", url, str(exc))
        raise

    await ctx.report_progress(0, 3, f"Fetching headers from {url}...")

    try:
        from tengu.stealth import get_stealth_layer

        stealth = get_stealth_layer()
        async with stealth.create_http_client(
            follow_redirects=follow_redirects,
            timeout=timeout_seconds,
            verify=False,  # Allow self-signed certs during pentesting
        ) as client:
            response = await client.get(url)
    except httpx.RequestError as exc:
        await audit.log_tool_call("analyze_headers", url, params, result="failed", error=str(exc))
        return {"tool": "analyze_headers", "url": url, "error": str(exc)}

    await ctx.report_progress(1, 3, "Analyzing security headers...")

    response_headers = {k.lower(): v for k, v in response.headers.items()}

    security_headers: list[SecurityHeader] = []
    score = 0
    max_score = 0

    for header_def in _SECURITY_HEADERS:
        name: str = str(header_def["name"])
        required: bool = bool(header_def["required"])
        recommendation: str = str(header_def["recommendation"])

        if not required:
            continue

        max_score += 10
        present = name.lower() in response_headers
        value = response_headers.get(name.lower()) if present else None
        header_score: str

        if present:
            score += 10
            header_score = "pass"
        else:
            header_score = "fail"

        security_headers.append(
            SecurityHeader(
                name=name,
                value=value,
                present=present,
                score=header_score,  # type: ignore[arg-type]
                recommendation=None if present else recommendation,
            )
        )

    # Check information disclosure headers
    disclosure_found = []
    for header_name in _INFORMATION_DISCLOSURE_HEADERS:
        if header_name.lower() in response_headers:
            disclosure_found.append(
                {
                    "header": header_name,
                    "value": response_headers[header_name.lower()],
                    "recommendation": f"Remove '{header_name}' header to prevent technology fingerprinting.",
                }
            )

    # Calculate grade
    percentage = (score / max_score * 100) if max_score > 0 else 0
    grade = _score_to_grade(int(percentage))

    result = HeaderAnalysisResult(
        url=url,
        headers=security_headers,
        score=int(percentage),
        grade=grade,
    )

    await ctx.report_progress(3, 3, "Analysis complete")
    await audit.log_tool_call("analyze_headers", url, params, result="completed")

    return {
        "tool": "analyze_headers",
        "url": str(response.url),
        "status_code": response.status_code,
        "score": result.score,
        "grade": result.grade,
        "security_headers": [h.model_dump() for h in result.headers],
        "information_disclosure": disclosure_found,
        "missing_headers": [h.name for h in result.headers if not h.present],
        "all_response_headers": dict(response.headers),
    }


def _score_to_grade(score: int) -> str:
    """Convert a 0-100 score to a letter grade."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"
