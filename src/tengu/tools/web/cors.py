"""CORS misconfiguration tester using httpx (pure Python)."""

from __future__ import annotations

import httpx
import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url
from tengu.types import CORSResult

logger = structlog.get_logger(__name__)

# Origins to test for CORS reflection vulnerabilities
_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://target.example.com.evil.com",
]


async def test_cors(
    ctx: Context,
    url: str,
    custom_origins: list[str] | None = None,
    timeout_seconds: int = 30,
) -> dict:
    """Test a URL for CORS (Cross-Origin Resource Sharing) misconfigurations.

    Sends requests with various Origin headers to detect if the server
    blindly reflects origins, allows null origins, or permits arbitrary
    cross-origin requests with credentials.

    Common CORS vulnerabilities detected:
    - Origin reflection (server echoes back any Origin header)
    - Null origin acceptance (dangerous with sandboxed iframes)
    - Subdomain wildcard bypass (e.g. evil.target.com accepted)
    - Credentials with wildcard (Access-Control-Allow-Credentials: true + *)
    - Trusted origin misconfiguration (pre-domain spoofing)

    Args:
        url: Target URL to test.
        custom_origins: Additional origin values to test.
        timeout_seconds: HTTP request timeout in seconds.

    Returns:
        CORS test results with identified vulnerabilities and evidence.
    """
    audit = get_audit_logger()
    params = {"url": url}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("test_cors", url, str(exc))
        raise

    test_origins = _TEST_ORIGINS.copy()
    if custom_origins:
        for o in custom_origins:
            try:
                sanitize_url(o)
                test_origins.append(o)
            except Exception:
                pass

    issues: list[str] = []
    test_results: list[dict] = []
    allow_origin: str | None = None
    allow_credentials = False

    await ctx.report_progress(0, len(test_origins), f"Testing CORS on {url}...")

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    async with stealth.create_http_client(
        follow_redirects=True,
        timeout=timeout_seconds,
        verify=False,
    ) as client:
        for i, origin in enumerate(test_origins):
            await ctx.report_progress(i, len(test_origins), f"Testing origin: {origin}")

            try:
                response = await client.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Content-Type,Authorization",
                    },
                )

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "false").lower()
                acam = response.headers.get("access-control-allow-methods", "")
                acah = response.headers.get("access-control-allow-headers", "")

                test_result: dict = {
                    "origin_tested": origin,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                    "access_control_allow_methods": acam,
                    "access_control_allow_headers": acah,
                    "status_code": response.status_code,
                    "vulnerable": False,
                    "issue": None,
                }

                # Check for vulnerabilities
                if acao == origin and origin not in ("", "*"):
                    test_result["vulnerable"] = True
                    issue = f"Server reflects arbitrary origin: '{origin}'"
                    test_result["issue"] = issue
                    issues.append(issue)
                    allow_origin = acao

                    if acac == "true":
                        allow_credentials = True
                        critical_issue = (
                            f"CRITICAL: Server allows credentials with reflected origin '{origin}'. "
                            "Attackers can make authenticated cross-origin requests."
                        )
                        issues.append(critical_issue)

                elif acao == "*" and acac == "true":
                    test_result["vulnerable"] = True
                    issue = "Wildcard (*) origin with Access-Control-Allow-Credentials: true"
                    test_result["issue"] = issue
                    issues.append(issue)

                elif acao == "null":
                    test_result["vulnerable"] = True
                    issue = "Null origin accepted — exploitable via sandboxed iframes"
                    test_result["issue"] = issue
                    issues.append(issue)

                test_results.append(test_result)

            except httpx.RequestError:
                continue

    await ctx.report_progress(len(test_origins), len(test_origins), "CORS test complete")
    await audit.log_tool_call("test_cors", url, params, result="completed")

    result = CORSResult(
        url=url,
        vulnerable=len(issues) > 0,
        issues=issues,
        allow_origin=allow_origin,
        allow_credentials=allow_credentials,
    )

    return {
        "tool": "test_cors",
        "url": url,
        "vulnerable": result.vulnerable,
        "severity": _assess_severity(issues, allow_credentials),
        "issues": issues,
        "test_results": test_results,
        "remediation": (
            "Implement a strict allowlist of trusted origins. "
            "Never reflect the Origin header value back. "
            "Only set Access-Control-Allow-Credentials: true for explicitly trusted origins."
        )
        if result.vulnerable
        else None,
    }


def _assess_severity(issues: list[str], credentials: bool) -> str:
    if not issues:
        return "none"
    if credentials:
        return "critical"
    if issues:
        return "high"
    return "medium"
