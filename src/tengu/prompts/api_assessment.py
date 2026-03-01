"""API security assessment prompts."""

from __future__ import annotations


def api_security_assessment(
    url: str,
    api_type: str = "rest",
    authenticated: bool = False,
) -> str:
    """Comprehensive API security assessment workflow.

    Args:
        url: API base URL or endpoint.
        api_type: API type — rest, graphql, grpc, soap.
        authenticated: Whether to include authenticated testing steps.
    """
    graphql_steps = (
        f"""
## GraphQL-Specific Tests
4a. `graphql_security_check(url="{url}")` — introspection, batching, depth limit, field suggestions
4b. Test for authorization bypass: access other users' data via ID manipulation
4c. Test for injection via GraphQL variables"""
        if api_type == "graphql"
        else ""
    )

    return f"""# API Security Assessment: {url}

## API Type: {api_type.upper()} | Authenticated: {authenticated}

## Phase 1 — Reconnaissance
1. `analyze_headers(url="{url}")` — security headers, CORS, server disclosure
2. `test_cors(url="{url}")` — CORS misconfiguration
3. `ssl_tls_check(host="...", port=443)` — TLS configuration
{graphql_steps}

## Phase 2 — Parameter Discovery
4. `arjun_discover(url="{url}", method="GET")` — discover hidden GET parameters
5. `arjun_discover(url="{url}", method="POST")` — discover hidden POST parameters
6. `ffuf_fuzz(url="{url}/FUZZ", wordlist="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt")` — endpoint fuzzing

## Phase 3 — Injection Testing
7. `sqlmap_scan(url="{url}?id=1", level=1, risk=1)` — SQL injection (adjust endpoint)
8. `xss_scan(url="{url}")` — XSS in API responses

## Phase 4 — Authorization Testing (OWASP API1, API5)
Test for:
- BOLA/IDOR: Change object IDs in endpoints (e.g. /api/users/123 → /api/users/124)
- Function Level Auth: Access admin endpoints (GET /api/admin/users)
- Mass Assignment: Send extra fields in POST/PUT requests

## Phase 5 — Business Logic
Test for:
- Unrestricted resource consumption (API4): flood requests without rate limiting
- SSRF via URL parameters (API7): inject `http://169.254.169.254/latest/meta-data/`
- Broken object property level authorization (API3): over-fetch/over-post

## OWASP API Security Top 10 Coverage
Resource: `owasp://api-security/top10` — full OWASP API Security Top 10 reference

## Expected Findings
- Missing authentication/authorization controls
- Exposed sensitive endpoints
- Injection vulnerabilities
- Information disclosure in error messages
- Rate limiting bypass
- CORS misconfiguration"""
