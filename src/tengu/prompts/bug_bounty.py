"""Bug bounty optimized workflow prompts."""

from __future__ import annotations


def bug_bounty_workflow(target: str, focus: str = "web") -> str:
    """Optimized bug bounty reconnaissance and testing workflow.

    Args:
        target: Target domain or application.
        focus: Focus area — web, api, mobile, network, cloud.
    """
    return f"""# Bug Bounty Workflow: {target} | Focus: {focus.upper()}

## IMPORTANT: Read Program Rules First
- Check in-scope vs out-of-scope targets
- Note excluded vulnerability types
- Understand disclosure and payment rules
- Check if automated scanners are allowed

## Phase 1 — Rapid Reconnaissance (30 min)
1. `whois_lookup(target="{target}")` — registrar, org info
2. `subfinder_enum(domain="{target}")` — passive subdomain enumeration
3. `amass_enum(domain="{target}", mode="passive")` — expand scope
4. `theharvester_scan(domain="{target}")` — emails, additional subdomains
5. `shodan_lookup(target="{target}")` — exposed services

## Phase 2 — Attack Surface Mapping (1 hour)
6. `dns_enumerate(domain="{target}")` — DNS records, SPF, DMARC
7. `gobuster_scan(target="https://{target}", mode="vhost")` — virtual hosts
8. `gowitness_screenshot(target="https://{target}")` — visual recon
9. `whatweb_scan(target="https://{target}")` — technology stack

## Phase 3 — Vulnerability Discovery
10. `nuclei_scan(target="https://{target}", severity=["high","critical"])` — template scan
11. `analyze_headers(url="https://{target}")` — security headers
12. `test_cors(url="https://{target}")` — CORS misconfiguration
13. `ssl_tls_check(host="{target}", port=443)` — TLS issues

## Phase 4 — High-Value Bug Classes
### Injection (P1-P2)
- `sqlmap_scan(url="https://{target}/search?q=1")` — SQLi on search/filter params
- `xss_scan(url="https://{target}")` — XSS in reflected params

### API Testing (P1-P2)
- `arjun_discover(url="https://{target}/api/v1/", method="GET")` — hidden params
- `ffuf_fuzz(url="https://{target}/api/FUZZ")` — endpoint discovery
- Test IDOR: Modify numeric IDs in API endpoints

### Authentication
- Test for default credentials on login pages
- Check for JWT vulnerabilities (alg:none, weak secrets)
- Verify 2FA bypass possibilities

## Quick Wins (Common BB Findings)
- CORS with `Access-Control-Allow-Origin: *` on authenticated endpoints
- Exposed `.git` directory: `nuclei_scan(tags=["exposure"])`
- IDOR in user profile, orders, documents
- Subdomain takeover: `subjack_check(domain="{target}")`
- S3 bucket misconfiguration via subdomain CNAME
- Hidden admin panels: `gobuster_scan(url="https://{target}")`
- Version disclosure in headers (CVE lookup)

## Evidence Collection
- Screenshot every finding with `gowitness_screenshot`
- Save request/response in reports
- Generate PoC with minimal payload
- `generate_report(findings=[...])` — formal report"""
