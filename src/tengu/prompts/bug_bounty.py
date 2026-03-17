"""Bug bounty optimized workflow prompts."""

from __future__ import annotations


def bug_bounty_focused(target: str, scope: str = "web") -> str:
    """Focused bug bounty pipeline — minimal tools, maximum signal.

    Uses 5-6 tools in a strict pipeline to avoid context overload and
    false positives. Best for time-boxed solo hunting sessions.

    Args:
        target: Target domain (must be in tengu.toml allowed_hosts).
                Use '*.target.com' in allowed_hosts for subdomain coverage.
        scope: Focus area — web (default), api, network.
    """
    phase3_scan = {
        "web": f'3. `nuclei_scan(target="https://{target}", severity=["high","critical"])` — template-based vulnerability detection',
        "api": f'3. `nuclei_scan(target="https://{target}", tags=["api","exposure"], severity=["high","critical"])` — API-specific templates',
        "network": '3. `cve_search(keyword="<service-name> <version>")` — CVE lookup for each service found in Phase 1',
    }

    phase4_exploit = {
        "web": f"""4. **Conditional — pick ONE based on Phase 3 results:**
   - If SQL injection indicators found: `sqlmap_scan(url="https://{target}/<endpoint>?param=test", level=1, risk=1)`
   - If XSS indicators found: `xss_scan(url="https://{target}/<endpoint>?param=test")`
   - If neither: skip this phase (no blind testing — reduces false positives)""",
        "api": f"""4. **Conditional — pick ONE based on Phase 3 results:**
   - If injection indicators: `sqlmap_scan(url="https://{target}/api/<endpoint>?param=test")`
   - If parameter issues: `arjun_discover(url="https://{target}/api/")` — hidden params
   - If neither: skip""",
        "network": """4. **Conditional — only if CVEs found in Phase 3:**
   - `searchsploit_query(query="<software> <version>")` — check exploit availability
   - Document findings without active exploitation""",
    }

    return f"""# Focused Bug Bounty: {target} | Scope: {scope.upper()}

## IMPORTANT: Allowlist Setup
Before starting, ensure your tengu.toml has:
```toml
allowed_hosts = ["*.{target}"]
```
This allows all discovered subdomains. Without the wildcard, subfinder results
will be blocked by the allowlist.

## Pipeline (5-6 tools max — strict order)

### Phase 1 — Recon (2 tools)
1. `subfinder_enum(domain="{target}")` — passive subdomain enumeration
2. `nmap_scan(target="{target}", scan_type="version", ports="80,443,8080,8443")` — service fingerprint

### Phase 2 — Scan (1 tool)
{phase3_scan.get(scope, phase3_scan["web"])}

### Phase 3 — Exploit (1 tool, conditional)
{phase4_exploit.get(scope, phase4_exploit["web"])}

### Phase 4 — Analysis (2 tools)
5. `correlate_findings(findings=[...])` — deduplicate and identify attack chains
6. `score_risk(findings=[...])` — prioritize by CVSS

## Decision Rules
- **WAF detected in nuclei output?** → Note in report, adjust expectations
- **No findings in Phase 2?** → Stop. Do NOT add more scanners hoping for results
- **Multiple tools report same vuln?** → `correlate_findings` will deduplicate automatically
- **Subdomain blocked by allowlist?** → Add `*.{target}` to tengu.toml

## Tool Count: {5 if scope == "network" else 6} max
Resist the urge to add more tools. More tools = more noise = worse results."""


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
