"""OSINT investigation workflow prompts."""

from __future__ import annotations


def osint_investigation(
    target: str,
    target_type: str = "domain",
    depth: str = "standard",
) -> str:
    """Comprehensive OSINT investigation workflow for authorized reconnaissance.

    Args:
        target: Target to investigate (domain, email, or organization name).
        target_type: Type of target — domain, email, org, ip.
        depth: Investigation depth — quick (5 min), standard (30 min), deep (2+ hours).
    """
    tool_map = {
        "domain": [
            "whois_lookup",
            "dns_enumerate",
            "subfinder_enum",
            "amass_enum",
            "dnsrecon_scan",
            "theharvester_scan",
            "whatweb_scan",
            "shodan_lookup",
        ],
        "ip": ["whois_lookup", "dns_enumerate", "shodan_lookup", "theharvester_scan"],
        "email": ["theharvester_scan"],
        "org": ["theharvester_scan", "shodan_lookup"],
    }
    tools = tool_map.get(target_type, tool_map["domain"])

    depth_notes = {
        "quick": "Run only the first 3 tools. Time budget: ~5 minutes.",
        "standard": "Run all passive tools. Time budget: ~30 minutes.",
        "deep": "Run all tools including active enumeration (amass active, dnsrecon axfr). Time budget: 2+ hours.",
    }

    return f"""# OSINT Investigation: {target} ({target_type})

## Investigation Parameters
- Target: {target}
- Target Type: {target_type}
- Depth: {depth} — {depth_notes.get(depth, depth_notes["standard"])}

## IMPORTANT: Passive-First Approach
Start with passive tools that do NOT interact directly with the target.
Only proceed to active enumeration after passive phase is complete.

## Phase 1 — Passive Reconnaissance (Zero Target Contact)
1. `whois_lookup(target="{target}")` — registrar, owner, dates, name servers
2. `dns_enumerate(domain="{target}")` — A, AAAA, MX, NS, TXT, DKIM records
3. `theharvester_scan(domain="{target}", sources="bing,crtsh,certspotter,dnsdumpster")` — emails, subdomains from public sources
4. `shodan_lookup(target="{target}", query_type="search", query="hostname:{target}")` — Shodan exposure

## Phase 2 — Active Subdomain Enumeration
5. `subfinder_enum(domain="{target}")` — passive subdomain sources (certificates, DNS records)
6. `amass_enum(domain="{target}", mode="passive")` — comprehensive passive mapping

## Phase 3 — Service Fingerprinting (if authorized for active)
7. `whatweb_scan(target="https://{target}", aggression=1)` — web technology stack
8. `dnsrecon_scan(domain="{target}", scan_type="std")` — DNS record deep dive

## Phase 4 — Synthesis
Correlate all findings:
- `correlate_findings(findings=[...])` — identify patterns and attack vectors
- `score_risk(findings=[...])` — prioritize by risk

## Expected Deliverables
- Complete subdomain list with IPs
- Email addresses (potential phishing targets or credential stuffing candidates)
- Technology stack (framework, CMS, WAF, CDN)
- Exposed services and ports (from Shodan)
- DNS configuration weaknesses (SPF, DMARC, zone transfer)
- Recommendations for scope expansion or penetration testing

## Tools for this investigation:
{chr(10).join(f"- {t}" for t in tools)}"""
