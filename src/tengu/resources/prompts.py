"""Prompt catalog resource — lists all available Tengu prompts with metadata."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Static prompt catalog
# Each entry: name, category, description, parameters
# Kept in sync with the functions registered in server.py via mcp.prompt().
# ---------------------------------------------------------------------------

_PROMPTS: list[dict] = [
    # ── Workflow ────────────────────────────────────────────────────────────
    {
        "name": "full_pentest",
        "category": "workflow",
        "description": "Full PTES-compliant penetration test across all 7 phases.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "scope", "required": False, "default": "full"},
            {"name": "engagement_type", "required": False, "default": "blackbox"},
        ],
    },
    {
        "name": "quick_recon",
        "category": "workflow",
        "description": "Quick reconnaissance workflow — passive + active recon in 7 steps.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
        ],
    },
    {
        "name": "web_app_assessment",
        "category": "workflow",
        "description": "Web application assessment following OWASP Top 10.",
        "parameters": [
            {"name": "url", "required": True, "default": None},
            {"name": "authenticated", "required": False, "default": False},
        ],
    },
    {
        "name": "api_security_assessment",
        "category": "workflow",
        "description": "Comprehensive API security assessment (REST, GraphQL, gRPC, SOAP).",
        "parameters": [
            {"name": "url", "required": True, "default": None},
            {"name": "api_type", "required": False, "default": "rest"},
            {"name": "authenticated", "required": False, "default": False},
        ],
    },
    {
        "name": "ad_assessment",
        "category": "workflow",
        "description": "Active Directory penetration test — enumeration, Kerberoasting, privilege escalation.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "domain", "required": True, "default": None},
            {"name": "credentials", "required": False, "default": "none"},
        ],
    },
    {
        "name": "container_assessment",
        "category": "workflow",
        "description": "Container and Kubernetes security assessment.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "scope", "required": False, "default": "image"},
        ],
    },
    {
        "name": "cloud_assessment",
        "category": "workflow",
        "description": "Cloud security assessment for AWS, Azure, or GCP.",
        "parameters": [
            {"name": "provider", "required": True, "default": None},
            {"name": "scope", "required": False, "default": "full"},
            {"name": "compliance", "required": False, "default": ""},
        ],
    },
    {
        "name": "bug_bounty_workflow",
        "category": "workflow",
        "description": "Optimized bug bounty reconnaissance and testing workflow.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "focus", "required": False, "default": "web"},
        ],
    },
    {
        "name": "compliance_assessment",
        "category": "workflow",
        "description": "Compliance-focused security assessment (PCI-DSS, HIPAA, SOC2, ISO27001).",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "framework", "required": False, "default": "pci-dss"},
        ],
    },
    {
        "name": "wireless_assessment",
        "category": "workflow",
        "description": "Wireless network penetration test workflow.",
        "parameters": [
            {"name": "interface", "required": False, "default": "wlan0"},
        ],
    },
    # ── Recon ────────────────────────────────────────────────────────────────
    {
        "name": "osint_investigation",
        "category": "recon",
        "description": "Comprehensive OSINT investigation for a domain, IP, email, or organisation.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "target_type", "required": False, "default": "domain"},
            {"name": "depth", "required": False, "default": "standard"},
        ],
    },
    # ── Vulnerability assessment ─────────────────────────────────────────────
    {
        "name": "assess_injection",
        "category": "vuln-assessment",
        "description": "Injection-focused assessment (SQL, XSS, command injection, SSTI).",
        "parameters": [
            {"name": "url", "required": True, "default": None},
            {"name": "injection_type", "required": False, "default": "sql"},
        ],
    },
    {
        "name": "assess_access_control",
        "category": "vuln-assessment",
        "description": "Broken Access Control assessment (OWASP A01).",
        "parameters": [
            {"name": "url", "required": True, "default": None},
        ],
    },
    {
        "name": "assess_crypto",
        "category": "vuln-assessment",
        "description": "Cryptographic failures assessment — TLS, cipher suites, certificate chain (OWASP A02).",
        "parameters": [
            {"name": "host", "required": True, "default": None},
        ],
    },
    {
        "name": "assess_misconfig",
        "category": "vuln-assessment",
        "description": "Security misconfiguration assessment — headers, exposed services, defaults (OWASP A05).",
        "parameters": [
            {"name": "target", "required": True, "default": None},
        ],
    },
    # ── Reporting ────────────────────────────────────────────────────────────
    {
        "name": "executive_report",
        "category": "reporting",
        "description": "Executive-level security report — business impact, risk summary, key recommendations.",
        "parameters": [
            {"name": "findings", "required": True, "default": None},
            {"name": "client_name", "required": True, "default": None},
            {"name": "engagement_date", "required": True, "default": None},
        ],
    },
    {
        "name": "technical_report",
        "category": "reporting",
        "description": "Technical findings report — detailed vulnerability write-ups with PoC and remediation.",
        "parameters": [
            {"name": "findings", "required": True, "default": None},
            {"name": "client_name", "required": True, "default": None},
            {"name": "scope", "required": True, "default": None},
            {"name": "methodology", "required": False, "default": "PTES"},
        ],
    },
    {
        "name": "full_pentest_report",
        "category": "reporting",
        "description": "Complete professional pentest report combining executive and technical sections.",
        "parameters": [
            {"name": "findings", "required": True, "default": None},
            {"name": "client_name", "required": True, "default": None},
            {"name": "scope", "required": True, "default": None},
            {"name": "rules_of_engagement", "required": True, "default": None},
            {"name": "methodology", "required": False, "default": "PTES"},
            {"name": "engagement_dates", "required": False, "default": ""},
        ],
    },
    {
        "name": "remediation_plan",
        "category": "reporting",
        "description": "Prioritised remediation roadmap with effort estimates and quick wins.",
        "parameters": [
            {"name": "findings", "required": True, "default": None},
            {"name": "priority", "required": False, "default": "risk"},
        ],
    },
    {
        "name": "finding_detail",
        "category": "reporting",
        "description": "Detailed finding documentation — description, impact, PoC, CVSS, remediation.",
        "parameters": [
            {"name": "vulnerability", "required": True, "default": None},
            {"name": "target", "required": True, "default": None},
            {"name": "evidence", "required": False, "default": ""},
            {"name": "cvss_vector", "required": False, "default": ""},
        ],
    },
    {
        "name": "risk_matrix",
        "category": "reporting",
        "description": "Risk matrix visualisation — likelihood vs impact grid for all findings.",
        "parameters": [
            {"name": "findings", "required": True, "default": None},
        ],
    },
    {
        "name": "retest_report",
        "category": "reporting",
        "description": "Retest/verification report comparing original findings with remediation status.",
        "parameters": [
            {"name": "original_findings", "required": True, "default": None},
            {"name": "retest_results", "required": True, "default": None},
        ],
    },
    {
        "name": "save_report",
        "category": "reporting",
        "description": "Save a pentest report to the Docker output volume for the report viewer.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "client_name", "required": False, "default": ""},
            {"name": "report_type", "required": False, "default": "full"},
            {"name": "output_format", "required": False, "default": "markdown"},
        ],
    },
    # ── Stealth ──────────────────────────────────────────────────────────────
    {
        "name": "stealth_assessment",
        "category": "stealth",
        "description": "Full pentest with maximum stealth — Tor, proxy rotation, timing jitter, OPSEC.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
        ],
    },
    {
        "name": "opsec_checklist",
        "category": "stealth",
        "description": "Pre-engagement OPSEC checklist — anonymity, attribution control, evidence handling.",
        "parameters": [],
    },
    # ── Quick actions ────────────────────────────────────────────────────────
    {
        "name": "crack_wifi",
        "category": "quick",
        "description": "WiFi password cracking workflow for a specific SSID.",
        "parameters": [
            {"name": "ssid", "required": True, "default": None},
            {"name": "interface", "required": False, "default": "wlan0"},
        ],
    },
    {
        "name": "explore_url",
        "category": "quick",
        "description": "Full exploration of a URL — recon, tech fingerprint, vulnerability scan.",
        "parameters": [
            {"name": "url", "required": True, "default": None},
            {"name": "depth", "required": False, "default": "normal"},
        ],
    },
    {
        "name": "go_stealth",
        "category": "quick",
        "description": "Activate stealth mode: Tor, proxy, User-Agent rotation, timing jitter.",
        "parameters": [
            {"name": "proxy_url", "required": False, "default": ""},
        ],
    },
    {
        "name": "find_secrets",
        "category": "quick",
        "description": "Find leaked credentials and secrets in git repositories or filesystems.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "scan_type", "required": False, "default": "git"},
        ],
    },
    {
        "name": "map_network",
        "category": "quick",
        "description": "Full network mapping — active hosts, open ports, services, OS fingerprinting.",
        "parameters": [
            {"name": "network", "required": True, "default": None},
        ],
    },
    {
        "name": "hunt_subdomains",
        "category": "quick",
        "description": "Aggressive subdomain enumeration combining subfinder, amass, and DNS brute-force.",
        "parameters": [
            {"name": "domain", "required": True, "default": None},
        ],
    },
    {
        "name": "find_vulns",
        "category": "quick",
        "description": "Quickly discover vulnerabilities in a target (IP, domain, or URL).",
        "parameters": [
            {"name": "target", "required": True, "default": None},
        ],
    },
    {
        "name": "pwn_target",
        "category": "quick",
        "description": "Guided exploitation workflow for a specific CVE against an authorised target.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "cve", "required": True, "default": None},
        ],
    },
    {
        "name": "msf_exploit_workflow",
        "category": "quick",
        "description": "Focused Metasploit exploitation workflow for a specific service.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "service", "required": False, "default": "ftp"},
        ],
    },
    # ── Social engineering ───────────────────────────────────────────────────
    {
        "name": "social_engineering_assessment",
        "category": "workflow",
        "description": "Guided workflow for a corporate social engineering security assessment.",
        "parameters": [
            {"name": "target", "required": True, "default": None},
            {"name": "scope", "required": False, "default": "full"},
            {"name": "engagement_type", "required": False, "default": "phishing"},
        ],
    },
]

_CATEGORIES: list[str] = ["workflow", "recon", "vuln-assessment", "reporting", "stealth", "quick"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_prompts_list() -> dict:
    """Return all prompts grouped by category with full metadata."""
    by_category: dict[str, list[dict]] = {c: [] for c in _CATEGORIES}
    for prompt in _PROMPTS:
        by_category[prompt["category"]].append(prompt)

    return {
        "total": len(_PROMPTS),
        "categories": _CATEGORIES,
        "prompts": _PROMPTS,
        "by_category": by_category,
    }


def get_prompts_by_category(category: str) -> list[dict] | None:
    """Return prompts for a specific category, or None if the category is unknown."""
    if category not in _CATEGORIES:
        return None
    return [p for p in _PROMPTS if p["category"] == category]


def list_categories() -> list[str]:
    """Return the list of valid prompt categories."""
    return list(_CATEGORIES)
