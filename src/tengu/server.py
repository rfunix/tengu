"""Tengu MCP Server — entry point.

Registers all tools, resources, and prompts with FastMCP.
"""

from __future__ import annotations

import json
import logging
import sys

import structlog
from fastmcp import FastMCP

# ── Tool imports ────────────────────────────────────────────────────────────
from tengu.executor.registry import check_all
from tengu.prompts.ad_assessment import ad_assessment
from tengu.prompts.api_assessment import api_security_assessment
from tengu.prompts.bug_bounty import bug_bounty_workflow
from tengu.prompts.compliance_assessment import compliance_assessment
from tengu.prompts.container_assessment import cloud_assessment, container_assessment

# New prompts v0.2
from tengu.prompts.osint_workflow import osint_investigation

# Workflow prompts
from tengu.prompts.pentest_workflow import full_pentest, quick_recon, web_app_assessment

# Quick action prompts (v0.2.1)
from tengu.prompts.quick_actions import (
    crack_wifi,
    explore_url,
    find_secrets,
    find_vulns,
    go_stealth,
    hunt_subdomains,
    map_network,
    pwn_target,
)

# Report prompts
from tengu.prompts.report_prompts import (
    executive_report,
    finding_detail,
    full_pentest_report,
    remediation_plan,
    retest_report,
    risk_matrix,
    technical_report,
)
from tengu.prompts.stealth_prompts import opsec_checklist, stealth_assessment

# Vulnerability assessment prompts
from tengu.prompts.vuln_assessment import (
    assess_access_control,
    assess_crypto,
    assess_injection,
    assess_misconfig,
)
from tengu.prompts.wireless_assessment import wireless_assessment

# Resources
from tengu.resources.checklists import get_checklist
from tengu.resources.owasp import get_category, get_category_checklist, get_top10_list
from tengu.resources.prompts import get_prompts_by_category, get_prompts_list, list_categories
from tengu.resources.ptes import get_phase, get_phases_overview
from tengu.tools.ad.crackmapexec import nxc_enum
from tengu.tools.ad.enum4linux import enum4linux_scan
from tengu.tools.ad.impacket import impacket_kerberoast

# Core tools (v0.1)
from tengu.tools.analysis.correlate import correlate_findings, score_risk
from tengu.tools.analysis.cve_tools import cve_lookup, cve_search

# New tools v0.2 — API + AD
from tengu.tools.api.arjun import arjun_discover
from tengu.tools.api.graphql import graphql_security_check

# New tools v0.2 — Bruteforce Tier 2
from tengu.tools.bruteforce.cewl import cewl_generate
from tengu.tools.bruteforce.hash_tools import hash_crack, hash_identify
from tengu.tools.bruteforce.hydra import hydra_attack
from tengu.tools.cloud.scoutsuite import scoutsuite_scan
from tengu.tools.container.trivy import trivy_scan
from tengu.tools.exploit.metasploit import (
    msf_module_info,
    msf_run_module,
    msf_search,
    msf_sessions_list,
)
from tengu.tools.exploit.searchsploit import searchsploit_query
from tengu.tools.iac.checkov import checkov_scan
from tengu.tools.injection.sqlmap import sqlmap_scan
from tengu.tools.injection.xss import xss_scan
from tengu.tools.osint.shodan import shodan_lookup
from tengu.tools.osint.theharvester import theharvester_scan
from tengu.tools.osint.webtech import whatweb_scan
from tengu.tools.proxy.zap import zap_active_scan, zap_get_alerts, zap_spider

# New tools v0.2 — OSINT + Recon
from tengu.tools.recon.amass import amass_enum
from tengu.tools.recon.dns import dns_enumerate
from tengu.tools.recon.dnsrecon import dnsrecon_scan
from tengu.tools.recon.gowitness import gowitness_screenshot
from tengu.tools.recon.httrack import httrack_mirror
from tengu.tools.recon.masscan import masscan_scan
from tengu.tools.recon.nmap import nmap_scan
from tengu.tools.recon.subfinder import subfinder_enum
from tengu.tools.recon.subjack import subjack_check
from tengu.tools.recon.whois import whois_lookup
from tengu.tools.reporting.generate import generate_report
from tengu.tools.secrets.gitleaks import gitleaks_scan

# New tools v0.2 — Secrets + Container + Cloud
from tengu.tools.secrets.trufflehog import trufflehog_scan
from tengu.tools.stealth.check_anonymity import check_anonymity
from tengu.tools.stealth.proxy_check import proxy_check
from tengu.tools.stealth.rotate_identity import rotate_identity

# New tools v0.2 — Stealth
from tengu.tools.stealth.tor_check import tor_check
from tengu.tools.stealth.tor_new_identity import tor_new_identity
from tengu.tools.utility import check_tools, validate_target
from tengu.tools.web.cors import test_cors
from tengu.tools.web.ffuf import ffuf_fuzz
from tengu.tools.web.gobuster import gobuster_scan
from tengu.tools.web.headers import analyze_headers
from tengu.tools.web.nikto import nikto_scan
from tengu.tools.web.nuclei import nuclei_scan
from tengu.tools.web.ssl_tls import ssl_tls_check
from tengu.tools.web.testssl import testssl_check

# New tools v0.2 — Web Tier 2
from tengu.tools.web.wpscan import wpscan_scan

# New tools v0.2 — Wireless + IaC
from tengu.tools.wireless.aircrack import aircrack_scan

# ── Logging setup ──────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# ── FastMCP server instance ────────────────────────────────────────────────────
mcp = FastMCP(
    "Tengu",
    instructions=(
        "Tengu is a pentesting MCP server that provides an intelligent abstraction layer "
        "over industry-standard security tools. "
        "Use tools for active scanning and testing, resources for reference data, "
        "and prompts to guide complete pentest workflows. "
        "All targets must be in the configured allowlist (tengu.toml). "
        "Destructive tools (msf_run_module, hydra_attack, impacket_kerberoast) require explicit human authorization. "
        "Stealth mode: enable [stealth] in tengu.toml to route traffic through Tor/proxychains."
    ),
)


# ── TOOLS ──────────────────────────────────────────────────────────────────────

# Utility tools
mcp.tool()(check_tools)
mcp.tool()(validate_target)

# Recon tools (v0.1)
mcp.tool()(nmap_scan)
mcp.tool()(masscan_scan)
mcp.tool()(subfinder_enum)
mcp.tool()(dns_enumerate)
mcp.tool()(whois_lookup)

# Recon tools (v0.2)
mcp.tool()(amass_enum)
mcp.tool()(dnsrecon_scan)
mcp.tool()(subjack_check)
mcp.tool()(gowitness_screenshot)
mcp.tool()(httrack_mirror)

# Web scanning tools (v0.1)
mcp.tool()(nuclei_scan)
mcp.tool()(nikto_scan)
mcp.tool()(ffuf_fuzz)
mcp.tool()(analyze_headers)
mcp.tool()(test_cors)
mcp.tool()(ssl_tls_check)

# Web scanning tools (v0.2)
mcp.tool()(gobuster_scan)
mcp.tool()(wpscan_scan)
mcp.tool()(testssl_check)

# OSINT tools (v0.2)
mcp.tool()(theharvester_scan)
mcp.tool()(shodan_lookup)
mcp.tool()(whatweb_scan)

# Injection tools
mcp.tool()(sqlmap_scan)
mcp.tool()(xss_scan)

# Exploitation tools
mcp.tool()(msf_search)
mcp.tool()(msf_module_info)
mcp.tool()(msf_run_module)
mcp.tool()(msf_sessions_list)
mcp.tool()(searchsploit_query)

# Brute force tools (v0.1)
mcp.tool()(hydra_attack)
mcp.tool()(hash_crack)
mcp.tool()(hash_identify)

# Brute force tools (v0.2)
mcp.tool()(cewl_generate)

# Proxy tools
mcp.tool()(zap_spider)
mcp.tool()(zap_active_scan)
mcp.tool()(zap_get_alerts)

# Analysis tools
mcp.tool()(correlate_findings)
mcp.tool()(score_risk)
mcp.tool()(cve_lookup)
mcp.tool()(cve_search)

# Reporting tools
mcp.tool()(generate_report)

# Secrets tools (v0.2)
mcp.tool()(trufflehog_scan)
mcp.tool()(gitleaks_scan)

# Container tools (v0.2)
mcp.tool()(trivy_scan)

# Cloud tools (v0.2)
mcp.tool()(scoutsuite_scan)

# API tools (v0.2)
mcp.tool()(arjun_discover)
mcp.tool()(graphql_security_check)

# Active Directory tools (v0.2)
mcp.tool()(enum4linux_scan)
mcp.tool()(nxc_enum)
mcp.tool()(impacket_kerberoast)

# Wireless tools (v0.2)
mcp.tool()(aircrack_scan)

# IaC tools (v0.2)
mcp.tool()(checkov_scan)

# Stealth tools (v0.2)
mcp.tool()(tor_check)
mcp.tool()(tor_new_identity)
mcp.tool()(check_anonymity)
mcp.tool()(proxy_check)
mcp.tool()(rotate_identity)


# ── RESOURCES ──────────────────────────────────────────────────────────────────


@mcp.resource("owasp://top10/2025")
def resource_owasp_top10() -> str:
    """OWASP Top 10:2025 — full category list with descriptions."""
    return json.dumps(get_top10_list(), indent=2)


@mcp.resource("owasp://top10/2025/{category_id}")
def resource_owasp_category(category_id: str) -> str:
    """OWASP Top 10:2025 category details (e.g. A01, A02, ..., A10)."""
    data = get_category(category_id)
    if not data:
        return json.dumps({"error": f"Category '{category_id}' not found."})
    return json.dumps(data, indent=2)


@mcp.resource("owasp://top10/2025/{category_id}/checklist")
def resource_owasp_checklist(category_id: str) -> str:
    """Testing checklist for a specific OWASP category."""
    data = get_category_checklist(category_id)
    if not data:
        return json.dumps({"error": f"Category '{category_id}' not found."})
    return json.dumps(data, indent=2)


@mcp.resource("ptes://phases")
def resource_ptes_overview() -> str:
    """PTES methodology — overview of all 7 phases."""
    return json.dumps(get_phases_overview(), indent=2)


@mcp.resource("ptes://phase/{phase_number}")
def resource_ptes_phase(phase_number: str) -> str:
    """PTES phase details (1-7): objectives, activities, tools, deliverables."""
    try:
        num = int(phase_number)
    except ValueError:
        return json.dumps({"error": "Phase number must be an integer (1-7)."})
    data = get_phase(num)
    if not data:
        return json.dumps({"error": f"Phase {num} not found."})
    return json.dumps(data, indent=2)


@mcp.resource("checklist://web-application")
def resource_checklist_web() -> str:
    """Web application penetration test checklist (OWASP Testing Guide)."""
    data = get_checklist("web-application")
    return json.dumps(data or {"error": "Checklist not found."}, indent=2)


@mcp.resource("checklist://api")
def resource_checklist_api() -> str:
    """API penetration test checklist (OWASP API Security Top 10)."""
    data = get_checklist("api")
    return json.dumps(data or {"error": "Checklist not found."}, indent=2)


@mcp.resource("checklist://network")
def resource_checklist_network() -> str:
    """Network infrastructure penetration test checklist."""
    data = get_checklist("network")
    return json.dumps(data or {"error": "Checklist not found."}, indent=2)


@mcp.resource("tools://catalog")
async def resource_tools_catalog() -> str:
    """Catalog of all Tengu-integrated tools with installation status."""
    result = await check_all(verbose=False)
    return json.dumps(result.model_dump(mode="json"), indent=2)


@mcp.resource("tools://{tool_name}/usage")
def resource_tool_usage(tool_name: str) -> str:
    """Usage guide for a specific integrated tool."""
    guides: dict[str, dict] = {  # type: ignore[type-arg]
        "nmap": {
            "name": "nmap",
            "description": "Network port scanner and service detector",
            "mcp_tool": "nmap_scan",
            "common_options": {
                "scan_type": "connect (no root), syn (stealthy, needs root), version (service detection)",
                "timing": "T0-T5 (T3 balanced, T4 fast, T5 aggressive)",
                "ports": "22,80,443 or 1-1024 or 1-65535",
            },
            "examples": [
                "nmap_scan(target='192.168.1.1', scan_type='version', ports='1-1024')",
                "nmap_scan(target='example.com', scan_type='connect', timing='T4')",
            ],
        },
        "nuclei": {
            "name": "nuclei",
            "description": "Template-based vulnerability scanner",
            "mcp_tool": "nuclei_scan",
            "common_options": {
                "severity": "info, low, medium, high, critical",
                "tags": "sqli, xss, rce, misconfiguration, exposure, cve",
                "templates": "cves/, misconfiguration/, exposures/, technologies/",
            },
            "examples": [
                "nuclei_scan(target='https://example.com', severity=['high','critical'])",
                "nuclei_scan(target='https://example.com', tags=['sqli','xss'])",
            ],
        },
        "sqlmap": {
            "name": "sqlmap",
            "description": "Automatic SQL injection detection and exploitation",
            "mcp_tool": "sqlmap_scan",
            "common_options": {
                "level": "1-5 (1=safe, 5=thorough but noisy)",
                "risk": "1-3 (1=safe, 3=heavy OR-based tests)",
                "dbms": "mysql, postgresql, mssql, oracle (auto-detect if empty)",
            },
            "examples": [
                "sqlmap_scan(url='https://example.com/search?q=test', level=1, risk=1)",
                "sqlmap_scan(url='https://example.com/login', method='POST', data='user=admin&pass=test')",
            ],
        },
        "metasploit": {
            "name": "metasploit",
            "description": "Exploitation framework (via RPC API)",
            "mcp_tools": ["msf_search", "msf_module_info", "msf_run_module", "msf_sessions_list"],
            "setup": "Start Metasploit RPC: msfrpcd -P your_password -a 127.0.0.1",
            "env_vars": ["MSF_RPC_PASSWORD", "MSF_RPC_HOST", "MSF_RPC_PORT"],
        },
        "trivy": {
            "name": "trivy",
            "description": "Container and IaC vulnerability scanner",
            "mcp_tool": "trivy_scan",
            "common_options": {
                "scan_type": "image, fs, repo, config, sbom",
                "severity": "HIGH,CRITICAL (comma-separated)",
            },
            "examples": [
                "trivy_scan(target='nginx:latest', scan_type='image')",
                "trivy_scan(target='/path/to/project', scan_type='fs')",
            ],
        },
        "amass": {
            "name": "amass",
            "description": "Attack surface mapping and subdomain enumeration",
            "mcp_tool": "amass_enum",
            "common_options": {
                "mode": "passive (no direct interaction), active (DNS brute-force + zone walk)",
            },
            "examples": [
                "amass_enum(domain='example.com', mode='passive')",
                "amass_enum(domain='example.com', mode='active')",
            ],
        },
    }

    guide = guides.get(tool_name.lower())
    if not guide:
        return json.dumps(
            {
                "error": f"No usage guide for '{tool_name}'",
                "available": list(guides.keys()),
            }
        )
    return json.dumps(guide, indent=2)


# ── NEW v0.2 RESOURCES ─────────────────────────────────────────────────────────


@mcp.resource("mitre://attack/tactics")
def resource_mitre_tactics() -> str:
    """MITRE ATT&CK Enterprise — tactics and key techniques for penetration testing."""
    from pathlib import Path

    data_path = Path(__file__).parent / "resources" / "data" / "mitre_attack.json"
    if data_path.exists():
        return data_path.read_text()
    return json.dumps({"error": "MITRE ATT&CK data not found. Run make install-dev."})


@mcp.resource("mitre://attack/technique/{technique_id}")
def resource_mitre_technique(technique_id: str) -> str:
    """MITRE ATT&CK technique details by ID (e.g. T1595, T1190)."""
    import re
    from pathlib import Path

    # Sanitize technique ID
    safe_id = re.sub(r"[^A-Z0-9.]", "", technique_id.upper())

    data_path = Path(__file__).parent / "resources" / "data" / "mitre_attack.json"
    if not data_path.exists():
        return json.dumps({"error": "MITRE ATT&CK data not found."})

    try:
        import json as _json

        data = _json.loads(data_path.read_text())
        for tactic in data.get("tactics", []):
            for technique in tactic.get("techniques", []):
                if technique.get("id") == safe_id:
                    return _json.dumps({**technique, "tactic": tactic["name"]}, indent=2)
        return json.dumps({"error": f"Technique '{safe_id}' not found."})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.resource("owasp://api-security/top10")
def resource_owasp_api_top10() -> str:
    """OWASP API Security Top 10 (2023) — categories with examples, prevention, and test tools."""
    from pathlib import Path

    data_path = Path(__file__).parent / "resources" / "data" / "owasp_api_top10.json"
    if data_path.exists():
        return data_path.read_text()
    return json.dumps({"error": "OWASP API Security data not found."})


@mcp.resource("owasp://api-security/top10/{category_id}")
def resource_owasp_api_category(category_id: str) -> str:
    """OWASP API Security Top 10 category details (API1-API10)."""
    import re
    from pathlib import Path

    safe_id = re.sub(r"[^A-Za-z0-9]", "", category_id).upper()

    data_path = Path(__file__).parent / "resources" / "data" / "owasp_api_top10.json"
    if not data_path.exists():
        return json.dumps({"error": "OWASP API Security data not found."})

    try:
        import json as _json

        data = _json.loads(data_path.read_text())
        for cat in data.get("categories", []):
            if cat.get("id", "").upper() == safe_id:
                return _json.dumps(cat, indent=2)
        return json.dumps({"error": f"Category '{safe_id}' not found. Use API1-API10."})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.resource("creds://defaults/{product}")
def resource_default_credentials(product: str) -> str:
    """Default credentials for network devices and software by product name."""
    import re
    from pathlib import Path

    safe_product = re.sub(r"[^a-zA-Z0-9 _\-]", "", product).strip().lower()

    data_path = Path(__file__).parent / "resources" / "data" / "default_credentials.json"
    if not data_path.exists():
        return json.dumps({"error": "Default credentials database not found."})

    try:
        import json as _json

        data = _json.loads(data_path.read_text())
        creds = data.get("credentials", [])

        if safe_product in ("all", "list", ""):
            return _json.dumps(
                {"total": len(creds), "categories": data.get("categories", [])}, indent=2
            )

        matches = [
            c
            for c in creds
            if safe_product in c.get("product", "").lower()
            or safe_product in c.get("category", "").lower()
        ]
        return _json.dumps(
            {"product": safe_product, "count": len(matches), "credentials": matches}, indent=2
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.resource("payloads://{payload_type}")
def resource_payloads(payload_type: str) -> str:
    """Security testing payloads by type: sqli, xss, ssti, lfi, ssrf, command_injection."""
    import re
    from pathlib import Path

    safe_type = re.sub(r"[^a-z_]", "", payload_type.lower())

    data_path = Path(__file__).parent / "resources" / "data" / "payloads.json"
    if not data_path.exists():
        return json.dumps({"error": "Payloads database not found."})

    try:
        import json as _json

        data = _json.loads(data_path.read_text())
        payloads = data.get("payloads", {})

        if safe_type in ("all", "list", ""):
            return _json.dumps({"available_types": list(payloads.keys())}, indent=2)

        payload_set = payloads.get(safe_type)
        if not payload_set:
            return json.dumps(
                {
                    "error": f"Payload type '{safe_type}' not found.",
                    "available": list(payloads.keys()),
                }
            )
        return _json.dumps(payload_set, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.resource("stealth://techniques")
def resource_stealth_techniques() -> str:
    """OPSEC and stealth techniques reference — Tor, proxychains, timing, DNS privacy."""
    from pathlib import Path

    data_path = Path(__file__).parent / "resources" / "data" / "stealth_techniques.json"
    if data_path.exists():
        return data_path.read_text()
    return json.dumps({"error": "Stealth techniques data not found."})


@mcp.resource("stealth://proxy-guide")
def resource_proxy_guide() -> str:
    """Proxy configuration guide — Tor, proxychains4, torsocks setup and troubleshooting."""
    from pathlib import Path

    data_path = Path(__file__).parent / "resources" / "data" / "proxy_guide.json"
    if data_path.exists():
        return data_path.read_text()
    return json.dumps({"error": "Proxy guide data not found."})


@mcp.resource("prompts://list")
def resource_prompts_list() -> str:
    """All available Tengu prompts — names, categories, descriptions, and parameters.

    Use this resource to discover what workflow prompts are available before
    suggesting them to the user. Categories: workflow, recon, vuln-assessment,
    reporting, stealth, quick.
    """
    return json.dumps(get_prompts_list(), indent=2)


@mcp.resource("prompts://category/{category}")
def resource_prompts_by_category(category: str) -> str:
    """Prompts filtered by category.

    Valid categories: workflow, recon, vuln-assessment, reporting, stealth, quick.
    Returns the list of prompts in that category with their parameters.
    """
    import re

    category = re.sub(r"[^a-z0-9\-]", "", category.lower())
    prompts = get_prompts_by_category(category)
    if prompts is None:
        return json.dumps(
            {
                "error": f"Unknown category: {category!r}",
                "available_categories": list_categories(),
            }
        )
    return json.dumps({"category": category, "count": len(prompts), "prompts": prompts}, indent=2)


# ── PROMPTS ───────────────────────────────────────────────────────────────────

# Workflow prompts (v0.1)
mcp.prompt()(full_pentest)
mcp.prompt()(quick_recon)
mcp.prompt()(web_app_assessment)

# Vulnerability assessment prompts (v0.1)
mcp.prompt()(assess_injection)
mcp.prompt()(assess_access_control)
mcp.prompt()(assess_crypto)
mcp.prompt()(assess_misconfig)

# Reporting prompts (v0.1)
mcp.prompt()(executive_report)
mcp.prompt()(technical_report)
mcp.prompt()(full_pentest_report)
mcp.prompt()(remediation_plan)
mcp.prompt()(finding_detail)
mcp.prompt()(risk_matrix)
mcp.prompt()(retest_report)

# New prompts (v0.2)
mcp.prompt()(osint_investigation)
mcp.prompt()(stealth_assessment)
mcp.prompt()(opsec_checklist)
mcp.prompt()(api_security_assessment)
mcp.prompt()(ad_assessment)
mcp.prompt()(container_assessment)
mcp.prompt()(cloud_assessment)
mcp.prompt()(bug_bounty_workflow)
mcp.prompt()(compliance_assessment)
mcp.prompt()(wireless_assessment)

# Quick action prompts (v0.2.1)
mcp.prompt()(crack_wifi)
mcp.prompt()(explore_url)
mcp.prompt()(go_stealth)
mcp.prompt()(find_secrets)
mcp.prompt()(map_network)
mcp.prompt()(hunt_subdomains)
mcp.prompt()(find_vulns)
mcp.prompt()(pwn_target)


# ── ENTRY POINT ────────────────────────────────────────────────────────────────


def main() -> None:
    """Start the Tengu MCP server."""
    import argparse

    from tengu.config import get_config

    parser = argparse.ArgumentParser(description="Tengu MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (SSE/HTTP only)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (SSE/HTTP only)")
    args = parser.parse_args()

    cfg = get_config()

    # Set log level from config
    log_level = getattr(logging, cfg.server.log_level.upper(), logging.INFO)
    logging.basicConfig(level=log_level, stream=sys.stderr)

    logger.info(
        "Starting Tengu MCP Server",
        version="0.2.1",
        log_level=cfg.server.log_level,
        allowed_hosts=cfg.targets.allowed_hosts,
        stealth_enabled=cfg.stealth.enabled,
        transport=args.transport,
    )

    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
