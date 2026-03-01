"""Compliance-focused security assessment prompts."""

from __future__ import annotations


def compliance_assessment(target: str, framework: str = "pci-dss") -> str:
    """Compliance-focused security assessment workflow.

    Args:
        target: Target system, application, or cloud environment.
        framework: Compliance framework — pci-dss, hipaa, soc2, iso27001, gdpr, nist.
    """
    framework_map = {
        "pci-dss": {
            "name": "PCI-DSS v4.0",
            "focus": "Payment card data security",
            "key_controls": [
                "Req 1-2: Network security controls and secure configurations",
                "Req 6: Secure software development and vulnerability management",
                "Req 7-8: Access control and identity management",
                "Req 10: Logging and monitoring",
                "Req 11: Security testing (penetration testing required annually)",
            ],
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "focus": "Protected Health Information (PHI)",
            "key_controls": [
                "Access Controls: Unique user ID, emergency access procedure",
                "Audit Controls: Hardware, software, and procedural mechanisms",
                "Integrity Controls: PHI not improperly altered or destroyed",
                "Transmission Security: PHI transmitted over networks",
            ],
        },
        "soc2": {
            "name": "SOC 2 Type II",
            "focus": "Trust Services Criteria",
            "key_controls": [
                "CC1-CC9: Common Criteria (COSO framework)",
                "Security, Availability, Confidentiality, Privacy, Processing Integrity",
            ],
        },
        "iso27001": {
            "name": "ISO/IEC 27001:2022",
            "focus": "Information Security Management System",
            "key_controls": [
                "Annex A: 93 controls across 4 themes",
                "Organizational, People, Physical, Technological controls",
            ],
        },
    }

    fw = framework_map.get(framework.lower(), framework_map["pci-dss"])

    return f"""# Compliance Assessment: {fw["name"]}
## Target: {target} | Focus: {fw["focus"]}

## Framework Key Controls
{chr(10).join(f"- {c}" for c in fw["key_controls"])}

## Phase 1 — Asset Inventory
1. `check_tools()` — document all security tools in use
2. `nmap_scan(target="{target}", scan_type="version", ports="1-65535")` — complete service inventory
3. Document all data flows involving sensitive data

## Phase 2 — Vulnerability Assessment (Required for {fw["name"]})
4. `nuclei_scan(target="{target}", severity=["medium","high","critical"])` — CVE and misconfiguration scanning
5. `ssl_tls_check(host="{target}", port=443)` — encryption in transit
6. `testssl_check(host="{target}", port=443)` — detailed TLS analysis

## Phase 3 — Access Control Review
7. Test for default credentials: check `creds://defaults/` resource
8. `analyze_headers(url="https://{target}")` — security headers
9. `test_cors(url="https://{target}")` — CORS policy

## Phase 4 — Logging and Monitoring Verification
10. Verify audit logs are enabled and centralized
11. Check log retention meets {framework.upper()} requirements
12. Verify alerting on security events

## Phase 5 — Reporting
13. `generate_report(findings=[...], client_name="Client", engagement_type="whitebox")` — compliance report
14. Map each finding to {framework.upper()} control references
15. Provide remediation timeline aligned with {framework.upper()} requirements

## Compliance Gap Analysis
For each finding, document:
- Control ID (e.g. PCI-DSS Req 6.3.3)
- Current State vs Required State
- Risk Rating
- Remediation Effort (Low/Medium/High)
- Owner and deadline"""
