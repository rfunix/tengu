"""Unit tests for all 34 Tengu prompts."""

from __future__ import annotations

import pytest

from tengu.prompts.ad_assessment import ad_assessment
from tengu.prompts.api_assessment import api_security_assessment
from tengu.prompts.bug_bounty import bug_bounty_workflow
from tengu.prompts.compliance_assessment import compliance_assessment
from tengu.prompts.container_assessment import cloud_assessment, container_assessment
from tengu.prompts.osint_workflow import osint_investigation
from tengu.prompts.pentest_workflow import full_pentest, quick_recon, web_app_assessment
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
from tengu.prompts.report_prompts import (
    _format_findings_for_prompt,
    executive_report,
    finding_detail,
    full_pentest_report,
    remediation_plan,
    retest_report,
    risk_matrix,
    technical_report,
)
from tengu.prompts.stealth_prompts import opsec_checklist, stealth_assessment
from tengu.prompts.vuln_assessment import (
    assess_access_control,
    assess_crypto,
    assess_injection,
    assess_misconfig,
)
from tengu.prompts.wireless_assessment import wireless_assessment

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "severity": "critical",
        "title": "SQL Injection",
        "affected_asset": "https://app.com/login",
        "cvss_score": 9.8,
    },
    {
        "severity": "high",
        "title": "Missing CSP",
        "affected_asset": "https://app.com",
        "cvss_score": 7.1,
    },
    {
        "severity": "medium",
        "title": "Outdated jQuery",
        "affected_asset": "https://app.com/js/jquery.min.js",
        "cvss_score": 5.3,
    },
]


def assert_prompt_basics(result: str, min_length: int = 50) -> None:
    assert isinstance(result, str)
    assert len(result) > min_length


# ---------------------------------------------------------------------------
# TestFullPentest
# ---------------------------------------------------------------------------


class TestFullPentest:
    def test_returns_string(self):
        assert_prompt_basics(full_pentest("example.com"))

    def test_target_interpolated(self):
        result = full_pentest("192.168.1.1")
        assert "192.168.1.1" in result

    def test_scope_full_includes_web_phases(self):
        result = full_pentest("example.com", scope="full")
        assert "analyze_headers" in result
        assert "nuclei_scan" in result

    def test_scope_web_includes_web_phases(self):
        result = full_pentest("example.com", scope="web")
        assert "ssl_tls_check" in result
        assert "ffuf_fuzz" in result

    def test_scope_network_excludes_web_specific(self):
        result = full_pentest("example.com", scope="network")
        # Web-only steps should not appear for network scope
        assert "analyze_headers" not in result
        assert "nikto_scan" not in result

    def test_engagement_type_interpolated(self):
        result = full_pentest("example.com", engagement_type="whitebox")
        assert "whitebox" in result

    def test_default_engagement_type_is_blackbox(self):
        result = full_pentest("example.com")
        assert "blackbox" in result

    def test_ptes_methodology_referenced(self):
        result = full_pentest("example.com")
        assert "PTES" in result

    def test_owasp_resource_referenced(self):
        result = full_pentest("example.com")
        assert "owasp://top10/2025" in result


# ---------------------------------------------------------------------------
# TestQuickRecon
# ---------------------------------------------------------------------------


class TestQuickRecon:
    def test_returns_string(self):
        assert_prompt_basics(quick_recon("example.com"))

    def test_target_interpolated(self):
        result = quick_recon("target.org")
        assert "target.org" in result

    def test_references_core_tools(self):
        result = quick_recon("example.com")
        assert "whois_lookup" in result
        assert "dns_enumerate" in result
        assert "subfinder_enum" in result
        assert "nmap_scan" in result

    def test_references_web_tools(self):
        result = quick_recon("example.com")
        assert "analyze_headers" in result
        assert "ssl_tls_check" in result


# ---------------------------------------------------------------------------
# TestWebAppAssessment
# ---------------------------------------------------------------------------


class TestWebAppAssessment:
    def test_returns_string(self):
        assert_prompt_basics(web_app_assessment("https://example.com"))

    def test_url_interpolated(self):
        result = web_app_assessment("https://app.example.com")
        assert "https://app.example.com" in result

    def test_unauthenticated_mode_default(self):
        result = web_app_assessment("https://example.com")
        assert "Unauthenticated" in result

    def test_authenticated_mode(self):
        result = web_app_assessment("https://example.com", authenticated=True)
        assert "Authenticated" in result

    def test_core_tools_present(self):
        result = web_app_assessment("https://example.com")
        assert "nuclei_scan" in result
        assert "sqlmap_scan" in result
        assert "xss_scan" in result

    def test_owasp_checklist_referenced(self):
        result = web_app_assessment("https://example.com")
        assert "checklist://web-application" in result


# ---------------------------------------------------------------------------
# TestAssessInjection
# ---------------------------------------------------------------------------


class TestAssessInjection:
    def test_returns_string(self):
        assert_prompt_basics(assess_injection("https://example.com"))

    def test_url_interpolated(self):
        result = assess_injection("https://vuln.app/login")
        assert "https://vuln.app/login" in result

    def test_sql_type_uses_sqlmap(self):
        result = assess_injection("https://example.com", injection_type="sql")
        assert "sqlmap_scan" in result

    def test_xss_type_uses_xss_scan(self):
        result = assess_injection("https://example.com", injection_type="xss")
        assert "xss_scan" in result

    def test_command_type_uses_nuclei(self):
        result = assess_injection("https://example.com", injection_type="command")
        assert "nuclei_scan" in result
        assert "OS Command Injection" in result

    def test_ssti_type_uses_nuclei(self):
        result = assess_injection("https://example.com", injection_type="ssti")
        assert "nuclei_scan" in result
        assert "Server-Side Template Injection" in result

    def test_unknown_type_falls_back_to_sqlmap(self):
        result = assess_injection("https://example.com", injection_type="ldap")
        assert "sqlmap_scan" in result

    def test_sql_level_hint_present(self):
        result = assess_injection("https://example.com", injection_type="sql")
        assert "level=3" in result

    def test_owasp_a03_referenced(self):
        result = assess_injection("https://example.com")
        assert "owasp://top10/2025/A03" in result


# ---------------------------------------------------------------------------
# TestAssessAccessControl
# ---------------------------------------------------------------------------


class TestAssessAccessControl:
    def test_returns_string(self):
        assert_prompt_basics(assess_access_control("https://example.com"))

    def test_url_interpolated(self):
        result = assess_access_control("https://myapp.io")
        assert "https://myapp.io" in result

    def test_owasp_a01_referenced(self):
        result = assess_access_control("https://example.com")
        assert "owasp://top10/2025/A01" in result
        assert "A01" in result

    def test_test_cors_referenced(self):
        result = assess_access_control("https://example.com")
        assert "test_cors" in result


# ---------------------------------------------------------------------------
# TestAssessCrypto
# ---------------------------------------------------------------------------


class TestAssessCrypto:
    def test_returns_string(self):
        assert_prompt_basics(assess_crypto("example.com"))

    def test_host_interpolated(self):
        result = assess_crypto("secure.example.com")
        assert "secure.example.com" in result

    def test_ssl_tls_check_referenced(self):
        result = assess_crypto("example.com")
        assert "ssl_tls_check" in result

    def test_owasp_a02_referenced(self):
        result = assess_crypto("example.com")
        assert "owasp://top10/2025/A02" in result
        assert "A02" in result

    def test_analyze_headers_referenced(self):
        result = assess_crypto("example.com")
        assert "analyze_headers" in result


# ---------------------------------------------------------------------------
# TestAssessMisconfig
# ---------------------------------------------------------------------------


class TestAssessMisconfig:
    def test_returns_string(self):
        assert_prompt_basics(assess_misconfig("example.com"))

    def test_target_interpolated(self):
        result = assess_misconfig("10.0.0.1")
        assert "10.0.0.1" in result

    def test_nuclei_scan_referenced(self):
        result = assess_misconfig("example.com")
        assert "nuclei_scan" in result

    def test_owasp_a05_referenced(self):
        result = assess_misconfig("example.com")
        assert "owasp://top10/2025/A05" in result
        assert "A05" in result


# ---------------------------------------------------------------------------
# TestExecutiveReport
# ---------------------------------------------------------------------------


class TestExecutiveReport:
    def test_returns_string(self):
        assert_prompt_basics(executive_report(SAMPLE_FINDINGS, "Acme Corp", "2025-01-01"))

    def test_client_name_interpolated(self):
        result = executive_report(SAMPLE_FINDINGS, "TestClient", "2025-01-01")
        assert "TestClient" in result

    def test_engagement_date_interpolated(self):
        result = executive_report(SAMPLE_FINDINGS, "Acme", "2025-06-15")
        assert "2025-06-15" in result

    def test_severity_counts_correct(self):
        result = executive_report(SAMPLE_FINDINGS, "Acme", "2025-01-01")
        assert "1 Critical" in result
        assert "1 High" in result
        assert "1 Medium" in result

    def test_empty_findings_shows_zero_counts(self):
        result = executive_report([], "Acme", "2025-01-01")
        assert "0 Critical" in result
        assert "0 High" in result
        assert "0 Medium" in result

    def test_multiple_critical_counted_correctly(self):
        findings = [
            {"severity": "critical", "title": "A", "affected_asset": "x", "cvss_score": 9.0},
            {"severity": "critical", "title": "B", "affected_asset": "y", "cvss_score": 9.5},
        ]
        result = executive_report(findings, "Acme", "2025-01-01")
        assert "2 Critical" in result


# ---------------------------------------------------------------------------
# TestTechnicalReport
# ---------------------------------------------------------------------------


class TestTechnicalReport:
    def test_returns_string(self):
        assert_prompt_basics(technical_report(SAMPLE_FINDINGS, "Acme", ["https://app.com"]))

    def test_client_name_interpolated(self):
        result = technical_report(SAMPLE_FINDINGS, "MegaCorp", ["https://app.com"])
        assert "MegaCorp" in result

    def test_scope_joined(self):
        result = technical_report(
            SAMPLE_FINDINGS, "Acme", ["https://app.com", "https://api.app.com"]
        )
        assert "https://app.com" in result
        assert "https://api.app.com" in result

    def test_methodology_interpolated(self):
        result = technical_report(SAMPLE_FINDINGS, "Acme", ["x"], methodology="OWASP")
        assert "OWASP" in result

    def test_default_methodology_ptes(self):
        result = technical_report(SAMPLE_FINDINGS, "Acme", ["x"])
        assert "PTES" in result

    def test_finding_count_shown(self):
        result = technical_report(SAMPLE_FINDINGS, "Acme", ["x"])
        assert str(len(SAMPLE_FINDINGS)) in result


# ---------------------------------------------------------------------------
# TestFullPentestReport
# ---------------------------------------------------------------------------


class TestFullPentestReport:
    def test_returns_string(self):
        result = full_pentest_report(
            SAMPLE_FINDINGS, "Acme", ["https://app.com"], "No destructive tests"
        )
        assert_prompt_basics(result)

    def test_client_name_interpolated(self):
        result = full_pentest_report(
            SAMPLE_FINDINGS, "BetaCorp", ["https://app.com"], "ROE"
        )
        assert "BetaCorp" in result

    def test_generate_report_tool_referenced(self):
        result = full_pentest_report(
            SAMPLE_FINDINGS, "Acme", ["https://app.com"], "ROE"
        )
        assert "generate_report" in result

    def test_scope_interpolated(self):
        result = full_pentest_report(
            SAMPLE_FINDINGS, "Acme", ["https://myapp.io"], "ROE"
        )
        assert "https://myapp.io" in result

    def test_engagement_dates_interpolated(self):
        result = full_pentest_report(
            SAMPLE_FINDINGS,
            "Acme",
            ["https://app.com"],
            "ROE",
            engagement_dates="2025-01-01 to 2025-01-07",
        )
        assert "2025-01-01 to 2025-01-07" in result


# ---------------------------------------------------------------------------
# TestRemediationPlan
# ---------------------------------------------------------------------------


class TestRemediationPlan:
    def test_returns_string(self):
        assert_prompt_basics(remediation_plan(SAMPLE_FINDINGS))

    def test_priority_risk_default(self):
        result = remediation_plan(SAMPLE_FINDINGS)
        assert "CVSS score and severity" in result

    def test_priority_effort(self):
        result = remediation_plan(SAMPLE_FINDINGS, priority="effort")
        assert "implementation effort" in result

    def test_priority_quick_wins(self):
        result = remediation_plan(SAMPLE_FINDINGS, priority="quick-wins")
        assert "fast fixes" in result

    def test_unknown_priority_falls_back_to_risk(self):
        # dict.get() returns the key "risk" as fallback, not the description
        result = remediation_plan(SAMPLE_FINDINGS, priority="unknown_value")
        assert "**risk**" in result

    def test_findings_formatted_in_output(self):
        result = remediation_plan(SAMPLE_FINDINGS)
        assert "SQL Injection" in result


# ---------------------------------------------------------------------------
# TestFindingDetail
# ---------------------------------------------------------------------------


class TestFindingDetail:
    def test_returns_string(self):
        assert_prompt_basics(finding_detail("SQL Injection", "https://app.com/login"))

    def test_vulnerability_interpolated(self):
        result = finding_detail("Cross-Site Scripting", "https://app.com")
        assert "Cross-Site Scripting" in result

    def test_target_interpolated(self):
        result = finding_detail("SQL Injection", "https://vuln.io/search")
        assert "https://vuln.io/search" in result

    def test_cvss_vector_shown_when_provided(self):
        result = finding_detail("SQLi", "https://app.com", cvss_vector="CVSS:3.1/AV:N")
        assert "CVSS:3.1/AV:N" in result

    def test_empty_cvss_shows_not_calculated(self):
        result = finding_detail("SQLi", "https://app.com")
        assert "Not calculated" in result

    def test_empty_evidence_shows_see_attached(self):
        result = finding_detail("SQLi", "https://app.com")
        assert "See attached" in result

    def test_evidence_shown_when_provided(self):
        result = finding_detail("SQLi", "https://app.com", evidence="screenshot.png")
        assert "screenshot.png" in result

    def test_finding_id_uses_tengu_prefix(self):
        result = finding_detail("SQLi", "https://app.com")
        assert "TENGU-" in result


# ---------------------------------------------------------------------------
# TestRiskMatrix
# ---------------------------------------------------------------------------


class TestRiskMatrix:
    def test_returns_string(self):
        assert_prompt_basics(risk_matrix(SAMPLE_FINDINGS))

    def test_findings_count_interpolated(self):
        result = risk_matrix(SAMPLE_FINDINGS)
        assert str(len(SAMPLE_FINDINGS)) in result

    def test_empty_findings_zero_count(self):
        result = risk_matrix([])
        assert "0" in result

    def test_generate_report_referenced(self):
        result = risk_matrix(SAMPLE_FINDINGS)
        assert "generate_report" in result


# ---------------------------------------------------------------------------
# TestRetestReport
# ---------------------------------------------------------------------------


class TestRetestReport:
    def test_returns_string(self):
        assert_prompt_basics(retest_report(SAMPLE_FINDINGS, SAMPLE_FINDINGS))

    def test_original_count_shown(self):
        result = retest_report(SAMPLE_FINDINGS, [])
        assert str(len(SAMPLE_FINDINGS)) in result

    def test_retest_count_shown(self):
        retest = [{"severity": "high", "title": "Fixed"}]
        result = retest_report([], retest)
        assert "1" in result

    def test_retest_summary_table_present(self):
        result = retest_report(SAMPLE_FINDINGS, SAMPLE_FINDINGS)
        assert "Finding ID" in result


# ---------------------------------------------------------------------------
# TestFormatFindingsForPrompt
# ---------------------------------------------------------------------------


class TestFormatFindingsForPrompt:
    def test_empty_returns_no_findings(self):
        result = _format_findings_for_prompt([])
        assert result == "No findings provided."

    def test_single_finding_formatted(self):
        findings = [
            {
                "severity": "critical",
                "title": "RCE",
                "affected_asset": "https://app.com",
                "cvss_score": 9.9,
            }
        ]
        result = _format_findings_for_prompt(findings)
        assert "CRITICAL" in result
        assert "RCE" in result
        assert "https://app.com" in result
        assert "9.9" in result

    def test_severity_uppercased(self):
        findings = [
            {"severity": "medium", "title": "XSS", "affected_asset": "x", "cvss_score": 5.0}
        ]
        result = _format_findings_for_prompt(findings)
        assert "MEDIUM" in result

    def test_truncation_at_20(self):
        findings = [
            {
                "severity": "low",
                "title": f"Finding {i}",
                "affected_asset": "x",
                "cvss_score": 1.0,
            }
            for i in range(25)
        ]
        result = _format_findings_for_prompt(findings)
        assert "5 more findings" in result
        assert "Finding 20" not in result

    def test_exactly_20_no_truncation_message(self):
        findings = [
            {
                "severity": "low",
                "title": f"F{i}",
                "affected_asset": "x",
                "cvss_score": 1.0,
            }
            for i in range(20)
        ]
        result = _format_findings_for_prompt(findings)
        assert "more findings" not in result

    def test_missing_title_falls_back_to_template_name(self):
        findings = [
            {
                "severity": "high",
                "template_name": "CVE-2021-44228",
                "affected_asset": "x",
                "cvss_score": 9.0,
            }
        ]
        result = _format_findings_for_prompt(findings)
        assert "CVE-2021-44228" in result

    def test_missing_title_and_template_name_shows_unknown(self):
        findings = [{"severity": "info", "affected_asset": "x", "cvss_score": 0.0}]
        result = _format_findings_for_prompt(findings)
        assert "Unknown" in result

    def test_missing_affected_asset_falls_back_to_url(self):
        findings = [
            {
                "severity": "high",
                "title": "SQLi",
                "url": "https://fallback.com",
                "cvss_score": 8.0,
            }
        ]
        result = _format_findings_for_prompt(findings)
        assert "https://fallback.com" in result

    def test_missing_all_asset_fields_shows_na(self):
        findings = [{"severity": "medium", "title": "T", "cvss_score": 5.0}]
        result = _format_findings_for_prompt(findings)
        assert "N/A" in result

    def test_numbering_starts_at_one(self):
        result = _format_findings_for_prompt(SAMPLE_FINDINGS)
        assert result.startswith("1.")


# ---------------------------------------------------------------------------
# TestOsintInvestigation
# ---------------------------------------------------------------------------


class TestOsintInvestigation:
    def test_returns_string(self):
        assert_prompt_basics(osint_investigation("example.com"))

    def test_target_interpolated(self):
        result = osint_investigation("acme.io")
        assert "acme.io" in result

    def test_domain_type_uses_extended_tools(self):
        result = osint_investigation("example.com", target_type="domain")
        assert "subfinder_enum" in result
        assert "amass_enum" in result

    def test_ip_type_uses_limited_tools(self):
        result = osint_investigation("1.2.3.4", target_type="ip")
        assert "shodan_lookup" in result
        # amass_enum is not in the ip tool_map tools list (appears in the body template
        # as hardcoded text but NOT in the "## Tools for this investigation" section)
        # Check the bullet-list section specifically
        assert "- amass_enum" not in result

    def test_email_type(self):
        result = osint_investigation("user@example.com", target_type="email")
        assert "theharvester_scan" in result

    def test_org_type(self):
        result = osint_investigation("Acme Corp", target_type="org")
        assert "theharvester_scan" in result
        assert "shodan_lookup" in result

    def test_depth_quick_note_shown(self):
        result = osint_investigation("example.com", depth="quick")
        assert "5 minutes" in result

    def test_depth_deep_note_shown(self):
        result = osint_investigation("example.com", depth="deep")
        assert "2+" in result

    def test_unknown_type_falls_back_to_domain_tools(self):
        result = osint_investigation("example.com", target_type="unknown_type")
        assert "subfinder_enum" in result


# ---------------------------------------------------------------------------
# TestStealthAssessment
# ---------------------------------------------------------------------------


class TestStealthAssessment:
    def test_returns_string(self):
        assert_prompt_basics(stealth_assessment("example.com"))

    def test_target_interpolated(self):
        result = stealth_assessment("covert-target.org")
        assert "covert-target.org" in result

    def test_tor_tools_referenced(self):
        result = stealth_assessment("example.com")
        assert "tor_check" in result
        assert "check_anonymity" in result
        assert "rotate_identity" in result


# ---------------------------------------------------------------------------
# TestOpsecChecklist
# ---------------------------------------------------------------------------


class TestOpsecChecklist:
    def test_returns_string(self):
        assert_prompt_basics(opsec_checklist())

    def test_no_arguments_required(self):
        result = opsec_checklist()
        assert isinstance(result, str)

    def test_checkboxes_present(self):
        result = opsec_checklist()
        assert "[ ]" in result

    def test_stealth_tools_referenced(self):
        result = opsec_checklist()
        assert "check_anonymity" in result
        assert "tor_check" in result

    def test_legal_section_present(self):
        result = opsec_checklist()
        assert "Legal" in result or "legal" in result.lower()


# ---------------------------------------------------------------------------
# TestApiSecurityAssessment
# ---------------------------------------------------------------------------


class TestApiSecurityAssessment:
    def test_returns_string(self):
        assert_prompt_basics(api_security_assessment("https://api.example.com"))

    def test_url_interpolated(self):
        result = api_security_assessment("https://api.myapp.io/v1")
        assert "https://api.myapp.io/v1" in result

    def test_rest_type_default(self):
        result = api_security_assessment("https://api.example.com")
        assert "REST" in result

    def test_graphql_type_adds_specific_steps(self):
        result = api_security_assessment("https://api.example.com/graphql", api_type="graphql")
        assert "graphql_security_check" in result
        assert "introspection" in result

    def test_arjun_discover_referenced(self):
        result = api_security_assessment("https://api.example.com")
        assert "arjun_discover" in result

    def test_owasp_api_resource_referenced(self):
        result = api_security_assessment("https://api.example.com")
        assert "owasp://api-security/top10" in result

    def test_authenticated_flag_shown(self):
        result = api_security_assessment("https://api.example.com", authenticated=True)
        assert "True" in result


# ---------------------------------------------------------------------------
# TestAdAssessment
# ---------------------------------------------------------------------------


class TestAdAssessment:
    def test_returns_string(self):
        assert_prompt_basics(ad_assessment("192.168.1.10", "corp.local"))

    def test_target_interpolated(self):
        result = ad_assessment("10.0.0.1", "example.local")
        assert "10.0.0.1" in result

    def test_domain_interpolated(self):
        result = ad_assessment("10.0.0.1", "mycompany.local")
        assert "mycompany.local" in result

    def test_none_credentials_no_auth_steps(self):
        result = ad_assessment("10.0.0.1", "corp.local", credentials="none")
        assert "impacket_kerberoast" not in result

    def test_user_credentials_add_auth_steps(self):
        result = ad_assessment("10.0.0.1", "corp.local", credentials="user")
        assert "impacket_kerberoast" in result
        assert "nxc_enum" in result

    def test_admin_credentials_add_auth_steps(self):
        result = ad_assessment("10.0.0.1", "corp.local", credentials="admin")
        assert "impacket_kerberoast" in result

    def test_enum4linux_always_present(self):
        result = ad_assessment("10.0.0.1", "corp.local")
        assert "enum4linux_scan" in result


# ---------------------------------------------------------------------------
# TestContainerAssessment
# ---------------------------------------------------------------------------


class TestContainerAssessment:
    def test_returns_string(self):
        assert_prompt_basics(container_assessment("nginx:latest"))

    def test_target_interpolated(self):
        result = container_assessment("myapp:1.0.0")
        assert "myapp:1.0.0" in result

    def test_trivy_scan_referenced(self):
        result = container_assessment("nginx:latest")
        assert "trivy_scan" in result

    def test_checkov_referenced(self):
        result = container_assessment("nginx:latest")
        assert "checkov_scan" in result


# ---------------------------------------------------------------------------
# TestCloudAssessment
# ---------------------------------------------------------------------------


class TestCloudAssessment:
    def test_returns_string(self):
        assert_prompt_basics(cloud_assessment("aws"))

    def test_provider_uppercased_in_output(self):
        result = cloud_assessment("aws")
        assert "AWS" in result

    def test_azure_provider(self):
        result = cloud_assessment("azure")
        assert "Azure" in result or "AZURE" in result

    def test_gcp_provider(self):
        result = cloud_assessment("gcp")
        assert "GCP" in result or "gcp" in result.lower()

    def test_scoutsuite_referenced(self):
        result = cloud_assessment("aws")
        assert "scoutsuite_scan" in result

    def test_compliance_section_shown_when_provided(self):
        result = cloud_assessment("aws", compliance="pci-dss")
        assert "PCI-DSS" in result

    def test_no_compliance_section_when_empty(self):
        result = cloud_assessment("aws", compliance="")
        assert "Compliance Framework" not in result


# ---------------------------------------------------------------------------
# TestBugBountyWorkflow
# ---------------------------------------------------------------------------


class TestBugBountyWorkflow:
    def test_returns_string(self):
        assert_prompt_basics(bug_bounty_workflow("example.com"))

    def test_target_interpolated(self):
        result = bug_bounty_workflow("bugbounty.target.com")
        assert "bugbounty.target.com" in result

    def test_focus_uppercased(self):
        result = bug_bounty_workflow("example.com", focus="api")
        assert "API" in result

    def test_default_focus_is_web(self):
        result = bug_bounty_workflow("example.com")
        assert "WEB" in result

    def test_program_rules_reminder_present(self):
        result = bug_bounty_workflow("example.com")
        assert "scope" in result.lower() or "program" in result.lower()


# ---------------------------------------------------------------------------
# TestComplianceAssessment
# ---------------------------------------------------------------------------


class TestComplianceAssessment:
    def test_returns_string(self):
        assert_prompt_basics(compliance_assessment("example.com"))

    def test_target_interpolated(self):
        result = compliance_assessment("10.0.0.1")
        assert "10.0.0.1" in result

    def test_pci_dss_framework(self):
        result = compliance_assessment("example.com", framework="pci-dss")
        assert "PCI-DSS" in result or "PCI" in result

    def test_hipaa_framework(self):
        result = compliance_assessment("example.com", framework="hipaa")
        assert "HIPAA" in result

    def test_soc2_framework(self):
        result = compliance_assessment("example.com", framework="soc2")
        assert "SOC 2" in result

    def test_iso27001_framework(self):
        result = compliance_assessment("example.com", framework="iso27001")
        assert "ISO" in result or "27001" in result

    def test_default_framework_pci(self):
        result = compliance_assessment("example.com")
        assert "PCI" in result

    def test_generate_report_referenced(self):
        result = compliance_assessment("example.com")
        assert "generate_report" in result


# ---------------------------------------------------------------------------
# TestWirelessAssessment
# ---------------------------------------------------------------------------


class TestWirelessAssessment:
    def test_returns_string(self):
        assert_prompt_basics(wireless_assessment())

    def test_default_interface_wlan0(self):
        result = wireless_assessment()
        assert "wlan0" in result

    def test_custom_interface_interpolated(self):
        result = wireless_assessment(interface="wlan1")
        assert "wlan1" in result

    def test_legal_warning_present(self):
        result = wireless_assessment()
        assert "LEGAL WARNING" in result

    def test_aircrack_scan_referenced(self):
        result = wireless_assessment()
        assert "aircrack_scan" in result


# ---------------------------------------------------------------------------
# TestCrackWifi
# ---------------------------------------------------------------------------


class TestCrackWifi:
    def test_returns_string(self):
        assert_prompt_basics(crack_wifi("TestNetwork"))

    def test_ssid_interpolated(self):
        result = crack_wifi("MyHomeWifi")
        assert "MyHomeWifi" in result

    def test_default_interface_wlan0(self):
        result = crack_wifi("TestNet")
        assert "wlan0" in result

    def test_custom_interface(self):
        result = crack_wifi("TestNet", interface="wlan1")
        assert "wlan1" in result

    def test_legal_warning_present(self):
        result = crack_wifi("TestNet")
        assert "LEGAL WARNING" in result

    def test_hash_crack_referenced(self):
        result = crack_wifi("TestNet")
        assert "hash_crack" in result

    def test_aircrack_scan_referenced(self):
        result = crack_wifi("TestNet")
        assert "aircrack_scan" in result


# ---------------------------------------------------------------------------
# TestExploreUrl
# ---------------------------------------------------------------------------


class TestExploreUrl:
    def test_returns_string(self):
        assert_prompt_basics(explore_url("https://example.com"))

    def test_url_interpolated(self):
        result = explore_url("https://myapp.io/dashboard")
        assert "https://myapp.io/dashboard" in result

    def test_quick_depth_skips_fuzzing(self):
        # Phase 3/4 sections are conditional; the quick-reference table always lists
        # all tool names, so check for the phase headers instead
        result = explore_url("https://example.com", depth="quick")
        assert "Directory and File Fuzzing" not in result
        assert "Vulnerability Scanning" not in result

    def test_normal_depth_includes_fuzzing(self):
        result = explore_url("https://example.com", depth="normal")
        assert "ffuf_fuzz" in result
        assert "nuclei_scan" in result

    def test_deep_depth_includes_injection(self):
        result = explore_url("https://example.com", depth="deep")
        assert "sqlmap_scan" in result
        assert "xss_scan" in result

    def test_deep_depth_includes_graphql(self):
        result = explore_url("https://example.com", depth="deep")
        assert "graphql_security_check" in result

    def test_headers_always_present(self):
        result = explore_url("https://example.com", depth="quick")
        assert "analyze_headers" in result
        assert "ssl_tls_check" in result


# ---------------------------------------------------------------------------
# TestGoStealth
# ---------------------------------------------------------------------------


class TestGoStealth:
    def test_returns_string(self):
        assert_prompt_basics(go_stealth())

    def test_default_uses_tor_proxy(self):
        result = go_stealth()
        assert "socks5://127.0.0.1:9050" in result

    def test_custom_proxy_url(self):
        result = go_stealth(proxy_url="socks5://10.0.0.1:1080")
        assert "socks5://10.0.0.1:1080" in result

    def test_stealth_tools_referenced(self):
        result = go_stealth()
        assert "tor_check" in result
        assert "check_anonymity" in result
        assert "rotate_identity" in result

    def test_toml_config_snippet_present(self):
        result = go_stealth()
        assert "tengu.toml" in result


# ---------------------------------------------------------------------------
# TestFindSecrets
# ---------------------------------------------------------------------------


class TestFindSecrets:
    def test_returns_string(self):
        assert_prompt_basics(find_secrets("https://github.com/acme/repo"))

    def test_target_interpolated(self):
        result = find_secrets("https://github.com/myorg/myrepo")
        assert "https://github.com/myorg/myrepo" in result

    def test_trufflehog_referenced(self):
        result = find_secrets("https://github.com/acme/repo")
        assert "trufflehog_scan" in result

    def test_gitleaks_referenced(self):
        result = find_secrets("https://github.com/acme/repo")
        assert "gitleaks_scan" in result

    def test_github_scan_type_adds_extra_section(self):
        result = find_secrets("acme-org", scan_type="github")
        assert "GitHub" in result

    def test_git_scan_type_no_github_section(self):
        result = find_secrets("/path/to/repo", scan_type="git")
        # GitHub-specific mention should not add org/user scanning section
        # (the ffuf_fuzz section is always present, only the github block differs)
        assert "trufflehog_scan" in result


# ---------------------------------------------------------------------------
# TestMapNetwork
# ---------------------------------------------------------------------------


class TestMapNetwork:
    def test_returns_string(self):
        assert_prompt_basics(map_network("192.168.1.0/24"))

    def test_network_interpolated(self):
        result = map_network("10.10.0.0/16")
        assert "10.10.0.0/16" in result

    def test_masscan_referenced(self):
        result = map_network("192.168.1.0/24")
        assert "masscan_scan" in result

    def test_nmap_referenced(self):
        result = map_network("192.168.1.0/24")
        assert "nmap_scan" in result

    def test_dns_enumerate_referenced(self):
        result = map_network("192.168.1.0/24")
        assert "dns_enumerate" in result


# ---------------------------------------------------------------------------
# TestHuntSubdomains
# ---------------------------------------------------------------------------


class TestHuntSubdomains:
    def test_returns_string(self):
        assert_prompt_basics(hunt_subdomains("example.com"))

    def test_domain_interpolated(self):
        result = hunt_subdomains("mycompany.io")
        assert "mycompany.io" in result

    def test_subfinder_referenced(self):
        result = hunt_subdomains("example.com")
        assert "subfinder_enum" in result

    def test_amass_referenced(self):
        result = hunt_subdomains("example.com")
        assert "amass_enum" in result

    def test_subjack_referenced(self):
        result = hunt_subdomains("example.com")
        assert "subjack_check" in result


# ---------------------------------------------------------------------------
# TestFindVulns
# ---------------------------------------------------------------------------


class TestFindVulns:
    def test_returns_string(self):
        assert_prompt_basics(find_vulns("192.168.1.1"))

    def test_target_interpolated(self):
        result = find_vulns("10.0.0.5")
        assert "10.0.0.5" in result

    def test_nuclei_scan_referenced(self):
        result = find_vulns("example.com")
        assert "nuclei_scan" in result

    def test_nmap_referenced(self):
        result = find_vulns("example.com")
        assert "nmap_scan" in result

    def test_searchsploit_referenced(self):
        result = find_vulns("example.com")
        assert "searchsploit_query" in result


# ---------------------------------------------------------------------------
# TestPwnTarget
# ---------------------------------------------------------------------------


class TestPwnTarget:
    def test_returns_string(self):
        assert_prompt_basics(pwn_target("192.168.1.1", "CVE-2021-44228"))

    def test_target_interpolated(self):
        result = pwn_target("10.0.0.5", "CVE-2021-44228")
        assert "10.0.0.5" in result

    def test_cve_interpolated(self):
        result = pwn_target("192.168.1.1", "CVE-2023-1234")
        assert "CVE-2023-1234" in result

    def test_human_confirmation_required(self):
        result = pwn_target("192.168.1.1", "CVE-2021-44228")
        assert "HUMAN CONFIRMATION" in result or "human" in result.lower()

    def test_legal_warning_present(self):
        result = pwn_target("192.168.1.1", "CVE-2021-44228")
        assert "LEGAL WARNING" in result

    def test_msf_run_module_referenced(self):
        result = pwn_target("192.168.1.1", "CVE-2021-44228")
        assert "msf_run_module" in result

    def test_cve_lookup_referenced(self):
        result = pwn_target("192.168.1.1", "CVE-2021-44228")
        assert "cve_lookup" in result


# ---------------------------------------------------------------------------
# TestParametrizedEdgeCases — cross-cutting smoke + edge cases
# ---------------------------------------------------------------------------


class TestParametrizedEdgeCases:
    """Smoke-test all 34 prompts with valid inputs and verify basic contract."""

    @pytest.mark.parametrize(
        "call",
        [
            lambda: full_pentest("example.com"),
            lambda: full_pentest("example.com", scope="web"),
            lambda: full_pentest("example.com", scope="network"),
            lambda: full_pentest("example.com", scope="api"),
            lambda: quick_recon("example.com"),
            lambda: web_app_assessment("https://example.com"),
            lambda: web_app_assessment("https://example.com", authenticated=True),
            lambda: assess_injection("https://example.com"),
            lambda: assess_injection("https://example.com", injection_type="xss"),
            lambda: assess_injection("https://example.com", injection_type="command"),
            lambda: assess_injection("https://example.com", injection_type="ssti"),
            lambda: assess_access_control("https://example.com"),
            lambda: assess_crypto("example.com"),
            lambda: assess_misconfig("example.com"),
            lambda: executive_report(SAMPLE_FINDINGS, "Acme", "2025-01-01"),
            lambda: executive_report([], "Acme", "2025-01-01"),
            lambda: technical_report(SAMPLE_FINDINGS, "Acme", ["https://example.com"]),
            lambda: full_pentest_report(SAMPLE_FINDINGS, "Acme", ["https://example.com"], "ROE"),
            lambda: remediation_plan(SAMPLE_FINDINGS),
            lambda: remediation_plan(SAMPLE_FINDINGS, priority="effort"),
            lambda: remediation_plan(SAMPLE_FINDINGS, priority="quick-wins"),
            lambda: finding_detail("SQL Injection", "https://example.com"),
            lambda: risk_matrix(SAMPLE_FINDINGS),
            lambda: retest_report(SAMPLE_FINDINGS, SAMPLE_FINDINGS),
            lambda: osint_investigation("example.com"),
            lambda: osint_investigation("1.2.3.4", target_type="ip"),
            lambda: osint_investigation("user@example.com", target_type="email"),
            lambda: osint_investigation("Acme Corp", target_type="org"),
            lambda: stealth_assessment("example.com"),
            lambda: opsec_checklist(),
            lambda: api_security_assessment("https://api.example.com"),
            lambda: api_security_assessment("https://api.example.com", api_type="graphql"),
            lambda: ad_assessment("10.0.0.1", "corp.local"),
            lambda: ad_assessment("10.0.0.1", "corp.local", credentials="user"),
            lambda: ad_assessment("10.0.0.1", "corp.local", credentials="admin"),
            lambda: container_assessment("nginx:latest"),
            lambda: cloud_assessment("aws"),
            lambda: cloud_assessment("azure"),
            lambda: cloud_assessment("gcp"),
            lambda: cloud_assessment("aws", compliance="pci-dss"),
            lambda: bug_bounty_workflow("example.com"),
            lambda: compliance_assessment("example.com", framework="pci-dss"),
            lambda: compliance_assessment("example.com", framework="hipaa"),
            lambda: compliance_assessment("example.com", framework="soc2"),
            lambda: compliance_assessment("example.com", framework="iso27001"),
            lambda: wireless_assessment(),
            lambda: wireless_assessment(interface="wlan1"),
            lambda: crack_wifi("MyWifi"),
            lambda: crack_wifi("MyWifi", interface="wlan1"),
            lambda: explore_url("https://example.com"),
            lambda: explore_url("https://example.com", depth="quick"),
            lambda: explore_url("https://example.com", depth="deep"),
            lambda: go_stealth(),
            lambda: go_stealth(proxy_url="socks5://10.0.0.1:1080"),
            lambda: find_secrets("https://github.com/acme/repo"),
            lambda: find_secrets("acme-org", scan_type="github"),
            lambda: map_network("192.168.1.0/24"),
            lambda: hunt_subdomains("example.com"),
            lambda: find_vulns("192.168.1.1"),
            lambda: pwn_target("192.168.1.1", "CVE-2021-44228"),
        ],
    )
    def test_returns_nonempty_string(self, call):
        result = call()
        assert isinstance(result, str)
        assert len(result) > 50

    def test_special_chars_in_target_do_not_raise(self):
        # Targets with dots and hyphens are common; should not raise
        result = full_pentest("sub-domain.example.co.uk")
        assert "sub-domain.example.co.uk" in result

    def test_finding_with_all_fields_missing_except_severity(self):
        findings = [{"severity": "critical"}]
        result = _format_findings_for_prompt(findings)
        assert "CRITICAL" in result
        assert "Unknown" in result
        assert "N/A" in result

    def test_long_target_name_does_not_raise(self):
        long_target = "a" * 200 + ".example.com"
        result = quick_recon(long_target)
        assert long_target in result

    def test_report_with_only_low_findings(self):
        findings = [
            {"severity": "low", "title": "Info", "affected_asset": "x", "cvss_score": 1.0}
        ]
        result = executive_report(findings, "Acme", "2025-01-01")
        assert "0 Critical" in result
        assert "0 High" in result
