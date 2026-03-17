"""Unit tests for finding deduplication and conflict resolution."""

from __future__ import annotations

from tengu.tools.analysis.correlate import (
    _TOOL_CONFIDENCE,
    _deduplicate_findings,
)
from tengu.tools.analysis.scoring import calculate_risk_score


class TestDeduplicateFindings:
    def test_two_identical_findings_same_endpoint_deduplicated(self):
        """Two tools reporting the same vuln on the same asset → 1 result."""
        findings = [
            {
                "tool": "nikto",
                "severity": "high",
                "affected_asset": "https://example.com/login",
                "owasp_category": "A03",
                "title": "XSS in login",
            },
            {
                "tool": "dalfox",
                "severity": "high",
                "affected_asset": "https://example.com/login",
                "owasp_category": "A03",
                "title": "Reflected XSS",
            },
        ]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 1
        assert len(conflicts) == 1
        # Dalfox has higher confidence than Nikto → should be kept
        assert deduped[0]["tool"] == "dalfox"

    def test_nikto_vs_nuclei_conflict_recorded(self):
        """Nikto 'high' vs Nuclei 'medium' → conflict, higher confidence wins."""
        findings = [
            {
                "tool": "nikto",
                "severity": "high",
                "affected_asset": "https://example.com",
                "owasp_category": "A05",
            },
            {
                "tool": "nuclei",
                "severity": "medium",
                "affected_asset": "https://example.com",
                "owasp_category": "A05",
            },
        ]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 1
        assert len(conflicts) == 1
        # Nuclei (0.85) > Nikto (0.50)
        assert deduped[0]["tool"] == "nuclei"
        assert conflicts[0]["kept"]["tool"] == "nuclei"
        assert conflicts[0]["duplicates"][0]["tool"] == "nikto"

    def test_no_duplicates_returns_all(self):
        """Distinct findings should all be returned unchanged."""
        findings = [
            {
                "tool": "nmap",
                "severity": "info",
                "affected_asset": "192.168.1.1",
                "owasp_category": "A06",
            },
            {
                "tool": "nuclei",
                "severity": "high",
                "affected_asset": "https://example.com",
                "owasp_category": "A03",
            },
        ]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 2
        assert len(conflicts) == 0

    def test_cve_id_based_dedup(self):
        """Findings sharing the same CVE on the same asset should deduplicate."""
        findings = [
            {
                "tool": "nuclei",
                "severity": "critical",
                "affected_asset": "https://example.com",
                "cve_ids": ["CVE-2024-1234"],
            },
            {
                "tool": "nikto",
                "severity": "high",
                "affected_asset": "https://example.com",
                "cve_ids": ["CVE-2024-1234"],
            },
        ]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 1
        assert deduped[0]["tool"] == "nuclei"

    def test_empty_findings(self):
        deduped, conflicts = _deduplicate_findings([])
        assert deduped == []
        assert conflicts == []

    def test_single_finding(self):
        findings = [{"tool": "nmap", "severity": "info", "affected_asset": "x"}]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 1
        assert len(conflicts) == 0

    def test_different_assets_not_deduplicated(self):
        """Same OWASP category but different assets → no dedup."""
        findings = [
            {
                "tool": "nikto",
                "severity": "high",
                "affected_asset": "https://a.example.com",
                "owasp_category": "A03",
            },
            {
                "tool": "nikto",
                "severity": "high",
                "affected_asset": "https://b.example.com",
                "owasp_category": "A03",
            },
        ]
        deduped, conflicts = _deduplicate_findings(findings)
        assert len(deduped) == 2
        assert len(conflicts) == 0


class TestToolConfidence:
    def test_known_tools_have_confidence(self):
        """Verify some key tools are in the confidence map."""
        assert "sqlmap" in _TOOL_CONFIDENCE
        assert "nikto" in _TOOL_CONFIDENCE
        assert "nuclei" in _TOOL_CONFIDENCE
        assert _TOOL_CONFIDENCE["sqlmap"] > _TOOL_CONFIDENCE["nikto"]

    def test_sqlmap_higher_than_nikto(self):
        assert _TOOL_CONFIDENCE["sqlmap"] > _TOOL_CONFIDENCE["nikto"]


class TestRiskScoreWithToolConfidence:
    def test_tool_confidence_lowers_nikto_score(self):
        """Nikto findings should be weighted lower than sqlmap findings."""
        nikto_findings = [
            {"tool": "nikto", "severity": "high"},
            {"tool": "nikto", "severity": "high"},
        ]
        sqlmap_findings = [
            {"tool": "sqlmap", "severity": "high"},
            {"tool": "sqlmap", "severity": "high"},
        ]
        confidence = {"nikto": 0.50, "sqlmap": 0.95}

        nikto_score = calculate_risk_score(nikto_findings, tool_confidence=confidence)
        sqlmap_score = calculate_risk_score(sqlmap_findings, tool_confidence=confidence)
        assert sqlmap_score > nikto_score

    def test_without_tool_confidence_identical(self):
        """Without tool_confidence, same-severity findings score equally."""
        findings_a = [{"tool": "nikto", "severity": "high"}]
        findings_b = [{"tool": "sqlmap", "severity": "high"}]

        score_a = calculate_risk_score(findings_a)
        score_b = calculate_risk_score(findings_b)
        assert score_a == score_b
