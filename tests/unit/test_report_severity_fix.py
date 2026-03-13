"""Regression tests for generate_report severity normalization (P0-1).

Ensures that findings with uppercase/mixed-case severity values are
not silently dropped during report generation.
"""

from __future__ import annotations

from tengu.tools.reporting.generate import _normalize_finding
from tengu.types import Finding


class TestSeverityNormalization:
    """P0-1: Finding with 'Critical' (uppercase) must not be dropped."""

    def test_uppercase_critical_normalized(self) -> None:
        raw = {
            "title": "SQL Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "description": "SQLi in search endpoint",
            "affected_asset": "http://example.com",
        }
        normalized = _normalize_finding(raw, 1)
        assert normalized["severity"] == "critical"

    def test_uppercase_high_normalized(self) -> None:
        raw = {
            "title": "XSS",
            "severity": "HIGH",
            "cvss_score": 7.1,
            "description": "XSS in search",
            "affected_asset": "http://example.com",
        }
        normalized = _normalize_finding(raw, 1)
        assert normalized["severity"] == "high"

    def test_mixed_case_medium_normalized(self) -> None:
        raw = {
            "title": "Missing headers",
            "severity": "Medium",
            "cvss_score": 5.0,
            "description": "Security headers missing",
            "affected_asset": "http://example.com",
        }
        normalized = _normalize_finding(raw, 1)
        assert normalized["severity"] == "medium"

    def test_informational_maps_to_info(self) -> None:
        raw = {
            "title": "Version disclosure",
            "severity": "Informational",
            "description": "Server version exposed",
            "affected_asset": "http://example.com",
        }
        normalized = _normalize_finding(raw, 1)
        assert normalized["severity"] == "info"

    def test_critical_finding_creates_valid_model(self) -> None:
        """Ensure a Critical finding can be parsed into a Finding model."""
        raw = {
            "title": "SQL Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "description": "SQLi in search endpoint",
            "affected_asset": "http://example.com",
        }
        normalized = _normalize_finding(raw, 1)
        finding = Finding(**normalized)
        assert finding.severity == "critical"
        assert finding.cvss_score == 9.8

    def test_seven_findings_all_preserved(self) -> None:
        """Regression: 7 findings including Critical must all be preserved."""
        raw_findings = [
            {
                "title": "SQLi",
                "severity": "Critical",
                "cvss_score": 9.8,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "MD5",
                "severity": "High",
                "cvss_score": 7.5,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "Files",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "XSS",
                "severity": "high",
                "cvss_score": 7.1,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "CORS",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "Headers",
                "severity": "medium",
                "cvss_score": 5.0,
                "description": "d",
                "affected_asset": "a",
            },
            {
                "title": "Version",
                "severity": "Medium",
                "cvss_score": 5.3,
                "description": "d",
                "affected_asset": "a",
            },
        ]
        parsed = []
        for i, raw_f in enumerate(raw_findings):
            normalized = _normalize_finding(raw_f, i + 1)
            parsed.append(Finding(**normalized))

        assert len(parsed) == 7
        assert sum(1 for f in parsed if f.severity == "critical") == 1
        assert sum(1 for f in parsed if f.severity == "high") == 3
        assert sum(1 for f in parsed if f.severity == "medium") == 3

    def test_cvss_score_as_string_coerced(self) -> None:
        raw = {
            "title": "Test",
            "severity": "high",
            "cvss_score": "7.5",
            "description": "d",
            "affected_asset": "a",
        }
        normalized = _normalize_finding(raw, 1)
        assert normalized["cvss_score"] == 7.5
        assert isinstance(normalized["cvss_score"], float)
