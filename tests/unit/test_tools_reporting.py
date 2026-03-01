"""Unit tests for report generation tools and pure helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from tengu.tools.reporting.generate import (
    _SEVERITY_WEIGHTS,
    _build_risk_matrix,
    _normalize_finding,
    _score_to_rating,
)
from tengu.types import Finding


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FINDING_COUNTER = 0


def _make_finding(severity: str = "high", title: str = "Test Finding") -> Finding:
    global _FINDING_COUNTER
    _FINDING_COUNTER += 1
    return Finding(
        id=f"TENGU-2026-{_FINDING_COUNTER:03d}",
        title=title,
        severity=severity,
        description="Test description",
        affected_asset="https://example.com",
        tool="nmap",
    )


# ---------------------------------------------------------------------------
# TestScoreToRating
# ---------------------------------------------------------------------------


class TestScoreToRating:
    def test_zero_is_informational(self):
        assert _score_to_rating(0.0) == "INFORMATIONAL"

    def test_one_is_low(self):
        assert _score_to_rating(1.0) == "LOW"

    def test_four_is_medium(self):
        assert _score_to_rating(4.0) == "MEDIUM"

    def test_seven_is_high(self):
        assert _score_to_rating(7.0) == "HIGH"

    def test_nine_is_critical(self):
        assert _score_to_rating(9.0) == "CRITICAL"

    def test_ten_is_critical(self):
        assert _score_to_rating(10.0) == "CRITICAL"


# ---------------------------------------------------------------------------
# TestBuildRiskMatrix
# ---------------------------------------------------------------------------


class TestBuildRiskMatrix:
    def test_empty_findings(self):
        matrix = _build_risk_matrix([])
        assert matrix.critical_count == 0
        assert matrix.high_count == 0
        assert matrix.total == 0
        assert matrix.risk_score == 0.0

    def test_counts_by_severity(self):
        findings = [
            _make_finding("critical"),
            _make_finding("critical"),
            _make_finding("high"),
            _make_finding("medium"),
            _make_finding("low"),
            _make_finding("info"),
        ]
        matrix = _build_risk_matrix(findings)
        assert matrix.critical_count == 2
        assert matrix.high_count == 1
        assert matrix.medium_count == 1
        assert matrix.low_count == 1
        assert matrix.info_count == 1
        assert matrix.total == 6

    def test_risk_score_positive_with_findings(self):
        findings = [_make_finding("critical")]
        matrix = _build_risk_matrix(findings)
        assert matrix.risk_score > 0

    def test_critical_gives_higher_score_than_info(self):
        critical_matrix = _build_risk_matrix([_make_finding("critical")])
        info_matrix = _build_risk_matrix([_make_finding("info")])
        assert critical_matrix.risk_score > info_matrix.risk_score

    def test_score_capped_at_ten(self):
        findings = [_make_finding("critical") for _ in range(20)]
        matrix = _build_risk_matrix(findings)
        assert matrix.risk_score <= 10.0

    def test_total_matches_finding_count(self):
        findings = [_make_finding() for _ in range(7)]
        matrix = _build_risk_matrix(findings)
        assert matrix.total == 7


# ---------------------------------------------------------------------------
# TestSeverityWeights
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    def test_critical_highest_weight(self):
        assert _SEVERITY_WEIGHTS["critical"] > _SEVERITY_WEIGHTS["high"]

    def test_info_lowest_weight(self):
        assert _SEVERITY_WEIGHTS["info"] < _SEVERITY_WEIGHTS["low"]

    def test_all_severities_present(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in _SEVERITY_WEIGHTS


# ---------------------------------------------------------------------------
# TestGenerateReport — async tests for generate_report function
# ---------------------------------------------------------------------------


def _make_finding_dict(
    severity: str = "high",
    title: str = "Test Finding",
    description: str = "Test description",
    affected_asset: str = "https://example.com",
    tool: str = "nmap",
) -> dict:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "affected_asset": affected_asset,
        "tool": tool,
    }


class TestGenerateReport:
    async def test_generate_markdown_report(self, mock_ctx):
        """format='markdown' — output is a string (markdown)."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            output_format="markdown",
        )

        assert result["output_format"] == "markdown"
        assert isinstance(result["content"], str)

    async def test_generate_html_report(self, mock_ctx):
        """format='html' — output contains html tag."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            output_format="html",
        )

        assert result["output_format"] == "html"
        assert "html" in result["content"].lower()

    async def test_generate_with_findings(self, mock_ctx):
        """findings=[{...}] — findings_count matches."""
        from tengu.tools.reporting.generate import generate_report

        findings = [
            _make_finding_dict("critical", "SQL Injection"),
            _make_finding_dict("high", "XSS"),
        ]

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            findings=findings,
        )

        assert result["findings_count"] == 2

    async def test_generate_empty_findings(self, mock_ctx):
        """findings=[] — report still generated with findings_count=0."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            findings=[],
        )

        assert result["findings_count"] == 0
        assert result["content"] != ""

    async def test_generate_with_output_path(self, mock_ctx):
        """output_path set — file written and saved_to returned."""
        from tengu.tools.reporting.generate import generate_report

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "report.md")

            result = await generate_report(
                mock_ctx,
                client_name="TestClient",
                output_path=output_path,
                output_format="markdown",
            )

        assert result["saved_to"] is not None
        assert "report.md" in result["saved_to"]

    async def test_generate_custom_client_name(self, mock_ctx):
        """client_name='My Client Corp' — in result."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="My Client Corp",
        )

        assert result["client_name"] == "My Client Corp"

    async def test_generate_tool_key(self, mock_ctx):
        """Result has tool='generate_report'."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
        )

        assert result["tool"] == "generate_report"

    async def test_generate_findings_with_severity(self, mock_ctx):
        """Finding with severity='critical' — overall_risk_score > 0."""
        from tengu.tools.reporting.generate import generate_report

        findings = [_make_finding_dict("critical", "Critical Vuln")]

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            findings=findings,
        )

        assert result["overall_risk_score"] > 0
        assert result["risk_rating"] in ("CRITICAL", "HIGH", "MEDIUM")

    async def test_generate_invalid_engagement_type(self, mock_ctx):
        """Invalid engagement_type defaults to 'blackbox'."""
        from tengu.tools.reporting.generate import generate_report

        # Should not raise, just default
        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            engagement_type="invalid_type",
        )

        assert result["tool"] == "generate_report"

    async def test_generate_report_type_risk_matrix(self, mock_ctx):
        """report_type='risk_matrix' uses different template but still returns content."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            report_type="risk_matrix",
        )

        assert result["report_type"] == "risk_matrix"
        assert isinstance(result["content"], str)

    async def test_generate_zero_risk_no_findings(self, mock_ctx):
        """No findings — overall_risk_score=0.0."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            findings=[],
        )

        assert result["overall_risk_score"] == 0.0

    async def test_generate_sorted_by_severity(self, mock_ctx):
        """Multiple findings — findings_count is correct regardless of order."""
        from tengu.tools.reporting.generate import generate_report

        findings = [
            _make_finding_dict("low", "Low Finding"),
            _make_finding_dict("critical", "Critical Finding"),
            _make_finding_dict("medium", "Medium Finding"),
        ]

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            findings=findings,
        )

        assert result["findings_count"] == 3

    async def test_generate_no_saved_path_without_output_path(self, mock_ctx):
        """No output_path — saved_to is None."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
        )

        assert result["saved_to"] is None

    async def test_generate_html_escaping(self, mock_ctx):
        """HTML format escapes special characters in content."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            output_format="html",
        )

        # The HTML output should have proper structure
        content = result["content"]
        assert "<!DOCTYPE html>" in content or "<html" in content

    async def test_generate_executive_report_type(self, mock_ctx):
        """report_type='executive' generates report successfully."""
        from tengu.tools.reporting.generate import generate_report

        result = await generate_report(
            mock_ctx,
            client_name="TestClient",
            report_type="executive",
            executive_summary="This is the executive summary.",
        )

        assert result["report_type"] == "executive"
        assert result["tool"] == "generate_report"


# ---------------------------------------------------------------------------
# TestNormalizeFinding — unit tests for _normalize_finding helper
# ---------------------------------------------------------------------------


class TestNormalizeFinding:
    def test_normalize_finding_auto_id(self):
        """Missing 'id' field — auto-generates an ID."""
        f = {"title": "XSS", "severity": "high", "description": "d", "tool": "dalfox"}
        result = _normalize_finding(f, 1)
        assert result["id"].startswith("TENGU-")

    def test_normalize_finding_url_to_affected_asset(self):
        """'url' field is mapped to 'affected_asset' when affected_asset absent."""
        f = {
            "title": "XSS",
            "severity": "high",
            "description": "d",
            "tool": "dalfox",
            "url": "https://example.com/search",
        }
        result = _normalize_finding(f, 1)
        assert result["affected_asset"] == "https://example.com/search"
        assert "url" not in result

    def test_normalize_finding_evidence_string(self):
        """String 'evidence' is converted to list[Evidence dict]."""
        f = {
            "title": "SQLi",
            "severity": "critical",
            "description": "d",
            "tool": "sqlmap",
            "evidence": "sqlmap output here",
        }
        result = _normalize_finding(f, 1)
        assert isinstance(result["evidence"], list)
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["content"] == "sqlmap output here"
        assert result["evidence"][0]["type"] == "tool_output"

    def test_normalize_finding_evidence_list_of_strings(self):
        """List[str] 'evidence' is converted to list[Evidence dict]."""
        f = {
            "title": "SQLi",
            "severity": "critical",
            "description": "d",
            "tool": "sqlmap",
            "evidence": ["line1", "line2"],
        }
        result = _normalize_finding(f, 1)
        assert isinstance(result["evidence"], list)
        assert len(result["evidence"]) == 2
        assert all(e["type"] == "tool_output" for e in result["evidence"])

    def test_normalize_finding_remediation_mapping(self):
        """'remediation' (string) is mapped to 'remediation_short'."""
        f = {
            "title": "XSS",
            "severity": "medium",
            "description": "d",
            "tool": "dalfox",
            "remediation": "Sanitize user input.",
        }
        result = _normalize_finding(f, 1)
        assert result["remediation_short"] == "Sanitize user input."
        assert "remediation" not in result

    def test_normalize_finding_removes_extra_keys(self):
        """Extra keys 'url', 'target', 'parameter' are removed."""
        f = {
            "title": "XSS",
            "severity": "medium",
            "description": "d",
            "tool": "dalfox",
            "affected_asset": "https://example.com",
            "url": "https://example.com/page",
            "target": "example.com",
            "parameter": "q",
        }
        result = _normalize_finding(f, 1)
        assert "url" not in result
        assert "target" not in result
        assert "parameter" not in result

    def test_normalize_finding_preserves_existing_affected_asset(self):
        """'affected_asset' is not overwritten when already present."""
        f = {
            "title": "XSS",
            "severity": "medium",
            "description": "d",
            "tool": "dalfox",
            "affected_asset": "https://example.com/original",
            "url": "https://example.com/other",
        }
        result = _normalize_finding(f, 1)
        assert result["affected_asset"] == "https://example.com/original"

    async def test_generate_report_with_simplified_findings(self, mock_ctx):
        """End-to-end: simplified AI format findings are parsed — findings_count > 0."""
        from tengu.tools.reporting.generate import generate_report

        simplified_findings = [
            {
                "title": "SQL Injection",
                "severity": "critical",
                "description": "The login form is vulnerable to SQLi.",
                "tool": "sqlmap",
                "url": "https://target.com/login",
                "evidence": "GET /login?id=1' -- HTTP/1.1 200 OK",
                "remediation": "Use parameterized queries.",
            },
            {
                "title": "Reflected XSS",
                "severity": "high",
                "description": "The search parameter reflects unescaped input.",
                "tool": "dalfox",
                "url": "https://target.com/search",
                "parameter": "q",
                "evidence": ["Payload: <script>alert(1)</script>", "Response: 200 OK"],
            },
        ]

        result = await generate_report(
            mock_ctx,
            client_name="Acme Corp",
            findings=simplified_findings,
        )

        assert result["findings_count"] == 2
        assert result["overall_risk_score"] > 0
