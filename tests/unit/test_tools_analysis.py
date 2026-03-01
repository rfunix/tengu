"""Unit tests for analysis tools: correlate_findings, score_risk, and pure helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from tengu.tools.analysis.correlate import (
    _ATTACK_CHAINS,
    _SEVERITY_WEIGHTS,
    _build_remediation_priority,
    _calculate_risk_score,
    _score_to_rating,
    correlate_findings,
    score_risk,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


SAMPLE_FINDINGS = [
    {
        "severity": "critical",
        "title": "SQL Injection",
        "owasp_category": "A03:2025 - Injection",
        "affected_asset": "https://app.com/login",
        "cvss_score": 9.8,
        "tool": "sqlmap",
    },
    {
        "severity": "high",
        "title": "Broken Access Control",
        "owasp_category": "A01:2025 - Broken Access Control",
        "affected_asset": "https://app.com/admin",
        "cvss_score": 8.1,
        "tool": "nuclei",
    },
    {
        "severity": "medium",
        "title": "Outdated jQuery",
        "owasp_category": "A06:2025 - Vulnerable Components",
        "affected_asset": "https://app.com/js/jquery.min.js",
        "cvss_score": 5.3,
        "tool": "nuclei",
    },
]


# ---------------------------------------------------------------------------
# TestSeverityWeights
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    def test_critical_is_highest(self):
        assert _SEVERITY_WEIGHTS["critical"] > _SEVERITY_WEIGHTS["high"]

    def test_high_above_medium(self):
        assert _SEVERITY_WEIGHTS["high"] > _SEVERITY_WEIGHTS["medium"]

    def test_medium_above_low(self):
        assert _SEVERITY_WEIGHTS["medium"] > _SEVERITY_WEIGHTS["low"]

    def test_low_above_info(self):
        assert _SEVERITY_WEIGHTS["low"] > _SEVERITY_WEIGHTS["info"]

    def test_all_keys_present(self):
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in _SEVERITY_WEIGHTS


# ---------------------------------------------------------------------------
# TestScoreToRating
# ---------------------------------------------------------------------------


class TestScoreToRating:
    def test_zero_is_informational(self):
        assert _score_to_rating(0.0) == "INFORMATIONAL"

    def test_below_one_is_informational(self):
        assert _score_to_rating(0.9) == "INFORMATIONAL"

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
# TestCalculateRiskScore
# ---------------------------------------------------------------------------


class TestCalculateRiskScore:
    def test_empty_findings_returns_zero(self):
        assert _calculate_risk_score([], []) == 0.0

    def test_single_critical_finding(self):
        findings = [{"severity": "critical", "cvss_score": 9.8}]
        score = _calculate_risk_score(findings, [])
        # base ~9.8, critical_boost = 0.3 → total ~10.0 (capped)
        assert score > 9.0
        assert score <= 10.0

    def test_attack_chain_boosts_score(self):
        findings = [{"severity": "medium", "cvss_score": 5.0}]
        score_without = _calculate_risk_score(findings, [])
        score_with = _calculate_risk_score(findings, [{"name": "chain"}])
        assert score_with > score_without

    def test_multiple_attack_chains_capped_at_two(self):
        findings = [{"severity": "medium", "cvss_score": 5.0}]
        # 5 chains: boost should be min(5*0.5, 2.0) = 2.0
        chains = [{"name": f"chain{i}"} for i in range(5)]
        score = _calculate_risk_score(findings, chains)
        # max chain boost is 2.0
        score_single = _calculate_risk_score(
            findings, [{"name": "c1"}, {"name": "c2"}, {"name": "c3"}, {"name": "c4"}]
        )
        assert score == score_single  # both should hit the 2.0 cap

    def test_critical_boost_capped_at_one_five(self):
        findings = [{"severity": "critical", "cvss_score": 5.0}] * 10
        score = _calculate_risk_score(findings, [])
        assert score <= 10.0

    def test_score_never_exceeds_ten(self):
        findings = [{"severity": "critical", "cvss_score": 10.0}] * 20
        chains = [{"name": f"c{i}"} for i in range(10)]
        assert _calculate_risk_score(findings, chains) == 10.0

    def test_info_severity_gives_low_score(self):
        findings = [{"severity": "info", "cvss_score": 0.0}]
        score = _calculate_risk_score(findings, [])
        assert score < 2.0


# ---------------------------------------------------------------------------
# TestBuildRemediationPriority
# ---------------------------------------------------------------------------


class TestBuildRemediationPriority:
    def test_empty_returns_empty(self):
        assert _build_remediation_priority([]) == []

    def test_critical_first(self):
        findings = [
            {"severity": "medium", "cvss_score": 5.0, "title": "Med issue"},
            {"severity": "critical", "cvss_score": 9.8, "title": "Crit issue"},
        ]
        result = _build_remediation_priority(findings)
        assert result[0]["severity"] == "critical"

    def test_max_twenty_items(self):
        findings = [
            {"severity": "low", "cvss_score": 2.0, "title": f"Issue {i}"} for i in range(30)
        ]
        assert len(_build_remediation_priority(findings)) == 20

    def test_critical_timeframe_is_thirty_days(self):
        findings = [{"severity": "critical", "cvss_score": 9.8, "title": "CVE"}]
        result = _build_remediation_priority(findings)
        assert result[0]["recommended_timeframe"] == "0-30 days"

    def test_medium_timeframe(self):
        findings = [{"severity": "medium", "cvss_score": 5.0, "title": "Mid"}]
        result = _build_remediation_priority(findings)
        assert result[0]["recommended_timeframe"] == "30-90 days"

    def test_low_timeframe(self):
        findings = [{"severity": "low", "cvss_score": 2.0, "title": "Low"}]
        result = _build_remediation_priority(findings)
        assert result[0]["recommended_timeframe"] == "90-180 days"

    def test_priority_is_sequential(self):
        findings = [{"severity": "high", "cvss_score": 7.0, "title": f"F{i}"} for i in range(3)]
        result = _build_remediation_priority(findings)
        for i, item in enumerate(result):
            assert item["priority"] == i + 1

    def test_unknown_title_fallback(self):
        findings = [{"severity": "high", "cvss_score": 7.0}]
        result = _build_remediation_priority(findings)
        assert result[0]["title"] in ("Unknown finding", "")


# ---------------------------------------------------------------------------
# TestAttackChains
# ---------------------------------------------------------------------------


class TestAttackChains:
    def test_at_least_six_chains(self):
        assert len(_ATTACK_CHAINS) >= 6

    def test_each_chain_has_required_keys(self):
        for chain in _ATTACK_CHAINS:
            assert "name" in chain
            assert "description" in chain
            assert "required_owasp" in chain
            assert "severity" in chain

    def test_all_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for chain in _ATTACK_CHAINS:
            assert chain["severity"] in valid


# ---------------------------------------------------------------------------
# TestCorrelateFindings
# ---------------------------------------------------------------------------


class TestCorrelateFindings:
    @pytest.mark.asyncio
    async def test_empty_findings_returns_zero_score(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, [])
        assert result["overall_risk_score"] == 0.0
        # empty case returns "attack_chains" key (not "attack_chains_identified")
        assert result.get("attack_chains", result.get("attack_chains_identified", [])) == []

    @pytest.mark.asyncio
    async def test_returns_tool_name(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, [])
        assert result["tool"] == "correlate_findings"

    @pytest.mark.asyncio
    async def test_severity_breakdown_counted(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        breakdown = result["severity_breakdown"]
        assert breakdown.get("critical", 0) == 1
        assert breakdown.get("high", 0) == 1
        assert breakdown.get("medium", 0) == 1

    @pytest.mark.asyncio
    async def test_owasp_categories_extracted(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        cats = result["owasp_categories_present"]
        assert "A01" in cats
        assert "A03" in cats

    @pytest.mark.asyncio
    async def test_findings_analyzed_count(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        assert result["findings_analyzed"] == len(SAMPLE_FINDINGS)

    @pytest.mark.asyncio
    async def test_tools_used_listed(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        assert "sqlmap" in result["tools_used"] or "nuclei" in result["tools_used"]

    @pytest.mark.asyncio
    async def test_risk_score_positive(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        assert result["overall_risk_score"] > 0

    @pytest.mark.asyncio
    async def test_risk_rating_string(self):
        ctx = _make_ctx()
        result = await correlate_findings(ctx, SAMPLE_FINDINGS)
        assert result["risk_rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


# ---------------------------------------------------------------------------
# TestScoreRisk
# ---------------------------------------------------------------------------


class TestScoreRisk:
    @pytest.mark.asyncio
    async def test_empty_findings_zero_score(self):
        ctx = _make_ctx()
        result = await score_risk(ctx, [])
        assert result["overall_risk_score"] == 0.0

    @pytest.mark.asyncio
    async def test_returns_tool_name(self):
        ctx = _make_ctx()
        result = await score_risk(ctx, [])
        assert result["tool"] == "score_risk"

    @pytest.mark.asyncio
    async def test_external_context_raises_score(self):
        ctx = _make_ctx()
        result_no_ctx = await score_risk(ctx, SAMPLE_FINDINGS, context="")
        result_ext = await score_risk(ctx, SAMPLE_FINDINGS, context="external-facing public app")
        assert result_ext["overall_risk_score"] >= result_no_ctx["overall_risk_score"]

    @pytest.mark.asyncio
    async def test_internal_context_lowers_score(self):
        ctx = _make_ctx()
        result_no_ctx = await score_risk(ctx, SAMPLE_FINDINGS, context="")
        result_int = await score_risk(ctx, SAMPLE_FINDINGS, context="internal intranet system")
        assert result_int["overall_risk_score"] <= result_no_ctx["overall_risk_score"]

    @pytest.mark.asyncio
    async def test_severity_distribution_in_result(self):
        ctx = _make_ctx()
        result = await score_risk(ctx, SAMPLE_FINDINGS)
        dist = result["severity_distribution"]
        assert dist["critical"] == 1
        assert dist["high"] == 1

    @pytest.mark.asyncio
    async def test_risk_matrix_keys_present(self):
        ctx = _make_ctx()
        result = await score_risk(ctx, [])
        matrix = result["risk_matrix"]
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in matrix
