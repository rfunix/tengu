"""Tests for the unified risk scoring algorithm."""

from __future__ import annotations

from tengu.tools.analysis.scoring import calculate_risk_score, score_to_rating


class TestCalculateRiskScore:
    def test_empty_findings(self) -> None:
        assert calculate_risk_score([]) == 0.0

    def test_single_critical_uses_cvss(self) -> None:
        findings = [{"severity": "critical", "cvss_score": 9.8}]
        score = calculate_risk_score(findings)
        # base=9.8 + critical_boost=0.3 = 10.0 (clamped)
        assert score == 10.0

    def test_mixed_severities_with_cvss(self) -> None:
        findings = [
            {"severity": "critical", "cvss_score": 9.8},
            {"severity": "high", "cvss_score": 7.5},
            {"severity": "high", "cvss_score": 7.5},
            {"severity": "high", "cvss_score": 7.1},
            {"severity": "medium", "cvss_score": 5.3},
            {"severity": "medium", "cvss_score": 5.0},
            {"severity": "medium", "cvss_score": 5.0},
        ]
        score = calculate_risk_score(findings)
        # base = avg(9.8,7.5,7.5,7.1,5.3,5.0,5.0) = 6.74
        # critical_boost = 0.3
        # total ≈ 7.0
        assert score >= 7.0
        assert score <= 8.0

    def test_falls_back_to_severity_weight_without_cvss(self) -> None:
        findings = [{"severity": "high"}]
        score = calculate_risk_score(findings)
        # base=7.5, no boosts → 7.5
        assert score == 7.5

    def test_informational_excluded_from_scoring(self) -> None:
        findings = [
            {"severity": "high", "cvss_score": 7.5},
            {"severity": "info", "cvss_score": 0.5},
        ]
        score = calculate_risk_score(findings)
        # Only high counted: base=7.5
        assert score == 7.5

    def test_attack_chain_boost(self) -> None:
        findings = [{"severity": "medium", "cvss_score": 5.0}]
        chains = [{"name": "chain1"}, {"name": "chain2"}]
        score_with = calculate_risk_score(findings, attack_chains=chains)
        score_without = calculate_risk_score(findings)
        assert score_with > score_without
        assert score_with == 6.0  # 5.0 + 2*0.5

    def test_context_multiplier(self) -> None:
        findings = [{"severity": "high", "cvss_score": 7.0}]
        score_external = calculate_risk_score(findings, context_multiplier=1.2)
        score_default = calculate_risk_score(findings, context_multiplier=1.0)
        assert score_external > score_default

    def test_clamped_to_10(self) -> None:
        findings = [
            {"severity": "critical", "cvss_score": 10.0},
            {"severity": "critical", "cvss_score": 10.0},
        ]
        chains = [{"name": "c1"}, {"name": "c2"}, {"name": "c3"}, {"name": "c4"}]
        score = calculate_risk_score(
            findings, attack_chains=chains, context_multiplier=1.5,
        )
        assert score == 10.0

    def test_cvss_score_as_string_is_coerced(self) -> None:
        findings = [{"severity": "high", "cvss_score": "7.5"}]
        score = calculate_risk_score(findings)
        assert score == 7.5

    def test_invalid_cvss_score_falls_back_to_zero(self) -> None:
        findings = [{"severity": "high", "cvss_score": "not_a_number"}]
        score = calculate_risk_score(findings)
        # Falls back to 0.0 for that finding
        assert score == 0.0


class TestScoreToRating:
    def test_critical(self) -> None:
        assert score_to_rating(9.0) == "CRITICAL"
        assert score_to_rating(10.0) == "CRITICAL"

    def test_high(self) -> None:
        assert score_to_rating(7.0) == "HIGH"
        assert score_to_rating(8.9) == "HIGH"

    def test_medium(self) -> None:
        assert score_to_rating(4.0) == "MEDIUM"
        assert score_to_rating(6.9) == "MEDIUM"

    def test_low(self) -> None:
        assert score_to_rating(1.0) == "LOW"
        assert score_to_rating(3.9) == "LOW"

    def test_informational(self) -> None:
        assert score_to_rating(0.0) == "INFORMATIONAL"
        assert score_to_rating(0.9) == "INFORMATIONAL"
