"""Unit tests for analysis tools."""

from __future__ import annotations

from tengu.tools.analysis.correlate import (
    _calculate_risk_score,
    _score_to_rating,
)
from tengu.tools.bruteforce.hash_tools import _HASH_PATTERNS


class TestRiskScoring:
    def test_empty_findings_score_zero(self):
        score = _calculate_risk_score([], [])
        assert score == 0.0

    def test_critical_finding_high_score(self):
        findings = [{"severity": "critical", "cvss_score": 9.8}]
        score = _calculate_risk_score(findings, [])
        assert score > 7.0

    def test_info_finding_low_score(self):
        findings = [{"severity": "info", "cvss_score": 0.0}]
        score = _calculate_risk_score(findings, [])
        assert score < 3.0

    def test_attack_chain_boosts_score(self):
        findings = [{"severity": "high", "cvss_score": 7.0}]
        score_no_chain = _calculate_risk_score(findings, [])
        score_with_chain = _calculate_risk_score(findings, [{"name": "Chain 1"}])
        assert score_with_chain > score_no_chain

    def test_score_capped_at_10(self):
        findings = [{"severity": "critical", "cvss_score": 10.0} for _ in range(20)]
        score = _calculate_risk_score(findings, [{"name": c} for c in range(10)])
        assert score <= 10.0


class TestScoreToRating:
    def test_critical_threshold(self):
        assert _score_to_rating(9.5) == "CRITICAL"

    def test_high_threshold(self):
        assert _score_to_rating(7.5) == "HIGH"

    def test_medium_threshold(self):
        assert _score_to_rating(5.0) == "MEDIUM"

    def test_low_threshold(self):
        assert _score_to_rating(2.0) == "LOW"

    def test_info_threshold(self):
        assert _score_to_rating(0.0) == "INFORMATIONAL"


class TestHashIdentification:
    def test_md5_pattern(self):
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        md5_pattern = next(p for p, name, _ in _HASH_PATTERNS if name == "MD5")
        assert md5_pattern.match(md5_hash)

    def test_sha1_pattern(self):
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha1_pattern = next(p for p, name, _ in _HASH_PATTERNS if name == "SHA-1")
        assert sha1_pattern.match(sha1_hash)

    def test_sha256_pattern(self):
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sha256_pattern = next(p for p, name, _ in _HASH_PATTERNS if name == "SHA-256")
        assert sha256_pattern.match(sha256_hash)

    def test_bcrypt_pattern(self):
        bcrypt_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        bcrypt_pattern = next(p for p, name, _ in _HASH_PATTERNS if name == "bcrypt")
        assert bcrypt_pattern.match(bcrypt_hash)
