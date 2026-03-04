"""Additional allowlist tests — covers internal helpers and uncovered branches."""

from __future__ import annotations

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.security.allowlist import (
    TargetAllowlist,
    _extract_host,
    _host_matches_pattern,
)

# ---------------------------------------------------------------------------
# TestExtractHost — internal helper
# ---------------------------------------------------------------------------


class TestExtractHost:
    def test_plain_ip(self):
        assert _extract_host("192.168.1.1") == "192.168.1.1"

    def test_hostname_lowercased(self):
        assert _extract_host("Example.COM") == "example.com"

    def test_url_https_extracts_host(self):
        assert _extract_host("https://example.com/path?q=1") == "example.com"

    def test_url_http_extracts_host(self):
        assert _extract_host("http://api.example.com:8080/v1") == "api.example.com"

    def test_cidr_returned_as_is(self):
        # Line 31: "/" in target → return target as-is for network matching
        result = _extract_host("192.168.1.0/24")
        assert result == "192.168.1.0/24"

    def test_strips_whitespace(self):
        assert _extract_host("  example.com  ") == "example.com"

    def test_ipv6_returned_as_is(self):
        result = _extract_host("::1")
        assert result == "::1"


# ---------------------------------------------------------------------------
# TestHostMatchesPattern — internal helper (edge cases)
# ---------------------------------------------------------------------------


class TestHostMatchesPattern:
    def test_exact_hostname_match(self):
        assert _host_matches_pattern("example.com", "example.com") is True

    def test_exact_hostname_no_match(self):
        assert _host_matches_pattern("evil.com", "example.com") is False

    def test_wildcard_matches_subdomain(self):
        assert _host_matches_pattern("api.example.com", "*.example.com") is True

    def test_wildcard_no_match(self):
        assert _host_matches_pattern("api.evil.com", "*.example.com") is False

    def test_cidr_matches_ip_in_range(self):
        assert _host_matches_pattern("192.168.1.50", "192.168.1.0/24") is True

    def test_cidr_no_match_ip_outside(self):
        assert _host_matches_pattern("10.0.0.1", "192.168.1.0/24") is False

    def test_hostname_against_cidr_pattern_returns_false(self):
        # Lines 54-58: inner ValueError when host is not an IP
        result = _host_matches_pattern("example.com", "192.168.1.0/24")
        assert result is False

    def test_invalid_cidr_pattern_returns_false(self):
        # Lines 56-58: outer ValueError when pattern is invalid CIDR
        result = _host_matches_pattern("192.168.1.1", "999.999.999.999/99")
        assert result is False

    def test_ip_vs_ip_exact_match(self):
        assert _host_matches_pattern("10.0.0.1", "10.0.0.1") is True

    def test_ip_vs_ip_no_match(self):
        assert _host_matches_pattern("10.0.0.1", "10.0.0.2") is False

    def test_pattern_case_normalized(self):
        assert _host_matches_pattern("example.com", "Example.COM") is True


# ---------------------------------------------------------------------------
# TestTargetAllowlistExtra — additional branch coverage
# ---------------------------------------------------------------------------


class TestTargetAllowlistExtra:
    def test_cidr_target_subnet_of_cidr_allowlist(self):
        # 192.168.1.0/24 is a subnet of 192.168.0.0/16 — should be allowed
        al = TargetAllowlist(
            allowed_hosts=["192.168.0.0/16"],
            blocked_hosts=[],
        )
        al.check("192.168.1.0/24")  # must not raise

    def test_cidr_target_not_subnet_of_cidr_allowlist(self):
        # 10.0.0.0/24 is NOT within 192.168.0.0/16 — must be rejected
        al = TargetAllowlist(
            allowed_hosts=["192.168.0.0/16"],
            blocked_hosts=[],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("10.0.0.0/24")

    def test_url_with_port_extracts_host(self):
        al = TargetAllowlist(allowed_hosts=["api.example.com"], blocked_hosts=[])
        al.check("https://api.example.com:443/endpoint")

    def test_multiple_blocked_patterns_first_match_wins(self):
        al = TargetAllowlist(
            allowed_hosts=[],
            blocked_hosts=["evil.com", "bad.org"],
        )
        with pytest.raises(TargetNotAllowedError, match="evil.com"):
            al.check("evil.com")

    def test_wildcard_blocked_pattern(self):
        al = TargetAllowlist(
            allowed_hosts=["*.example.com"],
            blocked_hosts=["*.gov"],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("anything.gov")

    def test_empty_allowed_and_blocked_permits(self):
        al = TargetAllowlist(allowed_hosts=[], blocked_hosts=[])
        # Should NOT raise — logs warning but allows
        al.check("any-target.com")

    def test_is_allowed_true(self):
        al = TargetAllowlist(allowed_hosts=["example.com"], blocked_hosts=[])
        assert al.is_allowed("example.com") is True

    def test_is_allowed_false_not_in_list(self):
        al = TargetAllowlist(allowed_hosts=["example.com"], blocked_hosts=[])
        assert al.is_allowed("other.com") is False

    def test_is_allowed_false_blocked(self):
        al = TargetAllowlist(allowed_hosts=[], blocked_hosts=["blocked.com"])
        assert al.is_allowed("blocked.com") is False
