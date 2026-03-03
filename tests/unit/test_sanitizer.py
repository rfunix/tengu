"""Unit tests for input sanitization."""

from __future__ import annotations

import pytest

from tengu.exceptions import InvalidInputError
from tengu.security.sanitizer import (
    sanitize_cve_id,
    sanitize_domain,
    sanitize_free_text,
    sanitize_hash,
    sanitize_port_spec,
    sanitize_target,
    sanitize_url,
)


class TestSanitizeTarget:
    def test_valid_ipv4(self):
        assert sanitize_target("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert sanitize_target("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert sanitize_target("sub.example.com") == "sub.example.com"

    def test_valid_cidr(self):
        result = sanitize_target("192.168.1.0/24")
        assert "192.168.1.0/24" in result

    def test_valid_url(self):
        assert sanitize_target("https://example.com") == "https://example.com"

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("")

    def test_too_long_raises(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("a" * 300)

    def test_shell_injection_semicolon(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("example.com; rm -rf /")

    def test_shell_injection_backtick(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("`id`")

    def test_shell_injection_dollar(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("$(cat /etc/passwd)")

    def test_shell_injection_pipe(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("example.com | cat /etc/passwd")

    def test_shell_injection_ampersand(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("example.com && evil_command")

    def test_invalid_target(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("not a valid target @!#")


class TestSanitizeUrl:
    def test_valid_https(self):
        assert sanitize_url("https://example.com/path") == "https://example.com/path"

    def test_valid_http(self):
        assert sanitize_url("http://example.com") == "http://example.com"

    def test_invalid_scheme_ftp(self):
        with pytest.raises(InvalidInputError):
            sanitize_url("ftp://example.com")

    def test_invalid_scheme_file(self):
        with pytest.raises(InvalidInputError):
            sanitize_url("file:///etc/passwd")

    def test_shell_injection_in_url(self):
        with pytest.raises(InvalidInputError):
            sanitize_url("https://example.com/`id`")


class TestSanitizePortSpec:
    def test_single_port(self):
        assert sanitize_port_spec("80") == "80"

    def test_port_range(self):
        assert sanitize_port_spec("80-443") == "80-443"

    def test_comma_separated(self):
        assert sanitize_port_spec("22,80,443") == "22,80,443"

    def test_mixed(self):
        assert sanitize_port_spec("22,80-90,443") == "22,80-90,443"

    def test_all_ports_alias(self):
        assert sanitize_port_spec("1-65535") == "1-65535"

    def test_port_out_of_range(self):
        with pytest.raises(InvalidInputError):
            sanitize_port_spec("99999")

    def test_shell_injection(self):
        with pytest.raises(InvalidInputError):
            sanitize_port_spec("80;rm -rf /")


class TestSanitizeDomain:
    def test_valid_domain(self):
        assert sanitize_domain("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert sanitize_domain("api.example.com") == "api.example.com"

    def test_wildcard_domain(self):
        assert sanitize_domain("*.example.com") == "*.example.com"

    def test_shell_injection(self):
        with pytest.raises(InvalidInputError):
            sanitize_domain("example.com; ls -la")

    def test_empty(self):
        with pytest.raises(InvalidInputError):
            sanitize_domain("")


class TestSanitizeHash:
    def test_valid_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert sanitize_hash(md5) == md5

    def test_valid_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sanitize_hash(sha256) == sha256

    def test_invalid_chars(self):
        with pytest.raises(InvalidInputError):
            sanitize_hash("abc123; rm -rf /")

    def test_too_long(self):
        with pytest.raises(InvalidInputError):
            sanitize_hash("a" * 2049)


class TestSanitizeCVEId:
    def test_valid_cve(self):
        assert sanitize_cve_id("CVE-2024-1234") == "CVE-2024-1234"

    def test_lowercase_normalized(self):
        assert sanitize_cve_id("cve-2024-1234") == "CVE-2024-1234"

    def test_invalid_format(self):
        with pytest.raises(InvalidInputError):
            sanitize_cve_id("not-a-cve")

    def test_injection_attempt(self):
        with pytest.raises(InvalidInputError):
            sanitize_cve_id("CVE-2024-1234; rm -rf /")


class TestSanitizeFreeText:
    def test_normal_query(self):
        result = sanitize_free_text("apache log4j 2.14")
        assert result == "apache log4j 2.14"

    def test_removes_shell_metacharacters(self):
        result = sanitize_free_text("apache; ls -la")
        assert ";" not in result
        assert "apache" in result

    def test_too_long(self):
        with pytest.raises(InvalidInputError):
            sanitize_free_text("a" * 600)

    def test_empty(self):
        with pytest.raises(InvalidInputError):
            sanitize_free_text("")
