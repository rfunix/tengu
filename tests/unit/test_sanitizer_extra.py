"""Additional sanitizer tests covering uncovered branches.

Complements tests/unit/test_sanitizer.py — focuses on the functions
and edge cases not yet exercised: wordlist path, scan_type, severity,
repo_url, docker_image, proxy_url, and missed branches in existing
sanitizers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tengu.exceptions import InvalidInputError
from tengu.security.sanitizer import (
    sanitize_cidr,
    sanitize_docker_image,
    sanitize_domain,
    sanitize_free_text,
    sanitize_port_spec,
    sanitize_proxy_url,
    sanitize_repo_url,
    sanitize_scan_type,
    sanitize_severity,
    sanitize_target,
    sanitize_url,
    sanitize_wordlist_path,
)

# ---------------------------------------------------------------------------
# sanitize_target — uncovered branches
# ---------------------------------------------------------------------------


class TestSanitizeTargetExtra:
    def test_target_with_space_invalid(self):
        # Space is not a shell metacharacter but fails hostname pattern → line 85
        with pytest.raises(InvalidInputError, match="not a valid"):
            sanitize_target("invalid hostname")

    def test_valid_ipv6_address(self):
        result = sanitize_target("::1")
        assert result == "::1"

    def test_hostname_lowercased(self):
        result = sanitize_target("Example.COM")
        assert result == "example.com"

    def test_url_target_delegates_to_sanitize_url(self):
        result = sanitize_target("https://example.com/path")
        assert "example.com" in result

    def test_cidr_target_normalized(self):
        result = sanitize_target("10.0.0.1/24")
        assert "/24" in result

    def test_embedded_newline_in_target_rejected(self):
        # strip() removes trailing \n, but embedded newline must be caught
        with pytest.raises(InvalidInputError):
            sanitize_target("example.com\nextra")

    def test_embedded_carriage_return_in_target_rejected(self):
        with pytest.raises(InvalidInputError):
            sanitize_target("example.com\rextra")


# ---------------------------------------------------------------------------
# sanitize_url — uncovered branches
# ---------------------------------------------------------------------------


class TestSanitizeUrlExtra:
    def test_url_no_host_raises(self):
        # Parsed scheme=https, netloc="" → line 104
        with pytest.raises(InvalidInputError, match="no host"):
            sanitize_url("https://")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(InvalidInputError, match="only http"):
            sanitize_url("ftp://example.com/file")

    def test_newline_in_url_rejected(self):
        with pytest.raises(InvalidInputError):
            sanitize_url("https://example.com\n/path")


# ---------------------------------------------------------------------------
# sanitize_domain — uncovered branches
# ---------------------------------------------------------------------------


class TestSanitizeDomainExtra:
    def test_invalid_domain_raises(self):
        # underscore is not in hostname pattern → line 125
        with pytest.raises(InvalidInputError, match="not a valid domain"):
            sanitize_domain("not_a_domain")

    def test_domain_with_space_raises(self):
        with pytest.raises(InvalidInputError):
            sanitize_domain("example .com")

    def test_domain_lowercased(self):
        result = sanitize_domain("Example.COM")
        assert result == "example.com"

    def test_wildcard_domain_accepted(self):
        result = sanitize_domain("*.example.com")
        assert result == "*.example.com"


# ---------------------------------------------------------------------------
# sanitize_cidr
# ---------------------------------------------------------------------------


class TestSanitizeCidr:
    def test_valid_cidr_v4(self):
        result = sanitize_cidr("192.168.1.0/24")
        assert "192.168.1.0/24" in result

    def test_invalid_cidr_raises(self):
        with pytest.raises(InvalidInputError, match="invalid CIDR"):
            sanitize_cidr("not-a-cidr")

    def test_host_bits_set_normalized(self):
        # strict=False normalizes 192.168.1.1/24 → 192.168.1.0/24
        result = sanitize_cidr("192.168.1.1/24")
        assert result == "192.168.1.0/24"


# ---------------------------------------------------------------------------
# sanitize_port_spec — uncovered aliases
# ---------------------------------------------------------------------------


class TestSanitizePortSpecExtra:
    def test_star_alias(self):
        assert sanitize_port_spec("*") == "1-65535"

    def test_all_alias(self):
        assert sanitize_port_spec("all") == "1-65535"

    def test_dash_alias(self):
        assert sanitize_port_spec("-") == "1-65535"

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError, match="cannot be empty"):
            sanitize_port_spec("")

    def test_port_zero_raises(self):
        with pytest.raises(InvalidInputError, match="out of range"):
            sanitize_port_spec("0")


# ---------------------------------------------------------------------------
# sanitize_wordlist_path
# ---------------------------------------------------------------------------


class TestSanitizeWordlistPath:
    def test_valid_home_path(self):
        # Path.home() is in the allowed_prefixes — use a virtual path (no file needed)
        home_wordlist = str(Path.home() / ".wordlists" / "rockyou.txt")
        result = sanitize_wordlist_path(home_wordlist)
        assert "rockyou.txt" in result

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError, match="cannot be empty"):
            sanitize_wordlist_path("")

    def test_shell_injection_raises(self):
        with pytest.raises(InvalidInputError, match="forbidden"):
            sanitize_wordlist_path("/tmp/list.txt; rm -rf /")

    def test_path_outside_allowed_raises(self):
        # /var/secret is outside all allowed prefixes
        with pytest.raises(InvalidInputError, match="outside allowed"):
            sanitize_wordlist_path("/var/secret/passwords.txt")

    def test_usr_share_path_accepted(self):
        result = sanitize_wordlist_path("/usr/share/wordlists/rockyou.txt")
        assert "rockyou.txt" in result

    def test_opt_path_accepted(self):
        result = sanitize_wordlist_path("/opt/seclists/Passwords/top1000.txt")
        assert "top1000.txt" in result


# ---------------------------------------------------------------------------
# sanitize_scan_type
# ---------------------------------------------------------------------------


class TestSanitizeScanType:
    def test_valid_type_returned(self):
        result = sanitize_scan_type("syn", ["syn", "connect", "udp"])
        assert result == "syn"

    def test_valid_type_normalized_lowercase(self):
        result = sanitize_scan_type("SYN", ["syn", "connect"])
        assert result == "syn"

    def test_invalid_type_raises(self):
        with pytest.raises(InvalidInputError, match="must be one of"):
            sanitize_scan_type("invalid", ["syn", "connect"])

    def test_stripped_whitespace(self):
        result = sanitize_scan_type("  connect  ", ["syn", "connect"])
        assert result == "connect"

    def test_custom_field_name_in_error(self):
        with pytest.raises(InvalidInputError) as exc_info:
            sanitize_scan_type("bad", ["a", "b"], field="mode")
        assert "mode" in str(exc_info.value)


# ---------------------------------------------------------------------------
# sanitize_severity
# ---------------------------------------------------------------------------


class TestSanitizeSeverity:
    def test_single_string_valid(self):
        result = sanitize_severity("critical")
        assert result == ["critical"]

    def test_comma_separated_string(self):
        result = sanitize_severity("high,medium,low")
        assert sorted(result) == ["high", "low", "medium"]

    def test_list_input(self):
        result = sanitize_severity(["critical", "high"])
        assert sorted(result) == ["critical", "high"]

    def test_uppercased_normalized_to_lower(self):
        result = sanitize_severity(["HIGH", "CRITICAL"])
        assert "high" in result
        assert "critical" in result

    def test_all_valid_levels(self):
        all_levels = ["info", "low", "medium", "high", "critical"]
        result = sanitize_severity(all_levels)
        assert sorted(result) == sorted(all_levels)

    def test_invalid_severity_raises(self):
        with pytest.raises(InvalidInputError, match="invalid severities"):
            sanitize_severity(["critical", "supercritical"])

    def test_invalid_in_list_raises(self):
        with pytest.raises(InvalidInputError):
            sanitize_severity(["high", "unknown", "critical"])


# ---------------------------------------------------------------------------
# sanitize_repo_url
# ---------------------------------------------------------------------------


class TestSanitizeRepoUrl:
    def test_valid_https_url(self):
        url = "https://github.com/user/repo"
        assert sanitize_repo_url(url) == url

    def test_valid_https_git_url(self):
        url = "https://github.com/user/repo.git"
        assert sanitize_repo_url(url) == url

    def test_valid_git_at_url(self):
        url = "git@github.com:user/repo.git"
        assert sanitize_repo_url(url) == url

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError, match="cannot be empty"):
            sanitize_repo_url("")

    def test_too_long_raises(self):
        with pytest.raises(InvalidInputError, match="too long"):
            sanitize_repo_url("https://github.com/" + "a" * 490)

    def test_shell_metachar_raises(self):
        with pytest.raises(InvalidInputError, match="forbidden"):
            sanitize_repo_url("https://github.com/user/repo; rm -rf /")

    def test_invalid_scheme_raises(self):
        with pytest.raises(InvalidInputError, match="not a valid git"):
            sanitize_repo_url("ftp://github.com/user/repo")

    def test_embedded_newline_raises(self):
        # strip() removes trailing \n; embedded newline must be caught
        with pytest.raises(InvalidInputError):
            sanitize_repo_url("https://github.com/user\n/repo")


# ---------------------------------------------------------------------------
# sanitize_docker_image
# ---------------------------------------------------------------------------


class TestSanitizeDockerImage:
    def test_valid_simple_image(self):
        result = sanitize_docker_image("nginx:latest")
        assert result == "nginx:latest"

    def test_valid_with_registry(self):
        result = sanitize_docker_image("gcr.io/myproject/myimage:v1.0")
        assert "gcr.io" in result

    def test_valid_no_tag(self):
        result = sanitize_docker_image("ubuntu")
        assert result == "ubuntu"

    def test_result_is_lowercased(self):
        result = sanitize_docker_image("NGINX:Latest")
        assert result == "nginx:latest"

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError, match="cannot be empty"):
            sanitize_docker_image("")

    def test_too_long_raises(self):
        with pytest.raises(InvalidInputError, match="too long"):
            sanitize_docker_image("nginx:" + "a" * 260)

    def test_shell_metachar_raises(self):
        with pytest.raises(InvalidInputError, match="forbidden"):
            sanitize_docker_image("nginx:latest; rm -rf /")

    def test_invalid_image_name_raises(self):
        # Space is not a shell metachar but fails the docker image pattern
        with pytest.raises(InvalidInputError, match="not a valid Docker"):
            sanitize_docker_image("nginx invalid image")


# ---------------------------------------------------------------------------
# sanitize_proxy_url
# ---------------------------------------------------------------------------


class TestSanitizeProxyUrl:
    def test_valid_socks5(self):
        url = "socks5://127.0.0.1:9050"
        assert sanitize_proxy_url(url) == url

    def test_valid_socks4(self):
        url = "socks4://127.0.0.1:1080"
        assert sanitize_proxy_url(url) == url

    def test_valid_http_proxy(self):
        url = "http://proxy.example.com:8080"
        assert sanitize_proxy_url(url) == url

    def test_valid_https_proxy(self):
        url = "https://proxy.example.com:3128"
        assert sanitize_proxy_url(url) == url

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError, match="cannot be empty"):
            sanitize_proxy_url("")

    def test_too_long_raises(self):
        with pytest.raises(InvalidInputError, match="too long"):
            sanitize_proxy_url("socks5://127.0.0.1:9050/" + "a" * 200)

    def test_shell_metachar_raises(self):
        with pytest.raises(InvalidInputError, match="forbidden"):
            sanitize_proxy_url("socks5://127.0.0.1:9050; rm -rf /")

    def test_invalid_scheme_raises(self):
        with pytest.raises(InvalidInputError, match="not a valid proxy"):
            sanitize_proxy_url("ftp://proxy.example.com:21")

    def test_embedded_newline_raises(self):
        # strip() removes trailing \n; embedded newline must be caught
        with pytest.raises(InvalidInputError):
            sanitize_proxy_url("socks5://127.0.0.1\n:9050")

    def test_no_port_accepted(self):
        # Port is optional in the pattern
        result = sanitize_proxy_url("socks5://127.0.0.1")
        assert result == "socks5://127.0.0.1"


# ---------------------------------------------------------------------------
# sanitize_free_text — additional edge cases
# ---------------------------------------------------------------------------


class TestSanitizeFreeTextExtra:
    def test_custom_max_length(self):
        with pytest.raises(InvalidInputError, match="too long"):
            sanitize_free_text("a" * 11, max_length=10)

    def test_removes_backtick(self):
        result = sanitize_free_text("apache `id`")
        assert "`" not in result

    def test_removes_dollar_sign(self):
        result = sanitize_free_text("apache $(env)")
        assert "$" not in result

    def test_strips_leading_trailing_whitespace(self):
        result = sanitize_free_text("  apache log4j  ")
        assert result == "apache log4j"

    def test_custom_field_name_in_error(self):
        with pytest.raises(InvalidInputError) as exc_info:
            sanitize_free_text("", field="search_term")
        assert "search_term" in str(exc_info.value)
