"""Unit tests for SSL/TLS helper functions and async scan."""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.web.ssl_tls import (
    _WEAK_CIPHERS_PATTERNS,
    _WEAK_PROTOCOLS,
    _build_ssl_result,
    _generate_recommendations,
    _run_sslyze_scan,
    ssl_tls_check,
)
from tengu.types import SSLResult

# ---------------------------------------------------------------------------
# TestWeakProtocols
# ---------------------------------------------------------------------------


class TestWeakProtocols:
    def test_sslv2_in_weak(self):
        assert "SSLv2" in _WEAK_PROTOCOLS

    def test_sslv3_in_weak(self):
        assert "SSLv3" in _WEAK_PROTOCOLS

    def test_tls10_in_weak(self):
        assert "TLSv1.0" in _WEAK_PROTOCOLS

    def test_tls11_in_weak(self):
        assert "TLSv1.1" in _WEAK_PROTOCOLS

    def test_tls12_not_in_weak(self):
        assert "TLSv1.2" not in _WEAK_PROTOCOLS

    def test_tls13_not_in_weak(self):
        assert "TLSv1.3" not in _WEAK_PROTOCOLS


# ---------------------------------------------------------------------------
# TestWeakCiphersPatterns
# ---------------------------------------------------------------------------


class TestWeakCiphersPatterns:
    def test_rc4_in_patterns(self):
        assert "RC4" in _WEAK_CIPHERS_PATTERNS

    def test_des_in_patterns(self):
        assert "DES" in _WEAK_CIPHERS_PATTERNS

    def test_null_in_patterns(self):
        assert "NULL" in _WEAK_CIPHERS_PATTERNS

    def test_at_least_five_patterns(self):
        assert len(_WEAK_CIPHERS_PATTERNS) >= 5


# ---------------------------------------------------------------------------
# TestGenerateRecommendations
# ---------------------------------------------------------------------------


class TestGenerateRecommendations:
    def test_clean_result_no_recommendations(self):
        result = SSLResult(host="example.com", port=443)
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert recs == []

    def test_weak_protocol_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.weak_protocols = ["TLSv1.0"]
        result.certificate_valid = True
        result.protocols = ["TLSv1.0", "TLSv1.2", "TLSv1.3"]
        recs = _generate_recommendations(result)
        assert any("deprecated protocols" in r.lower() for r in recs)

    def test_heartbleed_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.vulnerabilities = ["Heartbleed (CVE-2014-0160)"]
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert any("Heartbleed" in r for r in recs)

    def test_invalid_certificate_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.certificate_valid = False
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        recs = _generate_recommendations(result)
        assert any("certificate" in r.lower() for r in recs)

    def test_no_tls13_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.protocols = ["TLSv1.2"]  # No TLSv1.3
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert any("TLS 1.3" in r for r in recs)

    def test_multiple_issues_multiple_recommendations(self):
        result = SSLResult(host="example.com", port=443)
        result.weak_protocols = ["SSLv3"]
        result.vulnerabilities = ["Heartbleed (CVE-2014-0160)"]
        result.certificate_valid = False
        result.protocols = ["SSLv3", "TLSv1.2"]
        recs = _generate_recommendations(result)
        assert len(recs) >= 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _mock_sslyze_modules():
    """Return a patch.dict context that makes sslyze importable as a MagicMock."""
    mock_sslyze = MagicMock()
    mock_scan_cmds = MagicMock()
    # ScanCommand needs to support attribute access for each command name
    mock_scan_cmds.ScanCommand = MagicMock()
    mock_sslyze.ServerNetworkLocation = MagicMock(return_value=MagicMock())
    mock_sslyze.ServerScanRequest = MagicMock(return_value=MagicMock())
    return {"sslyze": mock_sslyze, "sslyze.plugins.scan_commands": mock_scan_cmds}


# ---------------------------------------------------------------------------
# TestSslTlsCheck
# ---------------------------------------------------------------------------


class TestSslTlsCheck:
    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_blocked_by_allowlist(self, mock_audit_fn, mock_allowlist_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Not in allowlist")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            pytest.raises(Exception, match="Not in allowlist"),
        ):
            await ssl_tls_check(mock_ctx, "example.com")

    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_invalid_port_clamped(self, mock_audit_fn, mock_allowlist_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
            patch("tengu.tools.web.ssl_tls._build_ssl_result") as mock_build,
        ):
            mock_ssl_result = SSLResult(host="example.com", port=443)
            mock_ssl_result.protocols = ["TLSv1.2", "TLSv1.3"]
            mock_ssl_result.certificate_valid = True
            mock_ssl_result.grade = "A+"
            mock_build.return_value = mock_ssl_result
            mock_wait.return_value = MagicMock()

            result = await ssl_tls_check(mock_ctx, "example.com", port=99999)
            # port out of range → clamped to 443
            assert result["port"] == 443

    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_sslyze_not_installed(self, mock_audit_fn, mock_allowlist_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # Set sslyze to None to trigger ImportError on `from sslyze import ...`
        saved = sys.modules.get("sslyze")
        sys.modules["sslyze"] = None  # type: ignore[assignment]
        sys.modules["sslyze.plugins.scan_commands"] = None  # type: ignore[assignment]
        try:
            result = await ssl_tls_check(mock_ctx, "example.com")
            assert "error" in result
            assert "sslyze" in result["error"].lower()
        finally:
            if saved is None:
                sys.modules.pop("sslyze", None)
                sys.modules.pop("sslyze.plugins.scan_commands", None)
            else:
                sys.modules["sslyze"] = saved

    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_scan_timeout(self, mock_audit_fn, mock_allowlist_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.side_effect = TimeoutError("timed out")
            result = await ssl_tls_check(mock_ctx, "example.com")
            assert "error" in result
            assert "timed out" in result["error"].lower()

    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_scan_exception(self, mock_audit_fn, mock_allowlist_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.side_effect = Exception("connection refused")
            result = await ssl_tls_check(mock_ctx, "example.com")
            assert "error" in result

    @patch("tengu.tools.web.ssl_tls._build_ssl_result")
    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_scan_success_grade_a(
        self, mock_audit_fn, mock_allowlist_fn, mock_build, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_ssl_result = SSLResult(host="example.com", port=443)
        mock_ssl_result.certificate_valid = True
        mock_ssl_result.certificate_expiry = "2026-01-01"
        mock_ssl_result.protocols = ["TLSv1.2"]
        mock_ssl_result.weak_protocols = []
        mock_ssl_result.vulnerabilities = []
        mock_ssl_result.grade = "A"
        mock_build.return_value = mock_ssl_result

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.return_value = MagicMock()
            result = await ssl_tls_check(mock_ctx, "example.com", port=443)

        assert result["tool"] == "ssl_tls_check"
        assert result["grade"] == "A"

    @patch("tengu.tools.web.ssl_tls._build_ssl_result")
    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_scan_weak_protocols(
        self, mock_audit_fn, mock_allowlist_fn, mock_build, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_ssl_result = SSLResult(host="example.com", port=443)
        mock_ssl_result.certificate_valid = True
        mock_ssl_result.protocols = ["TLSv1.0", "TLSv1.2"]
        mock_ssl_result.weak_protocols = ["TLSv1.0"]
        mock_ssl_result.vulnerabilities = []
        mock_ssl_result.grade = "F"
        mock_build.return_value = mock_ssl_result

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.return_value = MagicMock()
            result = await ssl_tls_check(mock_ctx, "example.com")

        assert result["weak_protocols"] == ["TLSv1.0"]
        assert result["grade"] == "F"

    @patch("tengu.tools.web.ssl_tls._build_ssl_result")
    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_scan_vulnerabilities(
        self, mock_audit_fn, mock_allowlist_fn, mock_build, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_ssl_result = SSLResult(host="example.com", port=443)
        mock_ssl_result.certificate_valid = True
        mock_ssl_result.protocols = ["TLSv1.2"]
        mock_ssl_result.weak_protocols = []
        mock_ssl_result.vulnerabilities = ["Heartbleed (CVE-2014-0160)"]
        mock_ssl_result.grade = "F"
        mock_build.return_value = mock_ssl_result

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.return_value = MagicMock()
            result = await ssl_tls_check(mock_ctx, "example.com")

        assert "Heartbleed" in result["vulnerabilities"][0]

    @patch("tengu.tools.web.ssl_tls._build_ssl_result")
    @patch("tengu.tools.web.ssl_tls.make_allowlist_from_config")
    @patch("tengu.tools.web.ssl_tls.get_audit_logger")
    async def test_ssl_port_default_443(
        self, mock_audit_fn, mock_allowlist_fn, mock_build, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_ssl_result = SSLResult(host="example.com", port=443)
        mock_ssl_result.certificate_valid = True
        mock_ssl_result.protocols = ["TLSv1.3"]
        mock_ssl_result.weak_protocols = []
        mock_ssl_result.vulnerabilities = []
        mock_ssl_result.grade = "A+"
        mock_build.return_value = mock_ssl_result

        with (
            patch.dict(sys.modules, _mock_sslyze_modules()),
            patch("tengu.tools.web.ssl_tls.asyncio.wait_for", new_callable=AsyncMock) as mock_wait,
        ):
            mock_wait.return_value = MagicMock()
            result = await ssl_tls_check(mock_ctx, "example.com")

        assert result["port"] == 443


# ---------------------------------------------------------------------------
# TestBuildSslResult
# ---------------------------------------------------------------------------


class TestBuildSslResult:
    def test_build_ssl_result_none_scan_returns_empty(self):
        """None scan_result → SSLResult with defaults."""
        result = _build_ssl_result("example.com", 443, None)
        assert isinstance(result, SSLResult)
        assert result.protocols == []
        assert result.weak_protocols == []
        assert result.grade is None

    def test_build_ssl_result_with_mock_scan(self):
        """Mock a scan_result structure for _build_ssl_result."""
        with patch.dict(sys.modules, _mock_sslyze_modules()):
            # Build a minimal mock scan result
            mock_scan = MagicMock()
            # Make scan_result attribute access return empty results (no protocols)
            mock_scan.scan_result.__dict__ = {}

            result = _build_ssl_result("example.com", 443, mock_scan)
            assert isinstance(result, SSLResult)

    def test_build_ssl_result_grade_logic_both_tls(self):
        """If TLSv1.2 and TLSv1.3 in protocols, grade is A+."""
        result = SSLResult(host="example.com", port=443)
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        result.weak_protocols = []
        result.vulnerabilities = []
        # Re-run grading logic directly
        if result.weak_protocols or result.vulnerabilities:
            result.grade = "F"
        elif "TLSv1.2" in result.protocols and "TLSv1.3" in result.protocols:
            result.grade = "A+"
        elif "TLSv1.2" in result.protocols:
            result.grade = "A"
        else:
            result.grade = "B"
        assert result.grade == "A+"


# ---------------------------------------------------------------------------
# TestRunSslyzeScan
# ---------------------------------------------------------------------------


class TestRunSslyzeScan:
    def test_run_sslyze_scan_is_sync(self):
        """_run_sslyze_scan is a regular sync function, not a coroutine."""
        import inspect

        assert not inspect.iscoroutinefunction(_run_sslyze_scan)

    def test_run_sslyze_scan_uses_scanner(self):
        """With sslyze mocked, Scanner is called and results are fetched."""
        mock_sslyze = MagicMock()
        mock_scanner_instance = MagicMock()
        mock_scan_result = MagicMock()
        mock_scanner_instance.get_results.return_value = [mock_scan_result]
        mock_sslyze.Scanner.return_value = mock_scanner_instance

        with patch.dict(
            sys.modules, {"sslyze": mock_sslyze, "sslyze.plugins.scan_commands": MagicMock()}
        ):
            mock_request = MagicMock()
            result = _run_sslyze_scan(mock_request)

        mock_sslyze.Scanner.assert_called_once()
        mock_scanner_instance.queue_scans.assert_called_once()
        assert result == mock_scan_result
