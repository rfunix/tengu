"""Unit tests for HTTP security headers analysis helpers and async function."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from tengu.tools.web.headers import (
    _INFORMATION_DISCLOSURE_HEADERS,
    _SECURITY_HEADERS,
    _score_to_grade,
    analyze_headers,
)

# ---------------------------------------------------------------------------
# TestScoreToGrade
# ---------------------------------------------------------------------------


class TestScoreToGrade:
    def test_90_or_above_is_a_plus(self):
        assert _score_to_grade(90) == "A+"
        assert _score_to_grade(100) == "A+"

    def test_80_to_89_is_a(self):
        assert _score_to_grade(80) == "A"
        assert _score_to_grade(89) == "A"

    def test_70_to_79_is_b(self):
        assert _score_to_grade(70) == "B"
        assert _score_to_grade(79) == "B"

    def test_60_to_69_is_c(self):
        assert _score_to_grade(60) == "C"
        assert _score_to_grade(69) == "C"

    def test_50_to_59_is_d(self):
        assert _score_to_grade(50) == "D"
        assert _score_to_grade(59) == "D"

    def test_below_50_is_f(self):
        assert _score_to_grade(49) == "F"
        assert _score_to_grade(0) == "F"


# ---------------------------------------------------------------------------
# TestSecurityHeadersConfig
# ---------------------------------------------------------------------------


class TestSecurityHeadersConfig:
    def test_at_least_eight_headers_defined(self):
        assert len(_SECURITY_HEADERS) >= 8

    def test_each_header_has_name(self):
        for hdr in _SECURITY_HEADERS:
            assert "name" in hdr
            assert isinstance(hdr["name"], str)
            assert hdr["name"]

    def test_each_header_has_required_flag(self):
        for hdr in _SECURITY_HEADERS:
            assert "required" in hdr
            assert isinstance(hdr["required"], bool)

    def test_each_header_has_recommendation(self):
        for hdr in _SECURITY_HEADERS:
            assert "recommendation" in hdr
            assert hdr["recommendation"]

    def test_hsts_is_required(self):
        hsts = next(
            (h for h in _SECURITY_HEADERS if h["name"] == "Strict-Transport-Security"), None
        )
        assert hsts is not None
        assert hsts["required"] is True

    def test_csp_is_required(self):
        csp = next((h for h in _SECURITY_HEADERS if h["name"] == "Content-Security-Policy"), None)
        assert csp is not None
        assert csp["required"] is True

    def test_required_headers_count(self):
        required = [h for h in _SECURITY_HEADERS if h["required"]]
        # There should be at least 6 required headers
        assert len(required) >= 6


# ---------------------------------------------------------------------------
# TestInformationDisclosureHeaders
# ---------------------------------------------------------------------------


class TestInformationDisclosureHeaders:
    def test_server_header_in_list(self):
        assert "Server" in _INFORMATION_DISCLOSURE_HEADERS

    def test_x_powered_by_in_list(self):
        assert "X-Powered-By" in _INFORMATION_DISCLOSURE_HEADERS

    def test_at_least_four_entries(self):
        assert len(_INFORMATION_DISCLOSURE_HEADERS) >= 4

    def test_all_entries_are_strings(self):
        for header in _INFORMATION_DISCLOSURE_HEADERS:
            assert isinstance(header, str)
            assert header


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_stealth_client_with_response(response):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=response)

    mock_stealth_layer = MagicMock()
    mock_stealth_layer.create_http_client.return_value = mock_client

    return mock_stealth_layer, mock_client


def _make_full_headers_response():
    """Build a response that has all required security headers present."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com"
    mock_response.headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
    }
    return mock_response


def _make_empty_headers_response():
    """Build a response with no security headers (all missing)."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com"
    mock_response.headers = {}
    return mock_response


# ---------------------------------------------------------------------------
# TestAnalyzeHeaders
# ---------------------------------------------------------------------------


class TestAnalyzeHeaders:
    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_blocked_url(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Target blocked")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Target blocked"):
            await analyze_headers(mock_ctx, "https://example.com")

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_request_error(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("connection refused"))

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert "error" in result
        assert result["tool"] == "analyze_headers"

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_all_present_score_100(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert result["score"] == 100
        assert result["grade"] == "A+"

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_none_present_score_0(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_empty_headers_response()
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert result["score"] == 0
        assert result["grade"] == "F"

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_info_disclosure_detected(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        # Add a disclosure header
        mock_response.headers["server"] = "Apache/2.4.1"
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        disclosure_headers = [d["header"] for d in result["information_disclosure"]]
        assert "Server" in disclosure_headers

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_missing_headers_list(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_empty_headers_response()
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert "Content-Security-Policy" in result["missing_headers"]

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_tool_key(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert result["tool"] == "analyze_headers"

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_status_code_returned(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        mock_response.status_code = 301
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert result["status_code"] == 301

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_no_disclosure_when_clean(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        # No disclosure headers present
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert result["information_disclosure"] == []

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.headers.make_allowlist_from_config")
    @patch("tengu.tools.web.headers.get_audit_logger")
    async def test_analyze_headers_security_headers_list_returned(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_full_headers_response()
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await analyze_headers(mock_ctx, "https://example.com")
        assert "security_headers" in result
        assert isinstance(result["security_headers"], list)
        assert len(result["security_headers"]) > 0
