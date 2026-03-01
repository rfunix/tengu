"""Unit tests for CORS severity helper and test origins config."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from tengu.tools.web.cors import _TEST_ORIGINS, _assess_severity
from tengu.tools.web.cors import test_cors as cors_test

# ---------------------------------------------------------------------------
# TestAssessSeverity
# ---------------------------------------------------------------------------


class TestAssessSeverity:
    def test_no_issues_returns_none(self):
        assert _assess_severity([], False) == "none"

    def test_issues_without_credentials_is_high(self):
        assert _assess_severity(["Origin reflected"], False) == "high"

    def test_issues_with_credentials_is_critical(self):
        assert _assess_severity(["Origin reflected"], True) == "critical"

    def test_credentials_without_issues_is_none(self):
        # No issues → "none" even if credentials=True (unreachable in practice,
        # but tests the function branch)
        assert _assess_severity([], True) == "none"


# ---------------------------------------------------------------------------
# TestTestOriginsConfig
# ---------------------------------------------------------------------------


class TestTestOriginsConfig:
    def test_evil_com_present(self):
        assert "https://evil.com" in _TEST_ORIGINS

    def test_null_origin_present(self):
        assert "null" in _TEST_ORIGINS

    def test_at_least_three_test_origins(self):
        assert len(_TEST_ORIGINS) >= 3

    def test_all_entries_are_strings(self):
        for origin in _TEST_ORIGINS:
            assert isinstance(origin, str)
            assert origin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_stealth_client(options_return_value):
    """Build a stealth layer mock that returns an async HTTP client."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.options = AsyncMock(return_value=options_return_value)

    mock_stealth_layer = MagicMock()
    mock_stealth_layer.create_http_client.return_value = mock_client

    return mock_stealth_layer, mock_client


def _make_cors_response(acao="", acac="false", status=200):
    mock_response = MagicMock()
    mock_response.status_code = status
    mock_response.headers = {
        "access-control-allow-origin": acao,
        "access-control-allow-credentials": acac,
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "Content-Type",
    }
    return mock_response


# ---------------------------------------------------------------------------
# TestTestCors
# ---------------------------------------------------------------------------


class TestTestCors:
    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_blocked_url(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Not allowed")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Not allowed"):
            await cors_test(mock_ctx, "https://example.com")

        mock_audit.log_target_blocked.assert_awaited_once()

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_no_vulnerabilities(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # ACAO does not reflect origin — not vulnerable
        safe_resp = _make_cors_response(acao="https://trusted.com")
        mock_stealth_layer, mock_client = _make_stealth_client(safe_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is False
        assert result["issues"] == []

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_origin_reflected(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # Server reflects each origin back
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        def _reflect_origin(url, headers):
            origin = headers.get("Origin", "")
            resp = _make_cors_response(acao=origin)
            future = AsyncMock(return_value=resp)
            return future()

        mock_client.options = MagicMock(side_effect=_reflect_origin)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is True
        assert len(result["issues"]) > 0

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_origin_reflected_with_credentials(
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

        def _reflect_with_creds(url, headers):
            origin = headers.get("Origin", "")
            resp = _make_cors_response(acao=origin, acac="true")
            future = AsyncMock(return_value=resp)
            return future()

        mock_client.options = MagicMock(side_effect=_reflect_with_creds)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is True
        assert result["severity"] == "critical"
        # There should be a CRITICAL issue in the issues list
        assert any("CRITICAL" in issue for issue in result["issues"])

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_null_origin_accepted(
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

        def _null_response(url, headers):
            origin = headers.get("Origin", "")
            if origin == "null":
                resp = _make_cors_response(acao="null")
            else:
                resp = _make_cors_response(acao="https://trusted.com")
            future = AsyncMock(return_value=resp)
            return future()

        mock_client.options = MagicMock(side_effect=_null_response)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is True
        assert any("null" in issue.lower() for issue in result["issues"])

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_wildcard_with_credentials(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        wildcard_resp = _make_cors_response(acao="*", acac="true")
        mock_stealth_layer, mock_client = _make_stealth_client(wildcard_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is True

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_request_error_continues(
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
        # All requests fail with RequestError → should continue without crashing
        mock_client.options = AsyncMock(side_effect=httpx.RequestError("connection failed"))

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        # No crash; no results since all failed
        assert result["tool"] == "test_cors"
        assert result["vulnerable"] is False

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_custom_origins_added(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        safe_resp = _make_cors_response(acao="https://trusted.com")
        mock_stealth_layer, mock_client = _make_stealth_client(safe_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        await cors_test(mock_ctx, "https://example.com", custom_origins=["https://custom.com"])
        # Verify that options was called more than the default number of test origins
        call_count = mock_client.options.call_count
        assert call_count >= len(_TEST_ORIGINS) + 1

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_returns_remediation_when_vulnerable(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # Wildcard + credentials triggers vulnerability
        vuln_resp = _make_cors_response(acao="*", acac="true")
        mock_stealth_layer, mock_client = _make_stealth_client(vuln_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["vulnerable"] is True
        assert result["remediation"] is not None

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_returns_no_remediation_when_safe(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        safe_resp = _make_cors_response(acao="https://trusted.com")
        mock_stealth_layer, mock_client = _make_stealth_client(safe_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["remediation"] is None

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.cors.make_allowlist_from_config")
    @patch("tengu.tools.web.cors.get_audit_logger")
    async def test_cors_tool_key_in_result(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        safe_resp = _make_cors_response(acao="https://trusted.com")
        mock_stealth_layer, mock_client = _make_stealth_client(safe_resp)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await cors_test(mock_ctx, "https://example.com")
        assert result["tool"] == "test_cors"
