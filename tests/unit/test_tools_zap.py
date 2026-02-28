"""Unit tests for OWASP ZAP proxy tool helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from tengu.exceptions import ZAPConnectionError
from tengu.tools.proxy.zap import (
    _get_zap_config,
    _zap_request,
    zap_active_scan,
    zap_get_alerts,
    zap_spider,
)


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


# ---------------------------------------------------------------------------
# TestZapRequest
# ---------------------------------------------------------------------------


class TestZapRequest:
    @patch("tengu.tools.proxy.zap.httpx.AsyncClient")
    async def test_zap_request_success(self, mock_httpx_cls):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"scan": "1"}
        mock_response.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx_cls.return_value = mock_client

        result = await _zap_request("/JSON/spider/action/scan/", {"url": "https://example.com"})
        assert result == {"scan": "1"}

    @patch.dict("os.environ", {"ZAP_API_KEY": "secret-key"})
    @patch("tengu.tools.proxy.zap.httpx.AsyncClient")
    async def test_zap_request_adds_api_key(self, mock_httpx_cls):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx_cls.return_value = mock_client

        await _zap_request("/test/", {})
        _, kwargs = mock_client.get.call_args
        assert "apikey" in kwargs.get("params", {})

    @patch("tengu.tools.proxy.zap.httpx.AsyncClient")
    async def test_zap_request_connect_error_raises_zap_error(self, mock_httpx_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx_cls.return_value = mock_client

        with pytest.raises(ZAPConnectionError):
            await _zap_request("/JSON/test/")

    @patch("tengu.tools.proxy.zap.httpx.AsyncClient")
    async def test_zap_request_http_error_raises_zap_error(self, mock_httpx_cls):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()))
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx_cls.return_value = mock_client

        with pytest.raises(ZAPConnectionError):
            await _zap_request("/JSON/test/")

    @patch("tengu.tools.proxy.zap.httpx.AsyncClient")
    async def test_zap_request_none_params_defaults_empty(self, mock_httpx_cls):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"result": "ok"}
        mock_response.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx_cls.return_value = mock_client

        # params=None should default to {} internally
        result = await _zap_request("/JSON/test/", None)
        assert result == {"result": "ok"}


# ---------------------------------------------------------------------------
# TestZapSpider
# ---------------------------------------------------------------------------


class TestZapSpider:
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_spider_blocked_url(self, mock_allowlist_fn, mock_audit_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Target not allowed")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Target not allowed"):
            await zap_spider(mock_ctx, "https://example.com")

        mock_audit.log_target_blocked.assert_awaited_once()

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_spider_zap_connection_error(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_zap_req.side_effect = ZAPConnectionError("http://localhost:8080", "refused")

        result = await zap_spider(mock_ctx, "https://example.com")
        assert "error" in result
        assert result["tool"] == "zap_spider"

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_spider_no_wait(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_zap_req.return_value = {"scan": "42"}

        result = await zap_spider(mock_ctx, "https://example.com", wait_for_completion=False)
        assert result["status"] == "started"
        assert result["scan_id"] == "42"
        assert result["tool"] == "zap_spider"

    @patch("tengu.tools.proxy.zap.asyncio.sleep", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_spider_wait_completion(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_sleep, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # sequence: start → status 100 → results
        mock_zap_req.side_effect = [
            {"scan": "7"},            # start spider
            {"status": "100"},        # poll status → complete
            {"results": ["https://example.com/admin", "https://example.com/login"]},  # results
        ]

        result = await zap_spider(mock_ctx, "https://example.com", wait_for_completion=True)
        assert result["tool"] == "zap_spider"
        assert result["urls_discovered"] == 2

    @patch("tengu.tools.proxy.zap.time.monotonic")
    @patch("tengu.tools.proxy.zap.asyncio.sleep", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_spider_timeout(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_sleep, mock_time, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # Make time advance so timeout fires immediately
        mock_time.side_effect = [0, 9999, 9999, 9999]

        mock_zap_req.side_effect = [
            {"scan": "3"},       # start
            {"results": []},     # get results after timeout
        ]

        result = await zap_spider(mock_ctx, "https://example.com", wait_for_completion=True, timeout=1)
        assert result["tool"] == "zap_spider"


# ---------------------------------------------------------------------------
# TestZapActiveScan
# ---------------------------------------------------------------------------


class TestZapActiveScan:
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_active_scan_blocked_url(self, mock_allowlist_fn, mock_audit_fn, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Blocked")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Blocked"):
            await zap_active_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_active_scan_connection_error(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_zap_req.side_effect = ZAPConnectionError("http://localhost:8080", "refused")

        result = await zap_active_scan(mock_ctx, "https://example.com")
        assert "error" in result
        assert result["tool"] == "zap_active_scan"

    @patch("tengu.tools.proxy.zap.asyncio.sleep", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_active_scan_with_policy(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_sleep, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_zap_req.side_effect = [
            {"scan": "5"},
            {"status": "100"},
        ]

        await zap_active_scan(mock_ctx, "https://example.com", policy="MyPolicy")
        # Check that policy was used in the request call
        first_call_params = mock_zap_req.call_args_list[0][0][1]
        assert "scanPolicyName" in first_call_params
        assert first_call_params["scanPolicyName"] == "MyPolicy"

    @patch("tengu.tools.proxy.zap.asyncio.sleep", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    @patch("tengu.tools.proxy.zap.get_audit_logger")
    @patch("tengu.tools.proxy.zap.make_allowlist_from_config")
    async def test_zap_active_scan_completes(self, mock_allowlist_fn, mock_audit_fn, mock_zap_req, mock_sleep, mock_ctx):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_zap_req.side_effect = [
            {"scan": "10"},
            {"status": "100"},
        ]

        result = await zap_active_scan(mock_ctx, "https://example.com")
        assert result["tool"] == "zap_active_scan"
        assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# TestZapGetAlerts
# ---------------------------------------------------------------------------


class TestZapGetAlerts:
    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_no_filters(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {
            "alerts": [
                {"id": "1", "alert": "XSS", "risk": "High", "confidence": "High",
                 "url": "https://example.com", "description": "XSS found",
                 "solution": "Sanitize output", "reference": "", "cweid": "79",
                 "wascid": "8", "evidence": "<script>", "param": "q", "attack": "<script>alert(1)</script>"},
            ]
        }

        result = await zap_get_alerts(mock_ctx)
        assert result["tool"] == "zap_get_alerts"
        assert result["total_alerts"] == 1
        assert result["alerts"][0]["name"] == "XSS"

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_high_risk_filter(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {"alerts": []}

        await zap_get_alerts(mock_ctx, risk_level="High")
        call_params = mock_zap_req.call_args[0][1]
        assert call_params.get("riskid") == "3"

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_medium_filter(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {"alerts": []}

        await zap_get_alerts(mock_ctx, risk_level="Medium")
        call_params = mock_zap_req.call_args[0][1]
        assert call_params.get("riskid") == "2"

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_invalid_risk_filter(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {"alerts": []}

        await zap_get_alerts(mock_ctx, risk_level="Unknown")
        call_params = mock_zap_req.call_args[0][1]
        assert "riskid" not in call_params

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_connection_error(self, mock_zap_req, mock_ctx):
        mock_zap_req.side_effect = ZAPConnectionError("http://localhost:8080", "refused")

        result = await zap_get_alerts(mock_ctx)
        assert result["tool"] == "zap_get_alerts"
        assert "error" in result

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_with_url_filter(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {"alerts": []}

        await zap_get_alerts(mock_ctx, url="https://example.com")
        call_params = mock_zap_req.call_args[0][1]
        assert "baseurl" in call_params

    @patch("tengu.tools.proxy.zap._zap_request", new_callable=AsyncMock)
    async def test_zap_get_alerts_risk_summary(self, mock_zap_req, mock_ctx):
        mock_zap_req.return_value = {
            "alerts": [
                {"id": "1", "alert": "XSS", "risk": "High", "confidence": "High",
                 "url": "", "description": "", "solution": "", "reference": "",
                 "cweid": "", "wascid": "", "evidence": "", "param": "", "attack": ""},
                {"id": "2", "alert": "SQLi", "risk": "High", "confidence": "High",
                 "url": "", "description": "", "solution": "", "reference": "",
                 "cweid": "", "wascid": "", "evidence": "", "param": "", "attack": ""},
                {"id": "3", "alert": "Info", "risk": "Informational", "confidence": "Low",
                 "url": "", "description": "", "solution": "", "reference": "",
                 "cweid": "", "wascid": "", "evidence": "", "param": "", "attack": ""},
            ]
        }

        result = await zap_get_alerts(mock_ctx)
        assert result["risk_summary"]["High"] == 2
        assert result["risk_summary"]["Informational"] == 1


class TestGetZapConfig:
    def test_defaults_when_no_env(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        base_url, api_key = _get_zap_config()
        assert base_url == "http://localhost:8080"
        assert api_key == ""

    def test_custom_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("ZAP_BASE_URL", "http://zap.corp.com:8090")
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        base_url, api_key = _get_zap_config()
        assert base_url == "http://zap.corp.com:8090"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.setenv("ZAP_API_KEY", "my-secret-key")
        _, api_key = _get_zap_config()
        assert api_key == "my-secret-key"

    def test_returns_tuple_of_two_strings(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        result = _get_zap_config()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert all(isinstance(v, str) for v in result)

    def test_both_env_vars_used(self, monkeypatch):
        monkeypatch.setenv("ZAP_BASE_URL", "http://10.0.0.5:8080")
        monkeypatch.setenv("ZAP_API_KEY", "abc123")
        base_url, api_key = _get_zap_config()
        assert base_url == "http://10.0.0.5:8080"
        assert api_key == "abc123"
