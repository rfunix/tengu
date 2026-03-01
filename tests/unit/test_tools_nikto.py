"""Unit tests for Nikto web scanner output parser and async nikto_scan function."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.web.nikto import _parse_nikto_output, nikto_scan

# ---------------------------------------------------------------------------
# TestParseNiktoOutput
# ---------------------------------------------------------------------------


def _make_nikto_json(vulnerabilities: list | None = None) -> str:
    return json.dumps({"vulnerabilities": vulnerabilities or []})


def _make_vuln(
    vuln_id: str = "700001",
    osvdb: str = "OSVDB-0",
    method: str = "GET",
    url: str = "/test",
    msg: str = "Server leaks information",
) -> dict:
    return {
        "id": vuln_id,
        "OSVDB": osvdb,
        "method": method,
        "url": url,
        "msg": msg,
        "references": {"url": []},
    }


class TestParseNiktoOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_nikto_output("") == []

    def test_single_json_vulnerability(self):
        output = _make_nikto_json([_make_vuln()])
        result = _parse_nikto_output(output)
        assert len(result) == 1
        assert result[0]["id"] == "700001"

    def test_message_extracted(self):
        output = _make_nikto_json([_make_vuln(msg="Apache version disclosure")])
        result = _parse_nikto_output(output)
        assert result[0]["message"] == "Apache version disclosure"

    def test_url_extracted(self):
        output = _make_nikto_json([_make_vuln(url="/admin/config.php")])
        result = _parse_nikto_output(output)
        assert result[0]["url"] == "/admin/config.php"

    def test_method_extracted(self):
        output = _make_nikto_json([_make_vuln(method="POST")])
        result = _parse_nikto_output(output)
        assert result[0]["method"] == "POST"

    def test_osvdb_extracted(self):
        output = _make_nikto_json([_make_vuln(osvdb="OSVDB-3268")])
        result = _parse_nikto_output(output)
        assert result[0]["osvdb"] == "OSVDB-3268"

    def test_multiple_vulnerabilities(self):
        vulns = [_make_vuln(vuln_id=str(i)) for i in range(5)]
        output = _make_nikto_json(vulns)
        result = _parse_nikto_output(output)
        assert len(result) == 5

    def test_empty_vulnerabilities_list(self):
        output = _make_nikto_json([])
        assert _parse_nikto_output(output) == []

    def test_text_fallback_plus_prefix(self):
        text = "+ Apache/2.4.49 appears to be outdated\n+ Allowed HTTP Methods: GET, POST"
        result = _parse_nikto_output(text)
        assert len(result) == 2
        assert "Apache" in result[0]["message"]

    def test_text_fallback_skips_non_plus_lines(self):
        text = "- Nikto v2.1.6\n+ Server: Apache/2.4.49\n[INFO] scan complete"
        result = _parse_nikto_output(text)
        # Only lines starting with "+ " are captured
        assert len(result) == 1
        assert "Apache" in result[0]["message"]

    def test_invalid_json_uses_text_fallback(self):
        text = "not json\n+ XSS vulnerability found"
        result = _parse_nikto_output(text)
        assert len(result) == 1

    def test_text_fallback_message_strips_prefix(self):
        text = "+ Outdated jQuery detected"
        result = _parse_nikto_output(text)
        assert result[0]["message"] == "Outdated jQuery detected"


# ---------------------------------------------------------------------------
# Helpers for nikto_scan tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_nikto_config(scan_timeout=300, nikto_path=None):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = scan_timeout
    cfg.tools.paths.nikto = nikto_path
    return cfg


def _make_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


# ---------------------------------------------------------------------------
# TestNiktoScan
# ---------------------------------------------------------------------------


class TestNiktoScan:
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    async def test_nikto_blocked_url(self, mock_audit_fn, mock_allowlist_fn, mock_config, mock_ctx):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Blocked")
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Blocked"):
            await nikto_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_tuning_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", tuning="1234")
        args = mock_run.call_args[0][0]
        assert "-Tuning" in args
        t_idx = args.index("-Tuning")
        assert args[t_idx + 1] == "1234"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_ssl_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", ssl=True)
        args = mock_run.call_args[0][0]
        assert "-ssl" in args

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_custom_port(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", port=8080)
        args = mock_run.call_args[0][0]
        assert "-port" in args
        p_idx = args.index("-port")
        assert args[p_idx + 1] == "8080"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_stealth_proxy(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = True
        mock_stealth_layer.proxy_url = "http://127.0.0.1:8080"
        mock_stealth_layer.inject_proxy_flags.side_effect = lambda tool, args: (
            args + ["-useproxy", "http://127.0.0.1:8080"]
        )
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        assert "-useproxy" in args

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_output_parsing(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        nikto_json = _make_nikto_json([_make_vuln(msg="Apache server version disclosure")])
        mock_run.return_value = (nikto_json, "", 0)

        result = await nikto_scan(mock_ctx, "https://example.com")
        assert result["findings_count"] == 1
        assert result["findings"][0]["message"] == "Apache server version disclosure"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_default_scan(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nikto_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        # Nikto requires -h flag
        assert "-h" in args
        assert result["tool"] == "nikto"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_run_error(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        mock_run.side_effect = Exception("nikto not found")

        with pytest.raises(Exception, match="nikto not found"):
            await nikto_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_tool_key(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nikto_scan(mock_ctx, "https://example.com")
        assert result["tool"] == "nikto"
