"""Unit tests for FFUF output parser and async ffuf_fuzz function."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.web.ffuf import _parse_ffuf_output, ffuf_fuzz

# ---------------------------------------------------------------------------
# TestParseFfufOutput
# ---------------------------------------------------------------------------


def _make_ffuf_output(results: list[dict] | None = None) -> str:
    return json.dumps({
        "commandline": "ffuf -u https://example.com/FUZZ -w wordlist.txt",
        "time": "2024-01-01T00:00:00Z",
        "results": results or [],
    })


def _make_result_entry(
    url: str = "https://example.com/admin",
    status: int = 200,
    length: int = 1024,
    words: int = 50,
    lines: int = 30,
    redirect: str = "",
    fuzz_word: str = "admin",
) -> dict:
    return {
        "url": url,
        "status": status,
        "length": length,
        "words": words,
        "lines": lines,
        "redirectlocation": redirect,
        "input": {"FUZZ": fuzz_word},
    }


class TestParseFfufOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_ffuf_output("") == []

    def test_invalid_json_returns_empty(self):
        assert _parse_ffuf_output("not json {{{") == []

    def test_valid_single_result(self):
        entry = _make_result_entry(url="https://example.com/admin", status=200)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com/admin"
        assert results[0]["status"] == 200

    def test_length_extracted(self):
        entry = _make_result_entry(length=2048)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["length"] == 2048

    def test_redirect_location_extracted(self):
        entry = _make_result_entry(redirect="https://example.com/admin/")
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["redirect_location"] == "https://example.com/admin/"

    def test_fuzz_word_extracted(self):
        entry = _make_result_entry(fuzz_word="robots.txt")
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["input"] == "robots.txt"

    def test_multiple_results(self):
        entries = [
            _make_result_entry(url=f"https://example.com/path{i}") for i in range(5)
        ]
        output = _make_ffuf_output(entries)
        results = _parse_ffuf_output(output)
        assert len(results) == 5

    def test_empty_results_list(self):
        output = _make_ffuf_output([])
        results = _parse_ffuf_output(output)
        assert results == []

    def test_words_and_lines_extracted(self):
        entry = _make_result_entry(words=100, lines=50)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["words"] == 100
        assert results[0]["lines"] == 50


# ---------------------------------------------------------------------------
# Helpers for ffuf_fuzz tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_config_mock(
    wordlist="/usr/share/wordlists/common.txt",
    scan_timeout=300,
    ffuf_path=None,
):
    cfg = MagicMock()
    cfg.tools.defaults.wordlist_path = wordlist
    cfg.tools.defaults.scan_timeout = scan_timeout
    cfg.tools.paths.ffuf = ffuf_path
    return cfg


def _make_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


def _make_ffuf_json_output(results=None):
    if results is None:
        results = []
    return json.dumps({"results": results}), "", 0


# ---------------------------------------------------------------------------
# TestFfufFuzz
# ---------------------------------------------------------------------------


class TestFfufFuzz:
    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_auto_adds_fuzz_marker(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        # URL without FUZZ
        result = await ffuf_fuzz(mock_ctx, "https://example.com")
        # Result URL should have FUZZ appended
        assert "FUZZ" in result["url"]

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_existing_fuzz_marker(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ")
        # FUZZ should appear exactly once in the result URL
        assert result["url"].count("FUZZ") == 1

    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    async def test_ffuf_blocked_by_allowlist(self, mock_audit_fn, mock_allowlist_fn, mock_config, mock_ctx):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Blocked")
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Blocked"):
            await ffuf_fuzz(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_with_extensions(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", extensions=[".php", ".html"])
        args = mock_run.call_args[0][0]
        assert "-e" in args
        e_idx = args.index("-e")
        assert ".php" in args[e_idx + 1]

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_invalid_extension_filtered(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        # "../evil" is an invalid extension — should be filtered out
        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", extensions=["../evil"])
        args = mock_run.call_args[0][0]
        # -e should NOT appear since no valid extensions
        assert "-e" not in args

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_filter_codes(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", filter_codes=[404, 403])
        args = mock_run.call_args[0][0]
        assert "-fc" in args

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_match_codes(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", match_codes=[200, 301])
        args = mock_run.call_args[0][0]
        assert "-mc" in args

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_threads_clamped_max(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", threads=500)
        args = mock_run.call_args[0][0]
        t_idx = args.index("-t")
        assert int(args[t_idx + 1]) <= 200

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_threads_clamped_min(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", threads=0)
        args = mock_run.call_args[0][0]
        t_idx = args.index("-t")
        assert int(args[t_idx + 1]) >= 1

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_rate_limit(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", rate=100)
        args = mock_run.call_args[0][0]
        assert "-rate" in args
        rate_idx = args.index("-rate")
        assert args[rate_idx + 1] == "100"

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_custom_headers(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", headers={"Cookie": "session=abc123"})
        args = mock_run.call_args[0][0]
        assert "-H" in args
        h_idx = args.index("-H")
        assert "Cookie" in args[h_idx + 1]

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_crlf_in_header_blocked(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = _make_ffuf_json_output()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ", headers={"X-Test": "val\r\nX-Injected: evil"})
        args = mock_run.call_args[0][0]
        # CRLF characters should be stripped (preventing header injection)
        joined = " ".join(args)
        assert "\r\n" not in joined
        assert "\r" not in joined
        assert "\n" not in joined

    @patch("tengu.tools.web.ffuf.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.ffuf.get_config")
    @patch("tengu.tools.web.ffuf.make_allowlist_from_config")
    @patch("tengu.tools.web.ffuf.get_audit_logger")
    @patch("tengu.tools.web.ffuf.resolve_tool_path", return_value="/usr/bin/ffuf")
    @patch("tengu.tools.web.ffuf.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_ffuf_parses_json_output(
        self, mock_stealth, mock_rl, mock_resolve, mock_audit_fn, mock_allowlist_fn, mock_config, mock_run, mock_ctx
    ):
        mock_config.return_value = _make_config_mock()
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

        # Provide valid JSON with one result
        ffuf_result_entry = _make_result_entry(url="https://example.com/admin", status=200)
        mock_run.return_value = _make_ffuf_json_output([ffuf_result_entry])

        result = await ffuf_fuzz(mock_ctx, "https://example.com/FUZZ")
        assert result["results_count"] == 1
        assert result["results"][0]["url"] == "https://example.com/admin"
