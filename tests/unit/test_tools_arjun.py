"""Unit tests for Arjun parameter discovery parser."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.api.arjun import _VALID_METHODS, _parse_arjun_output

# ---------------------------------------------------------------------------
# TestValidMethods
# ---------------------------------------------------------------------------


class TestValidMethods:
    def test_get_present(self):
        assert "GET" in _VALID_METHODS

    def test_post_present(self):
        assert "POST" in _VALID_METHODS

    def test_json_present(self):
        assert "JSON" in _VALID_METHODS

    def test_all_uppercase(self):
        for method in _VALID_METHODS:
            assert method == method.upper()


# ---------------------------------------------------------------------------
# TestParseArjunOutput
# ---------------------------------------------------------------------------


class TestParseArjunOutput:
    def test_empty_returns_empty(self):
        assert _parse_arjun_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_arjun_output("   ") == []

    def test_arjun_key_format(self):
        data = {"arjun": ["id", "username", "page"]}
        result = _parse_arjun_output(json.dumps(data))
        assert "id" in result
        assert "username" in result
        assert "page" in result

    def test_nested_params_format(self):
        data = {"https://example.com": {"params": ["token", "csrf"]}}
        result = _parse_arjun_output(json.dumps(data))
        assert "token" in result
        assert "csrf" in result

    def test_list_format(self):
        data = ["q", "search", "page"]
        result = _parse_arjun_output(json.dumps(data))
        assert "q" in result
        assert "search" in result

    def test_deduplication_preserving_order(self):
        data = {"arjun": ["id", "id", "name", "id"]}
        result = _parse_arjun_output(json.dumps(data))
        assert result.count("id") == 1

    def test_invalid_json_fallback(self):
        # Fallback: line-by-line regex search
        text = '  "token": "abc123",\n  "page": 1,'
        result = _parse_arjun_output(text)
        assert "token" in result
        assert "page" in result

    def test_fallback_skips_arjun_url_method_keys(self):
        text = '  "arjun": "v2",\n  "url": "...",\n  "method": "GET",\n  "debug": true'
        result = _parse_arjun_output(text)
        # arjun/url/method should be excluded by the fallback filter
        assert "arjun" not in result
        assert "url" not in result
        assert "method" not in result
        assert "debug" in result

    def test_nested_dict_in_value(self):
        data = {"mysite": {"parameters": ["search", "filter"]}}
        result = _parse_arjun_output(json.dumps(data))
        assert "search" in result
        assert "filter" in result


# ---------------------------------------------------------------------------
# TestArjunDiscover
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_arjun_mocks(
    stdout: str = '{"arjun": ["id", "token"]}',
    allowlist_raises: Exception | None = None,
    run_raises: Exception | None = None,
):
    """Build standard mocks for arjun_discover tests."""
    mock_cfg = MagicMock()
    mock_cfg.tools.defaults.scan_timeout = 300

    mock_audit = MagicMock()
    mock_audit.log_tool_call = AsyncMock()
    mock_audit.log_target_blocked = AsyncMock()

    mock_allowlist = MagicMock()
    if allowlist_raises:
        mock_allowlist.check.side_effect = allowlist_raises
    else:
        mock_allowlist.check.return_value = None

    mock_rl = MagicMock()
    mock_rl.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl.__aexit__ = AsyncMock(return_value=False)

    if run_raises:
        mock_run = AsyncMock(side_effect=run_raises)
    else:
        mock_run = AsyncMock(return_value=(stdout, "", 0))

    return mock_cfg, mock_audit, mock_allowlist, mock_rl, mock_run


class TestArjunDiscover:
    async def test_allowlist_block_raises_and_logs(self, mock_ctx):
        exc = Exception("Target not in allowlist")
        mock_cfg, mock_audit, mock_allowlist, mock_rl, mock_run = _make_arjun_mocks(
            allowlist_raises=exc
        )
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=("", "", 0),
            ),
            pytest.raises(Exception, match="Target not in allowlist"),
        ):
            await arjun_discover(mock_ctx, "http://target.local")

        mock_audit.log_target_blocked.assert_called_once()

    async def test_invalid_method_coerced_to_get(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, mock_run = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=('{"arjun":[]}', "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local", method="INVALID")

        assert result["method"] == "GET"

    async def test_valid_post_method_preserved(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, mock_run = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=('{"arjun":[]}', "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local", method="POST")

        assert result["method"] == "POST"

    async def test_wordlist_arg_added_when_provided(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ('{"arjun":[]}', "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch("tengu.tools.api.arjun.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.api.arjun.sanitize_wordlist_path", return_value="/safe/wordlist.txt"
            ),
        ):
            await arjun_discover(mock_ctx, "http://target.local", wordlist="/custom/wordlist.txt")

        assert "-w" in captured_args
        assert "/safe/wordlist.txt" in captured_args

    async def test_no_wordlist_arg_when_empty(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ('{"arjun":[]}', "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch("tengu.tools.api.arjun.run_command", side_effect=fake_run),
        ):
            await arjun_discover(mock_ctx, "http://target.local", wordlist="")

        assert "-w" not in captured_args

    async def test_run_command_called_with_url_and_method(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ('{"arjun":[]}', "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch("tengu.tools.api.arjun.run_command", side_effect=fake_run),
        ):
            await arjun_discover(mock_ctx, "http://target.local", method="JSON")

        assert "-u" in captured_args
        assert "-m" in captured_args
        assert "JSON" in captured_args
        assert "--stable" in captured_args

    async def test_parameters_found_matches_parsed_output(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        stdout = '{"arjun": ["id", "token", "page"]}'
        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=(stdout, "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local")

        assert result["parameters_found"] == 3
        assert result["parameters"] == ["id", "token", "page"]

    async def test_result_keys_present(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=('{"arjun":[]}', "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local")

        for key in (
            "tool",
            "url",
            "method",
            "wordlist",
            "command",
            "duration_seconds",
            "parameters_found",
            "parameters",
            "raw_output_excerpt",
        ):
            assert key in result, f"Missing key: {key}"

    async def test_tool_name_is_arjun(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=('{"arjun":[]}', "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local")

        assert result["tool"] == "arjun"

    async def test_timeout_override_used(self, mock_ctx):
        captured_kwargs: dict = {}

        async def fake_run(args, **kw):
            captured_kwargs.update(kw)
            return ('{"arjun":[]}', "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch("tengu.tools.api.arjun.run_command", side_effect=fake_run),
        ):
            await arjun_discover(mock_ctx, "http://target.local", timeout=999)

        assert captured_kwargs.get("timeout") == 999

    async def test_run_command_exception_propagates_after_audit_log(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks(
            run_raises=RuntimeError("subprocess died")
        )
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                side_effect=RuntimeError("subprocess died"),
            ),
            pytest.raises(RuntimeError, match="subprocess died"),
        ):
            await arjun_discover(mock_ctx, "http://target.local")

        # audit.log_tool_call should have been called with result="failed"
        calls = mock_audit.log_tool_call.call_args_list
        assert any(c.kwargs.get("result") == "failed" for c in calls)

    async def test_raw_output_truncated_to_2000_chars(self, mock_ctx):
        long_stdout = "X" * 5000
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=(long_stdout, "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local")

        assert len(result["raw_output_excerpt"]) == 2000

    async def test_raw_output_full_when_short(self, mock_ctx):
        short_stdout = '{"arjun": ["q"]}'
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.api.arjun.run_command",
                new_callable=AsyncMock,
                return_value=(short_stdout, "", 0),
            ),
        ):
            result = await arjun_discover(mock_ctx, "http://target.local")

        assert result["raw_output_excerpt"] == short_stdout

    async def test_default_timeout_from_config(self, mock_ctx):
        captured_kwargs: dict = {}

        async def fake_run(args, **kw):
            captured_kwargs.update(kw)
            return ('{"arjun":[]}', "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_arjun_mocks()
        mock_cfg.tools.defaults.scan_timeout = 600
        from tengu.tools.api.arjun import arjun_discover

        with (
            patch("tengu.tools.api.arjun.get_config", return_value=mock_cfg),
            patch("tengu.tools.api.arjun.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.api.arjun.make_allowlist_from_config", return_value=mock_allowlist),
            patch("tengu.tools.api.arjun.resolve_tool_path", return_value="arjun"),
            patch("tengu.tools.api.arjun.rate_limited", return_value=mock_rl),
            patch("tengu.tools.api.arjun.run_command", side_effect=fake_run),
        ):
            await arjun_discover(mock_ctx, "http://target.local")

        assert captured_kwargs.get("timeout") == 600
