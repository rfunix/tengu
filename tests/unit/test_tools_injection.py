"""Unit tests for injection tools: sqlmap scan function and output parser."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.injection.sqlmap import _parse_sqlmap_output


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _mock_config():
    cfg = MagicMock()
    cfg.tools.paths.sqlmap = ""
    cfg.tools.defaults.scan_timeout = 300
    return cfg


def _setup_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


def _mock_stealth(enabled: bool = False, proxy_url: str = ""):
    stealth = MagicMock()
    stealth.enabled = enabled
    stealth.proxy_url = proxy_url
    stealth.inject_proxy_flags = MagicMock(
        side_effect=lambda tool, args: args + ["--proxy", proxy_url]
    )
    return stealth


# ---------------------------------------------------------------------------
# TestSqlmapScan — async tests for sqlmap_scan function
# ---------------------------------------------------------------------------


class TestSqlmapScan:
    async def test_sqlmap_blocked_url(self, mock_ctx):
        """Allowlist raises — exception re-raised."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
        ):
            allowlist_instance = MagicMock()
            allowlist_instance.check.side_effect = PermissionError("URL blocked")
            mock_allowlist.return_value = allowlist_instance

            with pytest.raises(PermissionError, match="URL blocked"):
                await sqlmap_scan(mock_ctx, "https://blocked.example.com/page")

    async def test_sqlmap_method_post(self, mock_ctx):
        """method='POST' with data adds --data to args."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(
                mock_ctx, "https://example.com/login", method="POST", data="user=admin&pass=test"
            )

        assert "--data" in captured_args

    async def test_sqlmap_method_get_default(self, mock_ctx):
        """method='GET' without data — --data not in args."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/search?q=test", method="GET")

        assert "--data" not in captured_args

    async def test_sqlmap_level_clamped_max(self, mock_ctx):
        """level=10 clamped to 5."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/page?id=1", level=10)

        level_arg = next((a for a in captured_args if a.startswith("--level=")), None)
        assert level_arg is not None
        assert int(level_arg.split("=")[1]) <= 5

    async def test_sqlmap_level_clamped_min(self, mock_ctx):
        """level=0 clamped to 1."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/page?id=1", level=0)

        level_arg = next((a for a in captured_args if a.startswith("--level=")), None)
        assert level_arg is not None
        assert int(level_arg.split("=")[1]) >= 1

    async def test_sqlmap_risk_clamped(self, mock_ctx):
        """risk=5 clamped to 3."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/page?id=1", risk=5)

        risk_arg = next((a for a in captured_args if a.startswith("--risk=")), None)
        assert risk_arg is not None
        assert int(risk_arg.split("=")[1]) <= 3

    async def test_sqlmap_dbms_whitelist(self, mock_ctx):
        """dbms='mysql' adds --dbms=mysql; dbms='invalid' is excluded."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args_mysql: list = []
        captured_args_invalid: list = []

        async def fake_run_mysql(args, timeout):
            captured_args_mysql.extend(args)
            return ("", "", 0)

        async def fake_run_invalid(args, timeout):
            captured_args_invalid.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run_mysql),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/?id=1", dbms="mysql")

        assert "--dbms" in captured_args_mysql

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run_invalid),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/?id=1", dbms="invaliddbms")

        assert "--dbms" not in captured_args_invalid

    async def test_sqlmap_stealth_proxy(self, mock_ctx):
        """Stealth enabled — --proxy flag injected in args."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        stealth = _mock_stealth(enabled=True, proxy_url="socks5://127.0.0.1:9050")

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=stealth),
            patch("tengu.tools.injection.sqlmap.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert "--proxy" in captured_args

    async def test_sqlmap_output_parsed(self, mock_ctx):
        """SQLMap output parsed for injection points."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        sqlmap_output = (
            "parameter 'id' is vulnerable. Do you want to keep testing?\n"
            "back-end DBMS: MySQL >= 5.0.12\n"
            "Type: boolean-based blind\n"
        )

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch(
                "tengu.tools.injection.sqlmap.run_command",
                AsyncMock(return_value=(sqlmap_output, "", 0)),
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert result["vulnerable"] is True
        assert "id" in result["vulnerable_parameters"]
        assert result["dbms"] is not None

    async def test_sqlmap_no_injections(self, mock_ctx):
        """Clean output — injections=[]."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch(
                "tengu.tools.injection.sqlmap.run_command",
                AsyncMock(return_value=("No parameters found to test", "", 0)),
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await sqlmap_scan(mock_ctx, "https://example.com/static")

        assert result["vulnerable"] is False
        assert result["vulnerable_parameters"] == []

    async def test_sqlmap_tool_key(self, mock_ctx):
        """Result has tool='sqlmap'."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", AsyncMock(return_value=("", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert result["tool"] == "sqlmap"

    async def test_sqlmap_audit_logged(self, mock_ctx):
        """audit.log_tool_call called."""
        from tengu.tools.injection.sqlmap import sqlmap_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.sqlmap.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.sqlmap.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap"),
            patch("tengu.tools.injection.sqlmap.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.sqlmap.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
            patch("tengu.tools.injection.sqlmap.run_command", AsyncMock(return_value=("", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert mock_audit.log_tool_call.call_count >= 1


# ---------------------------------------------------------------------------
# TestParseSqlmapOutput
# ---------------------------------------------------------------------------


class TestParseSqlmapOutput:
    def test_empty_output_returns_defaults(self):
        result = _parse_sqlmap_output("")
        assert result["vulnerable_params"] == []
        assert result["dbms"] is None
        assert result["injection_types"] == []

    def test_vulnerable_param_detected(self):
        output = "parameter 'id' is vulnerable. Do you want to keep testing the others?"
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]

    def test_multiple_params_detected(self):
        output = "parameter 'id' is vulnerable.\nparameter 'username' is vulnerable.\n"
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]
        assert "username" in result["vulnerable_params"]
        assert len(result["vulnerable_params"]) == 2

    def test_duplicate_params_not_repeated(self):
        output = "parameter 'id' is vulnerable.\nparameter 'id' is vulnerable.\n"
        result = _parse_sqlmap_output(output)
        assert result["vulnerable_params"].count("id") == 1

    def test_dbms_detected(self):
        output = "back-end DBMS: MySQL >= 5.0.12"
        result = _parse_sqlmap_output(output)
        assert result["dbms"] == "MySQL >= 5.0.12"

    def test_injection_type_detected(self):
        output = "Type: boolean-based blind"
        result = _parse_sqlmap_output(output)
        assert "boolean-based blind" in result["injection_types"]

    def test_multiple_injection_types(self):
        output = "Type: boolean-based blind\nType: time-based blind"
        result = _parse_sqlmap_output(output)
        assert len(result["injection_types"]) == 2

    def test_duplicate_injection_types_not_repeated(self):
        output = "Type: error-based\nType: error-based"
        result = _parse_sqlmap_output(output)
        assert result["injection_types"].count("error-based") == 1

    def test_case_insensitive_matching(self):
        output = "PARAMETER 'id' IS VULNERABLE"
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]

    def test_no_match_lines_ignored(self):
        output = "testing connection to the target URL\nsome random output\ngot a 301 redirect"
        result = _parse_sqlmap_output(output)
        assert result["vulnerable_params"] == []
        assert result["dbms"] is None
