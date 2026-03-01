"""Unit tests for masscan output parser."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.recon.masscan import _parse_masscan_json

# ---------------------------------------------------------------------------
# TestParseMasscanJson
# ---------------------------------------------------------------------------


class TestParseMasscanJson:
    def test_empty_string_returns_empty(self):
        assert _parse_masscan_json("") == []

    def test_whitespace_only_returns_empty(self):
        assert _parse_masscan_json("   ") == []

    def test_valid_json_single_host_single_port(self):
        data = [{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["port"] == 80
        assert result[0]["protocol"] == "tcp"
        assert result[0]["status"] == "open"

    def test_multiple_ports_per_host(self):
        data = [
            {
                "ip": "192.168.1.1",
                "ports": [
                    {"port": 22, "proto": "tcp", "status": "open"},
                    {"port": 443, "proto": "tcp", "status": "open"},
                ],
            }
        ]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 2
        ports = {r["port"] for r in result}
        assert ports == {22, 443}

    def test_multiple_hosts(self):
        data = [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "10.0.0.2", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
        ]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 2
        ips = {r["ip"] for r in result}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_trailing_comma_fixed(self):
        # Masscan sometimes emits JSON with trailing comma before closing bracket
        raw = '[{"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},'
        result = _parse_masscan_json(raw)
        assert len(result) == 1
        assert result[0]["port"] == 80

    def test_text_fallback_parses_discovered_port(self):
        text = "Discovered open port 22/tcp on 192.168.1.10"
        result = _parse_masscan_json(text)
        assert len(result) == 1
        assert result[0]["port"] == 22
        assert result[0]["protocol"] == "tcp"
        assert result[0]["ip"] == "192.168.1.10"
        assert result[0]["status"] == "open"

    def test_text_fallback_multiple_lines(self):
        text = (
            "Discovered open port 80/tcp on 10.0.0.1\n"
            "Discovered open port 443/tcp on 10.0.0.2\n"
            "some other line that doesn't match\n"
        )
        result = _parse_masscan_json(text)
        assert len(result) == 2

    def test_default_proto_is_tcp(self):
        data = [{"ip": "10.0.0.1", "ports": [{"port": 80, "status": "open"}]}]
        result = _parse_masscan_json(json.dumps(data))
        assert result[0]["protocol"] == "tcp"

    def test_empty_ports_list(self):
        data = [{"ip": "10.0.0.1", "ports": []}]
        result = _parse_masscan_json(json.dumps(data))
        assert result == []


# ---------------------------------------------------------------------------
# TestMasscanScan — async integration tests
# ---------------------------------------------------------------------------


def _make_masscan_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl):
    cfg = MagicMock()
    cfg.tools.paths.masscan = "/usr/bin/masscan"
    cfg.tools.defaults.scan_timeout = 60
    mock_config.return_value = cfg

    al = MagicMock()
    al.check = MagicMock()
    mock_allowlist.return_value = al

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    mock_audit.return_value = audit

    rl_ctx = MagicMock()
    rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    rl_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_rl.return_value = rl_ctx

    mock_run.return_value = ("", "", 0)

    return al, audit


@patch("tengu.tools.recon.masscan.rate_limited")
@patch("tengu.tools.recon.masscan.resolve_tool_path", return_value="/usr/bin/masscan")
@patch("tengu.tools.recon.masscan.get_audit_logger")
@patch("tengu.tools.recon.masscan.make_allowlist_from_config")
@patch("tengu.tools.recon.masscan.get_config")
@patch("tengu.tools.recon.masscan.run_command", new_callable=AsyncMock)
class TestMasscanScan:
    """Async tests for masscan_scan()."""

    async def test_masscan_blocked_target(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Allowlist rejection propagates as an exception."""
        al, _ = _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        al.check.side_effect = ValueError("target not allowed")
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        with pytest.raises(ValueError, match="target not allowed"):
            await masscan_scan(ctx, "192.168.1.0/24")

    async def test_masscan_rate_clamped_max(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Rate above 100_000 is clamped to 100_000."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        result = await masscan_scan(ctx, "192.168.1.1", rate=9_999_999)

        assert result["rate_pps"] == 100_000

    async def test_masscan_rate_clamped_min(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Rate of 0 is clamped to 1."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        result = await masscan_scan(ctx, "192.168.1.1", rate=0)

        assert result["rate_pps"] == 1

    async def test_masscan_custom_ports(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Custom port spec is passed with -p flag."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        await masscan_scan(ctx, "192.168.1.1", ports="80,443,8080")

        call_args = mock_run.call_args[0][0]
        assert "-p" in call_args
        idx = call_args.index("-p")
        assert "80" in call_args[idx + 1]

    async def test_masscan_output_parsed(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """JSON output is parsed into results list."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        data = [{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]
        mock_run.return_value = (json.dumps(data), "", 0)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        result = await masscan_scan(ctx, "10.0.0.1")

        assert result["open_ports_count"] == 1
        assert result["results"][0]["ip"] == "10.0.0.1"

    async def test_masscan_no_hosts_found(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Empty output → open_ports_count=0, results=[]."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        mock_run.return_value = ("", "", 0)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        result = await masscan_scan(ctx, "192.168.1.1")

        assert result["open_ports_count"] == 0
        assert result["results"] == []

    async def test_masscan_tool_key(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Result 'tool' key equals 'masscan'."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        result = await masscan_scan(ctx, "192.168.1.1")

        assert result["tool"] == "masscan"

    async def test_masscan_audit_logged(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """audit.log_tool_call is called during execution."""
        _, audit = _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        await masscan_scan(ctx, "192.168.1.1")

        assert audit.log_tool_call.call_count >= 1

    async def test_masscan_rate_in_args(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl
    ):
        """Rate value appears in --rate flag."""
        _setup_masscan_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_masscan_ctx()

        from tengu.tools.recon.masscan import masscan_scan

        await masscan_scan(ctx, "192.168.1.1", rate=500)

        call_args = mock_run.call_args[0][0]
        assert "--rate" in call_args
        idx = call_args.index("--rate")
        assert call_args[idx + 1] == "500"
