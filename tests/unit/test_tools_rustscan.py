"""Unit tests for rustscan_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.recon.rustscan import _parse_rustscan_output

_MOD = "tengu.tools.recon.rustscan"


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock() -> MagicMock:
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock() -> MagicMock:
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    return audit


@pytest.fixture
def ctx() -> MagicMock:
    return _make_ctx()


async def _run_rustscan(
    ctx: MagicMock,
    target: str = "192.168.1.1",
    ports: str = "1-1024",
    batch_size: int = 1500,
    stdout: str = "",
    blocked: bool = False,
) -> dict:  # type: ignore[type-arg]
    from tengu.tools.recon.rustscan import rustscan_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300
    allowlist_mock = MagicMock()
    if blocked:
        allowlist_mock.check.side_effect = TargetNotAllowedError("Target not allowed")

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_target", return_value=target),
        patch(f"{_MOD}.sanitize_port_spec", return_value=ports),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/rustscan"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
    ):
        return await rustscan_scan(ctx, target, ports=ports, batch_size=batch_size)


class TestRustscanScan:
    async def test_returns_tool_key(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx)
        assert result["tool"] == "rustscan"

    async def test_blocked_raises(self, ctx: MagicMock) -> None:
        with pytest.raises(TargetNotAllowedError):
            await _run_rustscan(ctx, blocked=True)

    async def test_batch_size_clamped_min(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx, batch_size=1)
        assert result["batch_size"] >= 100

    async def test_batch_size_clamped_max(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx, batch_size=999999)
        assert result["batch_size"] <= 65535

    async def test_open_ports_parsed(self, ctx: MagicMock) -> None:
        stdout = "Open 192.168.1.1:80\nOpen 192.168.1.1:443\n"
        result = await _run_rustscan(ctx, stdout=stdout)
        assert result["open_ports_count"] == 2
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]

    async def test_return_keys_present(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx)
        for key in (
            "tool",
            "target",
            "ports",
            "batch_size",
            "duration_seconds",
            "open_ports_count",
            "open_ports",
        ):
            assert key in result

    async def test_empty_stdout_zero_ports(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx, stdout="")
        assert result["open_ports_count"] == 0
        assert result["open_ports"] == []

    async def test_raw_output_excerpt_present(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx, stdout="some output")
        assert "raw_output_excerpt" in result

    async def test_long_output_truncated(self, ctx: MagicMock) -> None:
        long_stdout = "x" * 6000
        result = await _run_rustscan(ctx, stdout=long_stdout)
        assert len(result["raw_output_excerpt"]) <= 3000

    async def test_batch_size_within_range_preserved(self, ctx: MagicMock) -> None:
        result = await _run_rustscan(ctx, batch_size=2000)
        assert result["batch_size"] == 2000


class TestParseRustscanOutput:
    def test_empty_output(self) -> None:
        result = _parse_rustscan_output("")
        assert result["open_ports"] == []

    def test_open_ports_detected(self) -> None:
        result = _parse_rustscan_output("Open 192.168.1.1:80\nOpen 192.168.1.1:443\n")
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]

    def test_ports_sorted(self) -> None:
        result = _parse_rustscan_output("Open 192.168.1.1:443\nOpen 192.168.1.1:80\n")
        assert result["open_ports"] == sorted(result["open_ports"])

    def test_duplicate_ports_not_repeated(self) -> None:
        result = _parse_rustscan_output("Open 192.168.1.1:80\nOpen 192.168.1.1:80\n")
        assert result["open_ports"].count(80) == 1

    def test_tcp_open_format_parsed(self) -> None:
        result = _parse_rustscan_output("80/tcp open http\n22/tcp open ssh\n")
        assert 80 in result["open_ports"]
        assert 22 in result["open_ports"]

    def test_invalid_port_line_skipped(self) -> None:
        result = _parse_rustscan_output("Open 192.168.1.1:notaport\n")
        assert result["open_ports"] == []

    def test_multiple_hosts_ports_collected(self) -> None:
        result = _parse_rustscan_output(
            "Open 10.0.0.1:22\nOpen 10.0.0.2:80\nOpen 10.0.0.1:443\n"
        )
        assert 22 in result["open_ports"]
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]
