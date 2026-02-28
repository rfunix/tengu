"""Additional registry tests — check_tool_async, _get_version, _print_status_table."""

from __future__ import annotations

import pytest

from tengu.executor.registry import (
    _print_status_table,
    check_tool_async,
)
from tengu.types import ToolsCheckResult, ToolStatus

# ---------------------------------------------------------------------------
# TestCheckToolAsync
# ---------------------------------------------------------------------------


class TestCheckToolAsync:
    @pytest.mark.asyncio
    async def test_available_tool_returns_status(self):
        status = await check_tool_async("python3", category="utility")
        assert status.available is True
        assert status.name == "python3"
        assert status.path is not None
        assert status.category == "utility"

    @pytest.mark.asyncio
    async def test_available_tool_has_version(self):
        status = await check_tool_async("python3")
        # python3 --version returns something like "Python 3.x.y"
        assert status.version is not None
        assert len(status.version) > 0

    @pytest.mark.asyncio
    async def test_unavailable_tool_returns_not_available(self):
        status = await check_tool_async("__nonexistent_tool_xyz__", category="test")
        assert status.available is False
        assert status.path is None
        assert status.version is None

    @pytest.mark.asyncio
    async def test_default_category_unknown(self):
        status = await check_tool_async("python3")
        assert status.category == "unknown"


# ---------------------------------------------------------------------------
# TestGetVersion (via check_tool_async)
# ---------------------------------------------------------------------------


class TestGetVersion:
    @pytest.mark.asyncio
    async def test_version_string_capped_at_120_chars(self):
        # _get_version returns at most 120 chars per line
        status = await check_tool_async("python3")
        if status.version:
            assert len(status.version) <= 120

    @pytest.mark.asyncio
    async def test_version_is_string_or_none(self):
        status = await check_tool_async("python3")
        assert status.version is None or isinstance(status.version, str)


# ---------------------------------------------------------------------------
# TestPrintStatusTable
# ---------------------------------------------------------------------------


class TestPrintStatusTable:
    def test_prints_without_error(self, capsys):
        result = ToolsCheckResult(
            tools=[
                ToolStatus(name="nmap", available=True, path="/usr/bin/nmap", category="recon"),
                ToolStatus(name="sqlmap", available=False, category="injection"),
            ],
            total=2,
            available=1,
        )
        _print_status_table(result)
        captured = capsys.readouterr()
        assert "nmap" in captured.out
        assert "sqlmap" in captured.out

    def test_shows_checkmark_for_available(self, capsys):
        result = ToolsCheckResult(
            tools=[ToolStatus(name="nmap", available=True, path="/bin/nmap", category="recon")],
            total=1,
            available=1,
        )
        _print_status_table(result)
        assert "✓" in capsys.readouterr().out

    def test_shows_cross_for_unavailable(self, capsys):
        result = ToolsCheckResult(
            tools=[ToolStatus(name="sqlmap", available=False, category="injection")],
            total=1,
            available=0,
        )
        _print_status_table(result)
        assert "✗" in capsys.readouterr().out

    def test_shows_not_found_for_missing_path(self, capsys):
        result = ToolsCheckResult(
            tools=[ToolStatus(name="missing", available=False, category="web")],
            total=1,
            available=0,
        )
        _print_status_table(result)
        assert "not found" in capsys.readouterr().out

    def test_groups_by_category(self, capsys):
        result = ToolsCheckResult(
            tools=[
                ToolStatus(name="nmap", available=True, path="/bin/nmap", category="recon"),
                ToolStatus(name="nuclei", available=True, path="/bin/nuclei", category="web"),
                ToolStatus(name="sqlmap", available=False, category="injection"),
            ],
            total=3,
            available=2,
        )
        _print_status_table(result)
        out = capsys.readouterr().out
        assert "recon" in out
        assert "web" in out
        assert "injection" in out

    def test_shows_totals(self, capsys):
        result = ToolsCheckResult(
            tools=[
                ToolStatus(name="nmap", available=True, path="/bin/nmap", category="recon"),
                ToolStatus(name="sqlmap", available=False, category="injection"),
            ],
            total=2,
            available=1,
        )
        _print_status_table(result)
        out = capsys.readouterr().out
        assert "Total: 2" in out
        assert "Available: 1" in out

    def test_empty_tools_list(self, capsys):
        result = ToolsCheckResult(tools=[], total=0, available=0)
        _print_status_table(result)
        out = capsys.readouterr().out
        assert "Total: 0" in out
