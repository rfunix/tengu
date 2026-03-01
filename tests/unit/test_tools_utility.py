"""Unit tests for utility tools: check_tools and validate_target."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.types import ToolsCheckResult, ToolStatus


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_tools_result(available: int = 3, missing: int = 2) -> ToolsCheckResult:
    tools = []
    for i in range(available):
        tools.append(
            ToolStatus(name=f"tool{i}", available=True, path=f"/usr/bin/tool{i}", category="recon")
        )
    for i in range(missing):
        tools.append(ToolStatus(name=f"missing{i}", available=False, category="web"))
    return ToolsCheckResult(
        tools=tools,
        total=available + missing,
        available=available,
        missing=missing,
    )


# ---------------------------------------------------------------------------
# TestCheckTools
# ---------------------------------------------------------------------------


class TestCheckTools:
    async def test_check_tools_returns_dict(self, mock_ctx):
        """Result is a dict."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result()

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert isinstance(result, dict)

    async def test_check_tools_summary_key(self, mock_ctx):
        """Result has 'summary' key with total, available, missing."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result(available=10, missing=5)

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert "summary" in result
        assert result["summary"]["total"] == 15
        assert result["summary"]["available"] == 10
        assert result["summary"]["missing"] == 5

    async def test_check_tools_lists_tools(self, mock_ctx):
        """Result has 'tools' key listing tool entries."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result()

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert "tools" in result
        assert isinstance(result["tools"], list)

    async def test_check_tools_some_available(self, mock_ctx):
        """Available tools appear with available=True in tool list."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result(available=2, missing=1)

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        available_tools = [t for t in result["tools"] if t["available"]]
        assert len(available_tools) == 2

    async def test_check_tools_missing_tools_list(self, mock_ctx):
        """missing_tools key lists names of unavailable tools."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result(available=1, missing=2)

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert "missing_tools" in result
        assert len(result["missing_tools"]) == 2

    async def test_check_tools_install_hint_when_missing(self, mock_ctx):
        """install_hint provided when tools are missing."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result(available=1, missing=3)

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert result["install_hint"] is not None

    async def test_check_tools_no_hint_when_all_available(self, mock_ctx):
        """install_hint is None when all tools are available."""
        from tengu.tools.utility import check_tools

        result_data = _make_tools_result(available=5, missing=0)

        with patch("tengu.tools.utility.check_all", AsyncMock(return_value=result_data)):
            result = await check_tools(mock_ctx)

        assert result["install_hint"] is None


# ---------------------------------------------------------------------------
# TestValidateTarget
# ---------------------------------------------------------------------------


class TestValidateTarget:
    async def test_validate_target_valid_ip(self, mock_ctx):
        """'192.168.1.1' is a valid IP — valid=True."""
        from tengu.tools.utility import validate_target

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None

        with patch("tengu.tools.utility.make_allowlist_from_config", return_value=mock_allowlist):
            result = await validate_target(mock_ctx, "192.168.1.1")

        assert result["valid"] is True

    async def test_validate_target_valid_hostname(self, mock_ctx):
        """'example.com' is a valid hostname — valid=True."""
        from tengu.tools.utility import validate_target

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None

        with patch("tengu.tools.utility.make_allowlist_from_config", return_value=mock_allowlist):
            result = await validate_target(mock_ctx, "example.com")

        assert result["valid"] is True

    async def test_validate_target_invalid_target(self, mock_ctx):
        """'not valid!' with shell characters — valid=False, reason set."""
        from tengu.tools.utility import validate_target

        result = await validate_target(mock_ctx, "not valid!")

        assert result["valid"] is False
        assert result["reason"] != ""

    async def test_validate_target_blocked(self, mock_ctx):
        """Target blocked by allowlist — allowed=False."""
        from tengu.tools.utility import validate_target

        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = PermissionError("Target not in allowlist")

        with patch("tengu.tools.utility.make_allowlist_from_config", return_value=mock_allowlist):
            result = await validate_target(mock_ctx, "192.168.1.1")

        assert result["allowed"] is False
        assert "allowlist" in result["reason"].lower() or "not in" in result["reason"].lower()

    async def test_validate_target_target_key(self, mock_ctx):
        """Result always contains 'target' key."""
        from tengu.tools.utility import validate_target

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None

        with patch("tengu.tools.utility.make_allowlist_from_config", return_value=mock_allowlist):
            result = await validate_target(mock_ctx, "10.0.0.1")

        assert "target" in result
        assert result["target"] == "10.0.0.1"

    async def test_validate_target_allowed_reason(self, mock_ctx):
        """Allowed target has reason indicating success."""
        from tengu.tools.utility import validate_target

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None

        with patch("tengu.tools.utility.make_allowlist_from_config", return_value=mock_allowlist):
            result = await validate_target(mock_ctx, "10.10.10.10")

        assert result["allowed"] is True
        assert result["reason"] != ""
