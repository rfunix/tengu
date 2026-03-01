"""Unit tests for tool executor registry."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tengu.exceptions import ToolNotFoundError
from tengu.executor.registry import (
    _TOOL_CATALOG,
    _print_status_table,
    check_all,
    check_tool,
    check_tool_async,
    resolve_tool_path,
)

# ---------------------------------------------------------------------------
# TestToolCatalog
# ---------------------------------------------------------------------------


class TestToolCatalog:
    def test_is_list(self):
        assert isinstance(_TOOL_CATALOG, list)

    def test_has_many_tools(self):
        assert len(_TOOL_CATALOG) >= 20

    def test_each_entry_has_name(self):
        for entry in _TOOL_CATALOG:
            assert "name" in entry
            assert isinstance(entry["name"], str)

    def test_each_entry_has_category(self):
        for entry in _TOOL_CATALOG:
            assert "category" in entry
            assert isinstance(entry["category"], str)

    def test_nmap_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nmap" in names

    def test_nuclei_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nuclei" in names

    def test_sqlmap_present(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "sqlmap" in names

    def test_categories_include_recon(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "recon" in categories

    def test_categories_include_web(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "web" in categories

    def test_categories_include_exploit(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "exploit" in categories

    def test_no_duplicate_names(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# TestCheckTool
# ---------------------------------------------------------------------------


class TestCheckTool:
    def test_python3_found(self):
        result = check_tool("python3")
        assert result.name == "python3"
        assert result.available is True
        assert result.path is not None

    def test_nonexistent_tool_not_available(self):
        result = check_tool("this_tool_does_not_exist_xyz")
        assert result.available is False
        assert result.path is None

    def test_category_preserved(self):
        result = check_tool("python3", category="utility")
        assert result.category == "utility"

    def test_returns_tool_status(self):
        from tengu.types import ToolStatus

        result = check_tool("python3")
        assert isinstance(result, ToolStatus)

    def test_name_preserved_in_result(self):
        result = check_tool("python3")
        assert result.name == "python3"


# ---------------------------------------------------------------------------
# TestResolveToolPath
# ---------------------------------------------------------------------------


class TestResolveToolPath:
    def test_configured_path_takes_priority(self):
        result = resolve_tool_path("nmap", configured_path="/usr/custom/nmap")
        assert result == "/usr/custom/nmap"

    def test_python3_resolved_from_path(self):
        result = resolve_tool_path("python3")
        assert "python3" in result

    def test_missing_tool_raises_tool_not_found(self):
        with pytest.raises(ToolNotFoundError):
            resolve_tool_path("tool_that_definitely_does_not_exist_abc123")

    def test_tool_not_found_includes_tool_name(self):
        try:
            resolve_tool_path("phantom_tool_xyz")
        except ToolNotFoundError as exc:
            assert "phantom_tool_xyz" in str(exc)


# ---------------------------------------------------------------------------
# TestCheckToolAsync
# ---------------------------------------------------------------------------


class TestCheckToolAsync:
    """Tests for check_tool_async() — async version with version detection."""

    async def test_python3_async_available(self):
        """check_tool_async finds python3 and marks it available."""
        result = await check_tool_async("python3", "utility")
        assert result.available is True
        assert result.name == "python3"

    async def test_missing_tool_async_not_available(self):
        """check_tool_async marks a missing tool as not available."""
        result = await check_tool_async("nonexistent_tool_xyz_abc123", "test")
        assert result.available is False
        assert result.path is None

    async def test_missing_tool_async_path_is_none(self):
        """check_tool_async sets path=None for missing tools."""
        result = await check_tool_async("totally_fake_tool_qrs", "test")
        assert result.path is None

    async def test_version_field_populated_for_available_tool(self):
        """check_tool_async populates version (str or None) without crashing."""
        result = await check_tool_async("python3", "utility")
        # Version can be a string or None depending on --version output
        assert result.version is None or isinstance(result.version, str)

    async def test_category_preserved_in_async_result(self):
        """check_tool_async preserves the category argument in the result."""
        result = await check_tool_async("python3", "utility")
        assert result.category == "utility"

    async def test_name_preserved_in_async_result(self):
        """check_tool_async preserves the tool name in the result."""
        result = await check_tool_async("python3", "utility")
        assert result.name == "python3"

    async def test_missing_tool_category_preserved(self):
        """check_tool_async preserves category even for missing tools."""
        result = await check_tool_async("ghost_tool_xyz", "recon")
        assert result.category == "recon"

    async def test_returns_tool_status_instance(self):
        """check_tool_async always returns a ToolStatus instance."""
        from tengu.types import ToolStatus

        result = await check_tool_async("python3", "utility")
        assert isinstance(result, ToolStatus)

    async def test_missing_returns_tool_status_instance(self):
        """check_tool_async returns ToolStatus even for missing tools."""
        from tengu.types import ToolStatus

        result = await check_tool_async("fake_tool_does_not_exist", "test")
        assert isinstance(result, ToolStatus)


# ---------------------------------------------------------------------------
# TestCheckAll
# ---------------------------------------------------------------------------


class TestCheckAll:
    """Tests for check_all() — full catalog check."""

    async def test_check_all_returns_tools_check_result(self):
        """check_all returns a ToolsCheckResult instance."""
        from tengu.types import ToolsCheckResult

        result = await check_all(verbose=False)
        assert isinstance(result, ToolsCheckResult)

    async def test_check_all_total_matches_catalog(self):
        """check_all total count equals the length of _TOOL_CATALOG."""
        result = await check_all(verbose=False)
        assert result.total == len(_TOOL_CATALOG)

    async def test_check_all_available_plus_missing_equals_total(self):
        """check_all: available + missing always equals total."""
        result = await check_all(verbose=False)
        assert result.available + result.missing == result.total

    async def test_check_all_tools_list_has_correct_length(self):
        """check_all tools list length equals total."""
        result = await check_all(verbose=False)
        assert len(result.tools) == result.total

    async def test_check_all_verbose_calls_print(self):
        """check_all(verbose=True) calls print (prints the status table)."""
        with patch("builtins.print") as mock_print:
            await check_all(verbose=True)
        assert mock_print.called

    async def test_check_all_verbose_false_skips_print(self):
        """check_all(verbose=False) does not call _print_status_table."""
        with patch("tengu.executor.registry._print_status_table") as mock_table:
            await check_all(verbose=False)
        mock_table.assert_not_called()

    async def test_check_all_available_is_non_negative(self):
        """check_all available count is always >= 0."""
        result = await check_all(verbose=False)
        assert result.available >= 0

    async def test_check_all_missing_is_non_negative(self):
        """check_all missing count is always >= 0."""
        result = await check_all(verbose=False)
        assert result.missing >= 0

    async def test_check_all_python3_is_available(self):
        """check_all finds python3 as available (it runs the tests)."""
        result = await check_all(verbose=False)
        python3_statuses = [t for t in result.tools if t.name == "python3"]
        assert python3_statuses, "python3 must be in catalog"
        assert python3_statuses[0].available is True


# ---------------------------------------------------------------------------
# TestPrintStatusTable
# ---------------------------------------------------------------------------


class TestPrintStatusTable:
    """Tests for _print_status_table()."""

    def test_print_status_table_runs_without_error(self):
        """_print_status_table does not raise with a mixed-availability result."""
        from tengu.types import ToolsCheckResult, ToolStatus

        result = ToolsCheckResult(
            tools=[
                ToolStatus(name="nmap", available=True, path="/usr/bin/nmap", category="recon"),
                ToolStatus(name="fakemissing", available=False, category="test"),
            ],
            total=2,
            available=1,
            missing=1,
        )
        with patch("builtins.print"):
            _print_status_table(result)

    def test_print_status_table_with_empty_tools(self):
        """_print_status_table handles empty tools list without error."""
        from tengu.types import ToolsCheckResult

        result = ToolsCheckResult(tools=[], total=0, available=0, missing=0)
        with patch("builtins.print"):
            _print_status_table(result)

    def test_print_status_table_calls_print(self):
        """_print_status_table calls print at least once."""
        from tengu.types import ToolsCheckResult, ToolStatus

        result = ToolsCheckResult(
            tools=[ToolStatus(name="nmap", available=True, path="/usr/bin/nmap", category="recon")],
            total=1,
            available=1,
            missing=0,
        )
        with patch("builtins.print") as mock_print:
            _print_status_table(result)
        assert mock_print.called

    def test_print_status_table_groups_by_category(self):
        """_print_status_table groups tools by category (runs without error)."""
        from tengu.types import ToolsCheckResult, ToolStatus

        result = ToolsCheckResult(
            tools=[
                ToolStatus(name="nmap", available=True, path="/usr/bin/nmap", category="recon"),
                ToolStatus(
                    name="sqlmap", available=True, path="/usr/bin/sqlmap", category="injection"
                ),
                ToolStatus(name="hydra", available=False, category="bruteforce"),
            ],
            total=3,
            available=2,
            missing=1,
        )
        with patch("builtins.print"):
            _print_status_table(result)

    def test_print_status_table_summary_line_includes_total(self):
        """_print_status_table prints a summary that includes the total count."""
        from tengu.types import ToolsCheckResult, ToolStatus

        result = ToolsCheckResult(
            tools=[ToolStatus(name="nmap", available=True, path="/usr/bin/nmap", category="recon")],
            total=1,
            available=1,
            missing=0,
        )
        printed_lines = []
        with patch("builtins.print", side_effect=lambda *a, **kw: printed_lines.append(str(a))):
            _print_status_table(result)
        summary = " ".join(printed_lines)
        assert "1" in summary  # total appears somewhere


# ---------------------------------------------------------------------------
# TestResolveToolPathEdgeCases
# ---------------------------------------------------------------------------


class TestResolveToolPathEdgeCases:
    """Additional edge-case tests for resolve_tool_path()."""

    def test_git_resolved_from_path(self):
        """resolve_tool_path finds git in PATH (common on all systems)."""
        result = resolve_tool_path("git")
        assert "git" in result

    def test_configured_path_empty_string_falls_through_to_auto_detect(self):
        """An empty configured_path triggers auto-detection."""
        result = resolve_tool_path("python3", configured_path="")
        assert "python3" in result

    def test_configured_path_whitespace_treated_as_truthy(self):
        """A whitespace-only configured_path is accepted as-is (truthy)."""
        # "   " is truthy in Python, so resolve_tool_path returns it directly
        result = resolve_tool_path("nmap", configured_path="   ")
        assert result == "   "

    def test_returns_str(self):
        """resolve_tool_path always returns a str."""
        result = resolve_tool_path("python3")
        assert isinstance(result, str)

    def test_configured_path_returned_unchanged(self):
        """resolve_tool_path returns the exact configured_path string given."""
        result = resolve_tool_path("nmap", configured_path="/opt/custom/nmap")
        assert result == "/opt/custom/nmap"
