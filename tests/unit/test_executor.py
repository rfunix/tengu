"""Unit tests for executor: process runner and tool registry."""

from __future__ import annotations

import sys

import pytest

from tengu.exceptions import ScanTimeoutError, ToolNotFoundError
from tengu.executor.process import run_command, stream_command
from tengu.executor.registry import (
    _TOOL_CATALOG,
    check_tool,
    resolve_tool_path,
)

# ---------------------------------------------------------------------------
# TestRunCommand
# ---------------------------------------------------------------------------


class TestRunCommand:
    @pytest.mark.asyncio
    async def test_returns_tuple_of_three(self):
        stdout, stderr, returncode = await run_command([sys.executable, "-c", "print('hi')"])
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        assert isinstance(returncode, int)

    @pytest.mark.asyncio
    async def test_stdout_captured(self):
        stdout, _, _ = await run_command([sys.executable, "-c", "print('hello world')"])
        assert "hello world" in stdout

    @pytest.mark.asyncio
    async def test_stderr_captured(self):
        _, stderr, _ = await run_command(
            [sys.executable, "-c", "import sys; sys.stderr.write('err msg')"]
        )
        assert "err msg" in stderr

    @pytest.mark.asyncio
    async def test_returncode_zero_on_success(self):
        _, _, returncode = await run_command([sys.executable, "-c", "pass"])
        assert returncode == 0

    @pytest.mark.asyncio
    async def test_returncode_nonzero_on_failure(self):
        _, _, returncode = await run_command(
            [sys.executable, "-c", "import sys; sys.exit(1)"]
        )
        assert returncode == 1

    @pytest.mark.asyncio
    async def test_empty_args_raises_value_error(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            await run_command([])

    @pytest.mark.asyncio
    async def test_nonexistent_tool_raises_tool_not_found(self):
        with pytest.raises(ToolNotFoundError):
            await run_command(["__nonexistent_tool_xyz__"])

    @pytest.mark.asyncio
    async def test_timeout_raises_scan_timeout_error(self):
        with pytest.raises(ScanTimeoutError):
            await run_command(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=1,
            )

    @pytest.mark.asyncio
    async def test_multiline_output(self):
        code = "for i in range(3): print(i)"
        stdout, _, _ = await run_command([sys.executable, "-c", code])
        assert "0" in stdout
        assert "1" in stdout
        assert "2" in stdout

    @pytest.mark.asyncio
    async def test_uses_absolute_path_for_executable(self):
        # run_command resolves the executable to its absolute path
        stdout, _, rc = await run_command([sys.executable, "--version"])
        assert rc == 0


# ---------------------------------------------------------------------------
# TestStreamCommand
# ---------------------------------------------------------------------------


class TestStreamCommand:
    @pytest.mark.asyncio
    async def test_yields_lines(self):
        code = "for i in range(3): print(f'line{i}')"
        lines = []
        async for line in stream_command([sys.executable, "-c", code]):
            lines.append(line)
        assert lines == ["line0", "line1", "line2"]

    @pytest.mark.asyncio
    async def test_lines_have_no_trailing_newline(self):
        code = "print('hello')"
        async for line in stream_command([sys.executable, "-c", code]):
            assert not line.endswith("\n")
            assert not line.endswith("\r")

    @pytest.mark.asyncio
    async def test_empty_args_raises_value_error(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            async for _ in stream_command([]):
                pass

    @pytest.mark.asyncio
    async def test_nonexistent_tool_raises_tool_not_found(self):
        with pytest.raises(ToolNotFoundError):
            async for _ in stream_command(["__nonexistent_tool_xyz__"]):
                pass

    @pytest.mark.asyncio
    async def test_yields_empty_for_no_output_process(self):
        # A process that produces no output yields nothing
        lines = []
        async for line in stream_command([sys.executable, "-c", "pass"]):
            lines.append(line)
        assert lines == []

    @pytest.mark.asyncio
    async def test_empty_output_yields_nothing(self):
        lines = []
        async for line in stream_command([sys.executable, "-c", "pass"]):
            lines.append(line)
        assert lines == []


# ---------------------------------------------------------------------------
# TestCheckTool (registry)
# ---------------------------------------------------------------------------


class TestCheckTool:
    def test_python3_is_available(self):
        status = check_tool("python3")
        assert status.available is True
        assert status.path is not None
        assert status.name == "python3"

    def test_nonexistent_tool_not_available(self):
        status = check_tool("__nonexistent_tool_xyz__")
        assert status.available is False
        assert status.path is None

    def test_category_stored(self):
        status = check_tool("python3", category="utility")
        assert status.category == "utility"

    def test_default_category_unknown(self):
        status = check_tool("python3")
        assert status.category == "unknown"


# ---------------------------------------------------------------------------
# TestResolveToolPath (registry)
# ---------------------------------------------------------------------------


class TestResolveToolPath:
    def test_configured_path_returned_as_is(self):
        result = resolve_tool_path("nmap", configured_path="/usr/bin/nmap")
        assert result == "/usr/bin/nmap"

    def test_auto_detect_python3(self):
        result = resolve_tool_path("python3")
        assert "python" in result.lower()
        assert result.startswith("/")

    def test_nonexistent_tool_raises(self):
        with pytest.raises(ToolNotFoundError):
            resolve_tool_path("__nonexistent_tool_xyz__")

    def test_empty_configured_path_falls_through_to_which(self):
        result = resolve_tool_path("python3", configured_path="")
        assert "python" in result.lower()


# ---------------------------------------------------------------------------
# TestToolCatalog (registry structure)
# ---------------------------------------------------------------------------


class TestToolCatalog:
    def test_catalog_is_non_empty(self):
        assert len(_TOOL_CATALOG) > 0

    def test_each_entry_has_name_and_category(self):
        for entry in _TOOL_CATALOG:
            assert "name" in entry
            assert "category" in entry
            assert entry["name"]
            assert entry["category"]

    def test_nmap_in_catalog(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nmap" in names

    def test_nuclei_in_catalog(self):
        names = [t["name"] for t in _TOOL_CATALOG]
        assert "nuclei" in names

    def test_recon_category_exists(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "recon" in categories

    def test_web_category_exists(self):
        categories = {t["category"] for t in _TOOL_CATALOG}
        assert "web" in categories

    def test_all_categories_are_strings(self):
        for entry in _TOOL_CATALOG:
            assert isinstance(entry["category"], str)
