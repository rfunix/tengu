"""Unit tests for the httrack_mirror async tool."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.recon.httrack"


def _make_rate_limited_mock():
    mock_rl = MagicMock()

    @asynccontextmanager
    async def _fake(*args, **kwargs):
        yield

    mock_rl.side_effect = _fake
    return mock_rl


def _make_fixtures(*, allowlist_raises=False, run_stdout="", run_stderr="", run_rc=0):
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()

    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = 300

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()

    allowlist = MagicMock()
    if allowlist_raises:
        allowlist.check.side_effect = ValueError("blocked")
    else:
        allowlist.check.return_value = None

    return {
        "ctx": ctx,
        "cfg": cfg,
        "audit": audit,
        "allowlist": allowlist,
        "run_return": (run_stdout, run_stderr, run_rc),
    }


async def _call_httrack(
    mocks,
    target="http://example.com",
    depth=2,
    output_dir="/tmp/httrack",
    max_size=100,
    include_assets=True,
    timeout=None,
):
    from tengu.tools.recon.httrack import httrack_mirror

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/httrack"),
        patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
        patch(f"{TOOL_MODULE}._count_files_by_type", return_value={"html": 10, "js": 5, "css": 3}),
        patch(f"{TOOL_MODULE}._find_interesting", return_value=[]),
        patch(f"{TOOL_MODULE}._dir_size_mb", return_value=5.0),
    ):
        return await httrack_mirror(
            mocks["ctx"],
            target,
            depth=depth,
            output_dir=output_dir,
            max_size=max_size,
            include_assets=include_assets,
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# TestHttrackMirror
# ---------------------------------------------------------------------------


class TestHttrackMirror:
    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks)
        expected_keys = (
            "tool",
            "target",
            "output_dir",
            "depth",
            "max_size_mb",
            "include_assets",
            "pages_downloaded",
            "total_files",
            "total_size_mb",
            "duration_seconds",
            "file_types",
            "interesting_findings",
            "command",
            "raw_output",
        )
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "httrack"

    async def test_depth_clamped_to_max(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, depth=99)
        assert result["depth"] == 5

    async def test_depth_clamped_to_min(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, depth=0)
        assert result["depth"] == 1

    async def test_max_size_clamped_to_max(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, max_size=9999)
        assert result["max_size_mb"] == 500

    async def test_max_size_clamped_to_min(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, max_size=0)
        assert result["max_size_mb"] == 1

    async def test_output_dir_valid_tmp_preserved(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, output_dir="/tmp/mysite")
        assert result["output_dir"] == "/tmp/mysite"

    async def test_output_dir_valid_home_preserved(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, output_dir="/home/user/mirror")
        assert result["output_dir"] == "/home/user/mirror"

    async def test_output_dir_invalid_prefix_becomes_default(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, output_dir="/var/www/mirror")
        assert result["output_dir"] == "/tmp/httrack"

    async def test_output_dir_bad_chars_stripped_then_checked(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, output_dir="/var/;rm -rf /")
        assert result["output_dir"] == "/tmp/httrack"

    async def test_command_contains_depth_flag(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, depth=3)
        assert "-r3" in result["command"]

    async def test_command_contains_output_flag(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, output_dir="/tmp/testsite")
        assert "-O" in result["command"]
        assert "/tmp/testsite" in result["command"]

    async def test_no_assets_adds_exclusion_flags(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks, include_assets=False)
        assert "*.png" in result["command"] or "-*.png" in result["command"]

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_httrack(mocks, target="http://blocked.com")

    async def test_allowlist_blocked_logs_target_blocked(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError):
            await _call_httrack(mocks, target="http://blocked.com")
        mocks["audit"].log_target_blocked.assert_awaited_once()

    async def test_pages_downloaded_counts_html(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks)
        # _count_files_by_type mock returns {"html": 10, "js": 5, "css": 3}
        assert result["pages_downloaded"] == 10

    async def test_total_files_is_sum_of_file_types(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks)
        assert result["total_files"] == 18  # 10 + 5 + 3

    async def test_total_size_mb_returned(self):
        mocks = _make_fixtures()
        result = await _call_httrack(mocks)
        assert result["total_size_mb"] == 5.0

    async def test_audit_log_started_and_completed(self):
        mocks = _make_fixtures()
        await _call_httrack(mocks)
        calls = mocks["audit"].log_tool_call.await_args_list
        results = [c.kwargs.get("result") or c.args[3] for c in calls]
        assert "started" in results
        assert "completed" in results

    async def test_run_command_exception_logs_failed(self):
        mocks = _make_fixtures()
        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/httrack"),
            patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
            patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(side_effect=RuntimeError("timeout"))),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
        ):
            from tengu.tools.recon.httrack import httrack_mirror

            with pytest.raises(RuntimeError):
                await httrack_mirror(mocks["ctx"], "http://example.com")

        calls = mocks["audit"].log_tool_call.await_args_list
        results = [c.kwargs.get("result") or c.args[3] for c in calls]
        assert "failed" in results

    async def test_interesting_findings_included(self):
        mocks = _make_fixtures()
        findings = ["Found potential API key in config.js"]
        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/httrack"),
            patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
            patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=("", "", 0))),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
            patch(f"{TOOL_MODULE}._count_files_by_type", return_value={}),
            patch(f"{TOOL_MODULE}._find_interesting", return_value=findings),
            patch(f"{TOOL_MODULE}._dir_size_mb", return_value=1.0),
        ):
            from tengu.tools.recon.httrack import httrack_mirror

            result = await httrack_mirror(mocks["ctx"], "http://example.com")
        assert result["interesting_findings"] == findings

    async def test_timeout_uses_config_default(self):
        mocks = _make_fixtures()
        run_mock = AsyncMock(return_value=("", "", 0))
        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/httrack"),
            patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
            patch(f"{TOOL_MODULE}.run_command", new=run_mock),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
            patch(f"{TOOL_MODULE}._count_files_by_type", return_value={}),
            patch(f"{TOOL_MODULE}._find_interesting", return_value=[]),
            patch(f"{TOOL_MODULE}._dir_size_mb", return_value=0.0),
        ):
            from tengu.tools.recon.httrack import httrack_mirror

            await httrack_mirror(mocks["ctx"], "http://example.com", timeout=None)

        _, kwargs = run_mock.call_args
        assert kwargs.get("timeout") == 300 or run_mock.call_args[0][1] == 300


# ---------------------------------------------------------------------------
# TestHttrackHelpers
# ---------------------------------------------------------------------------


class TestHttrackHelpers:
    def test_sanitize_output_dir_valid_tmp(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir

        assert _sanitize_output_dir("/tmp/mydir") == "/tmp/mydir"

    def test_sanitize_output_dir_valid_home(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir

        assert _sanitize_output_dir("/home/user/sites") == "/home/user/sites"

    def test_sanitize_output_dir_bad_prefix_falls_back(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir

        assert _sanitize_output_dir("/etc/secrets") == "/tmp/httrack"

    def test_sanitize_output_dir_strips_bad_chars(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir

        result = _sanitize_output_dir("/tmp/dir;whoami")
        assert ";" not in result

    def test_count_files_empty_dir(self, tmp_path):
        from tengu.tools.recon.httrack import _count_files_by_type

        result = _count_files_by_type(tmp_path)
        assert result == {}

    def test_count_files_groups_by_extension(self, tmp_path):
        from tengu.tools.recon.httrack import _count_files_by_type

        (tmp_path / "a.html").write_text("x")
        (tmp_path / "b.html").write_text("x")
        (tmp_path / "c.js").write_text("x")
        result = _count_files_by_type(tmp_path)
        assert result["html"] == 2
        assert result["js"] == 1

    def test_count_files_no_extension_goes_to_other(self, tmp_path):
        from tengu.tools.recon.httrack import _count_files_by_type

        (tmp_path / "noext").write_text("x")
        result = _count_files_by_type(tmp_path)
        assert result.get("other", 0) == 1

    def test_find_interesting_detects_api_key(self, tmp_path):
        from tengu.tools.recon.httrack import _find_interesting

        (tmp_path / "config.js").write_text("api_key = 'abc123'")
        findings = _find_interesting(tmp_path)
        assert any("API key" in f for f in findings)

    def test_find_interesting_detects_todo(self, tmp_path):
        from tengu.tools.recon.httrack import _find_interesting

        (tmp_path / "app.js").write_text("// TODO: remove debug code")
        findings = _find_interesting(tmp_path)
        assert any("development note" in f for f in findings)

    def test_find_interesting_empty_dir(self, tmp_path):
        from tengu.tools.recon.httrack import _find_interesting

        assert _find_interesting(tmp_path) == []

    def test_find_interesting_nonexistent_dir(self):
        from tengu.tools.recon.httrack import _find_interesting

        result = _find_interesting(Path("/nonexistent/path/xyz"))
        assert result == []

    def test_dir_size_mb_empty_dir(self, tmp_path):
        from tengu.tools.recon.httrack import _dir_size_mb

        assert _dir_size_mb(tmp_path) == 0.0

    def test_dir_size_mb_nonexistent(self):
        from tengu.tools.recon.httrack import _dir_size_mb

        assert _dir_size_mb(Path("/nonexistent/xyz")) == 0.0

    def test_dir_size_mb_with_files(self, tmp_path):
        from tengu.tools.recon.httrack import _dir_size_mb

        (tmp_path / "file.html").write_bytes(b"x" * 1024 * 512)  # 0.5 MB
        size = _dir_size_mb(tmp_path)
        assert size > 0
