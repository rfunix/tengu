"""Unit tests for the gowitness_screenshot async tool."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.recon.gowitness"


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


async def _call_gowitness(
    mocks,
    target="http://example.com",
    mode="single",
    output_dir="/tmp/gowitness",
    timeout=None,
):
    from tengu.tools.recon.gowitness import gowitness_screenshot

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/gowitness"),
        patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
        patch(f"{TOOL_MODULE}.sanitize_target", side_effect=lambda t: t),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await gowitness_screenshot(
            mocks["ctx"], target, mode=mode, output_dir=output_dir, timeout=timeout
        )


# ---------------------------------------------------------------------------
# TestGowitnessScreenshot
# ---------------------------------------------------------------------------


class TestGowitnessScreenshot:
    async def test_invalid_mode_defaults_to_single(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, mode="invalid_mode")
        assert result["mode"] == "single"

    async def test_file_mode_uses_file_arg(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, mode="file", target="/tmp/urls.txt")
        assert "--file" in result["command"]
        assert "--url" not in result["command"]

    async def test_single_mode_uses_url_arg(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, mode="single", target="http://example.com")
        assert "--url" in result["command"]
        assert "--file" not in result["command"]

    async def test_output_dir_valid_tmp_preserved(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, output_dir="/tmp/screenshots")
        assert result["output_dir"] == "/tmp/screenshots"

    async def test_output_dir_valid_home_preserved(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, output_dir="/home/user/shots")
        assert result["output_dir"] == "/home/user/shots"

    async def test_output_dir_invalid_prefix_becomes_default(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, output_dir="/var/log/screenshots")
        assert result["output_dir"] == "/tmp/gowitness"

    async def test_output_dir_bad_chars_stripped_then_checked(self):
        """Characters like ';' are stripped; if what remains doesn't start with /tmp/ or /home/,
        fallback to /tmp/gowitness."""
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks, output_dir="/var/;rm -rf /")
        assert result["output_dir"] == "/tmp/gowitness"

    async def test_screenshots_counted_from_dir(self):
        mocks = _make_fixtures()
        fake_png = MagicMock(spec=Path)
        fake_png.suffix = ".png"
        fake_jpg = MagicMock(spec=Path)
        fake_jpg.suffix = ".jpg"
        fake_txt = MagicMock(spec=Path)
        fake_txt.suffix = ".txt"

        fake_dir = MagicMock(spec=Path)
        fake_dir.is_dir.return_value = True
        fake_dir.iterdir.return_value = [fake_png, fake_jpg, fake_txt]

        with patch(f"{TOOL_MODULE}.Path", return_value=fake_dir):
            result = await _call_gowitness(mocks, output_dir="/tmp/gowitness")

        assert result["screenshots_taken"] == 2

    async def test_no_screenshots_on_missing_dir(self):
        mocks = _make_fixtures()
        fake_dir = MagicMock(spec=Path)
        fake_dir.is_dir.return_value = False

        with patch(f"{TOOL_MODULE}.Path", return_value=fake_dir):
            result = await _call_gowitness(mocks, output_dir="/tmp/gowitness")

        assert result["screenshots_taken"] == 0
        assert result["screenshot_paths"] == []

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_gowitness(mocks, target="http://blocked.com")

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_gowitness(mocks)
        for key in (
            "tool",
            "target",
            "mode",
            "output_dir",
            "command",
            "duration_seconds",
            "screenshots_taken",
            "screenshot_paths",
            "raw_output",
        ):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "gowitness"
