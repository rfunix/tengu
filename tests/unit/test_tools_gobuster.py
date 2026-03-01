"""Unit tests for gobuster_scan: validation, sanitization, and output parsing."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock() -> MagicMock:
    """Return a MagicMock that behaves like an async context manager."""
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock() -> MagicMock:
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    return audit


def _make_allowlist_mock(blocked: bool = False) -> MagicMock:
    allowlist = MagicMock()
    if blocked:
        allowlist.check.side_effect = Exception("Target not allowed")
    return allowlist


@pytest.fixture
def ctx():
    return _make_ctx()


# ---------------------------------------------------------------------------
# Patch targets
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.web.gobuster"


async def _run_gobuster_async(
    ctx,
    target="http://example.com",
    mode="dir",
    wordlist="/tmp/wl.txt",
    extensions="",
    threads=10,
    stdout="",
    stderr="",
    returncode=0,
    blocked=False,
):
    """Helper to call gobuster_scan under full mock."""
    from tengu.tools.web.gobuster import gobuster_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_target", return_value=target),
        patch(f"{_MOD}.sanitize_wordlist_path", return_value=wordlist),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/gobuster"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=_make_allowlist_mock(blocked)),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, stderr, returncode))),
    ):
        return await gobuster_scan(
            ctx, target, mode=mode, wordlist=wordlist, extensions=extensions, threads=threads
        )


def _run_gobuster(ctx, **kwargs):
    return asyncio.run(_run_gobuster_async(ctx, **kwargs))


# ---------------------------------------------------------------------------
# TestGobusterModeValidation
# ---------------------------------------------------------------------------


class TestGobusterModeValidation:
    def test_invalid_mode_defaults_to_dir(self, ctx):
        result = _run_gobuster(ctx, mode="bogus")
        assert result["mode"] == "dir"

    def test_mode_dir_preserved(self, ctx):
        result = _run_gobuster(ctx, mode="dir")
        assert result["mode"] == "dir"

    def test_mode_vhost_preserved(self, ctx):
        result = _run_gobuster(ctx, mode="vhost")
        assert result["mode"] == "vhost"

    def test_mode_dns_preserved(self, ctx):
        result = _run_gobuster(ctx, mode="dns")
        assert result["mode"] == "dns"

    def test_mode_fuzz_preserved(self, ctx):
        result = _run_gobuster(ctx, mode="fuzz")
        assert result["mode"] == "fuzz"


# ---------------------------------------------------------------------------
# TestGobusterThreadsClamping
# ---------------------------------------------------------------------------


class TestGobusterThreadsClamping:
    def test_threads_clamped_min(self, ctx):
        result = _run_gobuster(ctx, threads=0)
        assert "-t 1" in result["command"]

    def test_threads_clamped_max(self, ctx):
        result = _run_gobuster(ctx, threads=100)
        assert "-t 50" in result["command"]

    def test_threads_within_range_preserved(self, ctx):
        result = _run_gobuster(ctx, threads=20)
        assert "-t 20" in result["command"]


# ---------------------------------------------------------------------------
# TestGobusterExtensions
# ---------------------------------------------------------------------------


class TestGobusterExtensions:
    def test_extensions_sanitized_bad_chars(self, ctx):
        # extensions with shell metacharacters — only alphanumeric, comma, dot kept
        result = _run_gobuster(ctx, mode="dir", extensions="php;rm -rf /,html")
        assert ";" not in result["command"]

    def test_extensions_only_in_dir_mode(self, ctx):
        # In vhost mode extensions must NOT be added even if provided
        result = _run_gobuster(ctx, mode="vhost", extensions="php,html")
        assert "-x" not in result["command"]

    def test_extensions_added_in_dir_mode(self, ctx):
        result = _run_gobuster(ctx, mode="dir", extensions="php,html")
        assert "-x" in result["command"]

    def test_empty_extensions_not_added(self, ctx):
        result = _run_gobuster(ctx, mode="dir", extensions="")
        assert "-x" not in result["command"]


# ---------------------------------------------------------------------------
# TestGobusterFindingsParsing
# ---------------------------------------------------------------------------


class TestGobusterFindingsParsing:
    def test_findings_parsed_from_stdout(self, ctx):
        stdout = "/admin (Status: 200) [Size: 1234]\n/login (Status: 301)\n"
        result = _run_gobuster(ctx, stdout=stdout)
        assert result["findings_count"] == 2
        assert "/admin (Status: 200) [Size: 1234]" in result["findings"]

    def test_header_lines_starting_with_equals_excluded(self, ctx):
        stdout = (
            "===============================================================\n/path (Status: 200)\n"
        )
        result = _run_gobuster(ctx, stdout=stdout)
        assert result["findings_count"] == 1
        assert all(not f.startswith("=") for f in result["findings"])

    def test_lines_starting_with_bracket_excluded(self, ctx):
        stdout = "[+] Gobuster started\n/admin (Status: 200)\n"
        result = _run_gobuster(ctx, stdout=stdout)
        assert result["findings_count"] == 1
        assert "/admin (Status: 200)" in result["findings"]

    def test_empty_stdout_zero_findings(self, ctx):
        result = _run_gobuster(ctx, stdout="")
        assert result["findings_count"] == 0
        assert result["findings"] == []


# ---------------------------------------------------------------------------
# TestGobusterReturnStructure
# ---------------------------------------------------------------------------


class TestGobusterReturnStructure:
    def test_return_keys_present(self, ctx):
        result = _run_gobuster(ctx)
        expected_keys = {
            "tool",
            "target",
            "mode",
            "wordlist",
            "command",
            "duration_seconds",
            "findings_count",
            "findings",
            "raw_output",
            "errors",
        }
        assert expected_keys.issubset(result.keys())

    def test_tool_name_is_gobuster(self, ctx):
        result = _run_gobuster(ctx)
        assert result["tool"] == "gobuster"

    def test_errors_none_on_success(self, ctx):
        result = _run_gobuster(ctx, returncode=0, stderr="")
        assert result["errors"] is None

    def test_errors_set_on_failure(self, ctx):
        result = _run_gobuster(ctx, returncode=1, stderr="connection refused")
        assert result["errors"] == "connection refused"


# ---------------------------------------------------------------------------
# TestGobusterAllowlist
# ---------------------------------------------------------------------------


class TestGobusterAllowlist:
    async def test_allowlist_blocked_raises(self, ctx):
        from tengu.tools.web.gobuster import gobuster_scan

        rate_limited_mock = _make_rate_limited_mock()
        audit_mock = _make_audit_mock()
        cfg_mock = MagicMock()
        cfg_mock.tools.defaults.scan_timeout = 300

        blocked_allowlist = _make_allowlist_mock(blocked=True)
        raised = False
        try:
            with (
                patch(f"{_MOD}.get_config", return_value=cfg_mock),
                patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
                patch(f"{_MOD}.rate_limited", rate_limited_mock),
                patch(f"{_MOD}.sanitize_target", return_value="http://evil.com"),
                patch(f"{_MOD}.sanitize_wordlist_path", return_value="/tmp/wl.txt"),
                patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/gobuster"),
                patch(f"{_MOD}.make_allowlist_from_config", return_value=blocked_allowlist),
            ):
                await gobuster_scan(ctx, "http://evil.com")
        except Exception:
            raised = True
        assert raised, "Expected an exception when target is blocked"
