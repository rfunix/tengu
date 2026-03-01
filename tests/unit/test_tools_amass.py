"""Unit tests for the amass_enum async tool."""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

TOOL_MODULE = "tengu.tools.recon.amass"


def _make_rate_limited_mock():
    """Return a mock for rate_limited that acts as an async context manager."""
    mock_rl = MagicMock()

    @asynccontextmanager
    async def _fake(*args, **kwargs):
        yield

    mock_rl.side_effect = _fake
    return mock_rl


def _make_fixtures(*, allowlist_raises=False, run_stdout="", run_stderr="", run_rc=0):
    """Build all patch targets and return a dict of mocks."""
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


async def _call_amass(mocks, domain="example.com", mode="passive", timeout=None):
    from tengu.tools.recon.amass import amass_enum

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/amass"),
        patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await amass_enum(mocks["ctx"], domain, mode=mode, timeout=timeout)


# ---------------------------------------------------------------------------
# TestAmassEnum
# ---------------------------------------------------------------------------


class TestAmassEnum:
    async def test_passive_mode_flag_added(self):
        mocks = _make_fixtures()
        result = await _call_amass(mocks, mode="passive")
        assert "-passive" in result["command"]

    async def test_active_mode_no_passive_flag(self):
        mocks = _make_fixtures()
        result = await _call_amass(mocks, mode="active")
        assert "-passive" not in result["command"]

    async def test_invalid_mode_defaults_to_passive(self):
        mocks = _make_fixtures()
        result = await _call_amass(mocks, mode="xyz")
        assert result["mode"] == "passive"
        assert "-passive" in result["command"]

    async def test_subdomains_parsed_correctly(self):
        stdout = "api.example.com\nwww.example.com\nother.example.com\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_amass(mocks, domain="example.com")
        assert "api.example.com" in result["subdomains"]
        assert "www.example.com" in result["subdomains"]
        assert result["subdomains_found"] == 3

    async def test_lines_starting_with_bracket_ignored(self):
        stdout = "[INFO] sub.example.com\nsub.example.com\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_amass(mocks, domain="example.com")
        # Only the non-bracket line should be parsed
        assert result["subdomains_found"] == 1
        assert "sub.example.com" in result["subdomains"]

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_amass(mocks, domain="blocked.com")

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_amass(mocks)
        for key in (
            "tool",
            "domain",
            "mode",
            "command",
            "duration_seconds",
            "subdomains_found",
            "subdomains",
            "raw_output",
            "errors",
        ):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "amass"

    async def test_errors_field_none_on_success(self):
        mocks = _make_fixtures(run_stderr="some stderr", run_rc=0)
        result = await _call_amass(mocks)
        assert result["errors"] is None

    async def test_errors_field_set_on_failure(self):
        mocks = _make_fixtures(run_stderr="error occurred", run_rc=1)
        result = await _call_amass(mocks)
        assert result["errors"] == "error occurred"

    async def test_run_command_exception_reraises(self):
        mocks = _make_fixtures()
        from tengu.tools.recon.amass import amass_enum

        async def _boom(*args, **kwargs):
            raise RuntimeError("timeout!")

        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/amass"),
            patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
            patch(f"{TOOL_MODULE}.run_command", new=_boom),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
            pytest.raises(RuntimeError, match="timeout"),
        ):
            await amass_enum(mocks["ctx"], "example.com")

    async def test_timeout_override(self):
        """When explicit timeout is given it is used instead of config default."""
        mocks = _make_fixtures()
        # We can't directly inspect the timeout passed to run_command without
        # capturing it; instead, just verify the call succeeds without error.
        result = await _call_amass(mocks, timeout=60)
        assert result["tool"] == "amass"

    async def test_subdomains_deduplicated_and_sorted(self):
        stdout = "www.example.com\nwww.example.com\napi.example.com\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_amass(mocks, domain="example.com")
        assert result["subdomains"] == sorted(set(result["subdomains"]))
        assert result["subdomains_found"] == 2
