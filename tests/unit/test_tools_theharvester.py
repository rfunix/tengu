"""Unit tests for the theharvester_scan async tool."""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.osint.theharvester"


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


async def _call_harvester(
    mocks,
    domain="example.com",
    sources="bing,crtsh",
    limit=500,
    timeout=None,
):
    from tengu.tools.osint.theharvester import theharvester_scan

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/theHarvester"),
        patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await theharvester_scan(
            mocks["ctx"], domain, sources=sources, limit=limit, timeout=timeout
        )


# ---------------------------------------------------------------------------
# TestTheHarvesterScan
# ---------------------------------------------------------------------------


class TestTheHarvesterScan:
    async def test_limit_clamped_min(self):
        mocks = _make_fixtures()
        result = await _call_harvester(mocks, limit=0)
        # limit=0 → clamped to 1; must appear in command as "-l 1"
        assert "-l 1" in result["command"]

    async def test_limit_clamped_max(self):
        mocks = _make_fixtures()
        result = await _call_harvester(mocks, limit=9999)
        assert "-l 2000" in result["command"]

    async def test_sources_sanitized_removes_special_chars(self):
        mocks = _make_fixtures()
        result = await _call_harvester(mocks, sources="bing;ls -la,crtsh")
        # semicolon and spaces should be stripped
        assert ";" not in result["sources"]
        assert " " not in result["sources"]

    async def test_emails_parsed_from_section(self):
        stdout = "[*] Emails found:\nadmin@example.com\ninfo@example.com\n[*] Hosts found:\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_harvester(mocks, domain="example.com")
        assert "admin@example.com" in result["emails"]
        assert "info@example.com" in result["emails"]

    async def test_ips_parsed_from_hosts_section(self):
        stdout = "[*] Hosts found:\n192.168.1.100\n10.0.0.1\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_harvester(mocks, domain="example.com")
        assert "192.168.1.100" in result["ips"]
        assert "10.0.0.1" in result["ips"]

    async def test_subdomains_parsed_from_hosts_section(self):
        stdout = "[*] Hosts found:\napi.example.com\nmail.example.com\n192.168.1.1\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_harvester(mocks, domain="example.com")
        assert "api.example.com" in result["subdomains"]
        assert "mail.example.com" in result["subdomains"]

    async def test_full_output_emails_also_scanned(self):
        """Emails appearing anywhere in output (not just the section) should be captured."""
        stdout = "Some line with contact@example.com in it\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_harvester(mocks, domain="example.com")
        assert "contact@example.com" in result["emails"]

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_harvester(mocks, domain="blocked.com")

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_harvester(mocks)
        for key in (
            "tool",
            "domain",
            "sources",
            "command",
            "duration_seconds",
            "emails_found",
            "emails",
            "subdomains_found",
            "subdomains",
            "ips_found",
            "ips",
            "hosts",
            "raw_output",
        ):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "theHarvester"

    async def test_empty_output_returns_empty_lists(self):
        mocks = _make_fixtures(run_stdout="")
        result = await _call_harvester(mocks)
        assert result["emails"] == []
        assert result["subdomains"] == []
        assert result["ips"] == []
