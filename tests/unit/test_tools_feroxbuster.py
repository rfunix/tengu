"""Unit tests for feroxbuster_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.web.feroxbuster import _parse_feroxbuster_output

_MOD = "tengu.tools.web.feroxbuster"


def _make_ctx():
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock():
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock():
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    return audit


def _mock_stealth(enabled=False, proxy_url=""):
    stealth = MagicMock()
    stealth.enabled = enabled
    stealth.proxy_url = proxy_url
    stealth.inject_proxy_flags = MagicMock(
        side_effect=lambda tool, args: args + ["--proxy", proxy_url] if proxy_url else args
    )
    return stealth


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_feroxbuster(
    ctx,
    target="https://example.com",
    wordlist="/tmp/wl.txt",
    extensions="",
    threads=50,
    depth=4,
    stdout="",
    blocked=False,
):
    from tengu.tools.web.feroxbuster import feroxbuster_scan

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
        patch(f"{_MOD}.sanitize_wordlist_path", return_value=wordlist),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/feroxbuster"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await feroxbuster_scan(
            ctx,
            target,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads,
            depth=depth,
        )


class TestFeroxbusterScan:
    async def test_returns_tool_key(self, ctx):
        result = await _run_feroxbuster(ctx)
        assert result["tool"] == "feroxbuster"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_feroxbuster(ctx, blocked=True)

    async def test_threads_clamped_max(self, ctx):
        result = await _run_feroxbuster(ctx, threads=500)
        assert result["threads"] <= 100

    async def test_threads_clamped_min(self, ctx):
        result = await _run_feroxbuster(ctx, threads=0)
        assert result["threads"] >= 1

    async def test_depth_clamped_max(self, ctx):
        result = await _run_feroxbuster(ctx, depth=50)
        assert result["depth"] <= 10

    async def test_depth_clamped_min(self, ctx):
        result = await _run_feroxbuster(ctx, depth=0)
        assert result["depth"] >= 1

    async def test_findings_parsed(self, ctx):
        stdout = "200      GET      1l      2w      3c https://example.com/admin\n"
        result = await _run_feroxbuster(ctx, stdout=stdout)
        assert result["findings_count"] == 1

    async def test_return_keys_present(self, ctx):
        result = await _run_feroxbuster(ctx)
        for key in (
            "tool",
            "target",
            "wordlist",
            "threads",
            "depth",
            "duration_seconds",
            "findings_count",
            "findings",
        ):
            assert key in result

    async def test_audit_logged(self, ctx):
        from tengu.tools.web.feroxbuster import feroxbuster_scan

        rate_limited_mock = _make_rate_limited_mock()
        audit_mock = _make_audit_mock()
        cfg_mock = MagicMock()
        cfg_mock.tools.defaults.scan_timeout = 300
        allowlist_mock = MagicMock()

        with (
            patch(f"{_MOD}.get_config", return_value=cfg_mock),
            patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
            patch(f"{_MOD}.rate_limited", rate_limited_mock),
            patch(f"{_MOD}.sanitize_target", return_value="https://example.com"),
            patch(f"{_MOD}.sanitize_wordlist_path", return_value="/tmp/wl.txt"),
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/feroxbuster"),
            patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
            patch(f"{_MOD}.run_command", new=AsyncMock(return_value=("", "", 0))),
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
        ):
            await feroxbuster_scan(ctx, "https://example.com", wordlist="/tmp/wl.txt")

        assert audit_mock.log_tool_call.call_count >= 1


class TestParseFeroxbusterOutput:
    def test_empty_output(self):
        result = _parse_feroxbuster_output("")
        assert result == []

    def test_status_line_parsed(self):
        output = "200      GET      1l      2w      3c https://example.com/admin\n"
        result = _parse_feroxbuster_output(output)
        assert len(result) == 1
        assert result[0]["status"] == 200

    def test_url_extracted_from_line(self):
        output = "200      GET      1l      2w      3c https://example.com/admin\n"
        result = _parse_feroxbuster_output(output)
        assert result[0]["url"] == "https://example.com/admin"

    def test_non_status_lines_skipped(self):
        output = "Starting feroxbuster\n200      GET   1l  1w  1c https://example.com/admin\n"
        result = _parse_feroxbuster_output(output)
        assert len(result) == 1

    def test_multiple_findings(self):
        output = (
            "200      GET      1l      2w      3c https://example.com/admin\n"
            "301      GET      0l      0w      0c https://example.com/login\n"
            "403      GET      1l      1w      1c https://example.com/secret\n"
        )
        result = _parse_feroxbuster_output(output)
        assert len(result) == 3

    def test_status_codes_parsed_correctly(self):
        output = "404      GET      0l      0w      0c https://example.com/notfound\n"
        result = _parse_feroxbuster_output(output)
        assert result[0]["status"] == 404
