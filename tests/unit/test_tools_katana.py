"""Unit tests for katana_crawl."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.recon.katana import _parse_katana_output

_MOD = "tengu.tools.recon.katana"


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
    return stealth


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_katana(
    ctx,
    target="https://example.com",
    depth=3,
    concurrency=10,
    js_crawl=False,
    stdout="",
    blocked=False,
):
    from tengu.tools.recon.katana import katana_crawl

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
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/katana"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await katana_crawl(ctx, target, depth=depth, concurrency=concurrency, js_crawl=js_crawl)


class TestKatanaCrawl:
    async def test_returns_tool_key(self, ctx):
        result = await _run_katana(ctx)
        assert result["tool"] == "katana"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_katana(ctx, blocked=True)

    async def test_depth_clamped_max(self, ctx):
        result = await _run_katana(ctx, depth=50)
        assert result["depth"] <= 10

    async def test_depth_clamped_min(self, ctx):
        result = await _run_katana(ctx, depth=0)
        assert result["depth"] >= 1

    async def test_concurrency_clamped_max(self, ctx):
        result = await _run_katana(ctx, concurrency=999)
        assert result["concurrency"] <= 50

    async def test_concurrency_clamped_min(self, ctx):
        result = await _run_katana(ctx, concurrency=0)
        assert result["concurrency"] >= 1

    async def test_urls_parsed(self, ctx):
        stdout = "https://example.com/page1\nhttps://example.com/page2\n"
        result = await _run_katana(ctx, stdout=stdout)
        assert result["urls_found"] == 2

    async def test_return_keys_present(self, ctx):
        result = await _run_katana(ctx)
        for key in (
            "tool",
            "target",
            "depth",
            "concurrency",
            "js_crawl",
            "duration_seconds",
            "urls_found",
            "urls",
        ):
            assert key in result

    async def test_js_crawl_flag_reflected(self, ctx):
        result = await _run_katana(ctx, js_crawl=True)
        assert result["js_crawl"] is True

    async def test_audit_logged(self, ctx):
        from tengu.tools.recon.katana import katana_crawl

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
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/katana"),
            patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
            patch(f"{_MOD}.run_command", new=AsyncMock(return_value=("", "", 0))),
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
        ):
            await katana_crawl(ctx, "https://example.com")

        assert audit_mock.log_tool_call.call_count >= 1


class TestParseKatanaOutput:
    def test_empty_output(self):
        result = _parse_katana_output("")
        assert result == []

    def test_http_urls_extracted(self):
        result = _parse_katana_output("https://example.com/page\nhttp://example.com/login\n")
        assert len(result) == 2

    def test_non_urls_skipped(self):
        result = _parse_katana_output(
            "Starting crawler\nhttps://example.com/admin\nFinished\n"
        )
        assert len(result) == 1

    def test_duplicates_removed(self):
        result = _parse_katana_output(
            "https://example.com/page\nhttps://example.com/page\n"
        )
        assert len(result) == 1

    def test_only_https_scheme(self):
        result = _parse_katana_output("ftp://example.com/file\nhttps://example.com/page\n")
        assert len(result) == 1
        assert result[0] == "https://example.com/page"
