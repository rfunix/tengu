"""Unit tests for crlfuzz_scan: validation, sanitization, and output parsing."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.injection.crlfuzz import _parse_crlfuzz_output

_MOD = "tengu.tools.injection.crlfuzz"


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock() -> MagicMock:
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock() -> MagicMock:
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    return audit


def _mock_stealth(enabled: bool = False, proxy_url: str = "") -> MagicMock:
    stealth = MagicMock()
    stealth.enabled = enabled
    stealth.proxy_url = proxy_url
    return stealth


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_crlfuzz(
    ctx,
    url="https://example.com/redirect?url=test",
    threads=25,
    stdout="",
    stderr="",
    returncode=0,
    blocked=False,
):
    from tengu.tools.injection.crlfuzz import crlfuzz_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300
    allowlist_mock = MagicMock()
    if blocked:
        allowlist_mock.check.side_effect = Exception("Target not allowed")

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_url", return_value=url),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/crlfuzz"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, stderr, returncode))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await crlfuzz_scan(ctx, url, threads=threads)


class TestCrlfuzzScan:
    async def test_returns_tool_key(self, ctx):
        result = await _run_crlfuzz(ctx)
        assert result["tool"] == "crlfuzz"

    async def test_threads_clamped_max(self, ctx):
        result = await _run_crlfuzz(ctx, threads=200)
        assert result["threads"] <= 50

    async def test_threads_clamped_min(self, ctx):
        result = await _run_crlfuzz(ctx, threads=0)
        assert result["threads"] >= 1

    async def test_blocked_raises(self, ctx):
        with pytest.raises(Exception, match="Target not allowed"):
            await _run_crlfuzz(ctx, blocked=True)

    async def test_vulnerable_detected(self, ctx):
        out = "VULN https://example.com/redirect?url=test%0D%0AHeader:Injected\n"
        result = await _run_crlfuzz(ctx, stdout=out)
        assert result["vulnerable"] is True

    async def test_not_vulnerable(self, ctx):
        result = await _run_crlfuzz(ctx, stdout="")
        assert result["vulnerable"] is False

    async def test_return_keys_present(self, ctx):
        result = await _run_crlfuzz(ctx)
        for key in ("tool", "url", "threads", "duration_seconds", "vulnerable", "vulnerable_urls"):
            assert key in result


class TestParseCrlfuzzOutput:
    def test_empty_output(self):
        result = _parse_crlfuzz_output("")
        assert result["vulnerable"] is False
        assert result["vulnerable_urls"] == []

    def test_vuln_marker_detected(self):
        result = _parse_crlfuzz_output("VULN https://example.com/path")
        assert result["vulnerable"] is True
        assert len(result["vulnerable_urls"]) == 1

    def test_plus_marker_detected(self):
        result = _parse_crlfuzz_output("[+] CRLF injection found at https://example.com")
        assert result["vulnerable"] is True

    def test_multiple_vulns(self):
        output = "VULN url1\nVULN url2\n"
        result = _parse_crlfuzz_output(output)
        assert len(result["vulnerable_urls"]) == 2
