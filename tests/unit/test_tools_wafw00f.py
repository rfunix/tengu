"""Unit tests for wafw00f_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.web.wafw00f import _parse_wafw00f_output

_MOD = "tengu.tools.web.wafw00f"


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
    stealth.inject_proxy_flags = MagicMock(side_effect=lambda tool, args: args)
    return stealth


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_wafw00f(
    ctx,
    target="https://example.com",
    detect_all=False,
    stdout="",
    blocked=False,
):
    from tengu.tools.web.wafw00f import wafw00f_scan

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
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/wafw00f"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await wafw00f_scan(ctx, target, detect_all=detect_all)


class TestWafw00fScan:
    async def test_returns_tool_key(self, ctx):
        result = await _run_wafw00f(ctx)
        assert result["tool"] == "wafw00f"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_wafw00f(ctx, blocked=True)

    async def test_return_keys_present(self, ctx):
        result = await _run_wafw00f(ctx)
        for key in ("tool", "target", "duration_seconds", "waf_detected", "detections", "raw_output"):
            assert key in result

    async def test_waf_detected_from_output(self, ctx):
        out = "The site https://example.com is behind Cloudflare WAF\n"
        result = await _run_wafw00f(ctx, stdout=out)
        assert result["waf_detected"] is True

    async def test_no_waf(self, ctx):
        result = await _run_wafw00f(ctx, stdout="No WAF detected")
        assert result["waf_detected"] is False

    async def test_audit_logged(self, ctx):
        from tengu.tools.web.wafw00f import wafw00f_scan

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
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/wafw00f"),
            patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
            patch(f"{_MOD}.run_command", new=AsyncMock(return_value=("", "", 0))),
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
        ):
            await wafw00f_scan(ctx, "https://example.com")

        assert audit_mock.log_tool_call.call_count >= 1


class TestParseWafw00fOutput:
    def test_empty_output(self):
        result = _parse_wafw00f_output("")
        assert result["waf_detected"] is False
        assert result["detections"] == []

    def test_waf_detected(self):
        result = _parse_wafw00f_output("is behind Cloudflare WAF and detected")
        assert result["waf_detected"] is True

    def test_no_waf_detected(self):
        result = _parse_wafw00f_output("No WAF detected by wafw00f")
        assert result["waf_detected"] is False

    def test_detections_collected(self):
        output = (
            "The site https://example.com is behind Cloudflare WAF\n"
            "The site https://example.com is behind AWS WAF detected\n"
        )
        result = _parse_wafw00f_output(output)
        assert len(result["detections"]) == 2

    def test_no_waf_overrides_detections(self):
        output = "is behind some WAF detected\nNo WAF detected\n"
        result = _parse_wafw00f_output(output)
        assert result["waf_detected"] is False
