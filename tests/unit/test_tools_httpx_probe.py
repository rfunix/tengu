"""Unit tests for httpx_probe."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.recon.httpx_probe import _parse_httpx_output

_MOD = "tengu.tools.recon.httpx_probe"


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


async def _run_httpx_probe(
    ctx,
    target="https://example.com",
    threads=50,
    detect_tech=True,
    stdout="",
    blocked=False,
):
    from tengu.tools.recon.httpx_probe import httpx_probe

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
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/httpx"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await httpx_probe(ctx, target, threads=threads, detect_tech=detect_tech)


class TestHttpxProbe:
    async def test_returns_tool_key(self, ctx):
        result = await _run_httpx_probe(ctx)
        assert result["tool"] == "httpx"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_httpx_probe(ctx, blocked=True)

    async def test_threads_clamped_max(self, ctx):
        result = await _run_httpx_probe(ctx, threads=999)
        assert result["threads"] <= 200

    async def test_threads_clamped_min(self, ctx):
        result = await _run_httpx_probe(ctx, threads=0)
        assert result["threads"] >= 1

    async def test_json_output_parsed(self, ctx):
        stdout = (
            json.dumps({"url": "https://example.com", "status-code": 200, "title": "Test"})
            + "\n"
        )
        result = await _run_httpx_probe(ctx, stdout=stdout)
        assert result["probes_count"] == 1
        assert result["results"][0]["status_code"] == 200

    async def test_return_keys_present(self, ctx):
        result = await _run_httpx_probe(ctx)
        for key in ("tool", "target", "threads", "duration_seconds", "probes_count", "results"):
            assert key in result

    async def test_audit_logged(self, ctx):
        from tengu.tools.recon.httpx_probe import httpx_probe

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
            patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/httpx"),
            patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
            patch(f"{_MOD}.run_command", new=AsyncMock(return_value=("", "", 0))),
            patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
        ):
            await httpx_probe(ctx, "https://example.com")

        assert audit_mock.log_tool_call.call_count >= 1

    async def test_detect_tech_false_reflected(self, ctx):
        result = await _run_httpx_probe(ctx, detect_tech=False)
        assert "results" in result


class TestParseHttpxOutput:
    def test_empty_output(self):
        result = _parse_httpx_output("")
        assert result == []

    def test_json_line_parsed(self):
        line = json.dumps(
            {
                "url": "https://example.com",
                "status-code": 200,
                "title": "Test",
                "tech": ["nginx"],
            }
        )
        result = _parse_httpx_output(line)
        assert len(result) == 1
        assert result[0]["status_code"] == 200
        assert result[0]["technologies"] == ["nginx"]

    def test_title_extracted(self):
        line = json.dumps({"url": "https://example.com", "status-code": 200, "title": "My App"})
        result = _parse_httpx_output(line)
        assert result[0]["title"] == "My App"

    def test_plain_url_fallback(self):
        result = _parse_httpx_output("https://example.com")
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com"
        assert result[0]["status_code"] is None

    def test_invalid_json_skipped(self):
        result = _parse_httpx_output("{invalid json}\nhttps://example.com")
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com"

    def test_status_code_alt_key(self):
        line = json.dumps({"url": "https://example.com", "status_code": 301})
        result = _parse_httpx_output(line)
        assert result[0]["status_code"] == 301

    def test_multiple_json_lines(self):
        lines = "\n".join(
            [
                json.dumps({"url": "https://example.com/a", "status-code": 200}),
                json.dumps({"url": "https://example.com/b", "status-code": 404}),
            ]
        )
        result = _parse_httpx_output(lines)
        assert len(result) == 2
