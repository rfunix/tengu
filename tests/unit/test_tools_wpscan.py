"""Unit tests for wpscan_scan: validation, sanitization, and JSON parsing."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.web.wpscan"


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


def _make_allowlist_mock(blocked: bool = False) -> MagicMock:
    allowlist = MagicMock()
    if blocked:
        allowlist.check.side_effect = Exception("Target not allowed")
    return allowlist


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_wpscan_async(
    ctx,
    url="http://wordpress.example.com",
    enumerate="vp,vt,u",
    api_token="",
    threads=5,
    stdout="",
    returncode=0,
    blocked=False,
):
    """Run wpscan_scan under full mock."""
    from tengu.tools.web.wpscan import wpscan_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_url", return_value=url),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/wpscan"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=_make_allowlist_mock(blocked)),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", returncode))),
    ):
        return await wpscan_scan(
            ctx, url, enumerate=enumerate, api_token=api_token, threads=threads
        )


def _run_wpscan(ctx, **kwargs):
    return asyncio.run(_run_wpscan_async(ctx, **kwargs))


# ---------------------------------------------------------------------------
# TestWpscanEnumSanitization
# ---------------------------------------------------------------------------


class TestWpscanEnumSanitization:
    def test_enumerate_uppercase_removed(self, ctx):
        """Uppercase chars are stripped — only lowercase a-z and commas kept."""
        result = _run_wpscan(ctx, enumerate="VP,VT")
        # "VP,VT" → lower → "vp,vt" → sanitized stays "vp,vt"
        assert "vp,vt" in result["command"]

    def test_enumerate_special_chars_removed(self, ctx):
        result = _run_wpscan(ctx, enumerate="vp;rm -rf /")
        assert ";" not in result["command"]

    def test_enumerate_lowercase_preserved(self, ctx):
        result = _run_wpscan(ctx, enumerate="vp,vt,u")
        assert "vp,vt,u" in result["command"]


# ---------------------------------------------------------------------------
# TestWpscanThreadsClamping
# ---------------------------------------------------------------------------


class TestWpscanThreadsClamping:
    def test_threads_clamped_min(self, ctx):
        result = _run_wpscan(ctx, threads=0)
        assert "--threads 1" in result["command"]

    def test_threads_clamped_max(self, ctx):
        result = _run_wpscan(ctx, threads=30)
        assert "--threads 20" in result["command"]

    def test_threads_within_range_preserved(self, ctx):
        result = _run_wpscan(ctx, threads=10)
        assert "--threads 10" in result["command"]


# ---------------------------------------------------------------------------
# TestWpscanApiToken
# ---------------------------------------------------------------------------


class TestWpscanApiToken:
    def test_api_token_added_to_command(self, ctx):
        result = _run_wpscan(ctx, api_token="mysecrettoken")
        assert "--api-token" in result["command"]
        assert "mysecrettoken" in result["command"]

    def test_no_api_token_not_in_command(self, ctx):
        result = _run_wpscan(ctx, api_token="")
        assert "--api-token" not in result["command"]


# ---------------------------------------------------------------------------
# TestWpscanJsonParsing
# ---------------------------------------------------------------------------


def _make_wpscan_output(
    wp_version: str | None = "6.3",
    plugins: dict | None = None,
    themes: dict | None = None,
    users: dict | None = None,
) -> str:
    data: dict = {}
    if wp_version is not None:
        data["version"] = {"number": wp_version}
    if plugins is not None:
        data["plugins"] = plugins
    if themes is not None:
        data["themes"] = themes
    if users is not None:
        data["users"] = users
    return json.dumps(data)


class TestWpscanJsonParsing:
    def test_wordpress_version_extracted(self, ctx):
        stdout = _make_wpscan_output(wp_version="6.4.2")
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["wordpress_version"] == "6.4.2"

    def test_plugins_extracted(self, ctx):
        plugins = {
            "akismet": {"version": "5.3", "vulnerabilities": []},
            "contact-form-7": {"version": "5.8", "vulnerabilities": []},
        }
        stdout = _make_wpscan_output(plugins=plugins)
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["plugins_found"] == 2
        slugs = [p["slug"] for p in result["plugins"]]
        assert "akismet" in slugs
        assert "contact-form-7" in slugs

    def test_themes_extracted(self, ctx):
        themes = {
            "twentytwenty": {"version": "1.9", "vulnerabilities": []},
        }
        stdout = _make_wpscan_output(themes=themes)
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["themes_found"] == 1
        assert result["themes"][0]["slug"] == "twentytwenty"

    def test_users_extracted(self, ctx):
        users = {
            "1": {"username": "admin"},
            "2": {"username": "editor"},
        }
        stdout = _make_wpscan_output(users=users)
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["users_found"] == 2
        assert "admin" in result["users"]
        assert "editor" in result["users"]

    def test_vulnerabilities_aggregated_from_plugins(self, ctx):
        vuln = {"title": "XSS in akismet", "cvss": 6.1}
        plugins = {
            "akismet": {"version": "5.0", "vulnerabilities": [vuln]},
        }
        stdout = _make_wpscan_output(plugins=plugins)
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["vulnerabilities_found"] == 1
        assert result["vulnerabilities"][0]["title"] == "XSS in akismet"

    def test_vulnerabilities_aggregated_from_themes(self, ctx):
        vuln = {"title": "SQLi in theme", "cvss": 8.0}
        themes = {
            "badtheme": {"version": "1.0", "vulnerabilities": [vuln]},
        }
        stdout = _make_wpscan_output(themes=themes)
        result = _run_wpscan(ctx, stdout=stdout)
        assert result["vulnerabilities_found"] == 1

    def test_invalid_json_gives_empty_results(self, ctx):
        result = _run_wpscan(ctx, stdout="not valid json {{{")
        assert result["wordpress_version"] is None
        assert result["plugins"] == []
        assert result["themes"] == []
        assert result["users"] == []
        assert result["vulnerabilities"] == []

    def test_empty_stdout_gives_empty_results(self, ctx):
        result = _run_wpscan(ctx, stdout="")
        assert result["plugins_found"] == 0
        assert result["themes_found"] == 0


# ---------------------------------------------------------------------------
# TestWpscanReturnStructure
# ---------------------------------------------------------------------------


class TestWpscanReturnStructure:
    def test_return_keys_present(self, ctx):
        result = _run_wpscan(ctx)
        expected_keys = {
            "tool",
            "url",
            "command",
            "duration_seconds",
            "wordpress_version",
            "plugins_found",
            "themes_found",
            "users_found",
            "vulnerabilities_found",
            "plugins",
            "themes",
            "users",
            "vulnerabilities",
            "raw_output",
        }
        assert expected_keys.issubset(result.keys())

    def test_tool_name_is_wpscan(self, ctx):
        result = _run_wpscan(ctx)
        assert result["tool"] == "wpscan"

    def test_format_json_in_command(self, ctx):
        result = _run_wpscan(ctx)
        assert "--format json" in result["command"]


# ---------------------------------------------------------------------------
# TestWpscanAllowlist
# ---------------------------------------------------------------------------


class TestWpscanAllowlist:
    async def test_allowlist_blocked_raises(self, ctx):
        from tengu.tools.web.wpscan import wpscan_scan

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
                patch(f"{_MOD}.sanitize_url", return_value="http://blocked.com"),
                patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/wpscan"),
                patch(f"{_MOD}.make_allowlist_from_config", return_value=blocked_allowlist),
            ):
                await wpscan_scan(ctx, "http://blocked.com")
        except Exception:
            raised = True
        assert raised, "Expected an exception when target is blocked"
