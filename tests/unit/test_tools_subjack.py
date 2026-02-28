"""Unit tests for the subjack_check async tool."""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.recon.subjack"


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


async def _call_subjack(
    mocks,
    domain="example.com",
    subdomains_file="",
    threads=20,
    timeout=None,
):
    from tengu.tools.recon.subjack import subjack_check

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/subjack"),
        patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await subjack_check(
            mocks["ctx"],
            domain,
            subdomains_file=subdomains_file,
            threads=threads,
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# TestSubjackCheck
# ---------------------------------------------------------------------------


class TestSubjackCheck:
    async def test_threads_clamped_min(self):
        mocks = _make_fixtures()
        result = await _call_subjack(mocks, threads=0)
        # threads=0 → clamped to 1; command must contain "-t 1"
        assert "-t 1" in result["command"]

    async def test_threads_clamped_max(self):
        mocks = _make_fixtures()
        result = await _call_subjack(mocks, threads=200)
        assert "-t 100" in result["command"]

    async def test_default_wordlist_used_when_empty(self):
        mocks = _make_fixtures()
        result = await _call_subjack(mocks, subdomains_file="")
        assert "seclists" in result["command"].lower() or "subdomains" in result["command"].lower()

    async def test_custom_wordlist_in_command(self):
        mocks = _make_fixtures()
        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/subjack"),
            patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
            patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
            # sanitize_wordlist_path is imported locally in the function body;
            # patch it at the source module so the local import resolves to our mock
            patch(
                "tengu.security.sanitizer.sanitize_wordlist_path",
                side_effect=lambda p: p,
            ),
        ):
            from tengu.tools.recon.subjack import subjack_check

            result = await subjack_check(
                mocks["ctx"], "example.com", subdomains_file="/tmp/wordlist.txt"
            )
        assert "/tmp/wordlist.txt" in result["command"]

    async def test_vulnerable_line_detection_bracket(self):
        stdout = "sub.example.com [Vulnerable] github-pages\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_subjack(mocks)
        assert result["vulnerable_count"] == 1
        assert result["vulnerable_subdomains"][0]["status"] == "vulnerable"

    async def test_vulnerable_uppercase_detection(self):
        stdout = "sub.example.com VULNERABLE heroku\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_subjack(mocks)
        assert result["vulnerable_count"] == 1

    async def test_empty_output_no_vulnerabilities(self):
        mocks = _make_fixtures(run_stdout="")
        result = await _call_subjack(mocks)
        assert result["vulnerable_count"] == 0
        assert result["vulnerable_subdomains"] == []

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_subjack(mocks, domain="blocked.com")

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_subjack(mocks)
        for key in ("tool", "domain", "command", "duration_seconds",
                    "vulnerable_count", "vulnerable_subdomains", "raw_output", "errors"):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "subjack"

    async def test_errors_none_on_success(self):
        mocks = _make_fixtures(run_stderr="warn", run_rc=0)
        result = await _call_subjack(mocks)
        assert result["errors"] is None

    async def test_errors_set_on_nonzero_returncode(self):
        mocks = _make_fixtures(run_stderr="failed", run_rc=1)
        result = await _call_subjack(mocks)
        assert result["errors"] == "failed"
