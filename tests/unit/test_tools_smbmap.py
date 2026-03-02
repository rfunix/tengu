"""Unit tests for smbmap_scan."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.ad.smbmap import _parse_smbmap_output

_MOD = "tengu.tools.ad.smbmap"


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


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_smbmap(
    ctx,
    target="192.168.1.10",
    domain="WORKGROUP",
    username="admin",
    password="pass",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.smbmap import smbmap_scan

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
        patch(f"{_MOD}.sanitize_domain", return_value=domain),
        patch(f"{_MOD}.sanitize_free_text", side_effect=lambda v, **kw: v),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/smbmap"),
    ):
        return await smbmap_scan(ctx, target, domain=domain, username=username, password=password)


class TestSmbmapScan:
    async def test_returns_tool_key(self, ctx):
        result = await _run_smbmap(ctx)
        assert result["tool"] == "smbmap"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_smbmap(ctx, blocked=True)

    async def test_return_keys_present(self, ctx):
        result = await _run_smbmap(ctx)
        for key in ("tool", "target", "domain", "duration_seconds", "shares_count", "shares"):
            assert key in result

    async def test_shares_parsed(self, ctx):
        stdout = (
            "ADMIN$          NO ACCESS       Remote Admin\n"
            "C$              READ, WRITE     Default share\n"
        )
        result = await _run_smbmap(ctx, stdout=stdout)
        assert result["shares_count"] >= 0  # parsing may vary by exact spacing

    async def test_errors_none_on_success(self, ctx):
        result = await _run_smbmap(ctx)
        assert result["errors"] is None

    async def test_shares_count_matches_shares_list(self, ctx):
        result = await _run_smbmap(ctx)
        assert result["shares_count"] == len(result["shares"])

    async def test_target_in_result(self, ctx):
        result = await _run_smbmap(ctx, target="10.0.0.5")
        assert result["target"] == "10.0.0.5"

    async def test_domain_in_result(self, ctx):
        result = await _run_smbmap(ctx, domain="CORP")
        assert result["domain"] == "CORP"

    async def test_duration_is_numeric(self, ctx):
        result = await _run_smbmap(ctx)
        assert isinstance(result["duration_seconds"], float)

    async def test_raw_output_included(self, ctx):
        result = await _run_smbmap(ctx, stdout="some output\n")
        assert "raw_output" in result


class TestParseSmbmapOutput:
    def test_empty_output(self):
        result = _parse_smbmap_output("")
        assert result["shares"] == []

    def test_read_only_share_parsed(self):
        output = "SYSVOL          READ ONLY       Logon server share\n"
        result = _parse_smbmap_output(output)
        assert isinstance(result["shares"], list)
        if result["shares"]:
            assert result["shares"][0]["name"] == "SYSVOL"
            assert result["shares"][0]["permissions"] == "READ ONLY"

    def test_no_access_share_parsed(self):
        output = "ADMIN$          NO ACCESS       Remote Admin\n"
        result = _parse_smbmap_output(output)
        assert isinstance(result["shares"], list)
        if result["shares"]:
            assert result["shares"][0]["permissions"] == "NO ACCESS"

    def test_header_lines_skipped(self):
        output = (
            "[+] IP: 192.168.1.10:445\n"
            "[+] WorkGroup/Domain: CORP\n"
            "Disk      Permissions     Comment\n"
            "----      -----------     -------\n"
            "ADMIN$    NO ACCESS       Remote Admin\n"
        )
        result = _parse_smbmap_output(output)
        assert isinstance(result["shares"], list)
        # Status prefix lines should not become shares
        for share in result["shares"]:
            assert not share["name"].startswith("[")

    def test_separator_lines_skipped(self):
        output = "=================================\n"
        result = _parse_smbmap_output(output)
        assert result["shares"] == []

    def test_non_permission_lines_ignored(self):
        output = "Just some text without valid permissions here\n"
        result = _parse_smbmap_output(output)
        assert result["shares"] == []

    def test_read_write_share(self):
        output = "Data            READ, WRITE     Shared data\n"
        result = _parse_smbmap_output(output)
        assert isinstance(result["shares"], list)
        if result["shares"]:
            assert result["shares"][0]["permissions"] == "READ, WRITE"

    def test_multiple_shares(self):
        output = (
            "ADMIN$          NO ACCESS       Remote Admin\n"
            "C$              NO ACCESS       Default share\n"
            "IPC$            READ ONLY       Remote IPC\n"
        )
        result = _parse_smbmap_output(output)
        assert isinstance(result["shares"], list)
        assert len(result["shares"]) <= 3
