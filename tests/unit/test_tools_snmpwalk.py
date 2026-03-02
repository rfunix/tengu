"""Unit tests for snmpwalk_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.recon.snmpwalk import _parse_snmpwalk_output

_MOD = "tengu.tools.recon.snmpwalk"


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


@pytest.fixture
def ctx() -> MagicMock:
    return _make_ctx()


async def _run_snmpwalk(
    ctx: MagicMock,
    target: str = "192.168.1.1",
    community: str = "public",
    version: str = "2c",
    stdout: str = "",
    blocked: bool = False,
) -> dict:  # type: ignore[type-arg]
    from tengu.tools.recon.snmpwalk import snmpwalk_scan

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
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/snmpwalk"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
    ):
        return await snmpwalk_scan(ctx, target, community=community, version=version)


class TestSnmpwalkScan:
    async def test_returns_tool_key(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx)
        assert result["tool"] == "snmpwalk"

    async def test_blocked_raises(self, ctx: MagicMock) -> None:
        with pytest.raises(TargetNotAllowedError):
            await _run_snmpwalk(ctx, blocked=True)

    async def test_invalid_version_defaults_to_2c(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx, version="4")
        assert result["version"] == "2c"

    async def test_valid_version_1_preserved(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx, version="1")
        assert result["version"] == "1"

    async def test_valid_version_3_preserved(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx, version="3")
        assert result["version"] == "3"

    async def test_return_keys_present(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx)
        for key in (
            "tool",
            "target",
            "community",
            "version",
            "duration_seconds",
            "entries_count",
            "entries",
            "sys_info",
        ):
            assert key in result

    async def test_community_in_result(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx, community="private")
        assert result["community"] == "private"

    async def test_errors_none_on_success(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx)
        assert result["errors"] is None

    async def test_target_in_result(self, ctx: MagicMock) -> None:
        result = await _run_snmpwalk(ctx, target="10.0.0.1")
        assert result["target"] == "10.0.0.1"


class TestParseSnmpwalkOutput:
    def test_empty_output(self) -> None:
        result = _parse_snmpwalk_output("")
        assert result["entries"] == []
        assert result["sys_info"] == {}

    def test_entries_parsed(self) -> None:
        output = ".1.3.6.1.2.1.1.1.0 = STRING: Linux router\n"
        result = _parse_snmpwalk_output(output)
        assert len(result["entries"]) == 1

    def test_sysname_extracted(self) -> None:
        output = "sysName.0 = STRING: myrouter\n"
        result = _parse_snmpwalk_output(output)
        assert "name" in result["sys_info"]

    def test_sysdescr_extracted(self) -> None:
        output = "sysDescr.0 = STRING: Linux kernel 5.10\n"
        result = _parse_snmpwalk_output(output)
        assert "description" in result["sys_info"]

    def test_syslocation_extracted(self) -> None:
        output = "sysLocation.0 = STRING: Server Room A\n"
        result = _parse_snmpwalk_output(output)
        assert "location" in result["sys_info"]

    def test_entries_capped_at_200(self) -> None:
        output = "\n".join(f".1.2.3.{i}.0 = INTEGER: {i}" for i in range(300))
        result = _parse_snmpwalk_output(output)
        assert len(result["entries"]) <= 200

    def test_error_lines_skipped(self) -> None:
        output = "Error in packet\n.1.2.3.4 = INTEGER: 1\n"
        result = _parse_snmpwalk_output(output)
        assert all("Error" not in e for e in result["entries"])

    def test_oid_numeric_matched(self) -> None:
        output = ".1.3.6.1.2.1.1.5.0 = STRING: hostname\n"
        result = _parse_snmpwalk_output(output)
        assert "name" in result["sys_info"]
