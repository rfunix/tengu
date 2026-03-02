"""Unit tests for dnstwist_scan."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.osint.dnstwist import _parse_dnstwist_output

_MOD = "tengu.tools.osint.dnstwist"


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


async def _run_dnstwist(
    ctx: MagicMock,
    domain: str = "example.com",
    threads: int = 10,
    stdout: str = "",
    blocked: bool = False,
) -> dict:  # type: ignore[type-arg]
    from tengu.tools.osint.dnstwist import dnstwist_scan

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
        patch(f"{_MOD}.sanitize_target", return_value=domain),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/dnstwist"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
    ):
        return await dnstwist_scan(ctx, domain, threads=threads)


class TestDnstwistScan:
    async def test_returns_tool_key(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx)
        assert result["tool"] == "dnstwist"

    async def test_blocked_raises(self, ctx: MagicMock) -> None:
        with pytest.raises(TargetNotAllowedError):
            await _run_dnstwist(ctx, blocked=True)

    async def test_threads_clamped_max(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx, threads=100)
        assert result["threads"] <= 50

    async def test_threads_clamped_min(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx, threads=0)
        assert result["threads"] >= 1

    async def test_json_output_parsed(self, ctx: MagicMock) -> None:
        data = [
            {
                "fuzzer": "addition",
                "domain": "examplee.com",
                "dns_a": ["1.2.3.4"],
                "dns_mx": [],
            }
        ]
        stdout = json.dumps(data)
        result = await _run_dnstwist(ctx, stdout=stdout)
        assert result["suspicious_domains_count"] == 1

    async def test_return_keys_present(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx)
        for key in (
            "tool",
            "domain",
            "threads",
            "duration_seconds",
            "suspicious_domains_count",
            "suspicious_domains",
        ):
            assert key in result

    async def test_empty_output_zero_domains(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx, stdout="")
        assert result["suspicious_domains_count"] == 0
        assert result["suspicious_domains"] == []

    async def test_raw_output_excerpt_present(self, ctx: MagicMock) -> None:
        result = await _run_dnstwist(ctx, stdout="some output")
        assert "raw_output_excerpt" in result

    async def test_long_output_truncated(self, ctx: MagicMock) -> None:
        long_stdout = "x" * 6000
        result = await _run_dnstwist(ctx, stdout=long_stdout)
        assert len(result["raw_output_excerpt"]) <= 3000


class TestParseDnstwistOutput:
    def test_empty_output(self) -> None:
        result = _parse_dnstwist_output("")
        assert result == []

    def test_json_array_parsed(self) -> None:
        data = [{"fuzzer": "homoglyph", "domain": "examp1e.com", "dns_a": ["1.2.3.4"]}]
        result = _parse_dnstwist_output(json.dumps(data))
        assert len(result) == 1
        assert result[0]["domain"] == "examp1e.com"
        assert result[0]["registered"] is True

    def test_invalid_json_returns_empty(self) -> None:
        result = _parse_dnstwist_output("not json at all")
        assert result == []

    def test_registered_false_when_no_dns(self) -> None:
        data = [{"fuzzer": "addition", "domain": "examplee.com", "dns_a": [], "dns_mx": []}]
        result = _parse_dnstwist_output(json.dumps(data))
        assert result[0]["registered"] is False

    def test_registered_true_via_mx(self) -> None:
        data = [
            {"fuzzer": "addition", "domain": "examplee.com", "dns_a": [], "dns_mx": ["mx.example.com"]}
        ]
        result = _parse_dnstwist_output(json.dumps(data))
        assert result[0]["registered"] is True

    def test_multiple_entries(self) -> None:
        data = [
            {"fuzzer": "a", "domain": "d1.com", "dns_a": ["1.1.1.1"]},
            {"fuzzer": "b", "domain": "d2.com", "dns_a": ["2.2.2.2"]},
        ]
        result = _parse_dnstwist_output(json.dumps(data))
        assert len(result) == 2

    def test_missing_fields_handled(self) -> None:
        data = [{"domain": "minimal.com"}]
        result = _parse_dnstwist_output(json.dumps(data))
        assert result[0]["fuzzer"] == ""
        assert result[0]["dns_a"] == []
