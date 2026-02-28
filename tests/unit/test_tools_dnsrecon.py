"""Unit tests for the dnsrecon_scan async tool."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.recon.dnsrecon"


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


async def _call_dnsrecon(mocks, domain="example.com", scan_type="std", timeout=None):
    from tengu.tools.recon.dnsrecon import dnsrecon_scan

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/dnsrecon"),
        patch(f"{TOOL_MODULE}.sanitize_domain", side_effect=lambda d: d),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await dnsrecon_scan(mocks["ctx"], domain, scan_type=scan_type, timeout=timeout)


# ---------------------------------------------------------------------------
# TestDnsreconScan
# ---------------------------------------------------------------------------


class TestDnsreconScan:
    async def test_invalid_scan_type_defaults_to_std(self):
        mocks = _make_fixtures()
        result = await _call_dnsrecon(mocks, scan_type="invalid")
        assert result["scan_type"] == "std"

    @pytest.mark.parametrize("scan_type", ["std", "brt", "axfr", "rvl", "goo", "srv"])
    async def test_valid_scan_types_preserved(self, scan_type):
        mocks = _make_fixtures()
        result = await _call_dnsrecon(mocks, scan_type=scan_type)
        assert result["scan_type"] == scan_type

    async def test_json_output_parsed(self):
        records = [
            {"type": "A", "name": "example.com", "address": "93.184.216.34"},
            {"type": "MX", "name": "example.com", "exchange": "mail.example.com"},
        ]
        mocks = _make_fixtures(run_stdout=json.dumps(records))
        result = await _call_dnsrecon(mocks)
        assert result["records_found"] == 2
        assert result["records"][0]["type"] == "A"

    async def test_empty_json_array_gives_empty_records(self):
        mocks = _make_fixtures(run_stdout="[]")
        result = await _call_dnsrecon(mocks)
        assert result["records"] == []
        assert result["records_found"] == 0

    async def test_fallback_plain_text_parsed(self):
        stdout = "example.com A 93.184.216.34\nexample.com NS ns1.example.com\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_dnsrecon(mocks)
        assert result["records_found"] == 2
        assert result["records"][0]["raw"] == "example.com A 93.184.216.34"

    async def test_plain_text_lines_with_marker_skipped(self):
        stdout = "[*] Performing standard enumeration\n[+] Found NS\nexample.com A 1.2.3.4\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_dnsrecon(mocks)
        # Only the non-marker line should produce a record
        assert result["records_found"] == 1
        assert result["records"][0]["raw"] == "example.com A 1.2.3.4"

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_dnsrecon(mocks, domain="blocked.com")

    async def test_returncode_nonzero_sets_errors(self):
        mocks = _make_fixtures(run_stderr="dnsrecon failed", run_rc=1)
        result = await _call_dnsrecon(mocks)
        assert result["errors"] == "dnsrecon failed"

    async def test_returncode_zero_errors_none(self):
        mocks = _make_fixtures(run_stderr="some noise", run_rc=0)
        result = await _call_dnsrecon(mocks)
        assert result["errors"] is None

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_dnsrecon(mocks)
        for key in ("tool", "domain", "scan_type", "command", "duration_seconds",
                    "records_found", "records", "raw_output", "errors"):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "dnsrecon"
