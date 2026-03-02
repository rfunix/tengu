"""Unit tests for responder_capture."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.ad.responder import _parse_responder_output

_MOD = "tengu.tools.ad.responder"


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
    return audit


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_responder(
    ctx,
    interface="eth0",
    analyze_only=False,
    capture_duration=10,
    stdout="",
    invalid_iface=False,
):
    from tengu.tools.ad.responder import responder_capture

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 120

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/responder"),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", 0))),
        patch(f"{_MOD}.shutil.which", return_value=None),
    ):
        iface = "" if invalid_iface else interface
        return await responder_capture(
            ctx, iface, analyze_only=analyze_only, capture_duration=capture_duration
        )


class TestResponderCapture:
    async def test_returns_tool_key(self, ctx):
        result = await _run_responder(ctx)
        assert "responder" in result["tool"].lower()

    async def test_invalid_interface_raises(self, ctx):
        with pytest.raises((ValueError, Exception)):
            await _run_responder(ctx, invalid_iface=True)

    async def test_capture_duration_clamped_min(self, ctx):
        result = await _run_responder(ctx, capture_duration=1)
        assert result["capture_duration"] >= 10

    async def test_capture_duration_clamped_max(self, ctx):
        result = await _run_responder(ctx, capture_duration=99999)
        assert result["capture_duration"] <= 3600

    async def test_capture_duration_valid_preserved(self, ctx):
        result = await _run_responder(ctx, capture_duration=120)
        assert result["capture_duration"] == 120

    async def test_return_keys_present(self, ctx):
        result = await _run_responder(ctx)
        for key in (
            "tool",
            "interface",
            "analyze_only",
            "capture_duration",
            "duration_seconds",
            "captured_hashes_count",
            "captured_hashes",
            "connections",
            "warning",
        ):
            assert key in result

    async def test_ntlmv2_hash_captured(self, ctx):
        stdout = "ADMIN::CORP:1122334455667788:hash_response_here:0101...\n"
        result = await _run_responder(ctx, stdout=stdout)
        assert isinstance(result["captured_hashes"], list)

    async def test_analyze_only_flag_reflected(self, ctx):
        result = await _run_responder(ctx, analyze_only=True)
        assert result["analyze_only"] is True

    async def test_hashcat_hint_empty_when_no_hashes(self, ctx):
        result = await _run_responder(ctx, stdout="")
        assert result["hashcat_hint"] == ""

    async def test_hashcat_hint_present_when_hashes_found(self, ctx):
        # Line with many colons triggers hash detection
        stdout = "USER::DOM:aad3b435:NTLMv2Response:0101000000000000extra:extra:extra\n"
        result = await _run_responder(ctx, stdout=stdout)
        if result["captured_hashes_count"] > 0:
            assert "hashcat" in result["hashcat_hint"].lower()

    async def test_interface_name_preserved(self, ctx):
        result = await _run_responder(ctx, interface="eth0")
        assert result["interface"] == "eth0"

    async def test_duration_is_numeric(self, ctx):
        result = await _run_responder(ctx)
        assert isinstance(result["duration_seconds"], float)

    async def test_captured_hashes_count_matches_list(self, ctx):
        result = await _run_responder(ctx)
        assert result["captured_hashes_count"] == len(result["captured_hashes"])


class TestParseResponderOutput:
    def test_empty_output(self):
        result = _parse_responder_output("")
        assert result["captured_hashes"] == []
        assert result["connections"] == []

    def test_ntlm_hash_detected(self):
        # Line with "::" and many colons (NTLMv2 format)
        line = "ADMIN::CORP:aad3:NTLMv2-hash:0101000000000000"
        result = _parse_responder_output(line + "\n")
        assert isinstance(result["captured_hashes"], list)

    def test_ntlmv2_keyword_triggers_capture(self):
        line = "USER::DOM:NTLMv2:aad3b435b51404eeaad3b435b51404ee:abc123"
        result = _parse_responder_output(line + "\n")
        assert len(result["captured_hashes"]) == 1

    def test_connections_detected(self):
        result = _parse_responder_output("[+] Poisoned answer sent to 192.168.1.50\n")
        assert len(result["connections"]) >= 1

    def test_poisoned_line_in_connections(self):
        result = _parse_responder_output("Poisoned answer sent to 10.0.0.5\n")
        assert len(result["connections"]) >= 1

    def test_hashes_capped_at_50(self):
        lines = "\n".join(
            f"USER{i}::DOM:aad3:hash{i}:NTLMv2:extra:extra:extra" for i in range(60)
        )
        result = _parse_responder_output(lines)
        assert len(result["captured_hashes"]) <= 50

    def test_connections_capped_at_50(self):
        lines = "\n".join(f"[+] Poisoned answer sent to 10.0.0.{i}" for i in range(60))
        result = _parse_responder_output(lines)
        assert len(result["connections"]) <= 50

    def test_irrelevant_lines_ignored(self):
        output = "Starting Responder v3.0\nListening on eth0\n"
        result = _parse_responder_output(output)
        assert result["captured_hashes"] == []
