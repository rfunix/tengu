"""Unit tests for impacket expansion: secretsdump, psexec, wmiexec, smbclient."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.ad.impacket import (
    _parse_psexec_output,
    _parse_secretsdump_output,
    _parse_smbclient_output,
    _parse_wmiexec_output,
)

_MOD = "tengu.tools.ad.impacket"


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


# ─── impacket_secretsdump ───────────────────────────────────────────────────


async def _run_secretsdump(
    ctx,
    target="192.168.1.10",
    domain="corp.local",
    username="admin",
    password="pass",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.impacket import impacket_secretsdump

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
        patch(f"{_MOD}.shutil.which", return_value=None),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/impacket-secretsdump"),
    ):
        return await impacket_secretsdump(ctx, target, domain, username, password=password)


class TestImpacketSecretsdump:
    async def test_returns_tool_key(self, ctx):
        result = await _run_secretsdump(ctx)
        assert "impacket" in result["tool"].lower() or "secretsdump" in result["tool"].lower()

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_secretsdump(ctx, blocked=True)

    async def test_return_keys_present(self, ctx):
        result = await _run_secretsdump(ctx)
        for key in (
            "tool",
            "target",
            "domain",
            "duration_seconds",
            "sam_hashes_count",
            "ntds_hashes_count",
            "lsa_secrets_count",
            "sam_hashes",
            "ntds_hashes",
            "lsa_secrets",
            "hashcat_hint",
        ):
            assert key in result

    async def test_hashes_parsed_from_output(self, ctx):
        stdout = (
            "[*] Dumping local SAM hashes\n"
            "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        result = await _run_secretsdump(ctx, stdout=stdout)
        assert result["sam_hashes_count"] >= 1


class TestParseSecretsdumpOutput:
    def test_empty_output(self):
        result = _parse_secretsdump_output("")
        assert result["sam_hashes"] == []
        assert result["ntds_hashes"] == []
        assert result["lsa_secrets"] == []

    def test_sam_hashes_parsed(self):
        output = "[*] Dumping local SAM hashes\nadmin:500:LM:NT:::\n"
        result = _parse_secretsdump_output(output)
        assert len(result["sam_hashes"]) >= 1

    def test_ntds_hashes_parsed(self):
        output = "[*] Dumping Domain Credentials\nDomain\\user:1000:LM:NT:::\n"
        result = _parse_secretsdump_output(output)
        assert len(result["ntds_hashes"]) >= 1

    def test_sam_hashes_capped_at_50(self):
        header = "[*] Dumping local SAM hashes\n"
        hashes = "\n".join(f"user{i}:500:LM:NT:::" for i in range(60))
        result = _parse_secretsdump_output(header + hashes)
        assert len(result["sam_hashes"]) <= 50


# ─── impacket_psexec ────────────────────────────────────────────────────────


async def _run_psexec(
    ctx,
    target="192.168.1.10",
    domain=".",
    username="admin",
    command="whoami",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.impacket import impacket_psexec

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
        patch(f"{_MOD}.shutil.which", return_value=None),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/impacket-psexec"),
    ):
        return await impacket_psexec(ctx, target, domain, username, command)


class TestImpacketPsexec:
    async def test_returns_tool_key(self, ctx):
        result = await _run_psexec(ctx)
        assert "psexec" in result["tool"].lower()

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_psexec(ctx, blocked=True)

    async def test_return_keys_present(self, ctx):
        result = await _run_psexec(ctx)
        for key in (
            "tool",
            "target",
            "domain",
            "command",
            "duration_seconds",
            "output",
            "warning",
        ):
            assert key in result

    async def test_output_parsed(self, ctx):
        stdout = "[*] Connecting\nt\\admin\n"
        result = await _run_psexec(ctx, stdout=stdout)
        assert isinstance(result["output"], str)


class TestParsePsexecOutput:
    def test_empty_output(self):
        result = _parse_psexec_output("")
        assert result["output"] == ""
        assert result["lines"] == []

    def test_status_lines_filtered(self):
        result = _parse_psexec_output("[*] Connecting\n[+] Got shell\nnt authority\\system\n")
        assert "nt authority" in result["output"]
        assert "[*]" not in result["output"]

    def test_output_capped_at_50_lines(self):
        output = "\n".join(f"line {i}" for i in range(60))
        result = _parse_psexec_output(output)
        assert len(result["lines"]) <= 50


# ─── impacket_wmiexec ────────────────────────────────────────────────────────


async def _run_wmiexec(
    ctx,
    target="192.168.1.10",
    domain=".",
    username="admin",
    command="whoami",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.impacket import impacket_wmiexec

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
        patch(f"{_MOD}.shutil.which", return_value=None),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/impacket-wmiexec"),
    ):
        return await impacket_wmiexec(ctx, target, domain, username, command)


class TestImpacketWmiexec:
    async def test_returns_tool_key(self, ctx):
        result = await _run_wmiexec(ctx)
        assert "wmiexec" in result["tool"].lower()

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_wmiexec(ctx, blocked=True)

    async def test_return_keys_present(self, ctx):
        result = await _run_wmiexec(ctx)
        for key in (
            "tool",
            "target",
            "domain",
            "command",
            "duration_seconds",
            "output",
            "warning",
        ):
            assert key in result


class TestParseWmiexecOutput:
    def test_empty_output(self):
        result = _parse_wmiexec_output("")
        assert result["output"] == ""

    def test_status_lines_filtered(self):
        result = _parse_wmiexec_output("[*] WMI\nnt authority\\system\n")
        assert "nt authority" in result["output"]


# ─── impacket_smbclient ──────────────────────────────────────────────────────


async def _run_smbclient(
    ctx,
    target="192.168.1.10",
    domain=".",
    username="admin",
    action="list_shares",
    share="",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.impacket import impacket_smbclient

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
        patch(f"{_MOD}.shutil.which", return_value=None),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/impacket-smbclient"),
    ):
        return await impacket_smbclient(
            ctx, target, domain, username, action=action, share=share
        )


class TestImpacketSmbclient:
    async def test_returns_tool_key(self, ctx):
        result = await _run_smbclient(ctx)
        assert "smbclient" in result["tool"].lower()

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_smbclient(ctx, blocked=True)

    async def test_invalid_action_defaults_to_list_shares(self, ctx):
        result = await _run_smbclient(ctx, action="invalid_action")
        assert result["action"] == "list_shares"

    async def test_return_keys_present(self, ctx):
        result = await _run_smbclient(ctx)
        for key in (
            "tool",
            "target",
            "domain",
            "action",
            "duration_seconds",
            "shares",
            "files",
        ):
            assert key in result


class TestParseSmbclientOutput:
    def test_empty_output(self):
        result = _parse_smbclient_output("")
        assert result["shares"] == []
        assert result["files"] == []

    def test_status_lines_filtered(self):
        result = _parse_smbclient_output("[*] Connecting\nC$\nADMIN$\n")
        assert "C$" in result["shares"] or "C$" in result["files"]

    def test_shares_capped_at_50(self):
        output = "\n".join(f"SHARE{i}" for i in range(60))
        result = _parse_smbclient_output(output)
        assert len(result["shares"]) <= 50
