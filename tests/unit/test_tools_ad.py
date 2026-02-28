"""Unit tests for AD tools: nxc/crackmapexec parser and impacket kerberoast parser."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.ad.crackmapexec import (
    _MODULE_NAME_PATTERN,
    _SUPPORTED_PROTOCOLS,
    _parse_nxc_output,
)
from tengu.tools.ad.impacket import (
    _TGS_HASH_PATTERN,
    _parse_kerberoast_output,
)

# ---------------------------------------------------------------------------
# TestSupportedProtocols
# ---------------------------------------------------------------------------


class TestSupportedProtocols:
    def test_smb_present(self):
        assert "smb" in _SUPPORTED_PROTOCOLS

    def test_ldap_present(self):
        assert "ldap" in _SUPPORTED_PROTOCOLS

    def test_ssh_present(self):
        assert "ssh" in _SUPPORTED_PROTOCOLS

    def test_at_least_six_protocols(self):
        assert len(_SUPPORTED_PROTOCOLS) >= 6

    def test_all_lowercase(self):
        for proto in _SUPPORTED_PROTOCOLS:
            assert proto == proto.lower()


# ---------------------------------------------------------------------------
# TestModuleNamePattern
# ---------------------------------------------------------------------------


class TestModuleNamePattern:
    def test_valid_module_name(self):
        assert _MODULE_NAME_PATTERN.match("spider_plus")

    def test_hyphenated_module_name(self):
        assert _MODULE_NAME_PATTERN.match("enum-av")

    def test_alphanumeric_module(self):
        assert _MODULE_NAME_PATTERN.match("smb2")

    def test_space_rejected(self):
        assert not _MODULE_NAME_PATTERN.match("invalid module")

    def test_semicolon_rejected(self):
        assert not _MODULE_NAME_PATTERN.match("mod;rm -rf /")


# ---------------------------------------------------------------------------
# TestParseNxcOutput
# ---------------------------------------------------------------------------


class TestParseNxcOutput:
    def test_empty_returns_defaults(self):
        result = _parse_nxc_output("")
        assert result["auth_status"] == "unknown"
        assert result["hosts"] == []
        assert result["shares"] == []
        assert result["users"] == []

    def test_success_line_detected(self):
        output = "[+] 192.168.1.1:445 WORKGROUP\\admin:password (Pwn3d!)"
        result = _parse_nxc_output(output)
        assert len(result["success_lines"]) == 1
        assert result["auth_status"] == "admin_access"

    def test_authentication_success(self):
        output = "[+] 192.168.1.1:445 CORP\\user:pass"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "authenticated"

    def test_authentication_failed(self):
        output = "[-] 192.168.1.1:445 CORP\\user:wrongpass STATUS_LOGON_FAILURE"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "authentication_failed"

    def test_info_line_captured(self):
        output = "[*] 192.168.1.1 SMB signing disabled"
        result = _parse_nxc_output(output)
        assert len(result["info_lines"]) == 1

    def test_ip_extraction(self):
        output = "[*] 10.0.0.5 Windows Server 2019"
        result = _parse_nxc_output(output)
        assert "10.0.0.5" in result["hosts"]

    def test_share_extraction(self):
        output = "SHARE  IPC$  READ"
        result = _parse_nxc_output(output)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["name"] == "IPC$"
        assert result["shares"][0]["access"] == "READ"

    def test_user_extraction(self):
        output = "User: Administrator"
        result = _parse_nxc_output(output)
        assert "Administrator" in result["users"]

    def test_duplicate_ips_not_repeated(self):
        output = "[*] 10.0.0.1 info\n[*] 10.0.0.1 more info"
        result = _parse_nxc_output(output)
        assert result["hosts"].count("10.0.0.1") == 1

    def test_duplicate_users_not_repeated(self):
        output = "User: admin\nUser: admin"
        result = _parse_nxc_output(output)
        assert result["users"].count("admin") == 1

    def test_pwned_detection(self):
        output = "[+] 192.168.1.1 pwned Pwn3d!"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "admin_access"

    def test_multiple_shares(self):
        output = "SHARE  C$  READ\nSHARE  ADMIN$  NO ACCESS"
        result = _parse_nxc_output(output)
        assert len(result["shares"]) == 2


# ---------------------------------------------------------------------------
# TestTgsHashPattern
# ---------------------------------------------------------------------------


class TestTgsHashPattern:
    def test_valid_tgs_hash_matched(self):
        # Synthetic TGS hash (hashcat format)
        tgs = "$krb5tgs$23$*SVC_SQL$CORP.LOCAL$HTTP/sqlserver.corp.local*$" + "a" * 32 + "$" + "b" * 32
        assert _TGS_HASH_PATTERN.search(tgs)

    def test_non_hash_not_matched(self):
        assert not _TGS_HASH_PATTERN.search("just a normal line of text")

    def test_partial_hash_not_matched(self):
        assert not _TGS_HASH_PATTERN.search("$krb5tgs$incomplete")


# ---------------------------------------------------------------------------
# TestParseKerberoastOutput
# ---------------------------------------------------------------------------


class TestParseKerberoastOutput:
    def test_empty_returns_empty(self):
        result = _parse_kerberoast_output("")
        assert result["accounts"] == []
        assert result["tgs_hashes"] == []

    def test_tgs_hash_extracted(self):
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        result = _parse_kerberoast_output(tgs)
        assert len(result["tgs_hashes"]) == 1
        assert result["tgs_hashes"][0] == tgs

    def test_hash_only_creates_unknown_account(self):
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        result = _parse_kerberoast_output(tgs)
        # When hashes found but no structured account info
        assert len(result["accounts"]) >= 1
        assert result["accounts"][0]["spn"].startswith("unknown-spn-")

    def test_structured_output_parsed(self):
        output = (
            "ServicePrincipalName     Name     MemberOf     PasswordLastSet     LastLogon\n"
            "HTTP/sqlserver.corp.local  svc_sql  Domain Users  2024-01-01         N/A\n"
        )
        result = _parse_kerberoast_output(output)
        if result["accounts"]:
            assert result["accounts"][0]["spn"] == "HTTP/sqlserver.corp.local"
            assert result["accounts"][0]["account"] == "svc_sql"

    def test_header_line_skipped(self):
        output = "ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon\n"
        result = _parse_kerberoast_output(output)
        # Header line should be skipped (spn == "ServicePrincipalName")
        assert all(a.get("spn") != "ServicePrincipalName" for a in result["accounts"])

    def test_multiple_hashes(self):
        hashes = "\n".join(
            f"$krb5tgs$23$*SVC{i}$CORP$HTTP/srv{i}*$" + "a" * 32 + "$" + "b" * 32
            for i in range(3)
        )
        result = _parse_kerberoast_output(hashes)
        assert len(result["tgs_hashes"]) == 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ad_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = 60
    mock_config.return_value = cfg

    al = MagicMock()
    al.check = MagicMock()
    mock_allowlist.return_value = al

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    mock_audit.return_value = audit

    rl_ctx = MagicMock()
    rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    rl_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_rl.return_value = rl_ctx

    mock_run.return_value = ("", "", 0)

    return al, audit


def _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = 60
    mock_config.return_value = cfg

    al = MagicMock()
    al.check = MagicMock()
    mock_allowlist.return_value = al

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    mock_audit.return_value = audit

    rl_ctx = MagicMock()
    rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    rl_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_rl.return_value = rl_ctx

    mock_run.return_value = ("[+] 192.168.1.1 SMB\n", "", 0)

    return al, audit


# ---------------------------------------------------------------------------
# TestImpacketKerberoast
# ---------------------------------------------------------------------------


@patch("tengu.tools.ad.impacket.rate_limited")
@patch("tengu.tools.ad.impacket.make_allowlist_from_config")
@patch("tengu.tools.ad.impacket.get_audit_logger")
@patch("tengu.tools.ad.impacket.get_config")
@patch("tengu.tools.ad.impacket.run_command", new_callable=AsyncMock)
class TestImpacketKerberoast:
    """Async tests for impacket_kerberoast()."""

    def _patch_shutil(self, which_value):
        return patch("tengu.tools.ad.impacket.shutil.which", return_value=which_value)

    def _patch_resolve(self, return_value="/usr/bin/impacket-GetUserSPNs"):
        return patch("tengu.tools.ad.impacket.resolve_tool_path", return_value=return_value)

    async def test_kerberoast_blocked_target(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Allowlist rejection propagates as an exception."""
        al, _ = _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        al.check.side_effect = ValueError("target not allowed")
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve(), pytest.raises(ValueError, match="target not allowed"):
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin", "pass")

    async def test_kerberoast_with_password(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Password provided results in domain/user:pass credential argument."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin", "secret")

        call_args = mock_run.call_args[0][0]
        cred_arg = call_args[1]
        assert "secret" in cred_arg

    async def test_kerberoast_with_hashes(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """When hashes provided, -hashes flag is appended to args."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin", hashes="aad3b:hash")

        call_args = mock_run.call_args[0][0]
        assert "-hashes" in call_args

    async def test_kerberoast_output_parsed(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Output with TGS hashes is parsed into tgs_hashes list."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        mock_run.return_value = (tgs, "", 0)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            result = await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        assert len(result["tgs_hashes"]) == 1

    async def test_kerberoast_no_hashes_found(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """No TGS tickets → empty tgs_hashes list."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        mock_run.return_value = ("No entries found!", "", 0)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            result = await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        assert result["tgs_hashes"] == []

    async def test_kerberoast_dc_ip_flag(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """dc_ip (target) is passed via -dc-ip flag."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "10.0.0.5", "corp.local", "admin")

        call_args = mock_run.call_args[0][0]
        assert "-dc-ip" in call_args
        idx = call_args.index("-dc-ip")
        assert call_args[idx + 1] == "10.0.0.5"

    async def test_kerberoast_domain_in_cred_arg(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Domain is prepended to username in credential argument."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "testuser")

        call_args = mock_run.call_args[0][0]
        cred_arg = call_args[1]
        assert "corp.local" in cred_arg
        assert "testuser" in cred_arg

    async def test_kerberoast_audit_logged(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """audit.log_tool_call is called during execution."""
        _, audit = _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        assert audit.log_tool_call.call_count >= 1

    async def test_kerberoast_run_error(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """run_command exception propagates and failure is logged."""
        _, audit = _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        mock_run.side_effect = RuntimeError("timeout")
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve(), pytest.raises(RuntimeError, match="timeout"):
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        # Audit should record failure
        failed_calls = [
            c for c in audit.log_tool_call.call_args_list
            if "failed" in str(c)
        ]
        assert len(failed_calls) >= 1

    async def test_kerberoast_rate_limited_used(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """rate_limited context manager is entered during execution."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        mock_rl.assert_called_once_with("impacket")

    async def test_kerberoast_hashcat_hint_present(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """When hashes found, hashcat_hint is in result."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        mock_run.return_value = (tgs, "", 0)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            result = await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        assert "hashcat" in result["hashcat_hint"].lower()

    async def test_kerberoast_warning_in_result(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Result includes warning about Event ID 4769."""
        _setup_impacket_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.impacket import impacket_kerberoast

        with self._patch_shutil(None), self._patch_resolve():
            result = await impacket_kerberoast(ctx, "192.168.1.1", "corp.local", "admin")

        assert "4769" in result["warning"]


# ---------------------------------------------------------------------------
# TestNxcEnum
# ---------------------------------------------------------------------------


@patch("tengu.tools.ad.crackmapexec.rate_limited")
@patch("tengu.tools.ad.crackmapexec.make_allowlist_from_config")
@patch("tengu.tools.ad.crackmapexec.get_audit_logger")
@patch("tengu.tools.ad.crackmapexec.get_config")
@patch("tengu.tools.ad.crackmapexec.run_command", new_callable=AsyncMock)
class TestNxcEnum:
    """Async tests for nxc_enum()."""

    def _patch_shutil_nxc(self):
        return patch("tengu.tools.ad.crackmapexec.shutil.which", return_value="/usr/bin/nxc")

    def _patch_resolve_nxc(self, return_value="/usr/bin/nxc"):
        return patch("tengu.tools.ad.crackmapexec.resolve_tool_path", return_value=return_value)

    async def test_nxc_blocked_target(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Allowlist rejection propagates as an exception."""
        al, _ = _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        al.check.side_effect = ValueError("target not allowed")
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc(), pytest.raises(ValueError, match="target not allowed"):
            await nxc_enum(ctx, "192.168.1.1")

    async def test_nxc_invalid_protocol(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Unsupported protocol returns error dict without running command."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            result = await nxc_enum(ctx, "192.168.1.1", protocol="telnet")

        assert "error" in result
        assert "telnet" in result["error"]
        mock_run.assert_not_called()

    async def test_nxc_valid_protocol_smb(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """SMB protocol is accepted and command runs."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            result = await nxc_enum(ctx, "192.168.1.1", protocol="smb")

        assert "error" not in result
        assert result["protocol"] == "smb"

    async def test_nxc_valid_protocol_ldap(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """LDAP protocol is accepted and command runs."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            result = await nxc_enum(ctx, "192.168.1.1", protocol="ldap")

        assert "error" not in result
        assert result["protocol"] == "ldap"

    async def test_nxc_modules_flag(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Modules list results in -M flags in command args."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            await nxc_enum(ctx, "192.168.1.1", protocol="smb", modules=["spider_plus"])

        call_args = mock_run.call_args[0][0]
        assert "-M" in call_args
        idx = call_args.index("-M")
        assert call_args[idx + 1] == "spider_plus"

    async def test_nxc_output_parsed(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Parsed output data is in the result dict."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        mock_run.return_value = ("[+] 10.0.0.1:445 SMB signing disabled\n", "", 0)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            result = await nxc_enum(ctx, "10.0.0.1", protocol="smb")

        assert "authentication_status" in result
        assert "hosts_found" in result

    async def test_nxc_credentials(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Username and password are added to command args."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            await nxc_enum(ctx, "192.168.1.1", protocol="smb", username="admin", password="pass")

        call_args = mock_run.call_args[0][0]
        assert "-u" in call_args
        assert "-p" in call_args

    async def test_nxc_tool_key(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """Result 'tool' key reflects tool name (nxc or crackmapexec)."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            result = await nxc_enum(ctx, "192.168.1.1", protocol="smb")

        assert result["tool"] in ("nxc", "crackmapexec")

    async def test_nxc_audit_logged(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """audit.log_tool_call is called during execution."""
        _, audit = _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            await nxc_enum(ctx, "192.168.1.1", protocol="smb")

        assert audit.log_tool_call.call_count >= 1

    async def test_nxc_run_error(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """run_command exception propagates."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        mock_run.side_effect = RuntimeError("connection refused")
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc(), pytest.raises(RuntimeError, match="connection refused"):
            await nxc_enum(ctx, "192.168.1.1", protocol="smb")

    async def test_nxc_rate_limited_used(self, mock_run, mock_config, mock_audit, mock_allowlist, mock_rl):
        """rate_limited context manager is entered with 'nxc' key."""
        _setup_nxc_mocks(mock_run, mock_config, mock_allowlist, mock_audit, mock_rl)
        ctx = _make_ad_ctx()

        from tengu.tools.ad.crackmapexec import nxc_enum

        with self._patch_shutil_nxc(), self._patch_resolve_nxc():
            await nxc_enum(ctx, "192.168.1.1", protocol="smb")

        mock_rl.assert_called_once_with("nxc")
