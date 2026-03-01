"""Unit tests for enum4linux AD enumeration output parsers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.ad.enum4linux import _parse_enum4linux_output, _parse_enum4linux_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enum4linux_json(
    users: dict | list | None = None,
    groups: dict | None = None,
    shares: dict | None = None,
    password_policy: dict | None = None,
    smb_info: dict | None = None,
) -> str:
    data: dict = {}
    if users is not None:
        data["users"] = users
    if groups is not None:
        data["groups"] = groups
    if shares is not None:
        data["shares"] = shares
    if password_policy is not None:
        data["password_policy"] = password_policy
    if smb_info is not None:
        data["smb_info"] = smb_info
    return json.dumps(data)


# ---------------------------------------------------------------------------
# TestParseEnum4linuxOutput
# ---------------------------------------------------------------------------


class TestParseEnum4linuxOutput:
    def test_empty_returns_defaults(self):
        result = _parse_enum4linux_output("")
        assert result["users"] == []
        assert result["shares"] == []
        assert result["groups"] == []

    def test_invalid_json_falls_back_to_text_parser(self):
        # Non-JSON triggers _parse_enum4linux_text fallback
        result = _parse_enum4linux_output("user:[admin] rid:[500]")
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "admin"

    def test_json_users_dict_format(self):
        users = {
            "1000": {"username": "bob", "fullname": "Bob Smith", "description": "Staff"},
        }
        output = _make_enum4linux_json(users=users)
        result = _parse_enum4linux_output(output)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "bob"
        assert result["users"][0]["full_name"] == "Bob Smith"

    def test_json_users_list_format(self):
        users = [{"username": "alice", "rid": "1001"}]
        output = _make_enum4linux_json(users=users)
        result = _parse_enum4linux_output(output)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "alice"

    def test_json_groups_parsed(self):
        groups = {"512": {"groupname": "Domain Admins", "members": ["Administrator"]}}
        output = _make_enum4linux_json(groups=groups)
        result = _parse_enum4linux_output(output)
        assert len(result["groups"]) == 1
        assert result["groups"][0]["name"] == "Domain Admins"

    def test_json_shares_parsed(self):
        shares = {
            "ADMIN$": {"type": "Disk", "comment": "Remote Admin", "access": "NO ACCESS"},
            "C$": {"type": "Disk", "comment": "Default share", "access": "READ"},
        }
        output = _make_enum4linux_json(shares=shares)
        result = _parse_enum4linux_output(output)
        assert len(result["shares"]) == 2
        names = [s["name"] for s in result["shares"]]
        assert "ADMIN$" in names

    def test_json_password_policy_parsed(self):
        policy = {
            "min_password_length": 8,
            "account_lockout_threshold": 5,
        }
        output = _make_enum4linux_json(password_policy=policy)
        result = _parse_enum4linux_output(output)
        assert result["password_policy"]["min_length"] == 8
        assert result["password_policy"]["lockout_threshold"] == 5

    def test_json_smb_info_parsed(self):
        smb = {"os": "Windows Server 2019", "domain": "CORP"}
        output = _make_enum4linux_json(smb_info=smb)
        result = _parse_enum4linux_output(output)
        assert result["os_info"]["os"] == "Windows Server 2019"

    def test_json_empty_data_returns_defaults(self):
        output = json.dumps({})
        result = _parse_enum4linux_output(output)
        assert result["users"] == []
        assert result["shares"] == []


# ---------------------------------------------------------------------------
# TestParseEnum4linuxText
# ---------------------------------------------------------------------------


class TestParseEnum4linuxText:
    def test_empty_returns_defaults(self):
        result = _parse_enum4linux_text("")
        assert result["users"] == []
        assert result["shares"] == []
        assert result["groups"] == []

    def test_user_rid_extracted(self):
        text = "user:[Administrator] rid:[0x1f4]"
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "Administrator"
        assert result["users"][0]["rid"] == "0x1f4"

    def test_multiple_users(self):
        text = "user:[admin] rid:[500]\nuser:[guest] rid:[501]\nuser:[bob] rid:[1001]\n"
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 3

    def test_share_disk_extracted(self):
        text = "    ADMIN$    Disk    Remote Admin"
        result = _parse_enum4linux_text(text)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["name"] == "ADMIN$"
        assert result["shares"][0]["type"] == "Disk"

    def test_share_ipc_extracted(self):
        text = "    IPC$    IPC    Remote IPC"
        result = _parse_enum4linux_text(text)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["type"] == "IPC"

    def test_group_extracted(self):
        text = "group:[Domain Admins] rid:[0x200]"
        result = _parse_enum4linux_text(text)
        assert len(result["groups"]) == 1
        assert result["groups"][0]["name"] == "Domain Admins"

    def test_non_matching_lines_ignored(self):
        text = "[+] Getting domain SID...\n[*] Connecting to target...\n"
        result = _parse_enum4linux_text(text)
        assert result["users"] == []
        assert result["shares"] == []

    def test_mixed_output(self):
        text = (
            "user:[svc_sql] rid:[1105]\n"
            "    C$    Disk    Default Share\n"
            "group:[IT Staff] rid:[0x210]\n"
        )
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 1
        assert len(result["shares"]) == 1
        assert len(result["groups"]) == 1


# ---------------------------------------------------------------------------
# TestEnum4linuxScan
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_enum4linux_mocks(
    stdout: str = "{}",
    run_raises: Exception | None = None,
    which_returns: str | None = "/usr/bin/enum4linux-ng",
):
    """Build standard mocks for enum4linux_scan tests."""
    mock_cfg = MagicMock()
    mock_cfg.tools.defaults.scan_timeout = 300

    mock_audit = MagicMock()
    mock_audit.log_tool_call = AsyncMock()
    mock_audit.log_target_blocked = AsyncMock()

    mock_allowlist = MagicMock()
    mock_allowlist.check.return_value = None

    mock_rl = MagicMock()
    mock_rl.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl.__aexit__ = AsyncMock(return_value=False)

    if run_raises:
        mock_run = AsyncMock(side_effect=run_raises)
    else:
        mock_run = AsyncMock(return_value=(stdout, "", 0))

    return mock_cfg, mock_audit, mock_allowlist, mock_rl, mock_run


class TestEnum4linuxScan:
    async def test_allowlist_block_raises(self, mock_ctx):
        mock_cfg, mock_audit, _, mock_rl, mock_run = _make_enum4linux_mocks()
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Not allowed")
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            pytest.raises(Exception, match="Not allowed"),
        ):
            await enum4linux_scan(mock_ctx, "10.0.0.1")

        mock_audit.log_target_blocked.assert_called_once()

    async def test_enum4linux_ng_preferred_when_available(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=("{}", "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1")

        assert result["tool"] == "enum4linux-ng"

    async def test_enum4linux_fallback_when_ng_not_found(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value=None),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=("{}", "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1")

        assert result["tool"] == "enum4linux"

    async def test_credentials_args_added_when_provided(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("{}", "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch("tengu.tools.ad.enum4linux.run_command", side_effect=fake_run),
        ):
            await enum4linux_scan(mock_ctx, "10.0.0.1", username="admin", password="secret")

        assert "-u" in captured_args
        assert "admin" in captured_args
        assert "-p" in captured_args
        assert "secret" in captured_args

    async def test_no_credentials_args_when_not_provided(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("{}", "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch("tengu.tools.ad.enum4linux.run_command", side_effect=fake_run),
        ):
            await enum4linux_scan(mock_ctx, "10.0.0.1")

        assert "-u" not in captured_args
        assert "-p" not in captured_args

    async def test_result_keys_present(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=("{}", "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1")

        for key in (
            "tool",
            "target",
            "authenticated",
            "command",
            "duration_seconds",
            "users",
            "groups",
            "shares",
            "password_policy",
            "os_info",
            "raw_output_excerpt",
        ):
            assert key in result, f"Missing key: {key}"

    async def test_run_command_exception_propagates_with_audit_log(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                side_effect=RuntimeError("subprocess failed"),
            ),
            pytest.raises(RuntimeError, match="subprocess failed"),
        ):
            await enum4linux_scan(mock_ctx, "10.0.0.1")

        calls = mock_audit.log_tool_call.call_args_list
        assert any(c.kwargs.get("result") == "failed" for c in calls)

    async def test_timeout_override(self, mock_ctx):
        captured_kwargs: dict = {}

        async def fake_run(args, **kw):
            captured_kwargs.update(kw)
            return ("{}", "", 0)

        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch("tengu.tools.ad.enum4linux.run_command", side_effect=fake_run),
        ):
            await enum4linux_scan(mock_ctx, "10.0.0.1", timeout=120)

        assert captured_kwargs.get("timeout") == 120

    async def test_authenticated_false_when_no_credentials(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=("{}", "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1")

        assert result["authenticated"] is False

    async def test_authenticated_true_when_credentials_provided(self, mock_ctx):
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=("{}", "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1", username="admin", password="pass")

        assert result["authenticated"] is True

    async def test_raw_output_truncated_to_3000_chars(self, mock_ctx):
        long_stdout = "Z" * 7000
        mock_cfg, mock_audit, mock_allowlist, mock_rl, _ = _make_enum4linux_mocks()
        from tengu.tools.ad.enum4linux import enum4linux_scan

        with (
            patch("tengu.tools.ad.enum4linux.get_config", return_value=mock_cfg),
            patch("tengu.tools.ad.enum4linux.get_audit_logger", return_value=mock_audit),
            patch(
                "tengu.tools.ad.enum4linux.make_allowlist_from_config", return_value=mock_allowlist
            ),
            patch("tengu.tools.ad.enum4linux.shutil.which", return_value="/usr/bin/enum4linux-ng"),
            patch(
                "tengu.tools.ad.enum4linux.resolve_tool_path", return_value="/usr/bin/enum4linux-ng"
            ),
            patch("tengu.tools.ad.enum4linux.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.ad.enum4linux.run_command",
                new_callable=AsyncMock,
                return_value=(long_stdout, "", 0),
            ),
        ):
            result = await enum4linux_scan(mock_ctx, "10.0.0.1")

        assert len(result["raw_output_excerpt"]) == 3000
