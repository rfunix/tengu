"""Unit tests for tengu.tools.exploit.metasploit."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import MetasploitConnectionError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_msf_client(modules=None, sessions=None) -> MagicMock:
    client = MagicMock()
    client.modules = MagicMock()
    client.modules.search = MagicMock(return_value=modules or [])
    client.sessions = MagicMock()
    client.sessions.list = sessions or {}
    return client


# ---------------------------------------------------------------------------
# TestGetMsfClientImportError
# ---------------------------------------------------------------------------


class TestGetMsfClientImportError:
    def test_import_error_raises_metasploit_connection_error(self):
        """ImportError for pymetasploit3 raises MetasploitConnectionError."""
        # Avoid touching sys.modules (setting None entries triggers a beartype/Python 3.14
        # circular import bug). Instead, intercept at the builtins.__import__ level.
        import builtins

        from tengu.tools.exploit import metasploit as msf_mod

        original_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if "pymetasploit3" in name:
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with (
            patch("builtins.__import__", side_effect=fake_import),
            pytest.raises(MetasploitConnectionError) as exc_info,
        ):
            msf_mod._get_msf_client()
        assert "pymetasploit3" in str(exc_info.value).lower() or "N/A" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestMsfSearch
# ---------------------------------------------------------------------------


class TestMsfSearch:
    @pytest.mark.asyncio
    async def test_invalid_module_type_defaults_to_all(self):
        """Invalid module_type is coerced to 'all'."""
        ctx = _make_ctx()
        modules = [
            {
                "fullname": "exploit/test",
                "name": "Test",
                "type": "exploit",
                "rank": "great",
                "description": "desc",
                "disclosure_date": "",
                "references": [],
            }
        ]
        with patch("tengu.tools.exploit.metasploit._search_modules", return_value=modules):
            from tengu.tools.exploit.metasploit import msf_search

            result = await msf_search(ctx, "eternalblue", module_type="invalid_type")

        assert result["module_type"] == "all"

    @pytest.mark.asyncio
    async def test_valid_module_type_preserved(self):
        """Valid module_type is preserved in the result."""
        ctx = _make_ctx()
        with patch("tengu.tools.exploit.metasploit._search_modules", return_value=[]):
            from tengu.tools.exploit.metasploit import msf_search

            result = await msf_search(ctx, "test", module_type="exploit")

        assert result["module_type"] == "exploit"

    @pytest.mark.asyncio
    async def test_connection_error_returns_error_dict(self):
        """MetasploitConnectionError returns error dict with tool key."""
        ctx = _make_ctx()
        err = MetasploitConnectionError("127.0.0.1:55553", "refused")

        with patch("tengu.tools.exploit.metasploit._search_modules", side_effect=err):
            from tengu.tools.exploit.metasploit import msf_search

            result = await msf_search(ctx, "eternalblue")

        assert result["tool"] == "msf_search"
        assert "error" in result
        assert "127.0.0.1:55553" in result["error"]

    @pytest.mark.asyncio
    async def test_returns_modules_and_total(self):
        """Successful search returns tool, query, total, modules."""
        ctx = _make_ctx()
        modules = [
            {
                "fullname": "exploit/windows/smb/ms17_010_eternalblue",
                "name": "EternalBlue",
                "type": "exploit",
                "rank": "great",
                "description": "SMB exploit",
                "disclosure_date": "2017-03-14",
                "references": ["CVE-2017-0144"],
            }
        ]
        with patch("tengu.tools.exploit.metasploit._search_modules", return_value=modules):
            from tengu.tools.exploit.metasploit import msf_search

            result = await msf_search(ctx, "eternalblue")

        assert result["tool"] == "msf_search"
        assert result["query"] == "eternalblue"
        assert result["total"] == 1
        assert len(result["modules"]) == 1

    @pytest.mark.asyncio
    async def test_all_valid_module_types_accepted(self):
        """All valid module types pass through without coercion."""
        ctx = _make_ctx()
        valid_types = {"all", "exploit", "auxiliary", "post", "payload", "encoder", "evasion"}
        with patch("tengu.tools.exploit.metasploit._search_modules", return_value=[]):
            from tengu.tools.exploit.metasploit import msf_search

            for mtype in valid_types:
                result = await msf_search(ctx, "test", module_type=mtype)
                assert result["module_type"] == mtype


# ---------------------------------------------------------------------------
# TestMsfModuleInfo
# ---------------------------------------------------------------------------


class TestMsfModuleInfo:
    @pytest.mark.asyncio
    async def test_dangerous_chars_removed_from_path(self):
        """Characters outside [a-zA-Z0-9_/-] are stripped from module_path."""
        ctx = _make_ctx()
        info = {
            "name": "Test",
            "description": "",
            "references": [],
            "options": {},
            "targets": [],
            "rank": "",
        }

        with patch("tengu.tools.exploit.metasploit._get_module_info", return_value=info):
            from tengu.tools.exploit.metasploit import msf_module_info

            result = await msf_module_info(ctx, "exploit/test;rm -rf /")

        # The sanitized path must not contain ';', spaces, or shell chars
        assert ";" not in result["module"]
        assert " " not in result["module"]

    @pytest.mark.asyncio
    async def test_connection_error_returns_error_dict(self):
        """MetasploitConnectionError returns error dict with tool=msf_module_info."""
        ctx = _make_ctx()
        err = MetasploitConnectionError("127.0.0.1:55553", "refused")

        with patch("tengu.tools.exploit.metasploit._get_module_info", side_effect=err):
            from tengu.tools.exploit.metasploit import msf_module_info

            result = await msf_module_info(ctx, "exploit/windows/smb/ms17_010_eternalblue")

        assert result["tool"] == "msf_module_info"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_returns_module_info(self):
        """Successful call returns tool, module, and info fields."""
        ctx = _make_ctx()
        info = {
            "name": "EternalBlue",
            "description": "SMB exploit",
            "references": ["CVE-2017-0144"],
            "options": {"RHOSTS": {"required": True, "description": "Target"}},
            "targets": ["Windows 7"],
            "rank": "great",
        }
        with patch("tengu.tools.exploit.metasploit._get_module_info", return_value=info):
            from tengu.tools.exploit.metasploit import msf_module_info

            result = await msf_module_info(ctx, "exploit/windows/smb/ms17_010_eternalblue")

        assert result["tool"] == "msf_module_info"
        assert "module" in result
        assert result["name"] == "EternalBlue"
        assert result["rank"] == "great"


# ---------------------------------------------------------------------------
# TestMsfRunModule
# ---------------------------------------------------------------------------


class TestMsfRunModule:
    @pytest.mark.asyncio
    async def test_options_keys_sanitized(self):
        """Option keys with special chars have non-alphanumeric/underscore chars stripped."""
        ctx = _make_ctx()
        run_result = {"success": True, "job_id": 1, "uuid": "abc", "raw": "{}"}

        captured_options: dict = {}

        def fake_run(path, opts, target_index, payload="", payload_options=None):
            captured_options.update(opts)
            return run_result

        with patch("tengu.tools.exploit.metasploit._run_module", side_effect=fake_run):
            from tengu.tools.exploit.metasploit import msf_run_module

            await msf_run_module(ctx, "exploit/test", options={"RH;OSTS": "192.168.1.1"})

        # The key should have the ';' removed
        assert "RH;OSTS" not in captured_options
        assert "RHOSTS" in captured_options

    @pytest.mark.asyncio
    async def test_options_values_truncated_to_500(self):
        """Option values longer than 500 chars are truncated."""
        ctx = _make_ctx()
        long_value = "A" * 1000
        run_result = {"success": True, "job_id": 1, "uuid": "abc", "raw": "{}"}

        captured_options: dict = {}

        def fake_run(path, opts, target_index, payload="", payload_options=None):
            captured_options.update(opts)
            return run_result

        with patch("tengu.tools.exploit.metasploit._run_module", side_effect=fake_run):
            from tengu.tools.exploit.metasploit import msf_run_module

            await msf_run_module(ctx, "exploit/test", options={"RHOSTS": long_value})

        assert len(captured_options["RHOSTS"]) == 500

    @pytest.mark.asyncio
    async def test_newlines_removed_from_option_values(self):
        """Newline characters are stripped from option values."""
        ctx = _make_ctx()
        run_result = {"success": True, "job_id": 1, "uuid": "abc", "raw": "{}"}

        captured_options: dict = {}

        def fake_run(path, opts, target_index, payload="", payload_options=None):
            captured_options.update(opts)
            return run_result

        with patch("tengu.tools.exploit.metasploit._run_module", side_effect=fake_run):
            from tengu.tools.exploit.metasploit import msf_run_module

            await msf_run_module(ctx, "exploit/test", options={"CMD": "echo\nhello\r\nworld"})

        assert "\n" not in captured_options["CMD"]
        assert "\r" not in captured_options["CMD"]

    @pytest.mark.asyncio
    async def test_connection_error_returns_error_dict(self):
        """MetasploitConnectionError returns error dict with tool=msf_run_module."""
        ctx = _make_ctx()
        err = MetasploitConnectionError("127.0.0.1:55553", "refused")

        with patch("tengu.tools.exploit.metasploit._run_module", side_effect=err):
            from tengu.tools.exploit.metasploit import msf_run_module

            result = await msf_run_module(ctx, "exploit/test")

        assert result["tool"] == "msf_run_module"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_success_returns_job_and_uuid(self):
        """Successful run returns tool, module, success, job_id, uuid."""
        ctx = _make_ctx()
        run_result = {"success": True, "job_id": 42, "uuid": "deadbeef", "raw": "{}"}

        with patch("tengu.tools.exploit.metasploit._run_module", return_value=run_result):
            from tengu.tools.exploit.metasploit import msf_run_module

            result = await msf_run_module(ctx, "exploit/windows/smb/ms17_010_eternalblue")

        assert result["tool"] == "msf_run_module"
        assert result["success"] is True
        assert result["job_id"] == 42
        assert result["uuid"] == "deadbeef"

    @pytest.mark.asyncio
    async def test_empty_options_keys_are_discarded(self):
        """Option keys that reduce to empty string after sanitization are dropped."""
        ctx = _make_ctx()
        run_result = {"success": True, "job_id": 1, "uuid": "abc", "raw": "{}"}

        captured_options: dict = {}

        def fake_run(path, opts, target_index, payload="", payload_options=None):
            captured_options.update(opts)
            return run_result

        with patch("tengu.tools.exploit.metasploit._run_module", side_effect=fake_run):
            from tengu.tools.exploit.metasploit import msf_run_module

            await msf_run_module(ctx, "exploit/test", options={";;;": "value"})

        # The sanitized key would be empty, so it should be dropped
        assert ";;;" not in captured_options
        assert "" not in captured_options


# ---------------------------------------------------------------------------
# TestMsfSessionsList
# ---------------------------------------------------------------------------


class TestMsfSessionsList:
    @pytest.mark.asyncio
    async def test_connection_error_returns_error_dict(self):
        """MetasploitConnectionError returns error dict with tool=msf_sessions_list."""
        ctx = _make_ctx()
        err = MetasploitConnectionError("127.0.0.1:55553", "refused")

        with patch("tengu.tools.exploit.metasploit._list_sessions", side_effect=err):
            from tengu.tools.exploit.metasploit import msf_sessions_list

            result = await msf_sessions_list(ctx)

        assert result["tool"] == "msf_sessions_list"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_returns_sessions_and_count(self):
        """Successful call returns tool, count, sessions list."""
        ctx = _make_ctx()
        sessions = [
            {
                "id": "1",
                "type": "meterpreter",
                "target_host": "192.168.1.10",
                "tunnel_peer": "192.168.1.100:4444",
                "platform": "windows",
                "arch": "x64",
                "info": "NT AUTHORITY\\SYSTEM",
            }
        ]

        with patch("tengu.tools.exploit.metasploit._list_sessions", return_value=sessions):
            from tengu.tools.exploit.metasploit import msf_sessions_list

            result = await msf_sessions_list(ctx)

        assert result["tool"] == "msf_sessions_list"
        assert result["count"] == 1
        assert len(result["sessions"]) == 1
        assert result["sessions"][0]["type"] == "meterpreter"

    @pytest.mark.asyncio
    async def test_empty_sessions_returns_zero_count(self):
        """No active sessions returns count=0 and empty list."""
        ctx = _make_ctx()

        with patch("tengu.tools.exploit.metasploit._list_sessions", return_value=[]):
            from tengu.tools.exploit.metasploit import msf_sessions_list

            result = await msf_sessions_list(ctx)

        assert result["count"] == 0
        assert result["sessions"] == []


# ---------------------------------------------------------------------------
# TestSearchModulesInternal
# ---------------------------------------------------------------------------


class TestSearchModulesInternal:
    def test_returns_all_modules_when_type_all(self):
        mock_client = _make_msf_client(
            modules=[
                {
                    "fullname": "exploit/test",
                    "type": "exploit",
                    "name": "Test",
                    "rank": "great",
                    "description": "desc",
                    "disclosure_date": "",
                    "references": [],
                },
                {
                    "fullname": "auxiliary/aux",
                    "type": "auxiliary",
                    "name": "Aux",
                    "rank": "normal",
                    "description": "aux desc",
                    "disclosure_date": "",
                    "references": [],
                },
            ]
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _search_modules

            results = _search_modules("test", "all")

        assert len(results) == 2

    def test_filters_by_module_type(self):
        mock_client = _make_msf_client(
            modules=[
                {
                    "fullname": "exploit/test",
                    "type": "exploit",
                    "name": "Test",
                    "rank": "great",
                    "description": "desc",
                    "disclosure_date": "",
                    "references": [],
                },
                {
                    "fullname": "auxiliary/aux",
                    "type": "auxiliary",
                    "name": "Aux",
                    "rank": "normal",
                    "description": "aux",
                    "disclosure_date": "",
                    "references": [],
                },
            ]
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _search_modules

            results = _search_modules("test", "exploit")

        assert len(results) == 1
        assert results[0]["type"] == "exploit"

    def test_skips_modules_not_matching_type(self):
        mock_client = _make_msf_client(
            modules=[
                {
                    "fullname": "post/multi/recon/local_exploit_suggester",
                    "type": "post",
                    "name": "Post module",
                    "rank": "normal",
                    "description": "post",
                    "disclosure_date": "",
                    "references": [],
                }
            ]
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _search_modules

            results = _search_modules("test", "exploit")

        assert len(results) == 0

    def test_result_contains_expected_keys(self):
        mock_client = _make_msf_client(
            modules=[
                {
                    "fullname": "exploit/test",
                    "type": "exploit",
                    "name": "Test",
                    "rank": "great",
                    "description": "desc",
                    "disclosure_date": "2020-01-01",
                    "references": ["CVE-2020-1234"],
                }
            ]
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _search_modules

            results = _search_modules("test", "all")

        assert len(results) == 1
        for key in (
            "fullname",
            "name",
            "type",
            "rank",
            "description",
            "disclosure_date",
            "references",
        ):
            assert key in results[0]

    def test_references_capped_at_5(self):
        mock_client = _make_msf_client(
            modules=[
                {
                    "fullname": "exploit/test",
                    "type": "exploit",
                    "name": "Test",
                    "rank": "great",
                    "description": "desc",
                    "disclosure_date": "",
                    "references": [f"CVE-2020-{i}" for i in range(10)],
                }
            ]
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _search_modules

            results = _search_modules("test", "all")

        assert len(results[0]["references"]) <= 5


# ---------------------------------------------------------------------------
# TestGetModuleInfoInternal
# ---------------------------------------------------------------------------


class TestGetModuleInfoInternal:
    def test_returns_module_info_dict(self):
        # _get_module_info uses client.call("module.info", ...) — not client.modules.use
        mock_client = MagicMock()
        mock_client.call.return_value = {
            "name": "EternalBlue",
            "description": "SMB exploit",
            "references": ["CVE-2017-0144"],
            "options": {
                "RHOSTS": {"required": True, "desc": "Target host", "default": "", "type": "string"}
            },
            "targets": {0: "Windows 7", 1: "Windows 10"},
            "rank": "great",
        }

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/windows/smb/ms17_010_eternalblue")

        assert result["name"] == "EternalBlue"
        assert result["description"] == "SMB exploit"
        assert "RHOSTS" in result["options"]
        assert result["rank"] == "great"

    def test_options_parsed_with_required_flag(self):
        mock_client = MagicMock()
        mock_client.call.return_value = {
            "name": "Test",
            "description": "test",
            "references": [],
            "options": {
                "RHOSTS": {"required": True, "desc": "Target", "default": "", "type": "string"},
                "PORT": {"required": False, "desc": "Port", "default": "445", "type": "integer"},
            },
            "targets": {},
            "rank": "normal",
        }

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/test")

        assert result["options"]["RHOSTS"]["required"] is True
        assert result["options"]["PORT"]["required"] is False

    def test_exception_returns_error_dict(self):
        mock_client = MagicMock()
        mock_client.call.side_effect = Exception("Module not found")

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/invalid/module")

        assert "error" in result

    def test_targets_parsed_as_list(self):
        mock_client = MagicMock()
        mock_client.call.return_value = {
            "name": "Test",
            "description": "test",
            "references": [],
            "options": {},
            "targets": {0: "Windows 7", 1: "Windows 10", 2: "Windows Server 2016"},
            "rank": "great",
        }

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/windows/smb/test")

        assert isinstance(result["targets"], list)
        assert len(result["targets"]) == 3


# ---------------------------------------------------------------------------
# TestRunModuleInternal
# ---------------------------------------------------------------------------


class TestRunModuleInternal:
    def test_exploit_module_uses_execute_with_payload(self):
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 1, "uuid": "abc"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit._poll_for_session", return_value=None),
        ):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("exploit/windows/smb/ms17_010_eternalblue", {}, 0)

        mock_module.execute.assert_called_once()
        call_kwargs = mock_module.execute.call_args
        assert "payload" in call_kwargs.kwargs
        assert mock_module.target == 0

    def test_non_exploit_module_uses_execute_without_payload(self):
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 2, "uuid": "def"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("auxiliary/scanner/smb/smb_ms17_010", {}, 0)

        mock_module.execute.assert_called_once()
        call_kwargs = mock_module.execute.call_args
        assert "payload" not in call_kwargs.kwargs

    def test_success_returns_success_true(self):
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 42, "uuid": "deadbeef"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit._poll_for_session", return_value=None),
        ):
            from tengu.tools.exploit.metasploit import _run_module

            result = _run_module("exploit/test", {}, 0)

        assert result["success"] is True
        assert result["job_id"] == 42
        assert result["uuid"] == "deadbeef"

    def test_exception_returns_success_false(self):
        mock_module = MagicMock()
        mock_module.execute.side_effect = Exception("exploit failed")

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_module

            result = _run_module("exploit/test", {}, 0)

        assert result["success"] is False
        assert "error" in result

    def test_options_set_on_module(self):
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 1, "uuid": "abc"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit._poll_for_session", return_value=None),
        ):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("exploit/test", {"RHOSTS": "192.168.1.1", "LHOST": "10.0.0.1"}, 0)

        # Verify options were set on the module object
        mock_module.__setitem__.assert_called()


# ---------------------------------------------------------------------------
# TestMsfSessionCmd
# ---------------------------------------------------------------------------


class TestMsfSessionCmd:
    @pytest.mark.asyncio
    async def test_session_cmd_returns_output(self):
        """Successful command returns tool, session_id, command, output."""
        ctx = _make_ctx()
        run_result = {"output": "uid=1(daemon)\n", "session_type": "shell"}

        with patch("tengu.tools.exploit.metasploit._run_session_cmd", return_value=run_result):
            from tengu.tools.exploit.metasploit import msf_session_cmd

            result = await msf_session_cmd(ctx, "1", "id")

        assert result["tool"] == "msf_session_cmd"
        assert result["session_id"] == "1"
        assert result["command"] == "id"
        assert result["output"] == "uid=1(daemon)\n"
        assert result["session_type"] == "shell"

    @pytest.mark.asyncio
    async def test_session_cmd_connection_error(self):
        """MetasploitConnectionError returns error dict with tool=msf_session_cmd."""
        ctx = _make_ctx()
        err = MetasploitConnectionError("127.0.0.1:55553", "refused")

        with patch("tengu.tools.exploit.metasploit._run_session_cmd", side_effect=err):
            from tengu.tools.exploit.metasploit import msf_session_cmd

            result = await msf_session_cmd(ctx, "1", "id")

        assert result["tool"] == "msf_session_cmd"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_session_cmd_sanitizes_session_id(self):
        """Non-digit characters are stripped from session_id."""
        ctx = _make_ctx()
        run_result = {"output": "root\n", "session_type": "shell"}

        captured: dict = {}

        def fake_run(session_id, command, timeout):
            captured["session_id"] = session_id
            return run_result

        with patch("tengu.tools.exploit.metasploit._run_session_cmd", side_effect=fake_run):
            from tengu.tools.exploit.metasploit import msf_session_cmd

            await msf_session_cmd(ctx, "abc1def2", "whoami")

        assert captured["session_id"] == "12"

    @pytest.mark.asyncio
    async def test_session_cmd_reports_progress(self):
        """ctx.report_progress is called at least twice."""
        ctx = _make_ctx()
        run_result = {"output": "ok", "session_type": "shell"}

        with patch("tengu.tools.exploit.metasploit._run_session_cmd", return_value=run_result):
            from tengu.tools.exploit.metasploit import msf_session_cmd

            await msf_session_cmd(ctx, "1", "id")

        assert ctx.report_progress.await_count >= 2


# ---------------------------------------------------------------------------
# TestRunSessionCmdInternal
# ---------------------------------------------------------------------------


class TestRunSessionCmdInternal:
    def test_shell_session_prompt_detection(self):
        """Shell session exits loop immediately on prompt detection (# or $)."""
        mock_session = MagicMock()
        # First read returns content without a prompt; second returns the shell prompt
        mock_session.read.side_effect = ["uid=0(root)\n", "# "]

        mock_client = MagicMock()
        mock_client.sessions.list = {"1": {"type": "shell"}}
        mock_client.sessions.session.return_value = mock_session

        # monotonic always returns 0.0 so elapsed never reaches timeout
        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit.time.sleep"),
            patch("tengu.tools.exploit.metasploit.time.monotonic", return_value=0.0),
        ):
            from tengu.tools.exploit.metasploit import _run_session_cmd

            result = _run_session_cmd("1", "id", 30)

        mock_session.write.assert_called_once_with("id")
        assert mock_session.read.call_count == 2
        assert "uid=0(root)" in result["output"]
        assert result["session_type"] == "shell"

    def test_shell_session_inactivity_timeout(self):
        """Shell session exits when no new data arrives for _SESSION_READ_INACTIVITY_TIMEOUT."""
        mock_session = MagicMock()
        # Returns data once, then empty (simulates bind shell with no prompt)
        mock_session.read.side_effect = ["partial output", ""]

        mock_client = MagicMock()
        mock_client.sessions.list = {"1": {"type": "shell"}}
        mock_client.sessions.session.return_value = mock_session

        # Provide monotonic values that trigger inactivity timeout on the 2nd read
        # start_time=0.0, elapsed_check1=0.0, last_data_time=0.5, elapsed_check2=0.9, inactivity=2.9
        monotonic_values = iter([0.0, 0.0, 0.5, 0.9, 2.9])

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit.time.sleep"),
            patch(
                "tengu.tools.exploit.metasploit.time.monotonic",
                side_effect=monotonic_values,
            ),
        ):
            from tengu.tools.exploit.metasploit import _run_session_cmd

            result = _run_session_cmd("1", "id", 30)

        assert "partial output" in result["output"]
        assert result["session_type"] == "shell"

    def test_meterpreter_session_run_with_output(self):
        """Meterpreter session uses run_with_output and returns output."""
        mock_session = MagicMock()
        mock_session.run_with_output.return_value = "meterpreter output\n"

        mock_client = MagicMock()
        mock_client.sessions.list = {"2": {"type": "meterpreter"}}
        mock_client.sessions.session.return_value = mock_session

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_session_cmd

            result = _run_session_cmd("2", "sysinfo", 30)

        mock_session.run_with_output.assert_called_once_with(
            "sysinfo",
            end_strs=None,
            timeout=30,
            timeout_exception=False,
        )
        assert result["output"] == "meterpreter output\n"
        assert result["session_type"] == "meterpreter"

    def test_session_not_found(self):
        """Non-existent session ID returns error dict."""
        mock_client = MagicMock()
        mock_client.sessions.list = {}

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_session_cmd

            result = _run_session_cmd("99", "id", 10)

        assert "error" in result
        assert "99" in result["error"]

    def test_session_error_handling(self):
        """Exception during read/write returns error dict."""
        mock_session = MagicMock()
        mock_session.write.side_effect = Exception("broken pipe")

        mock_client = MagicMock()
        mock_client.sessions.list = {"1": {"type": "shell"}}
        mock_client.sessions.session.return_value = mock_session

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_session_cmd

            result = _run_session_cmd("1", "id", 5)

        assert "error" in result
        assert "broken pipe" in result["error"]


# ---------------------------------------------------------------------------
# TestListSessionsInternal
# ---------------------------------------------------------------------------


class TestListSessionsInternal:
    def test_returns_session_list(self):
        mock_client = _make_msf_client(
            sessions={
                "1": {
                    "type": "meterpreter",
                    "target_host": "192.168.1.10",
                    "tunnel_peer": "192.168.1.100:4444",
                    "platform": "windows",
                    "arch": "x64",
                    "info": "NT AUTHORITY\\SYSTEM",
                }
            }
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _list_sessions

            sessions = _list_sessions()

        assert len(sessions) == 1
        assert sessions[0]["type"] == "meterpreter"
        assert sessions[0]["target_host"] == "192.168.1.10"

    def test_empty_sessions_returns_empty_list(self):
        mock_client = _make_msf_client(sessions={})
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _list_sessions

            sessions = _list_sessions()

        assert sessions == []

    def test_exception_during_iteration_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.sessions.list.items.side_effect = Exception("session error")

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _list_sessions

            sessions = _list_sessions()

        # The function catches exceptions and returns empty list
        assert sessions == []

    def test_session_contains_expected_keys(self):
        mock_client = _make_msf_client(
            sessions={
                "5": {
                    "type": "shell",
                    "target_host": "10.0.0.5",
                    "tunnel_peer": "10.0.0.1:5555",
                    "platform": "linux",
                    "arch": "x64",
                    "info": "root",
                }
            }
        )
        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _list_sessions

            sessions = _list_sessions()

        assert len(sessions) == 1
        for key in ("id", "type", "target_host", "tunnel_peer", "platform", "arch", "info"):
            assert key in sessions[0]


# ---------------------------------------------------------------------------
# TestPollForSession
# ---------------------------------------------------------------------------


class TestPollForSession:
    def test_finds_session_by_uuid(self):
        """Returns session_id when exploit_uuid matches a session in sessions.list."""
        mock_client = MagicMock()
        mock_client.sessions.list = {
            "3": {"type": "shell", "exploit_uuid": "deadbeef-1234"},
        }

        # monotonic: start=0.0, first loop check=0.5 (within timeout)
        monotonic_values = iter([0.0, 0.5])

        with patch("tengu.tools.exploit.metasploit.time.monotonic", side_effect=monotonic_values):
            from tengu.tools.exploit.metasploit import _poll_for_session

            result = _poll_for_session(mock_client, "deadbeef-1234")

        assert result == "3"

    def test_returns_none_no_match(self):
        """Returns None when no session matches exploit_uuid within timeout."""
        mock_client = MagicMock()
        mock_client.sessions.list = {
            "1": {"type": "shell", "exploit_uuid": "different-uuid"},
        }

        # Advance time beyond _EXPLOIT_SESSION_POLL_TIMEOUT (10.0s) immediately
        monotonic_values = iter([0.0, 11.0])

        with (
            patch("tengu.tools.exploit.metasploit.time.monotonic", side_effect=monotonic_values),
            patch("tengu.tools.exploit.metasploit.time.sleep"),
        ):
            from tengu.tools.exploit.metasploit import _poll_for_session

            result = _poll_for_session(mock_client, "target-uuid")

        assert result is None

    def test_handles_exception_gracefully(self):
        """Returns None without raising when sessions.list raises an exception."""
        mock_client = MagicMock()
        mock_client.sessions.list = MagicMock(side_effect=Exception("RPC error"))

        # Advance time beyond timeout so the loop exits after the first failed iteration
        monotonic_values = iter([0.0, 11.0])

        with (
            patch("tengu.tools.exploit.metasploit.time.monotonic", side_effect=monotonic_values),
            patch("tengu.tools.exploit.metasploit.time.sleep"),
        ):
            from tengu.tools.exploit.metasploit import _poll_for_session

            result = _poll_for_session(mock_client, "any-uuid")

        assert result is None


# ---------------------------------------------------------------------------
# TestRunModuleSessionPolling
# ---------------------------------------------------------------------------


class TestRunModuleSessionPolling:
    def test_exploit_polls_for_session(self):
        """_run_module calls _poll_for_session for exploit modules and includes session_id."""
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 1, "uuid": "test-uuid-123"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch(
                "tengu.tools.exploit.metasploit._poll_for_session", return_value="5"
            ) as mock_poll,
        ):
            from tengu.tools.exploit.metasploit import _run_module

            result = _run_module("exploit/unix/ftp/vsftpd_234_backdoor", {}, 0)

        mock_poll.assert_called_once_with(mock_client, "test-uuid-123")
        assert result["session_id"] == "5"

    def test_auxiliary_does_not_poll(self):
        """_run_module does NOT call _poll_for_session for auxiliary modules."""
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 2, "uuid": "aux-uuid"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit._poll_for_session") as mock_poll,
        ):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("auxiliary/scanner/smb/smb_ms17_010", {}, 0)

        mock_poll.assert_not_called()

    def test_session_id_absent_when_poll_returns_none(self):
        """session_id key is absent in result when _poll_for_session returns None."""
        mock_module = MagicMock()
        mock_module.execute.return_value = {"job_id": 3, "uuid": "no-session-uuid"}

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with (
            patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client),
            patch("tengu.tools.exploit.metasploit._poll_for_session", return_value=None),
        ):
            from tengu.tools.exploit.metasploit import _run_module

            result = _run_module("exploit/test", {}, 0)

        assert result["success"] is True
        assert "session_id" not in result
