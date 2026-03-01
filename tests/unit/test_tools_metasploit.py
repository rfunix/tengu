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
        import sys

        saved = {k: v for k, v in sys.modules.items() if "pymetasploit3" in k}
        for key in list(sys.modules.keys()):
            if "pymetasploit3" in key:
                del sys.modules[key]

        with patch.dict("sys.modules", {"pymetasploit3": None, "pymetasploit3.msfrpc": None}):
            # Force reload to pick up the patched modules dict
            import importlib

            from tengu.tools.exploit import metasploit as msf_mod

            importlib.reload(msf_mod)
            with pytest.raises(MetasploitConnectionError) as exc_info:
                msf_mod._get_msf_client()
            assert "pymetasploit3" in str(exc_info.value).lower() or "N/A" in str(exc_info.value)

        # Restore
        sys.modules.update(saved)


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

        def fake_run(path, opts, target):
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

        def fake_run(path, opts, target):
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

        def fake_run(path, opts, target):
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

        def fake_run(path, opts, target):
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
        mock_module = MagicMock()
        mock_module.name = "EternalBlue"
        mock_module.description = "SMB exploit"
        mock_module.references = ["CVE-2017-0144"]
        mock_module.options = {
            "RHOSTS": {"required": True, "desc": "Target host", "default": "", "type": "string"}
        }
        mock_module.targets = {0: "Windows 7", 1: "Windows 10"}
        mock_module.rank = "great"

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/windows/smb/ms17_010_eternalblue")

        assert result["name"] == "EternalBlue"
        assert result["description"] == "SMB exploit"
        assert "RHOSTS" in result["options"]
        assert result["rank"] == "great"

    def test_options_parsed_with_required_flag(self):
        mock_module = MagicMock()
        mock_module.name = "Test"
        mock_module.description = "test"
        mock_module.references = []
        mock_module.options = {
            "RHOSTS": {"required": True, "desc": "Target", "default": "", "type": "string"},
            "PORT": {"required": False, "desc": "Port", "default": "445", "type": "integer"},
        }
        mock_module.targets = {}
        mock_module.rank = "normal"

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/test")

        assert result["options"]["RHOSTS"]["required"] is True
        assert result["options"]["PORT"]["required"] is False

    def test_exception_returns_error_dict(self):
        mock_client = MagicMock()
        mock_client.modules.use.side_effect = Exception("Module not found")

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _get_module_info

            result = _get_module_info("exploit/invalid/module")

        assert "error" in result

    def test_targets_parsed_as_list(self):
        mock_module = MagicMock()
        mock_module.name = "Test"
        mock_module.description = "test"
        mock_module.references = []
        mock_module.options = {}
        mock_module.targets = {0: "Windows 7", 1: "Windows 10", 2: "Windows Server 2016"}
        mock_module.rank = "great"

        mock_client = MagicMock()
        mock_client.modules.use.return_value = mock_module

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

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("exploit/windows/smb/ms17_010_eternalblue", {}, 0)

        mock_module.execute.assert_called_once()
        call_kwargs = mock_module.execute.call_args
        assert "payload" in call_kwargs.kwargs

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

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
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

        with patch("tengu.tools.exploit.metasploit._get_msf_client", return_value=mock_client):
            from tengu.tools.exploit.metasploit import _run_module

            _run_module("exploit/test", {"RHOSTS": "192.168.1.1", "LHOST": "10.0.0.1"}, 0)

        # Verify options were set on the module object
        mock_module.__setitem__.assert_called()


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
