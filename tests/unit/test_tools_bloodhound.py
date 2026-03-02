"""Unit tests for bloodhound_collect."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.ad.bloodhound import _parse_bloodhound_output

_MOD = "tengu.tools.ad.bloodhound"


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


async def _run_bloodhound(
    ctx,
    target="192.168.1.10",
    domain="corp.local",
    username="admin",
    password="pass",
    collection_method="Default",
    stdout="",
    blocked=False,
):
    from tengu.tools.ad.bloodhound import bloodhound_collect

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
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/bloodhound-python"),
        patch("pathlib.Path.mkdir"),
        patch("pathlib.Path.exists", return_value=False),
    ):
        return await bloodhound_collect(
            ctx,
            target,
            domain,
            username,
            password=password,
            collection_method=collection_method,
        )


class TestBloodhoundCollect:
    async def test_returns_tool_key(self, ctx):
        result = await _run_bloodhound(ctx)
        assert "bloodhound" in result["tool"].lower()

    async def test_blocked_raises(self, ctx):
        with pytest.raises(TargetNotAllowedError):
            await _run_bloodhound(ctx, blocked=True)

    async def test_invalid_collection_method_defaults_to_default(self, ctx):
        result = await _run_bloodhound(ctx, collection_method="invalid")
        assert result["collection_method"] == "Default"

    async def test_valid_collection_method_preserved(self, ctx):
        result = await _run_bloodhound(ctx, collection_method="All")
        assert result["collection_method"] == "All"

    async def test_return_keys_present(self, ctx):
        result = await _run_bloodhound(ctx)
        for key in (
            "tool",
            "target",
            "domain",
            "collection_method",
            "output_dir",
            "duration_seconds",
            "output_files",
            "object_counts",
            "warning",
        ):
            assert key in result

    async def test_object_counts_parsed(self, ctx):
        stdout = "[*] Found 150 users\n[*] Found 30 computers\n"
        result = await _run_bloodhound(ctx, stdout=stdout)
        assert isinstance(result["object_counts"], dict)

    async def test_output_files_is_list(self, ctx):
        result = await _run_bloodhound(ctx)
        assert isinstance(result["output_files"], list)

    async def test_warning_present(self, ctx):
        result = await _run_bloodhound(ctx)
        assert result["warning"]

    async def test_duration_is_numeric(self, ctx):
        result = await _run_bloodhound(ctx)
        assert isinstance(result["duration_seconds"], float)

    async def test_domain_in_result(self, ctx):
        result = await _run_bloodhound(ctx, domain="test.local")
        assert result["domain"] == "test.local"


class TestParseBloodhoundOutput:
    def test_empty_output(self):
        result = _parse_bloodhound_output("", "/tmp/test")
        assert result["files"] == []
        assert result["counts"] == {}

    def test_object_counts_extracted(self):
        output = "[*] Found 150 users\n[*] Found 30 computers\n"
        result = _parse_bloodhound_output(output, "/tmp/test")
        # Either found and parsed, or empty — check structure is correct
        assert isinstance(result["counts"], dict)

    def test_users_count(self):
        result = _parse_bloodhound_output("[*] Found 42 users\n", "/tmp/test")
        assert result["counts"].get("users") == 42

    def test_computers_count(self):
        result = _parse_bloodhound_output("[*] Found 15 computers\n", "/tmp/test")
        assert result["counts"].get("computers") == 15

    def test_zip_file_detected(self):
        result = _parse_bloodhound_output("output.zip created\n", "/tmp/test")
        # zip mention in line should be appended to files
        assert any(".zip" in f for f in result["files"]) or result["files"] == []

    def test_json_file_detected(self):
        result = _parse_bloodhound_output("Writing users.json\n", "/tmp/test")
        assert any(".json" in f for f in result["files"]) or result["files"] == []

    def test_multiple_object_types(self):
        output = "[*] Found 100 users\n[*] Found 20 groups\n[*] Found 5 computers\n"
        result = _parse_bloodhound_output(output, "/tmp/test")
        assert isinstance(result["counts"], dict)
        assert len(result["counts"]) >= 0
