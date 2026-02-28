"""Unit tests for testssl_check: tool discovery, validation, and JSON parsing."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import ToolNotFoundError

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.web.testssl"


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


def _make_allowlist_mock(blocked: bool = False) -> MagicMock:
    allowlist = MagicMock()
    if blocked:
        allowlist.check.side_effect = Exception("Target not allowed")
    return allowlist


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_testssl_async(ctx, host="example.com", port=443, severity_threshold="LOW",
                             stdout="[]", returncode=0, which_side_effect=None, blocked=False):
    """Run testssl_check under full mock."""
    from tengu.tools.web.testssl import testssl_check

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300

    # Default: testssl.sh found
    if which_side_effect is None:
        which_side_effect = ["/usr/bin/testssl.sh", None]

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_target", return_value=host),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=_make_allowlist_mock(blocked)),
        patch("shutil.which", side_effect=which_side_effect),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", returncode))),
    ):
        return await testssl_check(ctx, host, port=port, severity_threshold=severity_threshold)


def _run_testssl(ctx, **kwargs):
    return asyncio.run(_run_testssl_async(ctx, **kwargs))


# ---------------------------------------------------------------------------
# TestTestsslToolDiscovery
# ---------------------------------------------------------------------------


class TestTestsslToolDiscovery:
    async def test_tool_not_found_raises_tool_not_found_error(self, ctx):
        from tengu.tools.web.testssl import testssl_check

        audit_mock = _make_audit_mock()
        cfg_mock = MagicMock()
        cfg_mock.tools.defaults.scan_timeout = 300

        raised = False
        try:
            with (
                patch(f"{_MOD}.get_config", return_value=cfg_mock),
                patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
                patch(f"{_MOD}.sanitize_target", return_value="example.com"),
                patch(f"{_MOD}.make_allowlist_from_config", return_value=_make_allowlist_mock()),
                patch("shutil.which", return_value=None),
            ):
                await testssl_check(ctx, "example.com")
        except ToolNotFoundError:
            raised = True
        assert raised, "Expected ToolNotFoundError when testssl not found"

    def test_testssl_sh_preferred_over_testssl(self, ctx):
        # First which call returns testssl.sh path, testssl not reached
        result = _run_testssl(ctx, which_side_effect=["/usr/local/bin/testssl.sh", None])
        assert "testssl.sh" in result["command"]

    def test_testssl_fallback_when_sh_not_found(self, ctx):
        # testssl.sh not found, testssl found
        result = _run_testssl(ctx, which_side_effect=[None, "/usr/bin/testssl"])
        assert "testssl" in result["command"]


# ---------------------------------------------------------------------------
# TestTestsslSeverityValidation
# ---------------------------------------------------------------------------


class TestTestsslSeverityValidation:
    def test_invalid_severity_defaults_to_low(self, ctx):
        result = _run_testssl(ctx, severity_threshold="BOGUS")
        assert "--severity LOW" in result["command"]

    def test_valid_severity_info_preserved(self, ctx):
        result = _run_testssl(ctx, severity_threshold="INFO")
        assert "--severity INFO" in result["command"]

    def test_valid_severity_high_preserved(self, ctx):
        result = _run_testssl(ctx, severity_threshold="HIGH")
        assert "--severity HIGH" in result["command"]

    def test_valid_severity_critical_preserved(self, ctx):
        result = _run_testssl(ctx, severity_threshold="CRITICAL")
        assert "--severity CRITICAL" in result["command"]


# ---------------------------------------------------------------------------
# TestTestsslPortClamping
# ---------------------------------------------------------------------------


class TestTestsslPortClamping:
    def test_port_clamped_min(self, ctx):
        result = _run_testssl(ctx, port=0)
        assert ":1" in result["command"]

    def test_port_clamped_max(self, ctx):
        result = _run_testssl(ctx, port=99999)
        assert ":65535" in result["command"]

    def test_port_within_range_preserved(self, ctx):
        result = _run_testssl(ctx, port=8443)
        assert ":8443" in result["command"]


# ---------------------------------------------------------------------------
# TestTestsslJsonParsing
# ---------------------------------------------------------------------------


def _make_finding(
    item_id: str = "heartbleed",
    severity: str = "HIGH",
    finding: str = "vulnerable",
    cve: str = "CVE-2014-0160",
) -> dict:
    return {"id": item_id, "severity": severity, "finding": finding, "cve": cve}


class TestTestsslJsonParsing:
    def test_findings_parsed_from_json_list(self, ctx):
        items = [
            _make_finding("heartbleed", "HIGH", "vulnerable", "CVE-2014-0160"),
            _make_finding("robot", "MEDIUM", "VULNERABLE (same as ROBOT)", "CVE-2019-1559"),
        ]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["findings_count"] == 2

    def test_protocol_items_categorized_as_supported_protocols(self, ctx):
        items = [
            {"id": "protocol_tls1_2", "severity": "OK", "finding": "TLS 1.2 offered", "cve": ""},
        ]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert "protocol_tls1_2" in result["supported_protocols"]

    def test_protocol_item_without_offered_not_in_protocols(self, ctx):
        # "not supported" does NOT contain "offered" → not added to supported_protocols
        items = [
            {"id": "protocol_sslv2", "severity": "CRITICAL", "finding": "not supported", "cve": ""},
        ]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["supported_protocols"] == []

    def test_high_severity_in_vulnerabilities(self, ctx):
        items = [_make_finding("heartbleed", "HIGH", "vulnerable")]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["vulnerabilities_count"] == 1
        assert result["vulnerabilities"][0]["severity"] == "HIGH"

    def test_critical_severity_in_vulnerabilities(self, ctx):
        items = [_make_finding("poodle", "CRITICAL", "vulnerable", "CVE-2014-3566")]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["vulnerabilities_count"] == 1

    def test_medium_severity_in_vulnerabilities(self, ctx):
        items = [_make_finding("robot", "MEDIUM", "VULNERABLE")]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["vulnerabilities_count"] == 1

    def test_low_severity_not_in_vulnerabilities(self, ctx):
        items = [_make_finding("session_ticket", "LOW", "offered")]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["vulnerabilities_count"] == 0

    def test_info_severity_not_in_vulnerabilities(self, ctx):
        items = [_make_finding("info_item", "INFO", "some info")]
        result = _run_testssl(ctx, stdout=json.dumps(items))
        assert result["vulnerabilities_count"] == 0

    def test_invalid_json_gives_empty_results(self, ctx):
        result = _run_testssl(ctx, stdout="not json {{{")
        assert result["findings_count"] == 0
        assert result["vulnerabilities_count"] == 0
        assert result["supported_protocols"] == []

    def test_non_list_json_ignored(self, ctx):
        result = _run_testssl(ctx, stdout='{"key": "value"}')
        assert result["findings_count"] == 0


# ---------------------------------------------------------------------------
# TestTestsslReturnStructure
# ---------------------------------------------------------------------------


class TestTestsslReturnStructure:
    def test_return_keys_present(self, ctx):
        result = _run_testssl(ctx)
        expected_keys = {
            "tool", "host", "port", "command", "duration_seconds",
            "findings_count", "vulnerabilities_count",
            "supported_protocols", "vulnerabilities", "all_findings", "raw_output",
        }
        assert expected_keys.issubset(result.keys())

    def test_tool_name_is_testssl(self, ctx):
        result = _run_testssl(ctx)
        assert result["tool"] == "testssl"

    def test_host_and_port_in_return(self, ctx):
        result = _run_testssl(ctx, host="myhost.com", port=443)
        assert result["host"] == "myhost.com"
        assert result["port"] == 443


# ---------------------------------------------------------------------------
# TestTestsslAllowlist
# ---------------------------------------------------------------------------


class TestTestsslAllowlist:
    async def test_allowlist_blocked_raises(self, ctx):
        from tengu.tools.web.testssl import testssl_check

        audit_mock = _make_audit_mock()
        cfg_mock = MagicMock()
        cfg_mock.tools.defaults.scan_timeout = 300

        blocked_allowlist = _make_allowlist_mock(blocked=True)
        raised = False
        try:
            with (
                patch(f"{_MOD}.get_config", return_value=cfg_mock),
                patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
                patch(f"{_MOD}.sanitize_target", return_value="blocked.com"),
                patch(f"{_MOD}.make_allowlist_from_config", return_value=blocked_allowlist),
                patch("shutil.which", return_value="/usr/bin/testssl.sh"),
            ):
                await testssl_check(ctx, "blocked.com")
        except Exception:
            raised = True
        assert raised, "Expected an exception when target is blocked"
