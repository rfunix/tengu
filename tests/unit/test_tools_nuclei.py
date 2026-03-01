"""Unit tests for Nuclei output parser and async nuclei_scan function."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.web.nuclei import _parse_nuclei_output, nuclei_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_nuclei_line(
    template_id: str = "cve-2021-44228",
    name: str = "Log4Shell",
    severity: str = "critical",
    matched_at: str = "https://app.com/",
    cve_ids: list | None = None,
    cvss_score: float | None = 9.0,
    tags: list | None = None,
) -> str:
    return json.dumps(
        {
            "template-id": template_id,
            "info": {
                "name": name,
                "severity": severity,
                "description": "Remote code execution via Log4j",
                "classification": {
                    "cve-id": cve_ids or ["CVE-2021-44228"],
                    "cwe-id": ["CWE-502"],
                    "cvss-score": cvss_score,
                },
                "tags": tags or ["cve", "rce", "log4j"],
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            },
            "matched-at": matched_at,
            "type": "http",
            "extracted-results": [],
            "curl-command": "",
            "timestamp": "2024-01-01T00:00:00Z",
        }
    )


# ---------------------------------------------------------------------------
# TestParseNucleiOutput
# ---------------------------------------------------------------------------


class TestParseNucleiOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_nuclei_output("") == []

    def test_whitespace_only_returns_empty(self):
        assert _parse_nuclei_output("   \n  ") == []

    def test_single_valid_line(self):
        line = _make_nuclei_line()
        findings = _parse_nuclei_output(line)
        assert len(findings) == 1

    def test_template_id_extracted(self):
        line = _make_nuclei_line(template_id="sqli-error-based")
        findings = _parse_nuclei_output(line)
        assert findings[0]["template_id"] == "sqli-error-based"

    def test_template_name_extracted(self):
        line = _make_nuclei_line(name="XSS Reflected")
        findings = _parse_nuclei_output(line)
        assert findings[0]["template_name"] == "XSS Reflected"

    def test_severity_extracted(self):
        line = _make_nuclei_line(severity="high")
        findings = _parse_nuclei_output(line)
        assert findings[0]["severity"] == "high"

    def test_matched_url_extracted(self):
        line = _make_nuclei_line(matched_at="https://target.com/path")
        findings = _parse_nuclei_output(line)
        assert findings[0]["matched_url"] == "https://target.com/path"

    def test_cve_ids_extracted(self):
        line = _make_nuclei_line(cve_ids=["CVE-2021-44228", "CVE-2022-0001"])
        findings = _parse_nuclei_output(line)
        assert "CVE-2021-44228" in findings[0]["cve_ids"]

    def test_cvss_score_extracted(self):
        line = _make_nuclei_line(cvss_score=9.8)
        findings = _parse_nuclei_output(line)
        assert findings[0]["cvss_score"] == 9.8

    def test_tags_extracted(self):
        line = _make_nuclei_line(tags=["sqli", "owasp"])
        findings = _parse_nuclei_output(line)
        assert "sqli" in findings[0]["tags"]

    def test_invalid_json_line_skipped(self):
        lines = "not json\n" + _make_nuclei_line() + "\n{broken"
        findings = _parse_nuclei_output(lines)
        assert len(findings) == 1

    def test_multiple_findings(self):
        lines = "\n".join([_make_nuclei_line(template_id=f"tmpl-{i}") for i in range(5)])
        findings = _parse_nuclei_output(lines)
        assert len(findings) == 5

    def test_missing_info_block_defaults(self):
        minimal = json.dumps({"template-id": "minimal", "matched-at": "https://x.com"})
        findings = _parse_nuclei_output(minimal)
        assert len(findings) == 1
        assert findings[0]["severity"] == "unknown"

    def test_timestamp_extracted(self):
        line = _make_nuclei_line()
        findings = _parse_nuclei_output(line)
        assert findings[0]["timestamp"] == "2024-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Helpers for nuclei_scan tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_nuclei_config(nuclei_severity=None, scan_timeout=300, nuclei_path=None):
    cfg = MagicMock()
    cfg.tools.defaults.nuclei_severity = nuclei_severity or ["medium", "high", "critical"]
    cfg.tools.defaults.scan_timeout = scan_timeout
    cfg.tools.paths.nuclei = nuclei_path
    return cfg


def _make_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


# ---------------------------------------------------------------------------
# TestNucleiScan
# ---------------------------------------------------------------------------


class TestNucleiScan:
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    async def test_nuclei_blocked_url(
        self, mock_audit_fn, mock_allowlist_fn, mock_config, mock_ctx
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Target blocked")
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Target blocked"):
            await nuclei_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_templates_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nuclei_scan(mock_ctx, "https://example.com", templates=["cves/", "misconfiguration/"])
        args = mock_run.call_args[0][0]
        assert "-t" in args

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_tags_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nuclei_scan(mock_ctx, "https://example.com", tags=["xss", "sqli"])
        args = mock_run.call_args[0][0]
        assert "-tags" in args
        tags_idx = args.index("-tags")
        assert "xss" in args[tags_idx + 1]

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_severity_filter(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nuclei_scan(mock_ctx, "https://example.com", severity=["critical"])
        args = mock_run.call_args[0][0]
        assert "-severity" in args
        sev_idx = args.index("-severity")
        assert "critical" in args[sev_idx + 1]

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_stealth_proxy(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = True
        mock_stealth_layer.proxy_url = "socks5://127.0.0.1:9050"
        # inject_proxy_flags appends the -proxy flag
        mock_stealth_layer.inject_proxy_flags.side_effect = lambda tool, args: (
            args + ["-proxy", "socks5://127.0.0.1:9050"]
        )
        mock_stealth.return_value = mock_stealth_layer

        await nuclei_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        assert "-proxy" in args

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_output_parsing(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        nuclei_line = _make_nuclei_line(template_id="xss-reflected", severity="high")
        mock_run.return_value = (nuclei_line, "", 0)

        result = await nuclei_scan(mock_ctx, "https://example.com")
        assert result["findings_count"] == 1
        assert result["findings"][0]["template_id"] == "xss-reflected"
        assert result["severity_breakdown"]["high"] == 1

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_no_templates_no_tags(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nuclei_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        # No -t or -tags should be present
        assert "-tags" not in args
        assert result["tool"] == "nuclei"

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_timeout_respected(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config(scan_timeout=60)
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nuclei_scan(mock_ctx, "https://example.com", timeout=120)
        _, kwargs = mock_run.call_args
        assert kwargs.get("timeout") == 120

    @patch("tengu.tools.web.nuclei.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nuclei.get_config")
    @patch("tengu.tools.web.nuclei.make_allowlist_from_config")
    @patch("tengu.tools.web.nuclei.get_audit_logger")
    @patch("tengu.tools.web.nuclei.resolve_tool_path", return_value="/usr/bin/nuclei")
    @patch("tengu.tools.web.nuclei.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nuclei_tool_key(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nuclei_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nuclei_scan(mock_ctx, "https://example.com")
        assert result["tool"] == "nuclei"
