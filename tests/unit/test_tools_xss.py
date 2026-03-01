"""Unit tests for XSS scanner (dalfox) tool and output parser."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.injection.xss import _parse_dalfox_output


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _mock_config():
    cfg = MagicMock()
    cfg.tools.paths.dalfox = ""
    cfg.tools.defaults.scan_timeout = 300
    return cfg


def _setup_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


# ---------------------------------------------------------------------------
# TestXssScan — async tests for xss_scan function
# ---------------------------------------------------------------------------


class TestXssScan:
    async def test_xss_blocked_url(self, mock_ctx):
        """Allowlist raises — exception re-raised."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
        ):
            allowlist_instance = MagicMock()
            allowlist_instance.check.side_effect = PermissionError("URL blocked")
            mock_allowlist.return_value = allowlist_instance

            with pytest.raises(PermissionError, match="URL blocked"):
                await xss_scan(mock_ctx, "https://blocked.example.com/search")

    async def test_xss_no_vulnerabilities(self, mock_ctx):
        """Clean output — vulnerable=False, findings=[]."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", AsyncMock(return_value=("[]", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://secure.example.com/page")

        assert result["vulnerable"] is False
        assert result["findings"] == []

    async def test_xss_vulnerability_found(self, mock_ctx):
        """Output with XSS finding — vulnerability in result."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        xss_output = json.dumps(
            [
                {
                    "type": "Reflected",
                    "param": "q",
                    "payload": "<script>alert(1)</script>",
                    "evidence": "reflected",
                    "poc": "",
                }
            ]
        )

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch(
                "tengu.tools.injection.xss.run_command", AsyncMock(return_value=(xss_output, "", 0))
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://vuln.example.com/search")

        assert result["vulnerable"] is True
        assert result["findings_count"] == 1

    async def test_xss_remediation_included_when_vulnerable(self, mock_ctx):
        """Vulnerable target has remediation field in result."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        xss_output = json.dumps(
            [{"type": "DOM", "param": "search", "payload": "xss", "evidence": "", "poc": ""}]
        )

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch(
                "tengu.tools.injection.xss.run_command", AsyncMock(return_value=(xss_output, "", 0))
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://vuln.example.com/search")

        assert result["remediation"] is not None

    async def test_xss_tool_key(self, mock_ctx):
        """Result has tool='dalfox'."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", AsyncMock(return_value=("[]", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://example.com/")

        assert result["tool"] == "dalfox"

    async def test_xss_cookie_crlf_stripped(self, mock_ctx):
        """cookie with \\r\\n chars is stripped before passing to dalfox."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("[]", "", 0)

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await xss_scan(
                mock_ctx, "https://example.com/", cookie="session=abc\r\nX-Injected: evil"
            )

        # Cookie value passed should not contain CRLF
        if "--cookie" in captured_args:
            cookie_idx = captured_args.index("--cookie")
            cookie_val = captured_args[cookie_idx + 1]
            assert "\r" not in cookie_val
            assert "\n" not in cookie_val

    async def test_xss_audit_logged(self, mock_ctx):
        """audit.log_tool_call called on success."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", AsyncMock(return_value=("[]", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            await xss_scan(mock_ctx, "https://example.com/search")

        assert mock_audit.log_tool_call.call_count >= 1

    async def test_xss_with_parameter(self, mock_ctx):
        """parameter='q' — -p q included in args."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("[]", "", 0)

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await xss_scan(mock_ctx, "https://example.com/search", parameter="q")

        assert "-p" in captured_args
        assert "q" in captured_args

    async def test_xss_url_in_result(self, mock_ctx):
        """Result has url key with sanitized URL."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", AsyncMock(return_value=("[]", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://example.com/page")

        assert "url" in result

    async def test_xss_no_remediation_when_clean(self, mock_ctx):
        """No vulnerabilities — remediation is None."""
        from tengu.tools.injection.xss import xss_scan

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.injection.xss.get_config", return_value=_mock_config()),
            patch("tengu.tools.injection.xss.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.injection.xss.resolve_tool_path", return_value="/usr/bin/dalfox"),
            patch("tengu.tools.injection.xss.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.injection.xss.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.injection.xss.run_command", AsyncMock(return_value=("[]", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await xss_scan(mock_ctx, "https://clean.example.com/")

        assert result["remediation"] is None


# ---------------------------------------------------------------------------
# TestParseDalfoxOutput
# ---------------------------------------------------------------------------


def _make_dalfox_finding(
    finding_type: str = "Reflected",
    param: str = "q",
    payload: str = "<script>alert(1)</script>",
    evidence: str = "Response contains payload",
    poc: str = "https://example.com/search?q=<script>alert(1)</script>",
) -> dict:
    return {
        "type": finding_type,
        "param": param,
        "payload": payload,
        "evidence": evidence,
        "poc": poc,
    }


class TestParseDalfoxOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_dalfox_output("") == []

    def test_single_json_list_finding(self):
        findings_data = [_make_dalfox_finding()]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert len(result) == 1
        assert result[0]["type"] == "Reflected"
        assert result[0]["parameter"] == "q"

    def test_payload_extracted(self):
        findings_data = [_make_dalfox_finding(payload="<img src=x onerror=alert(1)>")]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert "<img" in result[0]["payload"]

    def test_poc_extracted(self):
        poc = "https://example.com/?xss=1"
        findings_data = [_make_dalfox_finding(poc=poc)]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert result[0]["poc"] == poc

    def test_multiple_findings(self):
        findings_data = [_make_dalfox_finding(param=f"param{i}") for i in range(4)]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert len(result) == 4

    def test_dict_json_wrapped_as_finding(self):
        data = {"type": "DOM", "param": "search", "payload": "xss", "evidence": "", "poc": ""}
        result = _parse_dalfox_output(json.dumps(data))
        assert len(result) == 1
        assert result[0]["type"] == "DOM"

    def test_invalid_json_fallback_v_marker(self):
        text = "[V] XSS detected in param 'q' with payload <script>alert(1)</script>"
        result = _parse_dalfox_output(text)
        assert len(result) == 1
        assert result[0]["type"] == "xss"
        assert "[V]" in result[0]["message"]

    def test_invalid_json_fallback_poc_marker(self):
        text = "POC: https://evil.com/?xss=<script>alert(1)</script>"
        result = _parse_dalfox_output(text)
        assert len(result) == 1

    def test_non_matching_lines_ignored_in_fallback(self):
        text = "Running scan...\n[INFO] testing parameter q\nScan complete."
        result = _parse_dalfox_output(text)
        assert result == []

    def test_empty_json_list_returns_empty(self):
        assert _parse_dalfox_output("[]") == []
