"""Unit tests for Trivy container scanner helpers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import InvalidInputError
from tengu.tools.container.trivy import (
    _VALID_SCAN_TYPES,
    _VALID_SEVERITIES,
    _parse_trivy_output,
    _sanitize_docker_image,
)

# ---------------------------------------------------------------------------
# TestSanitizeDockerImage
# ---------------------------------------------------------------------------


class TestSanitizeDockerImage:
    def test_valid_image_name(self):
        assert _sanitize_docker_image("nginx:latest") == "nginx:latest"

    def test_image_with_registry(self):
        assert _sanitize_docker_image("registry.example.com/myapp:1.0") == "registry.example.com/myapp:1.0"

    def test_image_with_digest(self):
        sha = "sha256:" + "a" * 64
        result = _sanitize_docker_image(f"nginx@{sha}")
        assert "nginx" in result

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("")

    def test_spaces_raise(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("nginx latest")

    def test_semicolon_raises(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("nginx;rm -rf /")

    def test_strips_whitespace(self):
        result = _sanitize_docker_image("  nginx:latest  ")
        assert result == "nginx:latest"


# ---------------------------------------------------------------------------
# TestValidScanTypes
# ---------------------------------------------------------------------------


class TestValidScanTypes:
    def test_image_present(self):
        assert "image" in _VALID_SCAN_TYPES

    def test_fs_present(self):
        assert "fs" in _VALID_SCAN_TYPES

    def test_repo_present(self):
        assert "repo" in _VALID_SCAN_TYPES

    def test_all_entries_are_strings(self):
        for scan_type in _VALID_SCAN_TYPES:
            assert isinstance(scan_type, str)


# ---------------------------------------------------------------------------
# TestValidSeverities
# ---------------------------------------------------------------------------


class TestValidSeverities:
    def test_critical_present(self):
        assert "CRITICAL" in _VALID_SEVERITIES

    def test_high_present(self):
        assert "HIGH" in _VALID_SEVERITIES

    def test_all_uppercase(self):
        for sev in _VALID_SEVERITIES:
            assert sev == sev.upper()


# ---------------------------------------------------------------------------
# TestParseTrivyOutput
# ---------------------------------------------------------------------------


def _make_trivy_output(results: list | None = None) -> str:
    return json.dumps({
        "SchemaVersion": 2,
        "Results": results or [],
    })


def _make_vuln(
    vuln_id: str = "CVE-2023-0001",
    pkg: str = "libssl",
    installed: str = "1.1.1",
    fixed: str = "1.1.2",
    severity: str = "HIGH",
    cvss: float | None = 7.5,
) -> dict:
    vuln: dict = {
        "VulnerabilityID": vuln_id,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Description": "Test vulnerability description",
    }
    if cvss is not None:
        vuln["CVSS"] = {"nvd": {"V3Score": cvss}}
    return vuln


def _make_result_entry(
    target: str = "nginx:latest (debian 11.6)",
    vuln_class: str = "os-pkgs",
    vulns: list | None = None,
) -> dict:
    return {
        "Target": target,
        "Class": vuln_class,
        "Type": "debian",
        "Vulnerabilities": vulns or [],
    }


class TestParseTrivyOutput:
    def test_empty_string_returns_defaults(self):
        result = _parse_trivy_output("")
        assert result["total"] == 0
        assert result["results"] == []

    def test_invalid_json_returns_defaults(self):
        result = _parse_trivy_output("not json {{{")
        assert result["total"] == 0

    def test_single_vulnerability(self):
        vuln = _make_vuln()
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["total"] == 1
        assert result["severity_counts"]["HIGH"] == 1

    def test_critical_vulnerability_counted(self):
        vuln = _make_vuln(severity="CRITICAL", cvss=9.8)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["severity_counts"]["CRITICAL"] == 1

    def test_multiple_vulns_total(self):
        vulns = [_make_vuln(vuln_id=f"CVE-{i}") for i in range(5)]
        entry = _make_result_entry(vulns=vulns)
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["total"] == 5

    def test_cvss_score_extracted(self):
        vuln = _make_vuln(cvss=8.1)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["top_vulns"][0]["cvss_score"] == 8.1

    def test_top_vulns_sorted_by_severity(self):
        low_vuln = _make_vuln(severity="LOW", cvss=2.0)
        critical_vuln = _make_vuln(vuln_id="CVE-CRITICAL", severity="CRITICAL", cvss=9.8)
        entry = _make_result_entry(vulns=[low_vuln, critical_vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        # CRITICAL should come first
        assert result["top_vulns"][0]["severity"] == "CRITICAL"

    def test_top_vulns_capped_at_20(self):
        vulns = [_make_vuln(vuln_id=f"CVE-{i}") for i in range(30)]
        entry = _make_result_entry(vulns=vulns)
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert len(result["top_vulns"]) <= 20

    def test_empty_results_array(self):
        output = _make_trivy_output([])
        result = _parse_trivy_output(output)
        assert result["total"] == 0

    def test_unknown_severity_mapped_to_unknown(self):
        vuln = _make_vuln(severity="MADEUP", cvss=None)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["severity_counts"]["UNKNOWN"] >= 1


# ---------------------------------------------------------------------------
# TestTrivyScan — async integration tests
# ---------------------------------------------------------------------------


def _make_trivy_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = 60
    mock_config.return_value = cfg

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    mock_audit.return_value = audit

    rl_ctx = MagicMock()
    rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    rl_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_rl.return_value = rl_ctx

    mock_run.return_value = ("", "", 0)
    return audit


@patch("tengu.tools.container.trivy.sanitize_wordlist_path", side_effect=lambda p: p)
@patch("tengu.tools.container.trivy.rate_limited")
@patch("tengu.tools.container.trivy.resolve_tool_path", return_value="/usr/bin/trivy")
@patch("tengu.tools.container.trivy.get_audit_logger")
@patch("tengu.tools.container.trivy.get_config")
@patch("tengu.tools.container.trivy.run_command", new_callable=AsyncMock)
class TestTrivyScan:
    """Async tests for trivy_scan()."""

    async def test_trivy_image_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='image' passes 'image' subcommand to run_command."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        await trivy_scan(ctx, "nginx:latest", scan_type="image")

        call_args = mock_run.call_args[0][0]
        assert "image" in call_args

    async def test_trivy_repo_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='repo' passes 'repo' subcommand."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        with patch("tengu.security.sanitizer.sanitize_url", side_effect=lambda u: u):
            await trivy_scan(ctx, "https://github.com/test/repo", scan_type="repo")

        call_args = mock_run.call_args[0][0]
        assert "repo" in call_args

    async def test_trivy_filesystem_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='fs' passes 'fs' subcommand."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        await trivy_scan(ctx, "/tmp", scan_type="fs")

        call_args = mock_run.call_args[0][0]
        assert "fs" in call_args

    async def test_trivy_invalid_scan_type(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Invalid scan_type returns error dict without calling run_command."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        result = await trivy_scan(ctx, "nginx:latest", scan_type="invalid")

        assert "error" in result
        mock_run.assert_not_called()

    async def test_trivy_severity_filter(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """severity filter appears in --severity flag."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        await trivy_scan(ctx, "nginx:latest", scan_type="image", severity="HIGH,CRITICAL")

        call_args = mock_run.call_args[0][0]
        assert "--severity" in call_args
        idx = call_args.index("--severity")
        assert "HIGH" in call_args[idx + 1]

    async def test_trivy_output_parsed(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """JSON output is parsed into vulnerability list."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        vuln = _make_vuln(severity="CRITICAL")
        entry = _make_result_entry(vulns=[vuln])
        mock_run.return_value = (_make_trivy_output([entry]), "", 0)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        result = await trivy_scan(ctx, "nginx:latest", scan_type="image")

        assert result["total_vulnerabilities"] == 1

    async def test_trivy_no_vulns(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Empty output → total_vulnerabilities=0."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        mock_run.return_value = ("", "", 0)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        result = await trivy_scan(ctx, "nginx:latest", scan_type="image")

        assert result["total_vulnerabilities"] == 0

    async def test_trivy_tool_key(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Result 'tool' key equals 'trivy'."""
        _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        result = await trivy_scan(ctx, "nginx:latest", scan_type="image")

        assert result["tool"] == "trivy"

    async def test_trivy_audit_logged(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """audit.log_tool_call is called during execution."""
        audit = _setup_trivy_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_trivy_ctx()

        from tengu.tools.container.trivy import trivy_scan

        await trivy_scan(ctx, "nginx:latest", scan_type="image")

        assert audit.log_tool_call.call_count >= 1
