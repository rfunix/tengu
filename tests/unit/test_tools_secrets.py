"""Unit tests for secrets scanning parsers: trufflehog and gitleaks."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.secrets.gitleaks import (
    _VALID_REPORT_FORMATS,
    _parse_gitleaks_output,
)
from tengu.tools.secrets.gitleaks import (
    _VALID_SCAN_TYPES as GITLEAKS_SCAN_TYPES,
)
from tengu.tools.secrets.gitleaks import (
    _redact_secret as gitleaks_redact,
)
from tengu.tools.secrets.trufflehog import (
    _VALID_SCAN_TYPES as TRUFFLEHOG_SCAN_TYPES,
)
from tengu.tools.secrets.trufflehog import (
    _parse_trufflehog_output,
)
from tengu.tools.secrets.trufflehog import (
    _redact_secret as trufflehog_redact,
)

# ---------------------------------------------------------------------------
# TestRedactSecretTrufflehog
# ---------------------------------------------------------------------------


class TestRedactSecretTrufflehog:
    def test_short_value_all_stars(self):
        # len <= 6*2=12 → all stars
        assert trufflehog_redact("hello") == "*****"

    def test_short_boundary_all_stars(self):
        assert trufflehog_redact("a" * 12) == "*" * 12

    def test_long_value_shows_prefix_and_suffix(self):
        result = trufflehog_redact("ABCDEF_secret_content_GHIJKL")
        assert result.startswith("ABCDEF")
        assert result.endswith("GHIJKL")
        assert "*" in result

    def test_empty_string(self):
        assert trufflehog_redact("") == ""

    def test_masked_section_capped_at_20_stars(self):
        # For very long secrets, masked section is at most 20 stars
        very_long = "A" * 6 + "secret_that_is_very_very_long_indeed" + "B" * 6
        result = trufflehog_redact(very_long)
        star_section = result[6:-6]
        assert len(star_section) <= 20


# ---------------------------------------------------------------------------
# TestParseTrufflehogOutput
# ---------------------------------------------------------------------------


def _make_trufflehog_line(
    detector: str = "AWS",
    verified: bool = False,
    raw: str = "AKIAIOSFODNN7EXAMPLE",
) -> str:
    return json.dumps({
        "DetectorName": detector,
        "Verified": verified,
        "Raw": raw,
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": "abc123",
                    "file": "config.py",
                    "line": 42,
                }
            }
        },
    })


class TestParseTrufflehogOutput:
    def test_empty_returns_empty(self):
        assert _parse_trufflehog_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_trufflehog_output("  \n\n  ") == []

    def test_invalid_json_skipped(self):
        assert _parse_trufflehog_output("not json\n{broken") == []

    def test_single_finding_parsed(self):
        line = _make_trufflehog_line(detector="AWS", verified=True)
        findings = _parse_trufflehog_output(line)
        assert len(findings) == 1
        assert findings[0]["detector"] == "AWS"

    def test_verified_finding_is_high_severity(self):
        line = _make_trufflehog_line(verified=True)
        findings = _parse_trufflehog_output(line)
        assert findings[0]["verified"] is True
        assert findings[0]["severity"] == "high"

    def test_unverified_finding_is_info_severity(self):
        line = _make_trufflehog_line(verified=False)
        findings = _parse_trufflehog_output(line)
        assert findings[0]["verified"] is False
        assert findings[0]["severity"] == "info"

    def test_secret_is_redacted(self):
        line = _make_trufflehog_line(raw="ABCDEF_very_long_secret_value_XYZ")
        findings = _parse_trufflehog_output(line)
        assert "ABCDEF_very_long_secret_value_XYZ" not in findings[0]["secret_redacted"]
        assert "*" in findings[0]["secret_redacted"]

    def test_camelcase_field_names(self):
        # CamelCase keys (trufflehog v3 output)
        line = json.dumps({
            "DetectorName": "GitHub",
            "Verified": True,
            "Raw": "ghp_" + "x" * 36,
            "SourceMetadata": {"Data": {}},
        })
        findings = _parse_trufflehog_output(line)
        assert findings[0]["detector"] == "GitHub"

    def test_lowercase_field_names(self):
        # Lowercase keys (alternate output format)
        line = json.dumps({
            "detectorName": "Slack",
            "verified": False,
            "raw": "xoxb-slack-token",
            "sourceMetadata": {"data": {}},
        })
        findings = _parse_trufflehog_output(line)
        assert findings[0]["detector"] == "Slack"

    def test_multiple_findings(self):
        lines = "\n".join([_make_trufflehog_line(detector=f"Detector{i}") for i in range(4)])
        findings = _parse_trufflehog_output(lines)
        assert len(findings) == 4

    def test_mixed_valid_and_invalid_lines(self):
        valid_line = _make_trufflehog_line()
        output = f"invalid json\n{valid_line}\n{{broken"
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestRedactSecretGitleaks
# ---------------------------------------------------------------------------


class TestRedactSecretGitleaks:
    def test_short_value_all_stars(self):
        # visible_chars=4, len <= 4*2=8 → all stars
        assert gitleaks_redact("short") == "*****"

    def test_short_boundary_all_stars(self):
        assert gitleaks_redact("a" * 8) == "*" * 8

    def test_long_value_shows_prefix_and_suffix(self):
        result = gitleaks_redact("ABCD_very_secret_value_WXYZ")
        assert result.startswith("ABCD")
        assert result.endswith("WXYZ")

    def test_masked_section_capped_at_16_stars(self):
        very_long = "A" * 4 + "s" * 40 + "B" * 4
        result = gitleaks_redact(very_long)
        star_section = result[4:-4]
        assert len(star_section) <= 16


# ---------------------------------------------------------------------------
# TestParseGitleaksOutput
# ---------------------------------------------------------------------------


def _make_gitleaks_item(
    rule_id: str = "aws-access-token",
    secret: str = "AKIAIOSFODNN7EXAMPLE",
    file_path: str = "config.py",
) -> dict:
    return {
        "RuleID": rule_id,
        "Description": "AWS Access Token",
        "File": file_path,
        "StartLine": 10,
        "Commit": "abc123def456",
        "Author": "dev@example.com",
        "Date": "2024-01-01",
        "Match": f"key={secret}",
        "Secret": secret,
    }


class TestParseGitleaksOutput:
    def test_empty_returns_empty(self):
        assert _parse_gitleaks_output("", "json") == []

    def test_whitespace_returns_empty(self):
        assert _parse_gitleaks_output("   ", "json") == []

    def test_invalid_json_returns_empty(self):
        assert _parse_gitleaks_output("not json", "json") == []

    def test_non_list_json_returns_empty(self):
        assert _parse_gitleaks_output('{"key": "value"}', "json") == []

    def test_valid_finding_parsed(self):
        item = _make_gitleaks_item()
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert len(findings) == 1
        assert findings[0]["rule"] == "aws-access-token"

    def test_secret_is_redacted(self):
        item = _make_gitleaks_item(secret="AKIAIOSFODNN7EXAMPLE_LONG")
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert "AKIAIOSFODNN7EXAMPLE_LONG" not in findings[0]["secret_redacted"]

    def test_severity_always_high(self):
        item = _make_gitleaks_item()
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert findings[0]["severity"] == "high"

    def test_multiple_findings(self):
        items = [_make_gitleaks_item(rule_id=f"rule-{i}") for i in range(3)]
        findings = _parse_gitleaks_output(json.dumps(items), "json")
        assert len(findings) == 3

    def test_lowercase_field_names(self):
        # Alternate lowercase field format
        item = {
            "ruleID": "github-pat",
            "description": "GitHub PAT",
            "file": "app.py",
            "startLine": 5,
            "commit": "deadbeef",
            "secret": "ghp_xxxxxx",
        }
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert len(findings) == 1
        assert findings[0]["rule"] == "github-pat"

    def test_non_dict_items_skipped(self):
        # Array with mix of dict and non-dict items
        output = json.dumps([_make_gitleaks_item(), "invalid", 42])
        findings = _parse_gitleaks_output(output, "json")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestValidScanTypes
# ---------------------------------------------------------------------------


class TestValidScanTypes:
    def test_gitleaks_has_detect(self):
        assert "detect" in GITLEAKS_SCAN_TYPES

    def test_gitleaks_has_dir(self):
        assert "dir" in GITLEAKS_SCAN_TYPES

    def test_trufflehog_has_git(self):
        assert "git" in TRUFFLEHOG_SCAN_TYPES

    def test_trufflehog_has_filesystem(self):
        assert "filesystem" in TRUFFLEHOG_SCAN_TYPES

    def test_gitleaks_report_formats(self):
        assert "json" in _VALID_REPORT_FORMATS
        assert "csv" in _VALID_REPORT_FORMATS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_secrets_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl):
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


def _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl):
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


# ---------------------------------------------------------------------------
# TestTrufflehogScan — async integration tests
# ---------------------------------------------------------------------------


@patch("tengu.tools.secrets.trufflehog.sanitize_wordlist_path", side_effect=lambda p: p)
@patch("tengu.tools.secrets.trufflehog.rate_limited")
@patch("tengu.tools.secrets.trufflehog.resolve_tool_path", return_value="/usr/bin/trufflehog")
@patch("tengu.tools.secrets.trufflehog.get_audit_logger")
@patch("tengu.tools.secrets.trufflehog.get_config")
@patch("tengu.tools.secrets.trufflehog.run_command", new_callable=AsyncMock)
class TestTrufflehogScan:
    """Async tests for trufflehog_scan()."""

    async def test_trufflehog_git_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='git' passes 'git' subcommand to run_command."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        with patch("tengu.tools.secrets.trufflehog.make_allowlist_from_config") as mock_al:
            al = MagicMock()
            al.check = MagicMock()
            mock_al.return_value = al
            await trufflehog_scan(ctx, "https://github.com/test/repo", scan_type="git")

        call_args = mock_run.call_args[0][0]
        assert "git" in call_args

    async def test_trufflehog_github_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='github' passes 'github' subcommand to run_command."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        with patch("tengu.tools.secrets.trufflehog.make_allowlist_from_config") as mock_al:
            al = MagicMock()
            al.check = MagicMock()
            mock_al.return_value = al
            await trufflehog_scan(ctx, "https://github.com/testorg", scan_type="github")

        call_args = mock_run.call_args[0][0]
        assert "github" in call_args

    async def test_trufflehog_filesystem_scan(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='filesystem' passes 'filesystem' subcommand."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

        call_args = mock_run.call_args[0][0]
        assert "filesystem" in call_args

    async def test_trufflehog_invalid_scan_type(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Invalid scan_type returns error dict without calling run_command."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        result = await trufflehog_scan(ctx, "/tmp", scan_type="ftp")

        assert "error" in result
        mock_run.assert_not_called()

    async def test_trufflehog_branch_flag(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Branch provided → --branch flag appears in args."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        with patch("tengu.tools.secrets.trufflehog.make_allowlist_from_config") as mock_al:
            al = MagicMock()
            al.check = MagicMock()
            mock_al.return_value = al
            await trufflehog_scan(ctx, "https://github.com/test/repo", scan_type="git", branch="main")

        call_args = mock_run.call_args[0][0]
        assert "--branch" in call_args

    async def test_trufflehog_output_parsed(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """JSON-line output is parsed into findings list."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        finding = json.dumps({
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {}},
        })
        mock_run.return_value = (finding, "", 0)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        result = await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

        assert result["secrets_found"] == 1
        assert len(result["findings"]) == 1

    async def test_trufflehog_no_secrets(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Empty output → secrets_found=0, findings=[]."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        mock_run.return_value = ("", "", 0)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        result = await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

        assert result["secrets_found"] == 0
        assert result["findings"] == []

    async def test_trufflehog_tool_key(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Result 'tool' key equals 'trufflehog'."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        result = await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

        assert result["tool"] == "trufflehog"

    async def test_trufflehog_audit_logged(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """audit.log_tool_call is called during execution."""
        audit = _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

        assert audit.log_tool_call.call_count >= 1

    async def test_trufflehog_run_error(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """run_command exception propagates."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        mock_run.side_effect = RuntimeError("scan crashed")
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        with pytest.raises(RuntimeError, match="scan crashed"):
            await trufflehog_scan(ctx, "/tmp", scan_type="filesystem")

    async def test_trufflehog_timeout(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Explicit timeout is forwarded to run_command."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.trufflehog import trufflehog_scan

        await trufflehog_scan(ctx, "/tmp", scan_type="filesystem", timeout=300)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("timeout") == 300

    async def test_trufflehog_ssh_url_forbidden_chars(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """SSH git URL with shell metacharacters raises InvalidInputError."""
        _setup_trufflehog_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.exceptions import InvalidInputError
        from tengu.tools.secrets.trufflehog import trufflehog_scan

        with pytest.raises(InvalidInputError):
            await trufflehog_scan(ctx, "git@github.com:org/repo;rm -rf /", scan_type="git")


# ---------------------------------------------------------------------------
# TestGitleaksScan — async integration tests
# ---------------------------------------------------------------------------


@patch("tengu.tools.secrets.gitleaks.sanitize_wordlist_path", side_effect=lambda p: p)
@patch("tengu.tools.secrets.gitleaks.rate_limited")
@patch("tengu.tools.secrets.gitleaks.resolve_tool_path", return_value="/usr/bin/gitleaks")
@patch("tengu.tools.secrets.gitleaks.get_audit_logger")
@patch("tengu.tools.secrets.gitleaks.get_config")
@patch("tengu.tools.secrets.gitleaks.run_command", new_callable=AsyncMock)
class TestGitleaksScan:
    """Async tests for gitleaks_scan()."""

    async def test_gitleaks_invalid_scan_type(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Invalid scan_type returns error dict without calling run_command."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="ftp")

        assert "error" in result
        mock_run.assert_not_called()

    async def test_gitleaks_report_format_json(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """report_format='json' is reflected in result and args."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="detect", report_format="json")

        assert result["report_format"] == "json"
        call_args = mock_run.call_args[0][0]
        assert "--report-format" in call_args
        idx = call_args.index("--report-format")
        assert call_args[idx + 1] == "json"

    async def test_gitleaks_report_format_fallback(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Invalid report_format falls back to 'json'."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="detect", report_format="invalid")

        assert result["report_format"] == "json"

    async def test_gitleaks_detect_subcommand(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """scan_type='detect' passes 'detect' subcommand to run_command."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        await gitleaks_scan(ctx, "/tmp", scan_type="detect")

        call_args = mock_run.call_args[0][0]
        assert "detect" in call_args

    async def test_gitleaks_output_parsed(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Valid JSON output is parsed into findings list."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        item = {
            "RuleID": "aws-access-token",
            "Description": "AWS Token",
            "File": "config.py",
            "StartLine": 10,
            "Commit": "abc123",
            "Author": "dev@example.com",
            "Date": "2024-01-01",
            "Match": "key=AKIA...",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        }
        mock_run.return_value = (json.dumps([item]), "", 0)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="detect")

        assert result["secrets_found"] == 1
        assert len(result["findings"]) == 1

    async def test_gitleaks_no_leaks(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Empty output → secrets_found=0, findings=[]."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        mock_run.return_value = ("", "", 0)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="detect")

        assert result["secrets_found"] == 0
        assert result["findings"] == []

    async def test_gitleaks_tool_key(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Result 'tool' key equals 'gitleaks'."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        result = await gitleaks_scan(ctx, "/tmp", scan_type="detect")

        assert result["tool"] == "gitleaks"

    async def test_gitleaks_audit_logged(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """audit.log_tool_call is called during execution."""
        audit = _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        await gitleaks_scan(ctx, "/tmp", scan_type="detect")

        assert audit.log_tool_call.call_count >= 1

    async def test_gitleaks_run_error(self, mock_run, mock_config, mock_audit, mock_resolve, mock_rl, mock_sanitize):
        """Non-zero exit with exception propagates."""
        _setup_gitleaks_mocks(mock_run, mock_config, mock_audit, mock_rl)
        mock_run.side_effect = RuntimeError("gitleaks failed")
        ctx = _make_secrets_ctx()

        from tengu.tools.secrets.gitleaks import gitleaks_scan

        with pytest.raises(RuntimeError, match="gitleaks failed"):
            await gitleaks_scan(ctx, "/tmp", scan_type="detect")
