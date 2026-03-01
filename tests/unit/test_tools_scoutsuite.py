"""Unit tests for ScoutSuite cloud security scanner helpers."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.cloud.scoutsuite import _VALID_PROVIDERS, _parse_scoutsuite_report

# ---------------------------------------------------------------------------
# TestValidProviders
# ---------------------------------------------------------------------------


class TestValidProviders:
    def test_aws_present(self):
        assert "aws" in _VALID_PROVIDERS

    def test_azure_present(self):
        assert "azure" in _VALID_PROVIDERS

    def test_gcp_present(self):
        assert "gcp" in _VALID_PROVIDERS

    def test_all_lowercase(self):
        for p in _VALID_PROVIDERS:
            assert p == p.lower()

    def test_at_least_three_providers(self):
        assert len(_VALID_PROVIDERS) >= 3


# ---------------------------------------------------------------------------
# TestParseScoutsuiteReport
# ---------------------------------------------------------------------------


def _write_results(tmp_dir: str, data: dict) -> None:
    """Write a fake scoutsuite_results.json to the expected path."""
    report_dir = Path(tmp_dir) / "scoutsuite-report"
    report_dir.mkdir(parents=True, exist_ok=True)
    results_path = report_dir / "scoutsuite_results.json"
    results_path.write_text(json.dumps(data))


class TestParseScoutsuiteReport:
    def test_missing_report_dir_returns_not_parsed(self):
        result = _parse_scoutsuite_report("/nonexistent/path/that/does/not/exist")
        assert result["parsed"] is False
        assert "error" in result

    def test_invalid_json_returns_not_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "scoutsuite-report"
            report_dir.mkdir(parents=True)
            (report_dir / "scoutsuite_results.json").write_text("not json {{{")
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is False
        assert "error" in result

    def test_empty_services_parsed_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, {"services": {}})
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is True
        assert result["total_flagged_items"] == 0
        assert result["top_findings"] == []

    def test_service_with_flagged_finding(self):
        data = {
            "services": {
                "s3": {
                    "findings": {
                        "s3-bucket-public": {
                            "flagged_items": 3,
                            "level": "danger",
                            "description": "S3 bucket publicly accessible",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is True
        assert result["total_flagged_items"] == 3
        assert len(result["top_findings"]) == 1
        assert result["top_findings"][0]["severity"] == "high"

    def test_warning_level_mapped_to_medium(self):
        data = {
            "services": {
                "iam": {
                    "findings": {
                        "iam-no-mfa": {
                            "flagged_items": 2,
                            "level": "warning",
                            "description": "MFA not enabled",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["top_findings"][0]["severity"] == "medium"

    def test_zero_flagged_items_not_included(self):
        data = {
            "services": {
                "ec2": {
                    "findings": {
                        "ec2-clean": {
                            "flagged_items": 0,
                            "level": "danger",
                            "description": "No issues",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["total_flagged_items"] == 0
        assert result["top_findings"] == []

    def test_top_findings_sorted_by_flagged_items(self):
        data = {
            "services": {
                "s3": {
                    "findings": {
                        "small-issue": {
                            "flagged_items": 1,
                            "level": "danger",
                            "description": "Small",
                        },
                        "big-issue": {
                            "flagged_items": 10,
                            "level": "danger",
                            "description": "Big",
                        },
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["top_findings"][0]["flagged_items"] == 10

    def test_multiple_services_total_flagged_summed(self):
        data = {
            "services": {
                "s3": {
                    "findings": {"f1": {"flagged_items": 5, "level": "danger", "description": "A"}}
                },
                "iam": {
                    "findings": {"f2": {"flagged_items": 3, "level": "warning", "description": "B"}}
                },
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["total_flagged_items"] == 8

    def test_top_findings_capped_at_20(self):
        findings = {
            f"finding-{i}": {
                "flagged_items": i + 1,
                "level": "danger",
                "description": f"Issue {i}",
            }
            for i in range(30)
        }
        data = {"services": {"s3": {"findings": findings}}}
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert len(result["top_findings"]) <= 20

    def test_services_summary_includes_service_name(self):
        data = {
            "services": {
                "rds": {
                    "findings": {
                        "rds-public": {
                            "flagged_items": 2,
                            "level": "danger",
                            "description": "RDS public",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert "rds" in result["services"]


# ---------------------------------------------------------------------------
# TestScoutsuiteScan
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_scout_mocks(stdout: str = "", run_raises: Exception | None = None):
    """Build standard mocks for scoutsuite_scan tests."""
    mock_cfg = MagicMock()
    mock_cfg.tools.defaults.scan_timeout = 300

    mock_audit = MagicMock()
    mock_audit.log_tool_call = AsyncMock()

    mock_rl = MagicMock()
    mock_rl.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl.__aexit__ = AsyncMock(return_value=False)

    if run_raises:
        mock_run = AsyncMock(side_effect=run_raises)
    else:
        mock_run = AsyncMock(return_value=(stdout, "", 0))

    return mock_cfg, mock_audit, mock_rl, mock_run


class TestScoutsuiteScan:
    async def test_invalid_provider_returns_error_dict(self, mock_ctx):
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        result = await scoutsuite_scan(mock_ctx, "invalid_cloud")
        assert result["tool"] == "scoutsuite"
        assert "error" in result
        assert "invalid_cloud" in result["error"]

    async def test_invalid_provider_no_run_command_called(self, mock_ctx):
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        mock_run = AsyncMock()
        with patch("tengu.tools.cloud.scoutsuite.run_command", mock_run):
            await scoutsuite_scan(mock_ctx, "not_a_provider")

        mock_run.assert_not_called()

    async def test_valid_provider_aws_builds_correct_args(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            result = await scoutsuite_scan(mock_ctx, "aws")

        assert result["tool"] == "scoutsuite"
        assert result["provider"] == "aws"
        assert "aws" in captured_args
        assert "--no-browser" in captured_args

    async def test_aws_with_profile_adds_profile_flag(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            await scoutsuite_scan(mock_ctx, "aws", profile="myprofile")

        assert "--profile" in captured_args
        assert "myprofile" in captured_args

    async def test_gcp_with_project_adds_project_flag(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            await scoutsuite_scan(mock_ctx, "gcp", project="my-gcp-project")

        assert "--project" in captured_args
        assert "my-gcp-project" in captured_args

    async def test_azure_with_subscription_adds_subscription_flag(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            await scoutsuite_scan(mock_ctx, "azure", subscription="sub-1234")

        assert "--subscription" in captured_args
        assert "sub-1234" in captured_args

    async def test_run_command_exception_propagates(self, mock_ctx):
        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks(
            run_raises=RuntimeError("command failed")
        )
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.cloud.scoutsuite.run_command",
                new_callable=AsyncMock,
                side_effect=RuntimeError("command failed"),
            ),
            pytest.raises(RuntimeError, match="command failed"),
        ):
            await scoutsuite_scan(mock_ctx, "aws")

    async def test_result_keys_present(self, mock_ctx):
        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.cloud.scoutsuite.run_command",
                new_callable=AsyncMock,
                return_value=("", "", 0),
            ),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            result = await scoutsuite_scan(mock_ctx, "aws")

        for key in (
            "tool",
            "provider",
            "report_dir",
            "command",
            "duration_seconds",
            "summary",
            "raw_output_excerpt",
        ):
            assert key in result, f"Missing key: {key}"

    async def test_raw_output_truncated_to_3000_chars(self, mock_ctx):
        long_stdout = "Y" * 6000
        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.cloud.scoutsuite.run_command",
                new_callable=AsyncMock,
                return_value=(long_stdout, "", 0),
            ),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            result = await scoutsuite_scan(mock_ctx, "aws")

        assert len(result["raw_output_excerpt"]) == 3000

    async def test_timeout_override_used(self, mock_ctx):
        captured_kwargs: dict = {}

        async def fake_run(args, **kw):
            captured_kwargs.update(kw)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            await scoutsuite_scan(mock_ctx, "aws", timeout=1800)

        assert captured_kwargs.get("timeout") == 1800

    async def test_aws_without_profile_no_profile_flag(self, mock_ctx):
        captured_args: list = []

        async def fake_run(args, **kw):
            captured_args.extend(args)
            return ("", "", 0)

        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch("tengu.tools.cloud.scoutsuite.run_command", side_effect=fake_run),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            await scoutsuite_scan(mock_ctx, "aws")

        assert "--profile" not in captured_args

    async def test_duration_seconds_in_result(self, mock_ctx):
        mock_cfg, mock_audit, mock_rl, _ = _make_scout_mocks()
        from tengu.tools.cloud.scoutsuite import scoutsuite_scan

        with (
            patch("tengu.tools.cloud.scoutsuite.get_config", return_value=mock_cfg),
            patch("tengu.tools.cloud.scoutsuite.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.cloud.scoutsuite.resolve_tool_path", return_value="scout"),
            patch("tengu.tools.cloud.scoutsuite.rate_limited", return_value=mock_rl),
            patch(
                "tengu.tools.cloud.scoutsuite.run_command",
                new_callable=AsyncMock,
                return_value=("", "", 0),
            ),
            patch(
                "tengu.tools.cloud.scoutsuite._parse_scoutsuite_report",
                return_value={"parsed": False},
            ),
        ):
            result = await scoutsuite_scan(mock_ctx, "gcp")

        assert isinstance(result["duration_seconds"], float | int)
        assert result["duration_seconds"] >= 0
