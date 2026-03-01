"""Unit tests for checkov_scan: framework validation, ID sanitization, and JSON parsing."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.iac.checkov"


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
    return audit


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_checkov_async(
    ctx, path="/tmp/iac", framework="all", check_ids="", skip_check_ids="", stdout="", returncode=0
):
    """Run checkov_scan under full mock."""
    from tengu.tools.iac.checkov import checkov_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_wordlist_path", return_value=path),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/checkov"),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", returncode))),
    ):
        return await checkov_scan(
            ctx, path, framework=framework, check_ids=check_ids, skip_check_ids=skip_check_ids
        )


def _run_checkov(ctx, **kwargs):
    return asyncio.run(_run_checkov_async(ctx, **kwargs))


# ---------------------------------------------------------------------------
# TestCheckovFrameworkValidation
# ---------------------------------------------------------------------------


class TestCheckovFrameworkValidation:
    def test_invalid_framework_defaults_to_all(self, ctx):
        result = _run_checkov(ctx, framework="bogus_framework")
        assert result["framework"] == "all"

    def test_framework_terraform_preserved(self, ctx):
        result = _run_checkov(ctx, framework="terraform")
        assert result["framework"] == "terraform"

    def test_framework_kubernetes_preserved(self, ctx):
        result = _run_checkov(ctx, framework="kubernetes")
        assert result["framework"] == "kubernetes"

    def test_framework_dockerfile_preserved(self, ctx):
        result = _run_checkov(ctx, framework="dockerfile")
        assert result["framework"] == "dockerfile"

    def test_framework_cloudformation_preserved(self, ctx):
        result = _run_checkov(ctx, framework="cloudformation")
        assert result["framework"] == "cloudformation"

    def test_framework_helm_preserved(self, ctx):
        result = _run_checkov(ctx, framework="helm")
        assert result["framework"] == "helm"


# ---------------------------------------------------------------------------
# TestCheckovFrameworkFlag
# ---------------------------------------------------------------------------


class TestCheckovFrameworkFlag:
    def test_framework_all_no_framework_flag_added(self, ctx):
        result = _run_checkov(ctx, framework="all")
        assert "--framework" not in result["command"]

    def test_framework_specific_adds_flag(self, ctx):
        result = _run_checkov(ctx, framework="terraform")
        assert "--framework terraform" in result["command"]

    def test_framework_kubernetes_adds_flag(self, ctx):
        result = _run_checkov(ctx, framework="kubernetes")
        assert "--framework kubernetes" in result["command"]


# ---------------------------------------------------------------------------
# TestCheckovCheckIdSanitization
# ---------------------------------------------------------------------------


class TestCheckovCheckIdSanitization:
    def test_check_ids_special_chars_stripped(self, ctx):
        result = _run_checkov(ctx, check_ids="CKV_AWS_1;rm -rf /,CKV_AWS_2")
        assert ";" not in result["command"]

    def test_check_ids_valid_format_preserved(self, ctx):
        result = _run_checkov(ctx, check_ids="CKV_AWS_1,CKV_AWS_2")
        assert "CKV_AWS_1,CKV_AWS_2" in result["command"]

    def test_skip_ids_special_chars_stripped(self, ctx):
        result = _run_checkov(ctx, skip_check_ids="CKV_K8S_1;evil")
        assert ";" not in result["command"]

    def test_skip_ids_valid_format_preserved(self, ctx):
        result = _run_checkov(ctx, skip_check_ids="CKV_K8S_1,CKV_K8S_2")
        assert "CKV_K8S_1,CKV_K8S_2" in result["command"]

    def test_empty_check_ids_not_added_to_command(self, ctx):
        result = _run_checkov(ctx, check_ids="")
        assert "--check" not in result["command"]

    def test_empty_skip_ids_not_added_to_command(self, ctx):
        result = _run_checkov(ctx, skip_check_ids="")
        assert "--skip-check" not in result["command"]

    def test_non_empty_check_ids_adds_check_flag(self, ctx):
        result = _run_checkov(ctx, check_ids="CKV_AWS_1")
        assert "--check" in result["command"]

    def test_non_empty_skip_ids_adds_skip_check_flag(self, ctx):
        result = _run_checkov(ctx, skip_check_ids="CKV_AWS_99")
        assert "--skip-check" in result["command"]


# ---------------------------------------------------------------------------
# TestCheckovJsonParsing
# ---------------------------------------------------------------------------


def _make_check(
    check_id: str = "CKV_AWS_1",
    resource: str = "aws_s3_bucket.my_bucket",
    file: str = "/main.tf",
    severity: str = "HIGH",
) -> dict:
    return {
        "check_id": check_id,
        "check_type": "terraform",
        "resource": resource,
        "repo_file_path": file,
        "file_line_range": [1, 10],
        "severity": severity,
        "guideline": f"https://docs.bridgecrew.io/docs/{check_id.lower()}",
    }


class TestCheckovJsonParsing:
    def test_json_dict_with_results_key_parsed(self, ctx):
        data = {
            "results": {
                "passed_checks": [_make_check("CKV_AWS_1"), _make_check("CKV_AWS_2")],
                "failed_checks": [_make_check("CKV_AWS_3")],
            }
        }
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert result["passed"] == 2
        assert result["failed"] == 1

    def test_json_dict_used_directly_when_no_results_key(self, ctx):
        data = {
            "passed_checks": [_make_check("CKV_AWS_1")],
            "failed_checks": [_make_check("CKV_AWS_2"), _make_check("CKV_AWS_3")],
        }
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert result["passed"] == 1
        assert result["failed"] == 2

    def test_json_list_treated_as_failed_checks(self, ctx):
        data = [_make_check("CKV_AWS_1"), _make_check("CKV_AWS_2")]
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert result["failed"] == 2
        assert result["passed"] == 0

    def test_passed_count_extracted(self, ctx):
        data = {
            "passed_checks": [_make_check() for _ in range(5)],
            "failed_checks": [],
        }
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert result["passed"] == 5

    def test_failed_checks_as_findings(self, ctx):
        check = _make_check("CKV_AWS_1", resource="aws_s3_bucket.test", severity="HIGH")
        data = {"failed_checks": [check]}
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["check_id"] == "CKV_AWS_1"
        assert finding["resource"] == "aws_s3_bucket.test"
        assert finding["severity"] == "HIGH"

    def test_finding_has_guideline_field(self, ctx):
        check = _make_check("CKV_AWS_1")
        data = {"failed_checks": [check]}
        result = _run_checkov(ctx, stdout=json.dumps(data))
        assert "guideline" in result["findings"][0]

    def test_invalid_json_gives_empty_findings(self, ctx):
        result = _run_checkov(ctx, stdout="not valid json {{{")
        assert result["passed"] == 0
        assert result["failed"] == 0
        assert result["findings"] == []

    def test_empty_stdout_gives_empty_findings(self, ctx):
        result = _run_checkov(ctx, stdout="")
        assert result["findings"] == []


# ---------------------------------------------------------------------------
# TestCheckovReturnStructure
# ---------------------------------------------------------------------------


class TestCheckovReturnStructure:
    def test_return_keys_present(self, ctx):
        result = _run_checkov(ctx)
        expected_keys = {
            "tool",
            "path",
            "framework",
            "command",
            "duration_seconds",
            "passed",
            "failed",
            "findings",
            "raw_output",
        }
        assert expected_keys.issubset(result.keys())

    def test_tool_name_is_checkov(self, ctx):
        result = _run_checkov(ctx)
        assert result["tool"] == "checkov"

    def test_output_json_flag_in_command(self, ctx):
        result = _run_checkov(ctx)
        assert "--output json" in result["command"]

    def test_no_allowlist_check_performed(self, ctx):
        # checkov scans local paths only — no allowlist import in the module
        import tengu.tools.iac.checkov as mod

        assert not hasattr(mod, "make_allowlist_from_config")
        # Verify that a successful scan returns the tool name without needing allowlist
        result = _run_checkov(ctx)
        assert result["tool"] == "checkov"
