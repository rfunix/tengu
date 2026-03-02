"""Unit tests for prowler_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.cloud.prowler import _parse_prowler_output

_MOD = "tengu.tools.cloud.prowler"


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
def ctx() -> MagicMock:
    return _make_ctx()


async def _run_prowler(
    ctx: MagicMock,
    provider: str = "aws",
    stdout: str = "",
    returncode: int = 0,
    invalid_provider: bool = False,
) -> dict:  # type: ignore[type-arg]
    from tengu.tools.cloud.prowler import prowler_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 600

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/prowler"),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", returncode))),
        patch("pathlib.Path.mkdir"),
    ):
        return await prowler_scan(ctx, provider if not invalid_provider else "evil_provider")


class TestProwlerScan:
    async def test_returns_tool_key(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx)
        assert result["tool"] == "prowler"

    async def test_invalid_provider_raises(self, ctx: MagicMock) -> None:
        with pytest.raises(ValueError):
            await _run_prowler(ctx, invalid_provider=True)

    async def test_return_keys_present(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx)
        for key in ("tool", "provider", "duration_seconds", "findings_summary", "critical_findings"):
            assert key in result

    async def test_provider_aws(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx, provider="aws")
        assert result["provider"] == "aws"

    async def test_provider_azure(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx, provider="azure")
        assert result["provider"] == "azure"

    async def test_provider_gcp(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx, provider="gcp")
        assert result["provider"] == "gcp"

    async def test_raw_output_excerpt_present(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx, stdout="some output")
        assert "raw_output_excerpt" in result

    async def test_long_output_truncated(self, ctx: MagicMock) -> None:
        long_stdout = "x" * 10000
        result = await _run_prowler(ctx, stdout=long_stdout)
        assert len(result["raw_output_excerpt"]) <= 5000

    async def test_report_dir_in_result(self, ctx: MagicMock) -> None:
        result = await _run_prowler(ctx)
        assert "report_dir" in result


class TestParseProwlerOutput:
    def test_empty_output(self) -> None:
        result = _parse_prowler_output("")
        assert result["counts"]["FAIL"] == 0
        assert result["counts"]["PASS"] == 0

    def test_fail_counted(self) -> None:
        result = _parse_prowler_output("CHECK FAIL S3 bucket public\nCHECK PASS IAM ok\n")
        assert result["counts"]["FAIL"] >= 1
        assert result["counts"]["PASS"] >= 1

    def test_critical_findings_captured(self) -> None:
        result = _parse_prowler_output("CHECK FAIL critical bucket exposed\n")
        assert len(result["critical_findings"]) > 0

    def test_warning_counted(self) -> None:
        result = _parse_prowler_output("CHECK WARNING something might be wrong\n")
        assert result["counts"]["WARNING"] >= 1

    def test_critical_findings_capped_at_20(self) -> None:
        lines = "\n".join(f"CHECK FAIL issue {i}" for i in range(30))
        result = _parse_prowler_output(lines)
        assert len(result["critical_findings"]) <= 20

    def test_counts_keys_present(self) -> None:
        result = _parse_prowler_output("")
        assert set(result["counts"].keys()) == {"FAIL", "PASS", "WARNING", "ERROR"}

    def test_error_line_counted(self) -> None:
        result = _parse_prowler_output("ERROR failed to connect to API\n")
        assert result["counts"]["ERROR"] >= 1
