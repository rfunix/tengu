"""Unit tests for the tool_pipeline helper function."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.tools.pipeline import PipelineResult, tool_pipeline


class TestPipelineResult:
    def test_attributes(self) -> None:
        r = PipelineResult(stdout="out", stderr="err", returncode=0, duration_seconds=1.23)
        assert r.stdout == "out"
        assert r.stderr == "err"
        assert r.returncode == 0
        assert r.duration_seconds == 1.23


class TestToolPipeline:
    """Tests for the tool_pipeline() function."""

    @pytest.fixture(autouse=True)
    def _setup_mocks(self, mock_ctx: MagicMock, mock_audit: AsyncMock) -> None:
        self.ctx = mock_ctx
        self.audit = mock_audit
        self.allowlist = MagicMock()
        self.allowlist.check = MagicMock(return_value=None)
        self.stealth = MagicMock()
        self.stealth.enabled = False
        self.stealth.proxy_url = None
        self.stealth.inject_proxy_flags = MagicMock(side_effect=lambda tool, args: args)

    def _patches(self) -> dict[str, MagicMock]:
        return {
            "tengu.tools.pipeline.get_audit_logger": MagicMock(return_value=self.audit),
            "tengu.tools.pipeline.make_allowlist_from_config": MagicMock(
                return_value=self.allowlist
            ),
            "tengu.tools.pipeline.get_stealth_layer": MagicMock(return_value=self.stealth),
            "tengu.tools.pipeline.run_command": AsyncMock(return_value=("output", "", 0)),
        }

    @pytest.mark.asyncio()
    async def test_basic_execution(self) -> None:
        patches = self._patches()
        with (
            patch.dict("tengu.tools.pipeline.__dict__", {}),
            patch(
                "tengu.tools.pipeline.get_audit_logger",
                patches["tengu.tools.pipeline.get_audit_logger"],
            ),
            patch(
                "tengu.tools.pipeline.make_allowlist_from_config",
                patches["tengu.tools.pipeline.make_allowlist_from_config"],
            ),
            patch(
                "tengu.tools.pipeline.get_stealth_layer",
                patches["tengu.tools.pipeline.get_stealth_layer"],
            ),
            patch("tengu.tools.pipeline.run_command", patches["tengu.tools.pipeline.run_command"]),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
            patch("tengu.tools.pipeline.rate_limited") as mock_rl,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600
            # Make rate_limited a no-op async context manager
            mock_rl.return_value.__aenter__ = AsyncMock()
            mock_rl.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await tool_pipeline(
                tool_name="test_tool",
                target="192.168.1.1",
                params={"target": "192.168.1.1"},
                args=["test_tool", "192.168.1.1"],
                ctx=self.ctx,
            )

            assert isinstance(result, PipelineResult)
            assert result.stdout == "output"
            assert result.returncode == 0
            self.allowlist.check.assert_called_once()
            assert self.audit.log_tool_call.call_count >= 2  # started + completed

    @pytest.mark.asyncio()
    async def test_allowlist_blocked(self) -> None:
        self.allowlist.check.side_effect = TargetNotAllowedError("evil.com")

        with (
            patch("tengu.tools.pipeline.get_audit_logger", return_value=self.audit),
            patch("tengu.tools.pipeline.make_allowlist_from_config", return_value=self.allowlist),
            patch("tengu.tools.pipeline.get_stealth_layer", return_value=self.stealth),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600
            with pytest.raises(TargetNotAllowedError):
                await tool_pipeline(
                    tool_name="test_tool",
                    target="evil.com",
                    params={},
                    args=["test_tool", "evil.com"],
                    ctx=self.ctx,
                )

            self.audit.log_target_blocked.assert_called_once()

    @pytest.mark.asyncio()
    async def test_custom_sanitizer(self) -> None:
        custom_sanitizer = MagicMock(return_value="sanitized.com")

        with (
            patch("tengu.tools.pipeline.get_audit_logger", return_value=self.audit),
            patch("tengu.tools.pipeline.make_allowlist_from_config", return_value=self.allowlist),
            patch("tengu.tools.pipeline.get_stealth_layer", return_value=self.stealth),
            patch("tengu.tools.pipeline.run_command", AsyncMock(return_value=("out", "", 0))),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
            patch("tengu.tools.pipeline.rate_limited") as mock_rl,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600
            mock_rl.return_value.__aenter__ = AsyncMock()
            mock_rl.return_value.__aexit__ = AsyncMock(return_value=False)

            await tool_pipeline(
                tool_name="test_tool",
                target="raw.com",
                params={},
                args=["test_tool", "raw.com"],
                ctx=self.ctx,
                sanitizer=custom_sanitizer,
            )

            custom_sanitizer.assert_called_once_with("raw.com")

    @pytest.mark.asyncio()
    async def test_stealth_injection(self) -> None:
        self.stealth.enabled = True
        self.stealth.proxy_url = "socks5://127.0.0.1:9050"
        self.stealth.inject_proxy_flags = MagicMock(
            return_value=["nmap", "--proxies", "socks5://127.0.0.1:9050", "target"]
        )

        with (
            patch("tengu.tools.pipeline.get_audit_logger", return_value=self.audit),
            patch("tengu.tools.pipeline.make_allowlist_from_config", return_value=self.allowlist),
            patch("tengu.tools.pipeline.get_stealth_layer", return_value=self.stealth),
            patch("tengu.tools.pipeline.run_command", AsyncMock(return_value=("out", "", 0))),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
            patch("tengu.tools.pipeline.rate_limited") as mock_rl,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600
            mock_rl.return_value.__aenter__ = AsyncMock()
            mock_rl.return_value.__aexit__ = AsyncMock(return_value=False)

            await tool_pipeline(
                tool_name="nmap",
                target="192.168.1.1",
                params={},
                args=["nmap", "192.168.1.1"],
                ctx=self.ctx,
            )

            self.stealth.inject_proxy_flags.assert_called_once_with("nmap", ["nmap", "192.168.1.1"])

    @pytest.mark.asyncio()
    async def test_no_rate_limit(self) -> None:
        with (
            patch("tengu.tools.pipeline.get_audit_logger", return_value=self.audit),
            patch("tengu.tools.pipeline.make_allowlist_from_config", return_value=self.allowlist),
            patch("tengu.tools.pipeline.get_stealth_layer", return_value=self.stealth),
            patch("tengu.tools.pipeline.run_command", AsyncMock(return_value=("out", "", 0))),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
            patch("tengu.tools.pipeline.rate_limited") as mock_rl,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600

            await tool_pipeline(
                tool_name="correlate",
                target="192.168.1.1",
                params={},
                args=["correlate", "192.168.1.1"],
                ctx=self.ctx,
                needs_rate_limit=False,
            )

            mock_rl.assert_not_called()

    @pytest.mark.asyncio()
    async def test_execution_failure_logs_audit(self) -> None:
        with (
            patch("tengu.tools.pipeline.get_audit_logger", return_value=self.audit),
            patch("tengu.tools.pipeline.make_allowlist_from_config", return_value=self.allowlist),
            patch("tengu.tools.pipeline.get_stealth_layer", return_value=self.stealth),
            patch("tengu.tools.pipeline.run_command", AsyncMock(side_effect=RuntimeError("boom"))),
            patch("tengu.tools.pipeline.get_config") as mock_cfg,
            patch("tengu.tools.pipeline.rate_limited") as mock_rl,
        ):
            mock_cfg.return_value.tools.defaults.scan_timeout = 600
            mock_rl.return_value.__aenter__ = AsyncMock()
            mock_rl.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(RuntimeError, match="boom"):
                await tool_pipeline(
                    tool_name="nmap",
                    target="192.168.1.1",
                    params={},
                    args=["nmap", "192.168.1.1"],
                    ctx=self.ctx,
                )

            # Should have "started" and "failed" audit entries
            calls = self.audit.log_tool_call.call_args_list
            assert any(
                c.kwargs.get("result") == "started" or (len(c.args) >= 4 and c.args[3] == "started")
                for c in calls
            )
            assert any(
                c.kwargs.get("result") == "failed" or (len(c.args) >= 4 and c.args[3] == "failed")
                for c in calls
            )
