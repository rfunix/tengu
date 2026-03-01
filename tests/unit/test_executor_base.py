"""Unit tests for ToolExecutor abstract base class."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tengu.exceptions import TargetNotAllowedError, ToolNotFoundError
from tengu.executor.base import ToolExecutor
from tengu.security.allowlist import TargetAllowlist
from tengu.security.audit import AuditLogger

# ---------------------------------------------------------------------------
# Concrete test subclass
# ---------------------------------------------------------------------------


class EchoExecutor(ToolExecutor):
    """Minimal concrete subclass for testing ToolExecutor."""

    tool_name = "python3"
    default_timeout = 30

    async def run(self, **kwargs: Any) -> Any:
        return await self._run(
            args=[sys.executable, "-c", "print('hello')"],
            target=kwargs.get("target", "test"),
            params=kwargs,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture
def permissive_allowlist() -> TargetAllowlist:
    return TargetAllowlist(allowed_hosts=[], blocked_hosts=[])


@pytest.fixture
def restrictive_allowlist() -> TargetAllowlist:
    return TargetAllowlist(allowed_hosts=["example.com"], blocked_hosts=["blocked.com"])


@pytest.fixture
def executor(audit_log: Path, permissive_allowlist: TargetAllowlist) -> EchoExecutor:
    with (
        patch("tengu.executor.base.make_allowlist_from_config", return_value=permissive_allowlist),
        patch(
            "tengu.executor.base.get_audit_logger",
            return_value=AuditLogger(audit_log),
        ),
    ):
        return EchoExecutor()


# ---------------------------------------------------------------------------
# TestToolExecutorInit
# ---------------------------------------------------------------------------


class TestToolExecutorInit:
    def test_instantiation_with_mocked_deps(
        self, audit_log: Path, permissive_allowlist: TargetAllowlist
    ):
        with (
            patch(
                "tengu.executor.base.make_allowlist_from_config",
                return_value=permissive_allowlist,
            ),
            patch(
                "tengu.executor.base.get_audit_logger",
                return_value=AuditLogger(audit_log),
            ),
        ):
            ex = EchoExecutor()
            assert ex.tool_name == "python3"
            assert ex.default_timeout == 30

    def test_tool_name_attribute(self, executor: EchoExecutor):
        assert executor.tool_name == "python3"

    def test_default_timeout_attribute(self, executor: EchoExecutor):
        assert executor.default_timeout == 30


# ---------------------------------------------------------------------------
# TestValidateTarget
# ---------------------------------------------------------------------------


class TestValidateTarget:
    def test_allowed_target_does_not_raise(
        self, audit_log: Path, permissive_allowlist: TargetAllowlist
    ):
        with (
            patch(
                "tengu.executor.base.make_allowlist_from_config",
                return_value=permissive_allowlist,
            ),
            patch(
                "tengu.executor.base.get_audit_logger",
                return_value=AuditLogger(audit_log),
            ),
        ):
            ex = EchoExecutor()
            ex._validate_target("192.168.1.1")  # should not raise

    def test_blocked_target_raises(self, audit_log: Path, restrictive_allowlist: TargetAllowlist):
        with (
            patch(
                "tengu.executor.base.make_allowlist_from_config",
                return_value=restrictive_allowlist,
            ),
            patch(
                "tengu.executor.base.get_audit_logger",
                return_value=AuditLogger(audit_log),
            ),
        ):
            ex = EchoExecutor()
            with pytest.raises(TargetNotAllowedError):
                ex._validate_target("blocked.com")

    def test_not_in_allowlist_raises(self, audit_log: Path, restrictive_allowlist: TargetAllowlist):
        with (
            patch(
                "tengu.executor.base.make_allowlist_from_config",
                return_value=restrictive_allowlist,
            ),
            patch(
                "tengu.executor.base.get_audit_logger",
                return_value=AuditLogger(audit_log),
            ),
        ):
            ex = EchoExecutor()
            with pytest.raises(TargetNotAllowedError):
                ex._validate_target("not-in-list.com")


# ---------------------------------------------------------------------------
# TestRun
# ---------------------------------------------------------------------------


class TestRun:
    @pytest.mark.asyncio
    async def test_run_happy_path_returns_output(self, executor: EchoExecutor, audit_log: Path):
        stdout, stderr, rc = await executor._run(
            args=[sys.executable, "-c", "print('hi')"],
            target="localhost",
            params={"test": True},
        )
        assert "hi" in stdout
        assert rc == 0

    @pytest.mark.asyncio
    async def test_run_logs_started_and_completed(self, executor: EchoExecutor, audit_log: Path):
        await executor._run(
            args=[sys.executable, "-c", "pass"],
            target="localhost",
            params={},
        )
        log_lines = audit_log.read_text().strip().split("\n")
        import json as _json

        events = [_json.loads(line)["result"] for line in log_lines if line]
        assert "started" in events
        assert "completed" in events

    @pytest.mark.asyncio
    async def test_run_logs_failed_on_error(self, executor: EchoExecutor, audit_log: Path):
        import json

        with pytest.raises(ToolNotFoundError):
            await executor._run(
                args=["__nonexistent_cmd__"],
                target="localhost",
                params={},
            )
        records = [json.loads(line) for line in audit_log.read_text().strip().split("\n") if line]
        results = [r["result"] for r in records]
        assert "failed" in results

    @pytest.mark.asyncio
    async def test_run_reraises_exception(self, executor: EchoExecutor):
        with pytest.raises(ToolNotFoundError):
            await executor._run(
                args=["__nonexistent_cmd__"],
                target="localhost",
                params={},
            )

    @pytest.mark.asyncio
    async def test_run_uses_default_timeout_when_none(self, executor: EchoExecutor):
        # timeout=None should use executor.default_timeout
        stdout, _, rc = await executor._run(
            args=[sys.executable, "-c", "print('ok')"],
            target="localhost",
            params={},
            timeout=None,
        )
        assert "ok" in stdout

    @pytest.mark.asyncio
    async def test_run_uses_custom_timeout(self, executor: EchoExecutor):
        stdout, _, rc = await executor._run(
            args=[sys.executable, "-c", "print('ok')"],
            target="localhost",
            params={},
            timeout=60,
        )
        assert "ok" in stdout


# ---------------------------------------------------------------------------
# TestResolvePath
# ---------------------------------------------------------------------------


class TestResolvePath:
    def test_resolve_python3_path(self, executor: EchoExecutor):
        path = executor._resolve_path()
        assert "python" in path.lower()

    def test_resolve_configured_path_returned_as_is(self, executor: EchoExecutor):
        path = executor._resolve_path(configured_path="/custom/path/mytool")
        assert path == "/custom/path/mytool"

    def test_resolve_nonexistent_tool_raises(self, audit_log: Path, permissive_allowlist):
        class MissingToolExecutor(ToolExecutor):
            tool_name = "__nonexistent_tool_xyz__"

            async def run(self, **kwargs: Any) -> Any:
                pass

        with (
            patch(
                "tengu.executor.base.make_allowlist_from_config",
                return_value=permissive_allowlist,
            ),
            patch(
                "tengu.executor.base.get_audit_logger",
                return_value=AuditLogger(audit_log),
            ),
        ):
            ex = MissingToolExecutor()
            with pytest.raises(ToolNotFoundError):
                ex._resolve_path()


# ---------------------------------------------------------------------------
# TestRunMethod (the public abstract method)
# ---------------------------------------------------------------------------


class TestRunMethod:
    @pytest.mark.asyncio
    async def test_run_method_invokes_internal_run(self, executor: EchoExecutor):
        # EchoExecutor.run() delegates to _run()
        result = await executor.run(target="localhost")
        stdout, _, rc = result
        assert "hello" in stdout
        assert rc == 0

    def test_cannot_instantiate_abstract_base(self):
        with pytest.raises(TypeError, match="abstract"):
            ToolExecutor()  # type: ignore[abstract]
