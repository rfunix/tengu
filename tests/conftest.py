"""Shared test fixtures for Tengu test suite.

Provides commonly used mocks and singleton resets to reduce boilerplate
across 90+ test files. Adoption is incremental — existing tests continue
to work without changes.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from tengu.config import TenguConfig, reset_config
from tengu.stealth.layer import reset_stealth_layer


@pytest.fixture()
def mock_config() -> TenguConfig:
    """Return a default TenguConfig suitable for unit tests.

    The config has no allowed hosts and default tool paths.
    Override specific fields in your test as needed.
    """
    return TenguConfig()


@pytest.fixture()
def mock_ctx() -> MagicMock:
    """Return a mock FastMCP Context with async report_progress."""
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.fixture()
def mock_audit() -> AsyncMock:
    """Return a mock AuditLogger with all async methods mocked.

    Usage:
        def test_something(mock_audit):
            with patch("tengu.security.audit.get_audit_logger", return_value=mock_audit):
                ...
    """
    audit = AsyncMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    audit.log_rate_limit = AsyncMock()
    return audit


@pytest.fixture()
def mock_allowlist() -> MagicMock:
    """Return a mock allowlist that accepts all targets by default.

    Usage:
        def test_something(mock_allowlist):
            with patch("tengu.security.allowlist.make_allowlist_from_config",
                       return_value=mock_allowlist):
                ...
    """
    allowlist = MagicMock()
    allowlist.check = MagicMock(return_value=None)  # accepts everything
    return allowlist


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:  # type: ignore[misc]
    """Reset all global singletons between tests to prevent state leakage."""
    reset_config()
    reset_stealth_layer()
    # Reset audit logger singleton
    import tengu.security.audit as _audit_mod

    _audit_mod._audit_logger = None
    # Reset rate limiter singleton
    import tengu.security.rate_limiter as _rl_mod

    if hasattr(_rl_mod, "_rate_limiter"):
        _rl_mod._rate_limiter = None
