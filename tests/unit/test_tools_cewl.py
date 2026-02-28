"""Unit tests for cewl_generate: parameter clamping, output file sanitization, word parsing."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_MOD = "tengu.tools.bruteforce.cewl"


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
    audit.log_target_blocked = AsyncMock()
    return audit


def _make_allowlist_mock(blocked: bool = False) -> MagicMock:
    allowlist = MagicMock()
    if blocked:
        allowlist.check.side_effect = Exception("Target not allowed")
    return allowlist


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_cewl_async(ctx, url="http://example.com", depth=2, min_word_length=6,
                          include_emails=False, output_file="/tmp/cewl_wordlist.txt",
                          stdout="", file_content=None, returncode=0, blocked=False):
    """Run cewl_generate under full mock."""
    from tengu.tools.bruteforce.cewl import cewl_generate

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_url", return_value=url),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/cewl"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=_make_allowlist_mock(blocked)),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, "", returncode))),
        patch(f"{_MOD}.Path") as mock_path_cls,
    ):
        # Configure Path mock for reading word file
        mock_path_instance = MagicMock()
        mock_path_cls.return_value = mock_path_instance
        if file_content is not None:
            mock_path_instance.read_text.return_value = file_content
        else:
            mock_path_instance.read_text.side_effect = OSError("File not found")

        return await cewl_generate(ctx, url, depth=depth, min_word_length=min_word_length,
                                   include_emails=include_emails, output_file=output_file)


def _run_cewl(ctx, **kwargs):
    return asyncio.run(_run_cewl_async(ctx, **kwargs))


# ---------------------------------------------------------------------------
# TestCewlDepthClamping
# ---------------------------------------------------------------------------


class TestCewlDepthClamping:
    def test_depth_clamped_min(self, ctx):
        result = _run_cewl(ctx, depth=0)
        assert result["depth"] == 1

    def test_depth_clamped_max(self, ctx):
        result = _run_cewl(ctx, depth=10)
        assert result["depth"] == 5

    def test_depth_within_range_preserved(self, ctx):
        result = _run_cewl(ctx, depth=3)
        assert result["depth"] == 3


# ---------------------------------------------------------------------------
# TestCewlMinWordLengthClamping
# ---------------------------------------------------------------------------


class TestCewlMinWordLengthClamping:
    def test_min_word_length_clamped_min(self, ctx):
        result = _run_cewl(ctx, min_word_length=1)
        assert result["min_word_length"] == 3

    def test_min_word_length_clamped_max(self, ctx):
        result = _run_cewl(ctx, min_word_length=25)
        assert result["min_word_length"] == 20

    def test_min_word_length_within_range_preserved(self, ctx):
        result = _run_cewl(ctx, min_word_length=8)
        assert result["min_word_length"] == 8


# ---------------------------------------------------------------------------
# TestCewlOutputFileSanitization
# ---------------------------------------------------------------------------


class TestCewlOutputFileSanitization:
    def test_output_file_bad_chars_stripped(self, ctx):
        # Shell chars should be stripped from the output path
        result = _run_cewl(ctx, output_file="/tmp/cewl;rm -rf /.txt")
        assert ";" not in result["wordlist_path"]
        assert " " not in result["wordlist_path"]

    def test_valid_tmp_path_preserved(self, ctx):
        result = _run_cewl(ctx, output_file="/tmp/my_wordlist.txt")
        assert result["wordlist_path"] == "/tmp/my_wordlist.txt"

    def test_non_tmp_prefix_becomes_default(self, ctx):
        result = _run_cewl(ctx, output_file="/var/evil/path.txt")
        assert result["wordlist_path"] == "/tmp/cewl_wordlist.txt"

    def test_empty_output_file_becomes_default(self, ctx):
        result = _run_cewl(ctx, output_file="")
        assert result["wordlist_path"] == "/tmp/cewl_wordlist.txt"


# ---------------------------------------------------------------------------
# TestCewlIncludeEmails
# ---------------------------------------------------------------------------


class TestCewlIncludeEmails:
    def test_include_emails_adds_email_flag(self, ctx):
        result = _run_cewl(ctx, include_emails=True)
        assert "--email" in result["command"]

    def test_no_include_emails_no_email_flag(self, ctx):
        result = _run_cewl(ctx, include_emails=False)
        assert "--email" not in result["command"]


# ---------------------------------------------------------------------------
# TestCewlWordParsing
# ---------------------------------------------------------------------------


class TestCewlWordParsing:
    def test_words_read_from_file(self, ctx):
        file_content = "password\nsecret\nadmin\n"
        result = _run_cewl(ctx, file_content=file_content)
        assert result["words_generated"] == 3
        assert "password" in result["sample_words"]

    def test_fallback_to_stdout_when_file_missing(self, ctx):
        stdout = "wordone\nwordtwo\nwordthree\n"
        result = _run_cewl(ctx, stdout=stdout, file_content=None)
        assert result["words_generated"] == 3
        assert "wordone" in result["sample_words"]

    def test_sample_words_limited_to_20(self, ctx):
        # 30 words in file — sample should be capped at 20
        file_content = "\n".join(f"word{i}" for i in range(30)) + "\n"
        result = _run_cewl(ctx, file_content=file_content)
        assert result["words_generated"] == 30
        assert len(result["sample_words"]) == 20

    def test_empty_lines_in_file_skipped(self, ctx):
        file_content = "word1\n\nword2\n\n\nword3\n"
        result = _run_cewl(ctx, file_content=file_content)
        assert result["words_generated"] == 3


# ---------------------------------------------------------------------------
# TestCewlReturnStructure
# ---------------------------------------------------------------------------


class TestCewlReturnStructure:
    def test_return_keys_present(self, ctx):
        result = _run_cewl(ctx)
        expected_keys = {
            "tool", "url", "depth", "min_word_length",
            "command", "duration_seconds", "words_generated",
            "wordlist_path", "sample_words",
        }
        assert expected_keys.issubset(result.keys())

    def test_tool_name_is_cewl(self, ctx):
        result = _run_cewl(ctx)
        assert result["tool"] == "cewl"

    def test_command_includes_depth_flag(self, ctx):
        result = _run_cewl(ctx, depth=3)
        assert "-d 3" in result["command"]

    def test_command_includes_min_length_flag(self, ctx):
        result = _run_cewl(ctx, min_word_length=5)
        assert "-m 5" in result["command"]


# ---------------------------------------------------------------------------
# TestCewlAllowlist
# ---------------------------------------------------------------------------


class TestCewlAllowlist:
    async def test_allowlist_blocked_raises(self, ctx):
        from tengu.tools.bruteforce.cewl import cewl_generate

        audit_mock = _make_audit_mock()
        cfg_mock = MagicMock()
        cfg_mock.tools.defaults.scan_timeout = 300

        blocked_allowlist = _make_allowlist_mock(blocked=True)
        raised = False
        try:
            with (
                patch(f"{_MOD}.get_config", return_value=cfg_mock),
                patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
                patch(f"{_MOD}.sanitize_url", return_value="http://blocked.com"),
                patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/cewl"),
                patch(f"{_MOD}.make_allowlist_from_config", return_value=blocked_allowlist),
            ):
                await cewl_generate(ctx, "http://blocked.com")
        except Exception:
            raised = True
        assert raised, "Expected an exception when target is blocked"
