"""Unit tests for subfinder output parser."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

from tengu.tools.recon.subfinder import _parse_subfinder_output

# ---------------------------------------------------------------------------
# TestParseSubfinderOutput
# ---------------------------------------------------------------------------


class TestParseSubfinderOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_subfinder_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_subfinder_output("   \n\n  ") == []

    def test_plain_text_subdomain(self):
        result = _parse_subfinder_output("api.example.com\nwww.example.com")
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_json_format_extracts_host(self):
        line = json.dumps({"host": "mail.example.com", "source": "crtsh"})
        result = _parse_subfinder_output(line)
        assert "mail.example.com" in result

    def test_comment_lines_skipped(self):
        result = _parse_subfinder_output("# comment\napi.example.com")
        assert "api.example.com" in result
        assert "# comment" not in result

    def test_duplicates_deduplicated(self):
        result = _parse_subfinder_output("api.example.com\napi.example.com\napi.example.com")
        assert result.count("api.example.com") == 1

    def test_output_is_sorted(self):
        raw = "z.example.com\na.example.com\nm.example.com"
        result = _parse_subfinder_output(raw)
        assert result == sorted(result)

    def test_plain_hostname_without_dot_skipped(self):
        result = _parse_subfinder_output("localhostname")
        assert "localhostname" not in result

    def test_mixed_json_and_plain(self):
        json_line = json.dumps({"host": "api.example.com"})
        raw = f"{json_line}\nwww.example.com"
        result = _parse_subfinder_output(raw)
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_json_without_host_key_falls_back_to_plain_if_dot(self):
        # JSON line without "host" key shouldn't add anything
        line = json.dumps({"source": "crtsh", "other": "data"})
        result = _parse_subfinder_output(line)
        # The line is parsed as JSON with empty host → skipped
        assert result == []


# ---------------------------------------------------------------------------
# TestSubfinderEnum — integration-style async tests
# ---------------------------------------------------------------------------


@patch("tengu.stealth.get_stealth_layer")
@patch("tengu.tools.recon.subfinder.rate_limited")
@patch("tengu.tools.recon.subfinder.resolve_tool_path", return_value="/usr/bin/subfinder")
@patch("tengu.tools.recon.subfinder.get_audit_logger")
@patch("tengu.tools.recon.subfinder.make_allowlist_from_config")
@patch("tengu.tools.recon.subfinder.get_config")
@patch("tengu.tools.recon.subfinder.run_command", new_callable=AsyncMock)
class TestSubfinderEnum:
    """Async tests for subfinder_enum()."""

    def _setup_mocks(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        # Config
        cfg = MagicMock()
        cfg.tools.paths.subfinder = "/usr/bin/subfinder"
        cfg.tools.defaults.scan_timeout = 60
        mock_config.return_value = cfg

        # Allowlist — permits everything by default
        al = MagicMock()
        al.check = MagicMock()
        mock_allowlist.return_value = al

        # Audit logger
        audit = MagicMock()
        audit.log_tool_call = AsyncMock()
        audit.log_target_blocked = AsyncMock()
        mock_audit.return_value = audit

        # rate_limited context manager
        rl_ctx = MagicMock()
        rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        rl_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_rl.return_value = rl_ctx

        # Stealth disabled
        stealth = MagicMock()
        stealth.enabled = False
        stealth.proxy_url = None
        mock_stealth.return_value = stealth

        # run_command default output
        mock_run.return_value = ("sub1.example.com\nsub2.example.com\n", "", 0)

        return al, audit

    def _make_ctx(self):
        ctx = AsyncMock()
        ctx.report_progress = AsyncMock()
        return ctx

    async def test_subfinder_blocked_domain(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Allowlist rejection propagates as an exception."""
        al, audit = self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        al.check.side_effect = ValueError("domain not allowed")
        ctx = self._make_ctx()

        import pytest

        from tengu.tools.recon.subfinder import subfinder_enum

        with pytest.raises(ValueError, match="domain not allowed"):
            await subfinder_enum(ctx, "evil.com")

    async def test_subfinder_sources_flag(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Sources list is passed as -sources flag."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        await subfinder_enum(ctx, "example.com", sources=["shodan", "virustotal"])

        call_args = mock_run.call_args[0][0]
        assert "-sources" in call_args
        idx = call_args.index("-sources")
        assert "shodan" in call_args[idx + 1]
        assert "virustotal" in call_args[idx + 1]

    async def test_subfinder_no_sources(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """No sources → no -sources flag in args."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        await subfinder_enum(ctx, "example.com", sources=None)

        call_args = mock_run.call_args[0][0]
        assert "-sources" not in call_args

    async def test_subfinder_stealth_proxy(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """When stealth is enabled with a proxy, inject_proxy_flags is called."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        stealth = MagicMock()
        stealth.enabled = True
        stealth.proxy_url = "socks5://127.0.0.1:9050"
        stealth.inject_proxy_flags = MagicMock(
            side_effect=lambda tool, args: args + ["-proxy", "socks5://127.0.0.1:9050"]
        )
        mock_stealth.return_value = stealth

        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        await subfinder_enum(ctx, "example.com")

        stealth.inject_proxy_flags.assert_called_once()

    async def test_subfinder_output_parsed(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Newline-separated subdomains are returned in result."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        mock_run.return_value = ("api.example.com\nwww.example.com\n", "", 0)
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        result = await subfinder_enum(ctx, "example.com")

        assert "api.example.com" in result["subdomains"]
        assert "www.example.com" in result["subdomains"]

    async def test_subfinder_unique_results(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Duplicate subdomains in output are removed."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        mock_run.return_value = ("api.example.com\napi.example.com\napi.example.com\n", "", 0)
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        result = await subfinder_enum(ctx, "example.com")

        assert result["subdomains"].count("api.example.com") == 1

    async def test_subfinder_tool_key(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Result dict has 'tool' key equal to 'subfinder'."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        result = await subfinder_enum(ctx, "example.com")

        assert result["tool"] == "subfinder"

    async def test_subfinder_audit_logged(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """audit.log_tool_call is called at least once."""
        _, audit = self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        await subfinder_enum(ctx, "example.com")

        assert audit.log_tool_call.call_count >= 1

    async def test_subfinder_timeout_passed(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Explicit timeout is forwarded to run_command."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        await subfinder_enum(ctx, "example.com", timeout=120)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("timeout") == 120

    async def test_subfinder_run_error(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """run_command raising an exception is propagated."""
        import pytest

        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        mock_run.side_effect = RuntimeError("process failed")
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        with pytest.raises(RuntimeError, match="process failed"):
            await subfinder_enum(ctx, "example.com")

    async def test_subfinder_count_in_result(
        self, mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
    ):
        """Result 'count' matches the number of discovered subdomains."""
        self._setup_mocks(
            mock_run, mock_config, mock_allowlist, mock_audit, mock_resolve, mock_rl, mock_stealth
        )
        mock_run.return_value = ("a.example.com\nb.example.com\nc.example.com\n", "", 0)
        ctx = self._make_ctx()

        from tengu.tools.recon.subfinder import subfinder_enum

        result = await subfinder_enum(ctx, "example.com")

        assert result["count"] == 3
