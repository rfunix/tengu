"""Custom exceptions for Tengu."""

from __future__ import annotations


class TenguError(Exception):
    """Base exception for all Tengu errors."""


class TargetNotAllowedError(TenguError):
    """Target is not in the allowlist or is explicitly blocked."""

    def __init__(self, target: str, reason: str = "") -> None:
        self.target = target
        msg = f"Target '{target}' is not allowed"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class ToolNotFoundError(TenguError):
    """External tool not found on the system."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(
            f"Tool '{tool}' not found. Run 'make install-tools' or install it manually."
        )


class ToolExecutionError(TenguError):
    """Error during execution of an external tool."""

    def __init__(self, tool: str, returncode: int, stderr: str = "") -> None:
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"Tool '{tool}' failed with exit code {returncode}: {stderr[:500]}")


class ScanTimeoutError(TenguError):
    """Scan exceeded the configured timeout."""

    def __init__(self, tool: str, timeout: int) -> None:
        self.tool = tool
        self.timeout = timeout
        super().__init__(f"Scan with '{tool}' exceeded timeout of {timeout}s")


class RateLimitError(TenguError):
    """Rate limit reached."""

    def __init__(
        self, message: str = "Rate limit reached. Please wait before making another request."
    ) -> None:
        super().__init__(message)


class InvalidInputError(TenguError):
    """Invalid or potentially malicious input."""

    def __init__(self, field: str, value: str, reason: str = "") -> None:
        self.field = field
        self.value = value
        msg = f"Invalid input for '{field}': '{value}'"
        if reason:
            msg += f" — {reason}"
        super().__init__(msg)


class ConfigError(TenguError):
    """Configuration error."""


class MetasploitConnectionError(TenguError):
    """Error connecting to Metasploit RPC."""

    def __init__(self, host: str, reason: str = "") -> None:
        msg = f"Could not connect to Metasploit RPC at {host}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class ZAPConnectionError(TenguError):
    """Error connecting to OWASP ZAP."""

    def __init__(self, url: str, reason: str = "") -> None:
        msg = f"Could not connect to OWASP ZAP at {url}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)
