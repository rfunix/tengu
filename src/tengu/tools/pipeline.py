"""Reusable tool pipeline: sanitize -> allowlist -> stealth -> rate_limit -> audit -> execute.

Eliminates ~20 lines of boilerplate per tool while preserving the full security pipeline.
Tools that need custom behavior can still call individual components directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target
from tengu.stealth import get_stealth_layer

logger = structlog.get_logger(__name__)


class PipelineResult:
    """Result of a tool pipeline execution."""

    __slots__ = ("stdout", "stderr", "returncode", "duration_seconds")

    def __init__(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
        duration_seconds: float,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.duration_seconds = duration_seconds


async def tool_pipeline(
    tool_name: str,
    target: str,
    params: dict[str, Any],
    args: list[str],
    ctx: Context,
    timeout: int | None = None,
    sanitizer: Callable[[str], str] = sanitize_target,
    needs_rate_limit: bool = True,
    stealth_tool_key: str | None = None,
    progress_message: str | None = None,
) -> PipelineResult:
    """Execute the full Tengu security pipeline for an external tool.

    Encapsulates: sanitize -> allowlist -> stealth -> rate_limit -> audit -> execute.

    Args:
        tool_name: Name used for audit logging, rate limiting, and stealth lookup.
        target: Raw target input (IP, hostname, URL, CIDR). Will be sanitized.
        params: Dict of parameters for audit logging (will be redacted automatically).
        args: Command arguments list. The target in args should already be the
              sanitized value (caller builds args after calling their sanitizers).
              Stealth proxy flags are injected automatically.
        ctx: FastMCP Context for progress reporting.
        timeout: Override scan timeout in seconds. Defaults to config scan_timeout.
        sanitizer: Callable to sanitize the target. Defaults to sanitize_target.
                   Pass sanitize_url for URL-based tools. Pass None to skip.
        needs_rate_limit: Whether to apply rate limiting. Default: True.
                          Set to False for analysis/correlation tools.
        stealth_tool_key: Tool key for stealth proxy injection. Defaults to tool_name.
                          Set to None to skip stealth injection entirely.
        progress_message: Custom start message. Defaults to "Starting {tool_name}...".

    Returns:
        PipelineResult with stdout, stderr, returncode, and duration_seconds.

    Raises:
        InvalidInputError: If sanitization fails.
        TargetNotAllowedError: If target is not in the allowlist.
        RateLimitError: If rate limit is exceeded.
        ToolNotFoundError: If the tool binary is not found.
        ScanTimeoutError: If execution exceeds timeout.
    """
    cfg = get_config()
    audit = get_audit_logger()

    # Step 1: Sanitize target
    if sanitizer is not None:
        target = sanitizer(target)

    # Step 2: Allowlist check
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked(tool_name, target, str(exc))
        raise

    # Step 3: Stealth proxy injection
    effective_stealth_key = stealth_tool_key if stealth_tool_key is not None else tool_name
    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url and effective_stealth_key:
        args = stealth.inject_proxy_flags(effective_stealth_key, args)

    # Step 4: Execute with rate limiting + audit
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout
    start_msg = progress_message or f"Starting {tool_name} on {target}..."
    await ctx.report_progress(0, 100, start_msg)

    async def _execute() -> PipelineResult:
        start = time.monotonic()
        await audit.log_tool_call(tool_name, target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            duration = time.monotonic() - start
            await audit.log_tool_call(tool_name, target, params, result="failed", error=str(exc))
            logger.error(
                "Tool execution failed",
                tool=tool_name,
                target=target,
                duration=f"{duration:.2f}s",
                error=str(exc),
            )
            raise

        duration = time.monotonic() - start
        await audit.log_tool_call(
            tool_name, target, params, result="completed", duration_seconds=duration
        )
        return PipelineResult(
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_seconds=round(duration, 2),
        )

    if needs_rate_limit:
        async with rate_limited(tool_name):
            result = await _execute()
    else:
        result = await _execute()

    await ctx.report_progress(100, 100, f"{tool_name} complete")
    return result
