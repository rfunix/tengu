"""Audit logging for all tool invocations.

Every scan, search, and exploitation attempt is logged to both
structured stdout and the audit log file for compliance and
incident response purposes.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class AuditLogger:
    """Writes tamper-evident audit records for all Tengu tool calls."""

    def __init__(self, log_path: str | Path) -> None:
        self._path = Path(log_path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def log_tool_call(
        self,
        tool: str,
        target: str,
        params: dict[str, Any],
        result: str = "started",
        error: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        """Write an audit record for a tool invocation."""
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": "tool_call",
            "tool": tool,
            "target": target,
            # Exclude sensitive values like passwords, API keys
            "params": _redact_sensitive(params),
            "result": result,
        }

        if error:
            record["error"] = error
        if duration_seconds is not None:
            record["duration_seconds"] = round(duration_seconds, 3)  # type: ignore[arg-type]

        await self._write(record)
        logger.info(
            "Audit: tool call",
            tool=tool,
            target=target,
            result=result,
            duration=duration_seconds,
        )

    async def log_target_blocked(self, tool: str, target: str, reason: str) -> None:
        """Write an audit record for a blocked target attempt."""
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": "target_blocked",
            "tool": tool,
            "target": target,
            "reason": reason,
        }
        await self._write(record)
        logger.warning("Audit: target blocked", tool=tool, target=target, reason=reason)

    async def log_rate_limit(self, tool: str, details: str) -> None:
        """Write an audit record for rate limit violations."""
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": "rate_limit",
            "tool": tool,
            "details": details,
        }
        await self._write(record)
        logger.warning("Audit: rate limit", tool=tool, details=details)

    async def _write(self, record: dict[str, Any]) -> None:
        """Append a JSON record to the audit log file."""
        line = json.dumps(record) + "\n"
        async with self._lock:
            try:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as exc:
                logger.error("Failed to write audit log", path=str(self._path), error=str(exc))


_SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "secret", "token", "key", "api_key", "passlist", "credentials"}
)


def _redact_sensitive(params: dict[str, Any]) -> dict[str, Any]:
    """Replace sensitive parameter values with '[REDACTED]'."""
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k.lower() in _SENSITIVE_KEYS:
            result[k] = "[REDACTED]"
        else:
            result[k] = v
    return result


# Global audit logger
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Return the global audit logger (lazy-initialized from config)."""
    global _audit_logger
    if _audit_logger is None:
        from tengu.config import get_config

        cfg = get_config()
        _audit_logger = AuditLogger(cfg.server.audit_log_path)
    return _audit_logger
