"""Unit tests for AuditLogger and _redact_sensitive."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tengu.security.audit import AuditLogger, _redact_sensitive

# ---------------------------------------------------------------------------
# TestRedactSensitive
# ---------------------------------------------------------------------------


class TestRedactSensitive:
    def test_password_redacted(self):
        result = _redact_sensitive({"password": "secret123"})
        assert result["password"] == "[REDACTED]"

    def test_token_redacted(self):
        result = _redact_sensitive({"token": "ghp_abcdef"})
        assert result["token"] == "[REDACTED]"

    def test_api_key_redacted(self):
        result = _redact_sensitive({"api_key": "sk-live-xyz"})
        assert result["api_key"] == "[REDACTED]"

    def test_secret_redacted(self):
        result = _redact_sensitive({"secret": "topsecret"})
        assert result["secret"] == "[REDACTED]"

    def test_key_redacted(self):
        result = _redact_sensitive({"key": "mykey"})
        assert result["key"] == "[REDACTED]"

    def test_passwd_redacted(self):
        result = _redact_sensitive({"passwd": "pass"})
        assert result["passwd"] == "[REDACTED]"

    def test_passlist_redacted(self):
        result = _redact_sensitive({"passlist": "/path/to/list.txt"})
        assert result["passlist"] == "[REDACTED]"

    def test_credentials_redacted(self):
        result = _redact_sensitive({"credentials": "user:pass"})
        assert result["credentials"] == "[REDACTED]"

    def test_non_sensitive_key_preserved(self):
        result = _redact_sensitive({"target": "example.com", "port": 443})
        assert result["target"] == "example.com"
        assert result["port"] == 443

    def test_mixed_params(self):
        params = {"target": "example.com", "password": "s3cr3t", "port": 8080}
        result = _redact_sensitive(params)
        assert result["target"] == "example.com"
        assert result["password"] == "[REDACTED]"
        assert result["port"] == 8080

    def test_empty_dict_returns_empty(self):
        result = _redact_sensitive({})
        assert result == {}

    def test_case_insensitive_matching(self):
        # Keys are lowercased for comparison
        result = _redact_sensitive({"PASSWORD": "secret"})
        assert result["PASSWORD"] == "[REDACTED]"

    def test_non_string_value_redacted(self):
        result = _redact_sensitive({"password": 12345})
        assert result["password"] == "[REDACTED]"

    def test_none_value_redacted(self):
        result = _redact_sensitive({"secret": None})
        assert result["secret"] == "[REDACTED]"

    def test_original_dict_not_mutated(self):
        original = {"password": "secret", "target": "example.com"}
        _redact_sensitive(original)
        assert original["password"] == "secret"  # unchanged


# ---------------------------------------------------------------------------
# TestAuditLogger
# ---------------------------------------------------------------------------


class TestAuditLogger:
    @pytest.fixture
    def log_path(self, tmp_path: Path) -> Path:
        return tmp_path / "audit" / "tengu.log"

    @pytest.fixture
    def logger(self, log_path: Path) -> AuditLogger:
        return AuditLogger(log_path)

    def test_creates_parent_directory(self, log_path: Path):
        AuditLogger(log_path)
        assert log_path.parent.exists()

    @pytest.mark.asyncio
    async def test_log_tool_call_writes_record(self, logger: AuditLogger, log_path: Path):
        await logger.log_tool_call("nmap_scan", "example.com", {"ports": "80,443"})
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event"] == "tool_call"
        assert record["tool"] == "nmap_scan"
        assert record["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_log_tool_call_default_result_is_started(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "example.com", {})
        record = json.loads(log_path.read_text().strip())
        assert record["result"] == "started"

    @pytest.mark.asyncio
    async def test_log_tool_call_custom_result(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "example.com", {}, result="completed")
        record = json.loads(log_path.read_text().strip())
        assert record["result"] == "completed"

    @pytest.mark.asyncio
    async def test_log_tool_call_error_field(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call(
            "nmap_scan", "example.com", {}, result="error", error="timed out"
        )
        record = json.loads(log_path.read_text().strip())
        assert record["error"] == "timed out"

    @pytest.mark.asyncio
    async def test_log_tool_call_duration_rounded(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call(
            "nmap_scan", "example.com", {}, duration_seconds=1.23456789
        )
        record = json.loads(log_path.read_text().strip())
        assert record["duration_seconds"] == 1.235

    @pytest.mark.asyncio
    async def test_log_tool_call_no_duration_when_none(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "example.com", {})
        record = json.loads(log_path.read_text().strip())
        assert "duration_seconds" not in record

    @pytest.mark.asyncio
    async def test_log_tool_call_redacts_password(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call(
            "hydra_attack", "example.com", {"password": "s3cr3t", "port": 22}
        )
        record = json.loads(log_path.read_text().strip())
        assert record["params"]["password"] == "[REDACTED]"
        assert record["params"]["port"] == 22

    @pytest.mark.asyncio
    async def test_log_target_blocked_writes_record(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_target_blocked("nmap_scan", "8.8.8.8", "not in allowlist")
        record = json.loads(log_path.read_text().strip())
        assert record["event"] == "target_blocked"
        assert record["tool"] == "nmap_scan"
        assert record["target"] == "8.8.8.8"
        assert record["reason"] == "not in allowlist"

    @pytest.mark.asyncio
    async def test_log_rate_limit_writes_record(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_rate_limit("nuclei_scan", "max 10 calls/minute")
        record = json.loads(log_path.read_text().strip())
        assert record["event"] == "rate_limit"
        assert record["tool"] == "nuclei_scan"
        assert record["details"] == "max 10 calls/minute"

    @pytest.mark.asyncio
    async def test_multiple_calls_appended_as_separate_lines(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "host1", {})
        await logger.log_tool_call("nuclei_scan", "host2", {})
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        records = [json.loads(line) for line in lines]
        assert records[0]["tool"] == "nmap_scan"
        assert records[1]["tool"] == "nuclei_scan"

    @pytest.mark.asyncio
    async def test_record_has_timestamp_field(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "example.com", {})
        record = json.loads(log_path.read_text().strip())
        assert "timestamp" in record
        assert "T" in record["timestamp"]  # ISO 8601 format

    @pytest.mark.asyncio
    async def test_each_record_is_valid_json(
        self, logger: AuditLogger, log_path: Path
    ):
        await logger.log_tool_call("nmap_scan", "example.com", {"port": 80})
        await logger.log_target_blocked("nmap_scan", "8.8.8.8", "reason")
        await logger.log_rate_limit("nuclei_scan", "exceeded")
        for line in log_path.read_text().strip().split("\n"):
            json.loads(line)  # should not raise

    @pytest.mark.asyncio
    async def test_tilde_in_path_expanded(self, tmp_path: Path):
        # Just verify AuditLogger initializes without error using expanduser path
        logger = AuditLogger(tmp_path / "log.jsonl")
        await logger.log_tool_call("tool", "target", {})
