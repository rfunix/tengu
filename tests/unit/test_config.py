"""Unit tests for configuration loading."""

from __future__ import annotations

import tempfile
from pathlib import Path

from tengu.config import load_config, reset_config


class TestConfigLoading:
    def setup_method(self):
        reset_config()

    def test_load_defaults_when_no_file(self):
        cfg = load_config("/nonexistent/path/tengu.toml")
        assert cfg.server.name == "Tengu"
        assert cfg.rate_limiting.max_scans_per_minute == 10

    def test_load_from_toml_file(self):
        toml_content = """
[server]
name = "TestTengu"
log_level = "DEBUG"

[targets]
allowed_hosts = ["test.example.com", "192.168.1.0/24"]
blocked_hosts = ["evil.com"]

[rate_limiting]
max_scans_per_minute = 5
max_concurrent_scans = 2
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            cfg = load_config(f.name)

        assert cfg.server.name == "TestTengu"
        assert cfg.server.log_level == "DEBUG"
        assert "test.example.com" in cfg.targets.allowed_hosts
        assert cfg.rate_limiting.max_scans_per_minute == 5
        Path(f.name).unlink()

    def test_env_var_overrides_config(self, monkeypatch):
        monkeypatch.setenv("TENGU_LOG_LEVEL", "WARNING")
        cfg = load_config("/nonexistent/path.toml")
        assert cfg.server.log_level == "WARNING"

    def test_nvd_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "test_key_123")
        cfg = load_config("/nonexistent/path.toml")
        assert cfg.cve.nvd_api_key == "test_key_123"

    def test_effective_blocked_hosts_includes_defaults(self):
        cfg = load_config("/nonexistent/path.toml")
        blocked = cfg.effective_blocked_hosts
        assert "localhost" in blocked
        assert "127.0.0.1" in blocked
        assert "*.gov" in blocked

    def test_effective_blocked_hosts_merges_user_config(self):
        toml_content = """
[targets]
blocked_hosts = ["myevilsite.com"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            cfg = load_config(f.name)

        blocked = cfg.effective_blocked_hosts
        assert "myevilsite.com" in blocked
        assert "localhost" in blocked  # Default still present
        Path(f.name).unlink()

    def test_effective_blocked_hosts_respects_explicit_allowed(self):
        """Hosts in allowed_hosts should be removed from the default blocklist."""
        toml_content = """
[targets]
allowed_hosts = ["127.0.0.1", "localhost"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            cfg = load_config(f.name)

        blocked = cfg.effective_blocked_hosts
        assert "127.0.0.1" not in blocked
        assert "localhost" not in blocked
        assert "*.gov" in blocked  # Other defaults remain
        Path(f.name).unlink()
