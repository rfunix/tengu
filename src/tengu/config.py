"""Configuration management for Tengu.

Parses tengu.toml and environment variables using Pydantic v2.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from tengu.exceptions import ConfigError
from tengu.stealth.config import StealthConfig

logger = structlog.get_logger(__name__)

_DEFAULT_BLOCKED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
    "*.gov",
    "*.mil",
    "*.edu",
]


class ServerConfig(BaseModel):
    name: str = "Tengu"
    log_level: str = "INFO"
    audit_log_path: str = "./logs/tengu-audit.log"


class TargetsConfig(BaseModel):
    allowed_hosts: list[str] = []
    blocked_hosts: list[str] = []

    @field_validator("allowed_hosts", "blocked_hosts", mode="before")
    @classmethod
    def ensure_list(cls, v: Any) -> list[str]:
        if v is None:
            return []
        return list(v)


class ToolPathsConfig(BaseModel):
    nmap: str = ""
    masscan: str = ""
    nuclei: str = ""
    nikto: str = ""
    ffuf: str = ""
    subfinder: str = ""
    sqlmap: str = ""
    dalfox: str = ""
    hydra: str = ""
    john: str = ""
    hashcat: str = ""
    searchsploit: str = ""
    metasploit_rpc: str = "https://127.0.0.1:55553"
    setoolkit: str = ""


class ToolDefaultsConfig(BaseModel):
    nmap_timing: str = "T3"
    nuclei_severity: list[str] = ["medium", "high", "critical"]
    scan_timeout: int = 600
    wordlist_path: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    password_wordlist_path: str = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"


class ToolsConfig(BaseModel):
    paths: ToolPathsConfig = Field(default_factory=ToolPathsConfig)
    defaults: ToolDefaultsConfig = Field(default_factory=ToolDefaultsConfig)


class RateLimitingConfig(BaseModel):
    max_scans_per_minute: int = 10
    max_concurrent_scans: int = 3


class CVEConfig(BaseModel):
    nvd_api_key: str = ""
    cache_path: str = "~/.tengu/cve_cache.db"
    cache_ttl_hours: int = 24


class CloudConfig(BaseModel):
    aws_profile: str = ""
    gcp_project: str = ""
    azure_subscription: str = ""


class OSINTConfig(BaseModel):
    shodan_api_key: str = ""


class TenguConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    rate_limiting: RateLimitingConfig = Field(default_factory=RateLimitingConfig)
    cve: CVEConfig = Field(default_factory=CVEConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    osint: OSINTConfig = Field(default_factory=OSINTConfig)

    @property
    def effective_blocked_hosts(self) -> list[str]:
        """Returns combined default + user-configured blocked hosts.

        Hosts explicitly listed in allowed_hosts are removed from the default
        blocklist, allowing lab/loopback targets (e.g. 127.0.0.1, localhost)
        to be scanned when intentionally permitted via tengu.toml.
        """
        explicitly_allowed = {h.strip().lower() for h in self.targets.allowed_hosts}
        base = [h for h in _DEFAULT_BLOCKED_HOSTS if h not in explicitly_allowed]
        return list(set(base + self.targets.blocked_hosts))


def load_config(config_path: str | Path | None = None) -> TenguConfig:
    """Load configuration from tengu.toml and environment variables.

    Priority: env vars > toml file > defaults.
    """
    if config_path is None:
        config_path = os.environ.get("TENGU_CONFIG_PATH", "./tengu.toml")

    path = Path(config_path).expanduser()

    raw: dict[str, Any] = {}
    if path.exists():
        try:
            with path.open("rb") as f:
                raw = tomllib.load(f)
            logger.info("Configuration loaded", path=str(path))
        except Exception as exc:
            raise ConfigError(f"Failed to parse {path}: {exc}") from exc
    else:
        logger.warning("Configuration file not found, using defaults", path=str(path))

    # Override with environment variables
    if log_level := os.environ.get("TENGU_LOG_LEVEL"):
        raw.setdefault("server", {})["log_level"] = log_level

    if nvd_key := os.environ.get("NVD_API_KEY"):
        raw.setdefault("cve", {})["nvd_api_key"] = nvd_key

    if shodan_key := os.environ.get("TENGU_SHODAN_API_KEY"):
        raw.setdefault("osint", {})["shodan_api_key"] = shodan_key

    if allowed_hosts := os.environ.get("TENGU_ALLOWED_HOSTS"):
        hosts = [h.strip() for h in allowed_hosts.split(",") if h.strip()]
        raw.setdefault("targets", {})["allowed_hosts"] = hosts

    return TenguConfig.model_validate(raw)


# Singleton — loaded once on first import
_config: TenguConfig | None = None


def get_config() -> TenguConfig:
    """Return the global configuration instance (lazy-loaded)."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reset_config() -> None:
    """Reset the singleton (useful for testing)."""
    global _config
    _config = None
