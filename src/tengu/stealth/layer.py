"""StealthLayer — central OPSEC orchestrator for all stealth features."""

from __future__ import annotations

import shutil
from typing import Any

import httpx
import structlog

from tengu.stealth.config import StealthConfig
from tengu.stealth.http_client import create_stealth_client
from tengu.stealth.timing import TimingController
from tengu.stealth.user_agents import UserAgentRotator

logger = structlog.get_logger(__name__)


class StealthLayer:
    """Orchestrates all stealth/OPSEC features."""

    def __init__(self, config: StealthConfig) -> None:
        self._config = config
        self._ua_rotator: UserAgentRotator | None = None
        self._timing: TimingController | None = None

        if config.enabled and config.user_agent.enabled:
            self._ua_rotator = UserAgentRotator(
                browser_type=config.user_agent.browser_type,
                rotate_every=config.user_agent.rotate_every,
            )

        if config.enabled and config.timing.enabled:
            self._timing = TimingController(
                min_delay_ms=config.timing.min_delay_ms,
                max_delay_ms=config.timing.max_delay_ms,
                jitter_percent=config.timing.jitter_percent,
            )

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def config(self) -> StealthConfig:
        return self._config

    @property
    def proxy_url(self) -> str | None:
        if self._config.enabled and self._config.proxy.enabled:
            return self._config.proxy.url
        return None

    def inject_proxy_flags(self, tool: str, args: list[str]) -> list[str]:
        """Inject proxy flags for tools that support native proxy.

        Supports: nmap, nuclei, ffuf, sqlmap, subfinder, nikto, gobuster,
                  wpscan, hydra, curl, wget

        Returns modified args list (copy, not mutated).
        """
        if not self.proxy_url:
            return args

        proxy = self.proxy_url
        injections: dict[str, list[str]] = {
            "nmap": ["--proxies", proxy],
            "nuclei": ["-proxy", proxy],
            "ffuf": ["-x", proxy],
            "sqlmap": ["--proxy", proxy],
            "subfinder": ["--proxy", proxy],
            "nikto": ["-useproxy", proxy],
            "gobuster": ["--proxy", proxy],
            "wpscan": ["--proxy", proxy],
            "curl": ["--proxy", proxy],
            "wget": [
                "--execute=use_proxy=on",
                f"--execute=http_proxy={proxy}",
            ],
            # v0.3 tools
            "commix": ["--proxy", proxy],
            "feroxbuster": ["--proxy", proxy],
            "wafw00f": ["--proxy", proxy],
        }

        flags = injections.get(tool)
        if flags:
            logger.debug("Injecting proxy flags", tool=tool, proxy=proxy)
            return [args[0]] + flags + args[1:]
        return args

    def get_wrapper_prefix(self) -> list[str]:
        """Return wrapper prefix args (proxychains4 or torsocks) if configured."""
        if not self._config.enabled:
            return []

        mode = self._config.wrapper.mode
        if mode == "proxychains":
            resolved = shutil.which("proxychains4") or shutil.which("proxychains")
            if resolved:
                return [resolved, "-q"]
        elif mode == "torsocks":
            resolved = shutil.which("torsocks")
            if resolved:
                return [resolved]
        return []

    def get_user_agent(self) -> str | None:
        if self._ua_rotator:
            return self._ua_rotator.get()
        return None

    async def wait_if_enabled(self) -> None:
        """Apply timing jitter if timing controller is active."""
        if self._timing:
            await self._timing.wait()

    def create_http_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Create an httpx AsyncClient pre-configured with proxy and UA."""
        return create_stealth_client(
            proxy_url=self.proxy_url,
            user_agent=self.get_user_agent(),
            **kwargs,
        )

    def get_proxy_env(self) -> dict[str, str]:
        """Return environment variables for proxy-aware tools."""
        if not self.proxy_url:
            return {}
        proxy = self.proxy_url
        return {
            "http_proxy": proxy,
            "https_proxy": proxy,
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
        }


# Singleton
_stealth_layer: StealthLayer | None = None


def get_stealth_layer() -> StealthLayer:
    """Return the global StealthLayer instance (lazy-loaded from config)."""
    global _stealth_layer
    if _stealth_layer is None:
        from tengu.config import get_config

        cfg = get_config()
        _stealth_layer = StealthLayer(cfg.stealth)
    return _stealth_layer


def reset_stealth_layer() -> None:
    """Reset the singleton (useful for testing)."""
    global _stealth_layer
    _stealth_layer = None
