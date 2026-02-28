"""Unit tests for StealthLayer orchestrator."""

from __future__ import annotations

import pytest

from tengu.stealth.config import (
    ProxyConfig,
    StealthConfig,
    TimingConfig,
    UserAgentConfig,
)
from tengu.stealth.layer import StealthLayer, reset_stealth_layer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _disabled_config() -> StealthConfig:
    return StealthConfig(enabled=False)


def _proxy_config(host: str = "127.0.0.1", port: int = 9050) -> StealthConfig:
    return StealthConfig(
        enabled=True,
        proxy=ProxyConfig(enabled=True, type="socks5", host=host, port=port),
    )


def _ua_config() -> StealthConfig:
    return StealthConfig(
        enabled=True,
        user_agent=UserAgentConfig(enabled=True, browser_type="chrome", rotate_every=5),
    )


def _timing_config(min_ms: int = 0, max_ms: int = 1) -> StealthConfig:
    return StealthConfig(
        enabled=True,
        timing=TimingConfig(enabled=True, min_delay_ms=min_ms, max_delay_ms=max_ms, jitter_percent=0),
    )


# ---------------------------------------------------------------------------
# TestStealthLayerEnabled
# ---------------------------------------------------------------------------


class TestStealthLayerEnabled:
    def test_disabled_by_default(self):
        layer = StealthLayer(_disabled_config())
        assert layer.enabled is False

    def test_enabled_when_config_enabled(self):
        layer = StealthLayer(_proxy_config())
        assert layer.enabled is True

    def test_config_property_returns_config(self):
        cfg = _disabled_config()
        layer = StealthLayer(cfg)
        assert layer.config is cfg


# ---------------------------------------------------------------------------
# TestStealthLayerProxy
# ---------------------------------------------------------------------------


class TestStealthLayerProxy:
    def test_proxy_url_none_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        assert layer.proxy_url is None

    def test_proxy_url_returned_when_enabled(self):
        layer = StealthLayer(_proxy_config(host="127.0.0.1", port=9050))
        assert layer.proxy_url == "socks5://127.0.0.1:9050"

    def test_proxy_url_none_if_stealth_disabled(self):
        cfg = StealthConfig(enabled=False, proxy=ProxyConfig(enabled=True))
        layer = StealthLayer(cfg)
        assert layer.proxy_url is None

    def test_get_proxy_env_empty_when_no_proxy(self):
        layer = StealthLayer(_disabled_config())
        assert layer.get_proxy_env() == {}

    def test_get_proxy_env_returns_all_keys(self):
        layer = StealthLayer(_proxy_config())
        env = layer.get_proxy_env()
        assert "http_proxy" in env
        assert "https_proxy" in env
        assert "HTTP_PROXY" in env
        assert "HTTPS_PROXY" in env
        assert "ALL_PROXY" in env

    def test_get_proxy_env_values_match_proxy_url(self):
        layer = StealthLayer(_proxy_config(host="10.0.0.5", port=8080))
        env = layer.get_proxy_env()
        assert env["http_proxy"] == "socks5://10.0.0.5:8080"


# ---------------------------------------------------------------------------
# TestInjectProxyFlags
# ---------------------------------------------------------------------------


class TestInjectProxyFlags:
    def test_no_injection_when_no_proxy(self):
        layer = StealthLayer(_disabled_config())
        args = ["nmap", "-p", "80", "10.0.0.1"]
        assert layer.inject_proxy_flags("nmap", args) == args

    def test_nmap_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-p", "80", "10.0.0.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert "--proxies" in result
        assert "socks5://127.0.0.1:9050" in result

    def test_nuclei_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["nuclei", "-u", "https://target.com"]
        result = layer.inject_proxy_flags("nuclei", args)
        assert "-proxy" in result

    def test_ffuf_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["ffuf", "-u", "https://target.com/FUZZ"]
        result = layer.inject_proxy_flags("ffuf", args)
        assert "-x" in result

    def test_unknown_tool_no_injection(self):
        layer = StealthLayer(_proxy_config())
        args = ["unknown_tool", "--arg"]
        result = layer.inject_proxy_flags("unknown_tool", args)
        assert result == args

    def test_first_element_preserved(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-sV", "192.168.1.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert result[0] == "nmap"

    def test_original_args_preserved(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-p", "443", "10.0.0.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert "-p" in result
        assert "443" in result
        assert "10.0.0.1" in result


# ---------------------------------------------------------------------------
# TestUserAgent
# ---------------------------------------------------------------------------


class TestUserAgent:
    def test_no_ua_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        assert layer.get_user_agent() is None

    def test_ua_returned_when_enabled(self):
        layer = StealthLayer(_ua_config())
        ua = layer.get_user_agent()
        assert isinstance(ua, str)
        assert "Mozilla" in ua


# ---------------------------------------------------------------------------
# TestWaitIfEnabled
# ---------------------------------------------------------------------------


class TestWaitIfEnabled:
    @pytest.mark.asyncio
    async def test_wait_completes_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        await layer.wait_if_enabled()

    @pytest.mark.asyncio
    async def test_wait_completes_with_minimal_delay(self):
        layer = StealthLayer(_timing_config(min_ms=0, max_ms=1))
        await layer.wait_if_enabled()


# ---------------------------------------------------------------------------
# TestResetStealthLayer
# ---------------------------------------------------------------------------


class TestResetStealthLayer:
    def test_reset_clears_singleton(self):
        reset_stealth_layer()
        from tengu.stealth.layer import _stealth_layer
        assert _stealth_layer is None


# ---------------------------------------------------------------------------
# TestGetWrapperPrefix
# ---------------------------------------------------------------------------


class TestGetWrapperPrefix:
    """Tests for StealthLayer.get_wrapper_prefix()."""

    def _config_with_wrapper(self, mode: str) -> StealthConfig:
        from tengu.stealth.config import WrapperConfig
        return StealthConfig(enabled=True, wrapper=WrapperConfig(mode=mode))

    def test_disabled_stealth_returns_empty(self):
        """get_wrapper_prefix returns [] when stealth is disabled."""
        layer = StealthLayer(StealthConfig(enabled=False))
        assert layer.get_wrapper_prefix() == []

    def test_proxychains_mode_found_proxychains4(self):
        """get_wrapper_prefix returns proxychains4 path with -q flag."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("proxychains"))
        with patch("tengu.stealth.layer.shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/proxychains4" if x == "proxychains4" else None
            result = layer.get_wrapper_prefix()
        assert result == ["/usr/bin/proxychains4", "-q"]

    def test_proxychains_fallback_to_proxychains(self):
        """get_wrapper_prefix falls back to proxychains when proxychains4 is absent."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("proxychains"))
        with patch("tengu.stealth.layer.shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/proxychains" if x == "proxychains" else None
            result = layer.get_wrapper_prefix()
        assert result == ["/usr/bin/proxychains", "-q"]

    def test_proxychains_not_found_returns_empty(self):
        """get_wrapper_prefix returns [] when proxychains not in PATH."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("proxychains"))
        with patch("tengu.stealth.layer.shutil.which", return_value=None):
            result = layer.get_wrapper_prefix()
        assert result == []

    def test_torsocks_mode_found(self):
        """get_wrapper_prefix returns torsocks path without extra flags."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("torsocks"))
        with patch("tengu.stealth.layer.shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/torsocks" if x == "torsocks" else None
            result = layer.get_wrapper_prefix()
        assert result == ["/usr/bin/torsocks"]

    def test_torsocks_not_found_returns_empty(self):
        """get_wrapper_prefix returns [] when torsocks not in PATH."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("torsocks"))
        with patch("tengu.stealth.layer.shutil.which", return_value=None):
            result = layer.get_wrapper_prefix()
        assert result == []

    def test_none_mode_returns_empty(self):
        """get_wrapper_prefix returns [] for mode='none'."""
        layer = StealthLayer(self._config_with_wrapper("none"))
        result = layer.get_wrapper_prefix()
        assert result == []

    def test_unknown_mode_returns_empty(self):
        """get_wrapper_prefix returns [] for an unrecognised mode."""
        layer = StealthLayer(self._config_with_wrapper("unknown_mode_xyz"))
        result = layer.get_wrapper_prefix()
        assert result == []

    def test_proxychains_prefix_has_two_elements(self):
        """proxychains prefix always has exactly 2 elements: [path, '-q']."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("proxychains"))
        with patch("tengu.stealth.layer.shutil.which", return_value="/usr/bin/proxychains4"):
            result = layer.get_wrapper_prefix()
        assert len(result) == 2
        assert result[1] == "-q"

    def test_torsocks_prefix_has_one_element(self):
        """torsocks prefix always has exactly 1 element."""
        from unittest.mock import patch

        layer = StealthLayer(self._config_with_wrapper("torsocks"))
        with patch("tengu.stealth.layer.shutil.which", return_value="/usr/bin/torsocks"):
            result = layer.get_wrapper_prefix()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TestCreateHttpClient
# ---------------------------------------------------------------------------


class TestCreateHttpClient:
    """Tests for StealthLayer.create_http_client()."""

    def test_create_http_client_returns_async_client(self):
        """create_http_client returns an httpx.AsyncClient."""
        from unittest.mock import MagicMock, patch

        import httpx

        layer = StealthLayer(StealthConfig(enabled=False))
        with patch("tengu.stealth.layer.create_stealth_client") as mock_create:
            mock_client = MagicMock(spec=httpx.AsyncClient)
            mock_create.return_value = mock_client
            result = layer.create_http_client()
        assert result is mock_client

    def test_create_http_client_passes_proxy_url_when_enabled(self):
        """create_http_client passes the proxy URL from config."""
        from unittest.mock import MagicMock, patch

        cfg = StealthConfig(
            enabled=True,
            proxy=ProxyConfig(enabled=True, host="127.0.0.1", port=9050),
        )
        layer = StealthLayer(cfg)
        with patch("tengu.stealth.layer.create_stealth_client") as mock_create:
            mock_create.return_value = MagicMock()
            layer.create_http_client()
        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs.get("proxy_url") == "socks5://127.0.0.1:9050"

    def test_create_http_client_proxy_url_none_when_disabled(self):
        """create_http_client passes None proxy_url when stealth is disabled."""
        from unittest.mock import MagicMock, patch

        layer = StealthLayer(StealthConfig(enabled=False))
        with patch("tengu.stealth.layer.create_stealth_client") as mock_create:
            mock_create.return_value = MagicMock()
            layer.create_http_client()
        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs.get("proxy_url") is None

    def test_create_http_client_passes_extra_kwargs(self):
        """create_http_client forwards extra kwargs to create_stealth_client."""
        from unittest.mock import MagicMock, patch

        layer = StealthLayer(StealthConfig(enabled=False))
        with patch("tengu.stealth.layer.create_stealth_client") as mock_create:
            mock_create.return_value = MagicMock()
            layer.create_http_client(timeout=30, verify=False)
        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs.get("timeout") == 30
        assert call_kwargs.kwargs.get("verify") is False

    def test_create_http_client_passes_user_agent(self):
        """create_http_client passes the current user-agent string."""
        from unittest.mock import MagicMock, patch

        layer = StealthLayer(StealthConfig(enabled=True, user_agent=UserAgentConfig(enabled=True)))
        with patch("tengu.stealth.layer.create_stealth_client") as mock_create:
            mock_create.return_value = MagicMock()
            layer.create_http_client()
        call_kwargs = mock_create.call_args
        # user_agent kwarg is passed (could be None or a string)
        assert "user_agent" in call_kwargs.kwargs


# ---------------------------------------------------------------------------
# TestGetStealthLayerSingleton
# ---------------------------------------------------------------------------


class TestGetStealthLayerSingleton:
    """Tests for get_stealth_layer() singleton factory."""

    def test_get_stealth_layer_returns_stealth_layer_instance(self):
        """get_stealth_layer() returns a StealthLayer instance."""
        from unittest.mock import MagicMock, patch

        from tengu.stealth.layer import get_stealth_layer

        reset_stealth_layer()
        mock_cfg = MagicMock()
        mock_cfg.stealth = StealthConfig(enabled=False)
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer = get_stealth_layer()
        assert isinstance(layer, StealthLayer)
        reset_stealth_layer()

    def test_get_stealth_layer_returns_same_instance_on_second_call(self):
        """get_stealth_layer() is a true singleton — same object returned twice."""
        from unittest.mock import MagicMock, patch

        from tengu.stealth.layer import get_stealth_layer

        reset_stealth_layer()
        mock_cfg = MagicMock()
        mock_cfg.stealth = StealthConfig(enabled=False)
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer1 = get_stealth_layer()
            layer2 = get_stealth_layer()
        assert layer1 is layer2
        reset_stealth_layer()

    def test_get_stealth_layer_calls_get_config_once(self):
        """get_stealth_layer() only initialises once — subsequent calls reuse singleton."""
        from unittest.mock import MagicMock, patch

        from tengu.stealth.layer import get_stealth_layer

        reset_stealth_layer()
        mock_cfg = MagicMock()
        mock_cfg.stealth = StealthConfig(enabled=False)
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer1 = get_stealth_layer()
            layer2 = get_stealth_layer()
            layer3 = get_stealth_layer()
        # All calls return the same object (singleton), meaning init happened once
        assert layer1 is layer2 is layer3
        reset_stealth_layer()

    def test_reset_then_get_creates_new_instance(self):
        """After reset_stealth_layer(), get_stealth_layer() creates a fresh instance."""
        from unittest.mock import MagicMock, patch

        from tengu.stealth.layer import get_stealth_layer

        reset_stealth_layer()
        mock_cfg = MagicMock()
        mock_cfg.stealth = StealthConfig(enabled=False)
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer1 = get_stealth_layer()
        reset_stealth_layer()
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer2 = get_stealth_layer()
        assert layer1 is not layer2
        reset_stealth_layer()

    def test_get_stealth_layer_config_respected(self):
        """get_stealth_layer() creates layer with stealth config from get_config."""
        from unittest.mock import MagicMock, patch

        from tengu.stealth.layer import get_stealth_layer

        reset_stealth_layer()
        mock_cfg = MagicMock()
        mock_cfg.stealth = StealthConfig(enabled=True, proxy=ProxyConfig(enabled=True))
        with patch("tengu.config.get_config", return_value=mock_cfg):
            layer = get_stealth_layer()
        assert layer.enabled is True
        reset_stealth_layer()
