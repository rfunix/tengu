"""Unit tests for tengu.tools.stealth.tor_check."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.stealth.config import ProxyConfig, StealthConfig
from tengu.stealth.layer import StealthLayer, reset_stealth_layer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_http_client(ipify_json=None, tor_json=None, ipify_error=None, tor_error=None):
    """Build a mock httpx.AsyncClient that returns preset responses.

    The client is called as an async context manager twice — once without
    proxy (real IP check) and once with proxy (Tor exit check).
    """
    real_ip_response = MagicMock()
    real_ip_response.json = MagicMock(return_value=ipify_json or {"ip": "1.2.3.4"})

    tor_response = MagicMock()
    tor_response.json = MagicMock(return_value=tor_json or {"IP": "10.0.0.1", "IsTor": True})

    def make_client(proxy=None, timeout=None):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        if proxy is None:
            # Real IP client
            if ipify_error:
                mock_client.get = AsyncMock(side_effect=ipify_error)
            else:
                mock_client.get = AsyncMock(return_value=real_ip_response)
        else:
            # Tor exit client
            if tor_error:
                mock_client.get = AsyncMock(side_effect=tor_error)
            else:
                mock_client.get = AsyncMock(return_value=tor_response)

        return mock_client

    return make_client


def _disabled_stealth() -> StealthLayer:
    return StealthLayer(StealthConfig(enabled=False))


def _proxy_stealth(proxy_url: str = "socks5://127.0.0.1:9050") -> StealthLayer:
    host, port_str = proxy_url.split("://")[1].rsplit(":", 1)
    return StealthLayer(
        StealthConfig(
            enabled=True,
            proxy=ProxyConfig(enabled=True, type="socks5", host=host, port=int(port_str)),
        )
    )


# ---------------------------------------------------------------------------
# TestTorCheckConnected
# ---------------------------------------------------------------------------


class TestTorCheckConnected:
    @pytest.mark.asyncio
    async def test_tor_connected_true_when_istor_true(self):
        """tor_connected=True when check.torproject.org returns IsTor=True."""
        reset_stealth_layer()
        make_client = _make_http_client(tor_json={"IP": "10.0.0.1", "IsTor": True})

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["tor_connected"] is True
        assert result["exit_ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_tor_connected_false_when_istor_false(self):
        """tor_connected=False when check.torproject.org returns IsTor=False."""
        reset_stealth_layer()
        make_client = _make_http_client(tor_json={"IP": "5.6.7.8", "IsTor": False})

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["tor_connected"] is False

    @pytest.mark.asyncio
    async def test_real_ip_fetched_from_ipify(self):
        """real_ip is populated from api.ipify.org response."""
        reset_stealth_layer()
        make_client = _make_http_client(ipify_json={"ip": "203.0.113.1"})

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["real_ip"] == "203.0.113.1"

    @pytest.mark.asyncio
    async def test_real_ip_is_unknown_on_failure(self):
        """real_ip='unknown' when the ipify request raises an exception."""
        reset_stealth_layer()
        make_client = _make_http_client(ipify_error=Exception("connection error"))

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["real_ip"] == "unknown"

    @pytest.mark.asyncio
    async def test_exit_ip_none_on_tor_failure(self):
        """exit_ip=None and tor_connected=False when Tor check raises."""
        reset_stealth_layer()
        make_client = _make_http_client(tor_error=Exception("SOCKS error"))

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["exit_ip"] is None
        assert result["tor_connected"] is False


# ---------------------------------------------------------------------------
# TestTorCheckProxyUrl
# ---------------------------------------------------------------------------


class TestTorCheckProxyUrl:
    @pytest.mark.asyncio
    async def test_uses_stealth_proxy_url_when_set(self):
        """When stealth has a proxy_url, that URL is used and returned."""
        reset_stealth_layer()
        stealth = _proxy_stealth("socks5://127.0.0.1:9050")
        make_client = _make_http_client()

        with (
            patch("tengu.tools.stealth.tor_check.get_stealth_layer", return_value=stealth),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["proxy_url"] == "socks5://127.0.0.1:9050"

    @pytest.mark.asyncio
    async def test_default_proxy_url_when_no_stealth(self):
        """When stealth has no proxy_url, default socks5://127.0.0.1:9050 is used."""
        reset_stealth_layer()
        stealth = _disabled_stealth()
        make_client = _make_http_client()

        with (
            patch("tengu.tools.stealth.tor_check.get_stealth_layer", return_value=stealth),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert result["proxy_url"] == "socks5://127.0.0.1:9050"

    @pytest.mark.asyncio
    async def test_result_has_expected_keys(self):
        """Result always contains all expected keys."""
        reset_stealth_layer()
        make_client = _make_http_client()

        with (
            patch(
                "tengu.tools.stealth.tor_check.get_stealth_layer", return_value=_disabled_stealth()
            ),
            patch("tengu.tools.stealth.tor_check.httpx.AsyncClient", side_effect=make_client),
        ):
            from tengu.tools.stealth.tor_check import tor_check

            result = await tor_check()

        assert "tor_connected" in result
        assert "exit_ip" in result
        assert "exit_country" in result
        assert "real_ip" in result
        assert "proxy_url" in result
