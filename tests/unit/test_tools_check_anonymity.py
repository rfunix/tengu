"""Unit tests for tengu.tools.stealth.check_anonymity."""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.stealth.config import ProxyConfig, StealthConfig
from tengu.stealth.layer import StealthLayer, reset_stealth_layer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _disabled_stealth() -> StealthLayer:
    return StealthLayer(StealthConfig(enabled=False))


def _proxy_stealth() -> StealthLayer:
    return StealthLayer(
        StealthConfig(
            enabled=True,
            proxy=ProxyConfig(enabled=True, type="socks5", host="127.0.0.1", port=9050),
        )
    )


def _make_tor_client(ip: str = "10.0.0.1", is_tor: bool = True, raise_exc=None):
    """Build a mock httpx.AsyncClient that returns a preset Tor-check response."""
    response = MagicMock()
    response.json = MagicMock(return_value={"IP": ip, "IsTor": is_tor})

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    if raise_exc:
        mock_client.get = AsyncMock(side_effect=raise_exc)
    else:
        mock_client.get = AsyncMock(return_value=response)
    return mock_client


# ---------------------------------------------------------------------------
# TestAnonymityLevel
# ---------------------------------------------------------------------------


class TestAnonymityLevel:
    @pytest.mark.asyncio
    async def test_anonymity_high_when_tor_and_no_dns_leak(self):
        """anonymity_level='high' and real_ip_exposed=False when using Tor with no DNS leak."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=True)

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        assert result["anonymity_level"] == "high"
        assert result["real_ip_exposed"] is False

    @pytest.mark.asyncio
    async def test_anonymity_medium_when_stealth_proxy_no_tor(self):
        """anonymity_level='medium' and real_ip_exposed=False when stealth+proxy but not Tor exit."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)
        stealth = _proxy_stealth()

        with (
            patch("tengu.tools.stealth.check_anonymity.get_stealth_layer", return_value=stealth),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        assert result["anonymity_level"] == "medium"
        assert result["real_ip_exposed"] is False

    @pytest.mark.asyncio
    async def test_anonymity_none_when_no_stealth_no_tor(self):
        """anonymity_level='none' and real_ip_exposed=True when no stealth and not Tor."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        assert result["anonymity_level"] == "none"
        assert result["real_ip_exposed"] is True

    @pytest.mark.asyncio
    async def test_anonymity_low_fallback(self):
        """anonymity_level='low' when Tor but DNS leak detected (or stealth but no proxy)."""
        reset_stealth_layer()
        # Tor exit but with a DNS leak — should yield 'low' due to dns_leak_detected
        # dns_leak = bool(dns_servers) and not tor_exit_node => if tor_exit_node but dns leak
        # Actually the condition: tor_exit_node and not dns_leak_detected → high
        # If tor_exit_node and dns_leak_detected → falls to elif stealth+proxy or elif not tor
        # To hit 'low': stealth.enabled=True but proxy_url=None (enabled but no proxy)
        from tengu.stealth.config import StealthConfig
        from tengu.stealth.layer import StealthLayer

        stealth_no_proxy = StealthLayer(StealthConfig(enabled=True))  # enabled but no proxy

        mock_client = _make_tor_client(is_tor=False)

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=stealth_no_proxy,
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        # stealth.enabled=True but no proxy_url → not "none" (stealth.enabled is True)
        # not tor and not (stealth.enabled and proxy_url) → won't be "medium"
        # → falls to "low"
        assert result["anonymity_level"] == "low"


# ---------------------------------------------------------------------------
# TestDnsLeak
# ---------------------------------------------------------------------------


class TestDnsLeak:
    @pytest.mark.asyncio
    async def test_dns_leak_detected_when_dns_servers_and_no_tor(self):
        """dns_leak_detected=True when DNS resolves and not a Tor exit node."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)

        # Simulate DNS resolution returning an IP
        fake_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.socket.getaddrinfo",
                return_value=fake_addr_info,
            ),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        assert result["dns_leak_detected"] is True
        assert len(result["dns_servers_detected"]) > 0

    @pytest.mark.asyncio
    async def test_no_dns_leak_when_no_dns_servers_resolved(self):
        """dns_leak_detected=False when no DNS addresses are resolved."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        assert result["dns_leak_detected"] is False
        assert result["dns_servers_detected"] == []

    @pytest.mark.asyncio
    async def test_no_dns_leak_when_tor_exit_node_even_if_dns_servers(self):
        """dns_leak_detected=False when Tor exit node (leak heuristic uses not tor_exit_node)."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=True)

        fake_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.socket.getaddrinfo",
                return_value=fake_addr_info,
            ),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        # dns_leak = bool(dns_servers) and not tor_exit_node → False because tor_exit_node=True
        assert result["dns_leak_detected"] is False


# ---------------------------------------------------------------------------
# TestRecommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    @pytest.mark.asyncio
    async def test_recommendations_include_tor_when_not_tor(self):
        """Recommendations mention Tor when not a Tor exit node."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        recs = " ".join(result["recommendations"])
        assert "Tor" in recs or "tor" in recs.lower()

    @pytest.mark.asyncio
    async def test_recommendations_include_dns_when_leak(self):
        """Recommendations mention DNS leak when one is detected."""
        reset_stealth_layer()
        mock_client = _make_tor_client(is_tor=False)
        fake_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0))]

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.socket.getaddrinfo",
                return_value=fake_addr_info,
            ),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        recs = " ".join(result["recommendations"])
        assert "DNS" in recs or "dns" in recs.lower()

    @pytest.mark.asyncio
    async def test_returns_correct_structure(self):
        """Result contains all expected keys."""
        reset_stealth_layer()
        mock_client = _make_tor_client()

        with (
            patch(
                "tengu.tools.stealth.check_anonymity.get_stealth_layer",
                return_value=_disabled_stealth(),
            ),
            patch(
                "tengu.tools.stealth.check_anonymity.httpx.AsyncClient", return_value=mock_client
            ),
            patch("tengu.tools.stealth.check_anonymity.socket.getaddrinfo", return_value=[]),
        ):
            from tengu.tools.stealth.check_anonymity import check_anonymity

            result = await check_anonymity()

        expected_keys = {
            "real_ip_exposed",
            "detected_ip",
            "tor_exit_node",
            "dns_leak_detected",
            "dns_servers_detected",
            "anonymity_level",
            "recommendations",
        }
        assert expected_keys.issubset(result.keys())
