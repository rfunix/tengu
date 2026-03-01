"""Unit tests for stealth tools: proxy_check and constants."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from tengu.tools.stealth.proxy_check import _ALLOWED_SCHEMES

# ---------------------------------------------------------------------------
# TestProxyCheck — async integration-style unit tests
# ---------------------------------------------------------------------------


class TestProxyCheck:
    async def test_proxy_check_invalid_scheme(self):
        """proxy_url with ftp:// scheme returns error in result."""
        from tengu.tools.stealth.proxy_check import proxy_check

        result = await proxy_check("ftp://proxy.example.com:21")

        assert result["reachable"] is False
        assert "error" in result
        assert "Invalid proxy scheme" in result["error"]

    async def test_proxy_check_socks5_valid(self):
        """socks5:// scheme is accepted (no scheme error)."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "1.2.3.4"}

        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {"headers": {}}

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("socks5://127.0.0.1:9050")

        assert "error" not in result or result.get("error") is None

    async def test_proxy_check_http_valid(self):
        """http:// scheme is accepted."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "5.5.5.5"}

        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {"headers": {}}

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("http://proxy.example.com:3128")

        assert result["proxy_url"] == "http://proxy.example.com:3128"
        assert "error" not in result or result.get("error") is None

    async def test_proxy_check_connection_error(self):
        """httpx raises ConnectError — result has reachable=False."""
        import httpx

        from tengu.tools.stealth.proxy_check import proxy_check

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("http://dead-proxy.example.com:9999")

        assert result["reachable"] is False

    async def test_proxy_check_anonymous_proxy(self):
        """Response headers don't reveal real IP — anonymity_level='anonymous' or 'elite'."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "5.5.5.5"}

        # No proxy-revealing headers
        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {"headers": {"Host": "httpbin.org"}}

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("socks5://127.0.0.1:9050")

        assert result["anonymity_level"] in ("anonymous", "elite")

    async def test_proxy_check_transparent_proxy(self):
        """Response includes X-Forwarded-For — anonymity_level='transparent'."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "1.2.3.4"}

        # Proxy-revealing header present
        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {
            "headers": {"X-Forwarded-For": "192.168.1.1", "Host": "httpbin.org"}
        }

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 404  # HTTPS fails — stays transparent

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("http://transparent-proxy.example.com:3128")

        assert result["anonymity_level"] == "transparent"

    async def test_proxy_check_latency_measured(self):
        """Latency is measured when connection is successful."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "9.9.9.9"}

        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {"headers": {}}

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("http://fast-proxy.example.com:8080")

        assert result["latency_ms"] is not None
        assert result["latency_ms"] >= 0

    async def test_proxy_check_tool_key(self):
        """Result always has proxy_url key."""
        from tengu.tools.stealth.proxy_check import proxy_check

        result = await proxy_check("ftp://invalid.scheme.com")

        assert "proxy_url" in result
        assert result["proxy_url"] == "ftp://invalid.scheme.com"

    async def test_proxy_check_successful_connection(self):
        """Valid response sets reachable=True."""
        from tengu.tools.stealth.proxy_check import proxy_check

        mock_resp_ip = MagicMock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {"origin": "203.0.113.1"}

        mock_resp_headers = MagicMock()
        mock_resp_headers.json.return_value = {"headers": {}}

        mock_resp_https = MagicMock()
        mock_resp_https.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_resp_ip, mock_resp_headers, mock_resp_https])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.tools.stealth.proxy_check.httpx.AsyncClient", return_value=mock_client):
            result = await proxy_check("http://working-proxy.example.com:8080")

        assert result["reachable"] is True
        assert result["exit_ip"] == "203.0.113.1"


# ---------------------------------------------------------------------------
# TestAllowedSchemes
# ---------------------------------------------------------------------------


class TestAllowedSchemes:
    def test_socks5_present(self):
        assert "socks5://" in _ALLOWED_SCHEMES

    def test_socks4_present(self):
        assert "socks4://" in _ALLOWED_SCHEMES

    def test_http_present(self):
        assert "http://" in _ALLOWED_SCHEMES

    def test_https_present(self):
        assert "https://" in _ALLOWED_SCHEMES

    def test_is_tuple_or_list(self):
        assert isinstance(_ALLOWED_SCHEMES, (tuple, list, frozenset, set))

    def test_at_least_four_schemes(self):
        assert len(_ALLOWED_SCHEMES) >= 4

    def test_all_end_with_double_slash(self):
        for scheme in _ALLOWED_SCHEMES:
            assert scheme.endswith("://"), f"{scheme!r} does not end with ://"

    def test_invalid_scheme_not_present(self):
        assert "ftp://" not in _ALLOWED_SCHEMES
