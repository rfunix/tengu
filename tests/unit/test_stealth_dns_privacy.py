"""Unit tests for DNS-over-HTTPS privacy resolver."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# TestResolveDoh
# ---------------------------------------------------------------------------


class TestResolveDoh:
    async def test_resolve_doh_success_a_record(self):
        """Mock httpx response with A record answer returns IP list."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Answer": [
                {"type": 1, "data": "93.184.216.34"},
                {"type": 1, "data": "93.184.216.35"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh("example.com", "https://cloudflare-dns.com/dns-query", "A")

        assert "93.184.216.34" in result
        assert "93.184.216.35" in result

    async def test_resolve_doh_success_aaaa_record(self):
        """AAAA record type returns IPv6 list."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Answer": [
                {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh(
                "example.com", "https://cloudflare-dns.com/dns-query", "AAAA"
            )

        assert "2606:2800:220:1:248:1893:25c8:1946" in result

    async def test_resolve_doh_filters_record_type(self):
        """Response with mix of A and AAAA — only type 1 (A) and 28 (AAAA) returned."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        # type 5 = CNAME, type 1 = A
        mock_response.json.return_value = {
            "Answer": [
                {"type": 5, "data": "alias.example.com."},  # CNAME — filtered out
                {"type": 1, "data": "1.2.3.4"},  # A — included
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh("example.com", "https://cloudflare-dns.com/dns-query", "A")

        assert "1.2.3.4" in result
        assert "alias.example.com." not in result

    async def test_resolve_doh_no_answer(self):
        """Response with empty Answer returns empty list."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"Answer": []}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh(
                "nx.example.com", "https://cloudflare-dns.com/dns-query", "A"
            )

        assert result == []

    async def test_resolve_doh_http_exception(self):
        """httpx raises — returns empty list (exception caught)."""
        import httpx

        from tengu.stealth.dns_privacy import resolve_doh

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh("example.com", "https://cloudflare-dns.com/dns-query", "A")

        assert result == []

    async def test_resolve_doh_custom_doh_url(self):
        """Custom doh_url used in request."""
        from tengu.stealth.dns_privacy import resolve_doh

        custom_url = "https://dns.google/resolve"

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"Answer": [{"type": 1, "data": "8.8.8.8"}]}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh("google.com", custom_url, "A")

        # Verify the custom URL was used in the get call
        call_args = mock_client.get.call_args
        assert call_args[0][0] == custom_url or call_args.args[0] == custom_url
        assert "8.8.8.8" in result

    async def test_resolve_doh_missing_answer_key(self):
        """Response missing Answer key returns empty list."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"Status": 0, "TC": False}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh("example.com", "https://cloudflare-dns.com/dns-query", "A")

        assert result == []

    async def test_resolve_doh_result_is_list(self):
        """Always returns a list, even on success."""
        from tengu.stealth.dns_privacy import resolve_doh

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"Answer": [{"type": 1, "data": "10.0.0.1"}]}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("tengu.stealth.dns_privacy.httpx.AsyncClient", return_value=mock_client):
            result = await resolve_doh(
                "internal.example.com", "https://cloudflare-dns.com/dns-query", "A"
            )

        assert isinstance(result, list)
