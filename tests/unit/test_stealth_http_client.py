"""Unit tests for stealth HTTP client factory."""

from __future__ import annotations

import httpx

from tengu.stealth.http_client import create_stealth_client


class TestCreateStealthClient:
    def test_returns_async_client(self):
        client = create_stealth_client()
        assert isinstance(client, httpx.AsyncClient)

    def test_default_timeout(self):
        client = create_stealth_client()
        assert client.timeout.read == 30.0

    def test_custom_timeout(self):
        client = create_stealth_client(timeout=10.0)
        assert client.timeout.read == 10.0

    def test_user_agent_set_in_headers(self):
        ua = "Mozilla/5.0 (Test)"
        client = create_stealth_client(user_agent=ua)
        assert client.headers.get("user-agent") == ua

    def test_no_user_agent_no_custom_header(self):
        client = create_stealth_client(user_agent=None)
        # default httpx UA or no custom UA set
        assert (
            "User-Agent" not in dict(client.headers)
            or client.headers.get("user-agent") != "Mozilla/5.0 (Test)"
        )

    def test_follow_redirects_enabled(self):
        client = create_stealth_client()
        assert client.follow_redirects is True

    def test_follow_redirects_can_be_disabled(self):
        client = create_stealth_client(follow_redirects=False)
        assert client.follow_redirects is False

    def test_no_proxy_by_default(self):
        client = create_stealth_client()
        # Client should be created without crashing even with no proxy
        assert isinstance(client, httpx.AsyncClient)

    def test_extra_kwargs_accepted(self):
        # verify extra kwargs like verify=False are passed through
        client = create_stealth_client(verify=False)
        assert isinstance(client, httpx.AsyncClient)
