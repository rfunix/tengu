"""Unit tests for the shodan_lookup async tool."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.osint.shodan"


def _make_fixtures(*, allowlist_raises=False, api_key="test-api-key"):
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()

    cfg = MagicMock()
    cfg.osint.shodan_api_key = api_key

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()

    allowlist = MagicMock()
    if allowlist_raises:
        allowlist.check.side_effect = ValueError("blocked")
    else:
        allowlist.check.return_value = None

    return {
        "ctx": ctx,
        "cfg": cfg,
        "audit": audit,
        "allowlist": allowlist,
    }


def _make_host_response():
    return {
        "ip_str": "1.2.3.4",
        "org": "Example Corp",
        "isp": "ExampleISP",
        "country_name": "United States",
        "city": "New York",
        "asn": "AS12345",
        "os": None,
        "hostnames": ["example.com"],
        "domains": ["example.com"],
        "ports": [80, 443],
        "tags": [],
        "vulns": [],
        "last_update": "2024-01-01T00:00:00",
        "data": [{"port": 80}, {"port": 443}],
    }


def _make_search_response(matches=None):
    if matches is None:
        matches = [
            {
                "ip_str": "5.6.7.8",
                "port": 8080,
                "org": "Some Org",
                "location": {"country_name": "Germany"},
                "hostnames": [],
                "product": "nginx",
                "version": "1.18",
                "cpe": ["cpe:/a:nginx:nginx:1.18"],
            }
        ]
    return {"total": len(matches), "matches": matches}


async def _call_shodan(
    mocks,
    target="1.2.3.4",
    query_type="host",
    query="",
    limit=20,
    httpx_response=None,
    httpx_raises=None,
    import_error=False,
):
    from tengu.tools.osint.shodan import shodan_lookup

    fake_resp = MagicMock()
    fake_resp.raise_for_status = MagicMock()
    if httpx_response is not None:
        fake_resp.json.return_value = httpx_response

    fake_client = MagicMock()
    if httpx_raises:
        fake_client.get = AsyncMock(side_effect=httpx_raises)
    else:
        fake_client.get = AsyncMock(return_value=fake_resp)

    fake_client_cm = MagicMock()
    fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client_cm.__aexit__ = AsyncMock(return_value=False)

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient.return_value = fake_client_cm

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.sanitize_target", side_effect=lambda t: t),
        patch(f"{TOOL_MODULE}.sanitize_free_text", side_effect=lambda t, **kw: t),
    ):
        if import_error:
            # Simulate ImportError for httpx by patching builtins.__import__
            import builtins
            real_import = builtins.__import__

            def _bad_import(name, *args, **kwargs):
                if name == "httpx":
                    raise ImportError("No module named 'httpx'")
                return real_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_bad_import):
                return await shodan_lookup(
                    mocks["ctx"], target, query_type=query_type, query=query, limit=limit
                )
        else:
            with patch.dict("sys.modules", {"httpx": fake_httpx}):
                return await shodan_lookup(
                    mocks["ctx"], target, query_type=query_type, query=query, limit=limit
                )


# ---------------------------------------------------------------------------
# TestShodanLookup
# ---------------------------------------------------------------------------


class TestShodanLookup:
    async def test_no_api_key_returns_error(self):
        mocks = _make_fixtures(api_key="")
        from tengu.tools.osint.shodan import shodan_lookup

        with (
            patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
            patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
            patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
            patch(f"{TOOL_MODULE}.sanitize_target", side_effect=lambda t: t),
        ):
            result = await shodan_lookup(mocks["ctx"], "1.2.3.4")

        assert "error" in result
        assert "API key" in result["error"]

    async def test_invalid_query_type_defaults_to_host(self):
        mocks = _make_fixtures()
        result = await _call_shodan(
            mocks,
            query_type="invalid",
            httpx_response=_make_host_response(),
        )
        assert result["query_type"] == "host"

    async def test_host_query_returns_correct_keys(self):
        mocks = _make_fixtures()
        result = await _call_shodan(
            mocks, query_type="host", httpx_response=_make_host_response()
        )
        for key in ("tool", "query_type", "target", "ip", "org", "isp", "country",
                    "ports", "vulnerabilities", "services_count"):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "shodan"
        assert result["query_type"] == "host"

    async def test_search_query_returns_correct_keys(self):
        mocks = _make_fixtures()
        result = await _call_shodan(
            mocks,
            query_type="search",
            query="apache country:BR",
            httpx_response=_make_search_response(),
        )
        for key in ("tool", "query_type", "query", "total_results", "results_returned", "results"):
            assert key in result, f"Missing key: {key}"
        assert result["query_type"] == "search"

    async def test_httpx_import_error_returns_error(self):
        mocks = _make_fixtures()
        result = await _call_shodan(mocks, import_error=True)
        assert "error" in result
        assert result["tool"] == "shodan"

    async def test_exception_returns_error_dict(self):
        mocks = _make_fixtures()
        result = await _call_shodan(mocks, httpx_raises=Exception("network error"))
        assert "error" in result
        assert "network error" in result["error"]

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_shodan(mocks, target="blocked.com", httpx_response=_make_host_response())

    async def test_host_services_count_from_data(self):
        mocks = _make_fixtures()
        resp = _make_host_response()
        resp["data"] = [{"port": 80}, {"port": 443}, {"port": 8080}]
        result = await _call_shodan(mocks, query_type="host", httpx_response=resp)
        assert result["services_count"] == 3

    async def test_search_results_limited(self):
        mocks = _make_fixtures()
        matches = [
            {"ip_str": f"1.1.1.{i}", "port": 80, "org": "Org",
             "location": {"country_name": "US"}, "hostnames": [],
             "product": None, "version": None, "cpe": []}
            for i in range(10)
        ]
        result = await _call_shodan(
            mocks,
            query_type="search",
            query="nginx",
            limit=5,
            httpx_response={"total": 10, "matches": matches},
        )
        assert result["results_returned"] <= 5
