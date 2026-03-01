"""Unit tests for the whois_lookup async tool."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.recon.whois"


def _make_fixtures(*, allowlist_raises=False):
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()

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
        "audit": audit,
        "allowlist": allowlist,
    }


def _make_whois_obj(**kwargs):
    """Build a minimal whois result object with the given attributes."""
    obj = MagicMock()
    defaults = {
        "registrar": "Example Registrar Inc.",
        "creation_date": datetime(2000, 1, 1),
        "expiration_date": datetime(2030, 1, 1),
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "status": ["clientTransferProhibited"],
        "emails": ["admin@example.com"],
        "org": "Example Org",
        "country": "US",
        "text": "raw whois output here",
    }
    defaults.update(kwargs)
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


async def _call_whois(mocks, target="example.com", whois_obj=None, whois_raises=None):
    from tengu.tools.recon.whois import whois_lookup

    # We patch loop.run_in_executor to return the whois_obj
    fake_loop = MagicMock()
    if whois_raises:
        fake_loop.run_in_executor = AsyncMock(side_effect=whois_raises)
    else:
        fake_loop.run_in_executor = AsyncMock(return_value=whois_obj or _make_whois_obj())

    with (
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.sanitize_target", side_effect=lambda t: t),
        patch(f"{TOOL_MODULE}.asyncio") as mock_asyncio,
    ):
        mock_asyncio.get_event_loop.return_value = fake_loop
        return await whois_lookup(mocks["ctx"], target)


# ---------------------------------------------------------------------------
# TestWhoisLookup
# ---------------------------------------------------------------------------


class TestWhoisLookup:
    async def test_successful_lookup_returns_dict(self):
        mocks = _make_fixtures()
        result = await _call_whois(mocks)
        assert result["tool"] == "whois_lookup"
        assert "error" not in result

    async def test_error_returns_error_key(self):
        mocks = _make_fixtures()
        result = await _call_whois(mocks, whois_raises=Exception("connection refused"))
        assert "error" in result
        assert "connection refused" in result["error"]
        assert result["tool"] == "whois_lookup"

    async def test_datetime_converted_to_isoformat(self):
        mocks = _make_fixtures()
        dt = datetime(2005, 6, 15, 10, 30, 0)
        w = _make_whois_obj(creation_date=dt)
        result = await _call_whois(mocks, whois_obj=w)
        assert result["creation_date"] == dt.isoformat()

    async def test_list_of_datetimes_uses_first(self):
        mocks = _make_fixtures()
        dt1 = datetime(2005, 1, 1)
        dt2 = datetime(2006, 1, 1)
        w = _make_whois_obj(creation_date=[dt1, dt2])
        result = await _call_whois(mocks, whois_obj=w)
        assert result["creation_date"] == dt1.isoformat()

    async def test_none_creation_date_handled(self):
        mocks = _make_fixtures()
        w = _make_whois_obj(creation_date=None)
        result = await _call_whois(mocks, whois_obj=w)
        assert result["creation_date"] is None

    async def test_name_servers_as_list(self):
        mocks = _make_fixtures()
        w = _make_whois_obj(name_servers=["ns1.example.com", "ns2.example.com"])
        result = await _call_whois(mocks, whois_obj=w)
        assert isinstance(result["name_servers"], list)
        assert "ns1.example.com" in result["name_servers"]

    async def test_name_servers_as_string(self):
        mocks = _make_fixtures()
        w = _make_whois_obj(name_servers="ns1.example.com")
        result = await _call_whois(mocks, whois_obj=w)
        assert isinstance(result["name_servers"], list)
        assert result["name_servers"] == ["ns1.example.com"]

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_whois(mocks, target="blocked.com")

    async def test_raw_excerpt_truncated(self):
        mocks = _make_fixtures()
        long_raw = "x" * 5000
        w = _make_whois_obj(text=long_raw)
        result = await _call_whois(mocks, whois_obj=w)
        assert len(result["raw_excerpt"]) == 2000

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_whois(mocks)
        for key in (
            "tool",
            "target",
            "registrar",
            "creation_date",
            "expiration_date",
            "name_servers",
            "status",
            "emails",
            "org",
            "country",
            "raw_excerpt",
        ):
            assert key in result, f"Missing key: {key}"

    async def test_none_name_servers_returns_empty_list(self):
        mocks = _make_fixtures()
        w = _make_whois_obj(name_servers=None)
        result = await _call_whois(mocks, whois_obj=w)
        assert result["name_servers"] == []
