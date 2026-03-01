"""Unit tests for DNS enumeration tool and constants."""

from __future__ import annotations

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from tengu.tools.recon.dns import _ALL_RECORD_TYPES


@pytest.fixture(autouse=True)
def patch_dns_exception_nxdomain():
    """Patch dns.exception to add NXDOMAIN (moved to dns.resolver in newer dnspython)."""
    if not hasattr(dns.exception, "NXDOMAIN"):
        dns.exception.NXDOMAIN = dns.resolver.NXDOMAIN
    if not hasattr(dns.exception, "NoAnswer"):
        dns.exception.NoAnswer = dns.resolver.NoAnswer
    yield
    # Clean up
    for attr in ("NXDOMAIN", "NoAnswer"):
        if hasattr(dns.exception, attr) and getattr(dns.exception, attr) is getattr(
            dns.resolver, attr, None
        ):
            with contextlib.suppress(AttributeError):
                delattr(dns.exception, attr)


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


# ---------------------------------------------------------------------------
# TestDnsEnumerate — async tests for dns_enumerate function
# ---------------------------------------------------------------------------


class TestDnsEnumerate:
    async def test_dns_blocked_domain(self, mock_ctx):
        """Allowlist raises — exception re-raised."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.side_effect = PermissionError("Domain not in allowlist")
            mock_allowlist.return_value = allowlist_instance

            with pytest.raises(PermissionError, match="Domain not in allowlist"):
                await dns_enumerate(mock_ctx, "blocked.example.com")

    async def test_dns_all_record_types(self, mock_ctx):
        """Default record types queried when none specified."""
        from tengu.tools.recon.dns import dns_enumerate

        queried_types: list[str] = []

        async def fake_resolve(domain, rtype):
            queried_types.append(rtype)
            raise dns.resolver.NoAnswer

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
            mock_resolver_cls.return_value = mock_resolver

            await dns_enumerate(mock_ctx, "example.com")

        # Defaults: A, AAAA, MX, NS, TXT, CNAME, SOA
        assert "A" in queried_types
        assert "MX" in queried_types
        assert "TXT" in queried_types

    async def test_dns_custom_record_types(self, mock_ctx):
        """record_types=['A', 'MX'] — only those queried."""
        from tengu.tools.recon.dns import dns_enumerate

        queried_types: list[str] = []

        async def fake_resolve(domain, rtype):
            queried_types.append(rtype)
            raise dns.resolver.NoAnswer

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
            mock_resolver_cls.return_value = mock_resolver

            await dns_enumerate(mock_ctx, "example.com", record_types=["A", "MX"])

        assert set(queried_types) == {"A", "MX"}

    async def test_dns_nxdomain(self, mock_ctx):
        """Resolver returns NXDOMAIN — errors['A'] == 'NXDOMAIN'."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN)
            mock_resolver_cls.return_value = mock_resolver

            result = await dns_enumerate(mock_ctx, "nonexistent.example.com", record_types=["A"])

        assert result["errors"].get("A") == "NXDOMAIN"
        assert result["records_found"] == 0

    async def test_dns_timeout(self, mock_ctx):
        """Resolver raises Timeout — error recorded, no exception raised."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.exception.Timeout)
            mock_resolver_cls.return_value = mock_resolver

            # Should not raise
            result = await dns_enumerate(mock_ctx, "slow.example.com", record_types=["A"])

        assert result["errors"].get("A") == "timeout"

    async def test_dns_a_record_result(self, mock_ctx):
        """Mock returns A record data — in result records_by_type."""
        from tengu.tools.recon.dns import dns_enumerate

        mock_rdata = MagicMock()
        mock_rdata.__str__ = MagicMock(return_value="1.2.3.4")

        mock_answer = MagicMock()
        mock_answer.ttl = 300
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        async def fake_resolve(domain, rtype):
            if rtype == "A":
                return mock_answer
            raise dns.resolver.NoAnswer

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
            mock_resolver_cls.return_value = mock_resolver

            result = await dns_enumerate(mock_ctx, "example.com", record_types=["A"])

        assert "A" in result["records_by_type"]
        assert "1.2.3.4" in result["records_by_type"]["A"]

    async def test_dns_tool_key(self, mock_ctx):
        """Result has tool='dns_enumerate'."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
            mock_resolver_cls.return_value = mock_resolver

            result = await dns_enumerate(mock_ctx, "example.com", record_types=["A"])

        assert result["tool"] == "dns_enumerate"

    async def test_dns_audit_logged(self, mock_ctx):
        """audit.log_tool_call called on success."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
            mock_resolver_cls.return_value = mock_resolver

            await dns_enumerate(mock_ctx, "example.com", record_types=["A"])

        mock_audit_instance.log_tool_call.assert_called_once()

    async def test_dns_no_exception_on_generic_error(self, mock_ctx):
        """Generic exception in resolver — other record types still returned."""
        from tengu.tools.recon.dns import dns_enumerate

        call_count = 0

        async def fake_resolve(domain, rtype):
            nonlocal call_count
            call_count += 1
            if rtype == "A":
                raise RuntimeError("Unexpected DNS error")
            raise dns.resolver.NoAnswer

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
            mock_resolver_cls.return_value = mock_resolver

            # Should not raise
            result = await dns_enumerate(mock_ctx, "example.com", record_types=["A", "MX"])

        assert "errors" in result
        assert "A" in result["errors"]

    async def test_dns_custom_nameserver(self, mock_ctx):
        """Custom nameserver IP is set on the resolver."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
            mock_resolver.nameservers = []
            mock_resolver_cls.return_value = mock_resolver

            await dns_enumerate(mock_ctx, "example.com", nameserver="8.8.8.8", record_types=["A"])

        assert mock_resolver.nameservers == ["8.8.8.8"]

    async def test_dns_domain_in_result(self, mock_ctx):
        """Result always contains domain field."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
            mock_resolver_cls.return_value = mock_resolver

            result = await dns_enumerate(mock_ctx, "example.com", record_types=["A"])

        assert "domain" in result
        assert "example.com" in result["domain"]

    async def test_dns_invalid_nameserver_uses_default(self, mock_ctx):
        """Invalid nameserver IP falls back to system resolver (no crash)."""
        from tengu.tools.recon.dns import dns_enumerate

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
            mock_resolver.nameservers = []
            mock_resolver_cls.return_value = mock_resolver

            # Should not raise
            await dns_enumerate(mock_ctx, "example.com", nameserver="not-an-ip", record_types=["A"])

        # nameservers should NOT have been set (invalid IP)
        assert mock_resolver.nameservers == []

    async def test_dns_records_found_count(self, mock_ctx):
        """records_found matches actual record count."""
        from tengu.tools.recon.dns import dns_enumerate

        mock_rdata = MagicMock()
        mock_rdata.__str__ = MagicMock(return_value="10.0.0.1")

        mock_answer = MagicMock()
        mock_answer.ttl = 60
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        async def fake_resolve(domain, rtype):
            if rtype == "A":
                return mock_answer
            raise dns.resolver.NoAnswer

        with (
            patch("tengu.tools.recon.dns.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.recon.dns.get_audit_logger") as mock_audit,
            patch("tengu.tools.recon.dns.dns.asyncresolver.Resolver") as mock_resolver_cls,
        ):
            mock_audit_instance = AsyncMock()
            mock_audit.return_value = mock_audit_instance

            allowlist_instance = MagicMock()
            allowlist_instance.check.return_value = None
            mock_allowlist.return_value = allowlist_instance

            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
            mock_resolver_cls.return_value = mock_resolver

            result = await dns_enumerate(mock_ctx, "example.com", record_types=["A"])

        assert result["records_found"] == 1


# ---------------------------------------------------------------------------
# TestAllRecordTypes
# ---------------------------------------------------------------------------


class TestAllRecordTypes:
    def test_a_record_present(self):
        assert "A" in _ALL_RECORD_TYPES

    def test_mx_record_present(self):
        assert "MX" in _ALL_RECORD_TYPES

    def test_ns_record_present(self):
        assert "NS" in _ALL_RECORD_TYPES

    def test_txt_record_present(self):
        assert "TXT" in _ALL_RECORD_TYPES

    def test_aaaa_record_present(self):
        assert "AAAA" in _ALL_RECORD_TYPES

    def test_cname_record_present(self):
        assert "CNAME" in _ALL_RECORD_TYPES

    def test_all_types_are_uppercase_strings(self):
        for rtype in _ALL_RECORD_TYPES:
            assert isinstance(rtype, str)
            assert rtype == rtype.upper()

    def test_at_least_eight_types(self):
        assert len(_ALL_RECORD_TYPES) >= 8

    def test_no_duplicates(self):
        assert len(_ALL_RECORD_TYPES) == len(set(_ALL_RECORD_TYPES))
