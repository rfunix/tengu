"""Unit tests for CVE lookup and search tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from tengu.types import CVERecord, CVSSMetrics


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_cvss(score: float = 9.8, severity: str = "CRITICAL", version: str = "3.1") -> CVSSMetrics:
    return CVSSMetrics(
        version=version,
        vector_string=f"CVSS:{version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=score,
        severity=severity,
    )


def _make_cve_record(
    cve_id: str = "CVE-2021-44228",
    description: str = "Log4Shell remote code execution",
    score: float = 10.0,
    severity: str = "CRITICAL",
) -> CVERecord:
    return CVERecord(
        id=cve_id,
        description=description,
        published="2021-12-10T10:15:09.143",
        last_modified="2023-04-03T18:15:07.197",
        cvss=[_make_cvss(score, severity)],
        cwe_ids=["CWE-502"],
        references=["https://nvd.nist.gov/vuln/detail/" + cve_id],
        affected_products=["cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"],
    )


# ---------------------------------------------------------------------------
# TestCveLookup
# ---------------------------------------------------------------------------


class TestCveLookup:
    async def test_cve_lookup_valid_id(self, mock_ctx):
        """Mock API response returns CVE data with CVSS score."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        record = _make_cve_record()

        with patch("tengu.tools.analysis.cve_tools.lookup_cve", AsyncMock(return_value=record)):
            result = await cve_lookup(mock_ctx, "CVE-2021-44228")

        assert result["found"] is True
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss_score"] == 10.0

    async def test_cve_lookup_not_found(self, mock_ctx):
        """API returns None (not found) — result has found=False."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        with patch("tengu.tools.analysis.cve_tools.lookup_cve", AsyncMock(return_value=None)):
            result = await cve_lookup(mock_ctx, "CVE-9999-99999")

        assert result["found"] is False
        assert "not found" in result["message"].lower()

    async def test_cve_lookup_invalid_id_format(self, mock_ctx):
        """'INVALID-123' raises InvalidInputError from sanitize_cve_id."""
        from tengu.exceptions import InvalidInputError
        from tengu.tools.analysis.cve_tools import cve_lookup

        with pytest.raises(InvalidInputError):
            await cve_lookup(mock_ctx, "INVALID-123")

    async def test_cve_lookup_network_error(self, mock_ctx):
        """lookup_cve raises — error propagates (or returns gracefully)."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        with (
            patch(
                "tengu.tools.analysis.cve_tools.lookup_cve",
                AsyncMock(side_effect=Exception("Network error")),
            ),
            pytest.raises(Exception, match="Network error"),
        ):
            await cve_lookup(mock_ctx, "CVE-2021-44228")

    async def test_cve_lookup_cvss_v3_score(self, mock_ctx):
        """Response with CVSS v3 — cvss_score present in result."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        record = _make_cve_record(score=9.8, severity="CRITICAL")

        with patch("tengu.tools.analysis.cve_tools.lookup_cve", AsyncMock(return_value=record)):
            result = await cve_lookup(mock_ctx, "CVE-2021-44228")

        assert result["cvss_score"] == 9.8
        assert result["severity"] == "CRITICAL"

    async def test_cve_lookup_tool_key(self, mock_ctx):
        """Result has cve_id key (tool identifier field)."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        record = _make_cve_record()

        with patch("tengu.tools.analysis.cve_tools.lookup_cve", AsyncMock(return_value=record)):
            result = await cve_lookup(mock_ctx, "CVE-2021-44228")

        assert "cve_id" in result

    async def test_cve_lookup_cve_id_uppercase(self, mock_ctx):
        """Lowercase 'cve-2021-44228' is normalized to uppercase by sanitize_cve_id."""
        from tengu.tools.analysis.cve_tools import cve_lookup

        record = _make_cve_record(cve_id="CVE-2021-44228")

        with patch(
            "tengu.tools.analysis.cve_tools.lookup_cve", AsyncMock(return_value=record)
        ) as mock_lookup:
            await cve_lookup(mock_ctx, "cve-2021-44228")

        # sanitize_cve_id uppercases CVE IDs
        call_arg = mock_lookup.call_args[0][0]
        assert call_arg == call_arg.upper()


# ---------------------------------------------------------------------------
# TestCveSearch
# ---------------------------------------------------------------------------


class TestCveSearch:
    async def test_cve_search_keyword(self, mock_ctx):
        """Mock API returns list of CVEs — results list present."""
        from tengu.tools.analysis.cve_tools import cve_search

        records = [_make_cve_record("CVE-2021-44228"), _make_cve_record("CVE-2022-22965")]

        with patch("tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=records)):
            result = await cve_search(mock_ctx, keyword="log4j")

        assert result["total_found"] == 2
        assert len(result["cves"]) == 2

    async def test_cve_search_severity_filter(self, mock_ctx):
        """severity='critical' is applied (uppercased)."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch(
            "tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])
        ) as mock_search:
            await cve_search(mock_ctx, keyword="apache", severity="critical")

        call_kwargs = mock_search.call_args[1]
        assert call_kwargs.get("severity") == "CRITICAL"

    async def test_cve_search_max_results(self, mock_ctx):
        """max_results=5 limits return (clamped between 1 and 100)."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch(
            "tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])
        ) as mock_search:
            await cve_search(mock_ctx, keyword="nginx", max_results=5)

        call_kwargs = mock_search.call_args[1]
        assert call_kwargs.get("results_per_page") == 5

    async def test_cve_search_empty_results(self, mock_ctx):
        """API returns empty list — total_found=0, cves=[]."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch("tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])):
            result = await cve_search(mock_ctx, keyword="nonexistent_product_xyz")

        assert result["total_found"] == 0
        assert result["cves"] == []

    async def test_cve_search_network_error(self, mock_ctx):
        """search_cves raises — error propagates."""
        from tengu.tools.analysis.cve_tools import cve_search

        with (
            patch(
                "tengu.tools.analysis.cve_tools.search_cves",
                AsyncMock(side_effect=Exception("NVD unreachable")),
            ),
            pytest.raises(Exception, match="NVD unreachable"),
        ):
            await cve_search(mock_ctx, keyword="openssl")

    async def test_cve_search_tool_key(self, mock_ctx):
        """Result has query and cves keys."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch("tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])):
            result = await cve_search(mock_ctx, keyword="test")

        assert "query" in result
        assert "cves" in result

    async def test_cve_search_no_severity(self, mock_ctx):
        """No severity filter — severity parameter is None in search call."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch(
            "tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])
        ) as mock_search:
            await cve_search(mock_ctx, keyword="apache")

        call_kwargs = mock_search.call_args[1]
        assert call_kwargs.get("severity") is None

    async def test_cve_search_invalid_severity(self, mock_ctx):
        """Unknown severity — treated as None (graceful handling)."""
        from tengu.tools.analysis.cve_tools import cve_search

        with patch(
            "tengu.tools.analysis.cve_tools.search_cves", AsyncMock(return_value=[])
        ) as mock_search:
            await cve_search(mock_ctx, keyword="apache", severity="EXTREME")

        # Invalid severity should be set to None
        call_kwargs = mock_search.call_args[1]
        assert call_kwargs.get("severity") is None

    async def test_cve_search_no_keyword_no_cpe(self, mock_ctx):
        """Neither keyword nor cpe_name provided — returns error dict."""
        from tengu.tools.analysis.cve_tools import cve_search

        result = await cve_search(mock_ctx)

        assert "error" in result
