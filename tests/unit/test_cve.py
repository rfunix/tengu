"""Unit tests for CVECache and CVE parsing helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.resources import cve as cve_mod
from tengu.resources.cve import (
    CVECache,
    _build_headers,
    _parse_cveorg,
    _parse_nvd_cve,
    lookup_cve,
    search_cves,
)
from tengu.types import CVERecord, CVSSMetrics

# ---------------------------------------------------------------------------
# TestCVECache
# ---------------------------------------------------------------------------


class TestCVECache:
    @pytest.fixture
    def db_path(self, tmp_path: Path) -> str:
        return str(tmp_path / "cve_test.db")

    @pytest.fixture
    def cache(self, db_path: str) -> CVECache:
        return CVECache(db_path)

    def test_creates_db_file(self, db_path: str):
        CVECache(db_path)
        assert Path(db_path).exists()

    def test_get_cve_miss_returns_none(self, cache: CVECache):
        result = cache.get_cve("CVE-2021-44228")
        assert result is None

    def test_set_and_get_cve(self, cache: CVECache):
        data = {"id": "CVE-2021-44228", "description": "Log4Shell", "published": "2021-12-09"}
        cache.set_cve("CVE-2021-44228", data)
        result = cache.get_cve("CVE-2021-44228")
        assert result is not None
        assert result["id"] == "CVE-2021-44228"
        assert result["description"] == "Log4Shell"

    def test_cve_id_normalized_to_uppercase(self, cache: CVECache):
        data = {"id": "cve-2021-44228"}
        cache.set_cve("cve-2021-44228", data)
        # Should be retrievable with uppercase key too
        result = cache.get_cve("CVE-2021-44228")
        assert result is not None

    def test_expired_cve_returns_none(self, cache: CVECache):
        data = {"id": "CVE-2021-44228"}
        cache.set_cve("CVE-2021-44228", data)
        # TTL of 0 hours means everything is expired
        result = cache.get_cve("CVE-2021-44228", ttl_hours=0)
        assert result is None

    def test_set_cve_overwrites_existing(self, cache: CVECache):
        cache.set_cve("CVE-2021-44228", {"description": "first"})
        cache.set_cve("CVE-2021-44228", {"description": "updated"})
        result = cache.get_cve("CVE-2021-44228")
        assert result["description"] == "updated"

    def test_get_search_miss_returns_none(self, cache: CVECache):
        result = cache.get_search("log4j:None:None:None:20")
        assert result is None

    def test_set_and_get_search(self, cache: CVECache):
        data = {"records": [{"id": "CVE-2021-44228"}]}
        cache.set_search("log4j:None:None:None:20", data)
        result = cache.get_search("log4j:None:None:None:20")
        assert result is not None
        assert result["records"][0]["id"] == "CVE-2021-44228"

    def test_expired_search_returns_none(self, cache: CVECache):
        data = {"records": []}
        cache.set_search("query_key", data)
        result = cache.get_search("query_key", ttl_hours=0)
        assert result is None

    def test_different_cve_ids_stored_independently(self, cache: CVECache):
        cache.set_cve("CVE-2021-44228", {"description": "log4shell"})
        cache.set_cve("CVE-2023-1234", {"description": "other"})
        r1 = cache.get_cve("CVE-2021-44228")
        r2 = cache.get_cve("CVE-2023-1234")
        assert r1["description"] == "log4shell"
        assert r2["description"] == "other"

    def test_creates_parent_directory(self, tmp_path: Path):
        nested = str(tmp_path / "nested" / "deep" / "cve.db")
        CVECache(nested)
        assert Path(nested).exists()


# ---------------------------------------------------------------------------
# TestParseNvdCve
# ---------------------------------------------------------------------------


def _make_nvd_vuln(
    cve_id: str = "CVE-2021-44228",
    description: str = "Log4Shell RCE",
    cvss_score: float = 10.0,
    severity: str = "CRITICAL",
) -> dict:
    """Build a minimal NVD API vulnerability record for testing."""
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-12-09T00:00:00.000",
            "lastModified": "2021-12-15T00:00:00.000",
            "descriptions": [
                {"lang": "en", "value": description},
                {"lang": "es", "value": "descripción en español"},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "baseScore": cvss_score,
                            "baseSeverity": severity,
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 6.0,
                    }
                ]
            },
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-502"},
                    ]
                }
            ],
            "references": [
                {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }


class TestParseNvdCve:
    def test_returns_cve_record(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert isinstance(result, CVERecord)

    def test_cve_id_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln(cve_id="CVE-2021-44228"))
        assert result.id == "CVE-2021-44228"

    def test_english_description_selected(self):
        result = _parse_nvd_cve(_make_nvd_vuln(description="Log4Shell RCE"))
        assert result.description == "Log4Shell RCE"

    def test_published_date_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert result.published == "2021-12-09T00:00:00.000"

    def test_last_modified_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert result.last_modified == "2021-12-15T00:00:00.000"

    def test_cvss_metrics_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln(cvss_score=10.0, severity="CRITICAL"))
        assert len(result.cvss) == 1
        assert isinstance(result.cvss[0], CVSSMetrics)
        assert result.cvss[0].base_score == 10.0
        assert result.cvss[0].severity == "CRITICAL"

    def test_cvss_version_31(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert result.cvss[0].version == "3.1"

    def test_cvss_vector_string_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert result.cvss[0].vector_string.startswith("CVSS:3.1")

    def test_cwe_ids_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert "CWE-502" in result.cwe_ids

    def test_references_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert len(result.references) == 2
        assert "apache.org" in result.references[0]

    def test_affected_products_parsed(self):
        result = _parse_nvd_cve(_make_nvd_vuln())
        assert len(result.affected_products) == 1
        assert "apache:log4j" in result.affected_products[0]

    def test_no_descriptions_falls_back_to_default(self):
        vuln = {"cve": {"id": "CVE-2000-0001", "descriptions": [], "metrics": {}}}
        result = _parse_nvd_cve(vuln)
        assert result.description == "No description available."

    def test_no_en_description_falls_back(self):
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "fr", "value": "description en français"}],
                "metrics": {},
            }
        }
        result = _parse_nvd_cve(vuln)
        assert result.description == "No description available."

    def test_cwe_nvd_other_excluded(self):
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {},
                "weaknesses": [{"description": [{"lang": "en", "value": "NVD-CWE-Other"}]}],
            }
        }
        result = _parse_nvd_cve(vuln)
        assert "NVD-CWE-Other" not in result.cwe_ids

    def test_references_capped_at_20(self):
        refs = [{"url": f"https://example.com/{i}"} for i in range(25)]
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {},
                "references": refs,
            }
        }
        result = _parse_nvd_cve(vuln)
        assert len(result.references) == 20

    def test_affected_products_capped_at_20(self):
        cpe_matches = [
            {"vulnerable": True, "criteria": f"cpe:2.3:a:vendor:product{i}:*"} for i in range(25)
        ]
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {},
                "configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}],
            }
        }
        result = _parse_nvd_cve(vuln)
        assert len(result.affected_products) == 20


# ---------------------------------------------------------------------------
# TestParseCveOrg
# ---------------------------------------------------------------------------


def _make_cveorg_record(
    cve_id: str = "CVE-2021-44228",
    description: str = "Log4Shell vulnerability",
    published: str = "2021-12-09T00:00:00",
) -> dict:
    """Build a minimal CVE.org API record for testing."""
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "datePublished": published,
            "dateUpdated": "2021-12-15T00:00:00",
        },
        "containers": {
            "cna": {
                "descriptions": [
                    {"lang": "en", "value": description},
                ],
                "references": [
                    {"url": "https://example.com/advisory"},
                ],
            }
        },
    }


class TestParseCveOrg:
    def test_returns_cve_record(self):
        result = _parse_cveorg(_make_cveorg_record())
        assert isinstance(result, CVERecord)

    def test_cve_id_parsed(self):
        result = _parse_cveorg(_make_cveorg_record(cve_id="CVE-2021-44228"))
        assert result.id == "CVE-2021-44228"

    def test_english_description_selected(self):
        result = _parse_cveorg(_make_cveorg_record(description="Log4Shell vulnerability"))
        assert result.description == "Log4Shell vulnerability"

    def test_published_date_parsed(self):
        result = _parse_cveorg(_make_cveorg_record(published="2021-12-09T00:00:00"))
        assert result.published == "2021-12-09T00:00:00"

    def test_references_parsed(self):
        result = _parse_cveorg(_make_cveorg_record())
        assert len(result.references) == 1
        assert "example.com" in result.references[0]

    def test_no_cvss_data_empty_list(self):
        result = _parse_cveorg(_make_cveorg_record())
        assert result.cvss == []

    def test_en_prefix_lang_accepted(self):
        record = {
            "cveMetadata": {"cveId": "CVE-2000-0001", "datePublished": "", "dateUpdated": ""},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en_US", "value": "US English description"}],
                    "references": [],
                }
            },
        }
        result = _parse_cveorg(record)
        assert result.description == "US English description"

    def test_no_en_description_falls_back(self):
        record = {
            "cveMetadata": {"cveId": "CVE-2000-0001", "datePublished": "", "dateUpdated": ""},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "fr", "value": "description française"}],
                    "references": [],
                }
            },
        }
        result = _parse_cveorg(record)
        assert result.description == "No description available."

    def test_references_capped_at_20(self):
        refs = [{"url": f"https://example.com/{i}"} for i in range(25)]
        record = {
            "cveMetadata": {"cveId": "CVE-2000-0001", "datePublished": "", "dateUpdated": ""},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "test"}],
                    "references": refs,
                }
            },
        }
        result = _parse_cveorg(record)
        assert len(result.references) == 20


# ---------------------------------------------------------------------------
# TestBuildHeaders
# ---------------------------------------------------------------------------


class TestBuildHeaders:
    def test_without_api_key_no_api_key_header(self):
        headers = _build_headers("")
        assert "apiKey" not in headers

    def test_without_api_key_has_accept_header(self):
        headers = _build_headers("")
        assert headers["Accept"] == "application/json"

    def test_with_api_key_includes_api_key_header(self):
        headers = _build_headers("my-api-key-123")
        assert headers["apiKey"] == "my-api-key-123"

    def test_with_api_key_has_accept_header(self):
        headers = _build_headers("my-api-key-123")
        assert headers["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# Helpers for async tests
# ---------------------------------------------------------------------------


def _make_nvd_response(cve_id: str = "CVE-2021-44228", description: str = "Log4Shell") -> dict:
    """Build a minimal NVD API HTTP response payload."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2021-12-09T00:00:00.000",
                    "lastModified": "2021-12-15T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {},
                }
            }
        ]
    }


def _make_httpx_mock(response_data: dict) -> tuple:
    """Return (mock_client, mock_class) for a single httpx call."""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = response_data

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    mock_client_ctx = MagicMock()
    mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_class = MagicMock(return_value=mock_client_ctx)
    return mock_client, mock_class


# ---------------------------------------------------------------------------
# TestGetCache
# ---------------------------------------------------------------------------


class TestGetCache:
    def test_returns_cve_cache_instance(self, tmp_path):
        cve_mod._cache = None
        with patch("tengu.resources.cve.get_config") as mock_cfg:
            mock_cfg.return_value.cve.cache_path = str(tmp_path / "cve.db")
            cache = cve_mod._get_cache()
        assert isinstance(cache, CVECache)

    def test_singleton_returns_same_instance(self, tmp_path):
        cve_mod._cache = None
        with patch("tengu.resources.cve.get_config") as mock_cfg:
            mock_cfg.return_value.cve.cache_path = str(tmp_path / "cve2.db")
            first = cve_mod._get_cache()
            second = cve_mod._get_cache()
        assert first is second

    def teardown_method(self, method):
        # Reset global state between tests
        cve_mod._cache = None


# ---------------------------------------------------------------------------
# TestRateLimitWait
# ---------------------------------------------------------------------------


class TestRateLimitWait:
    async def test_no_sleep_when_no_previous_request(self):
        cve_mod._last_request_time = 0.0
        with patch("tengu.resources.cve.get_config") as mock_cfg:
            mock_cfg.return_value.cve.nvd_api_key = ""
            mock_cfg.return_value.cve.cache_path = ":memory:"
            # Should complete without error
            await cve_mod._rate_limit_wait(has_api_key=False)

    async def test_completes_without_error_with_api_key(self):
        cve_mod._last_request_time = 0.0
        with patch("tengu.resources.cve.get_config") as mock_cfg:
            mock_cfg.return_value.cve.nvd_api_key = "some-key"
            mock_cfg.return_value.cve.cache_path = ":memory:"
            await cve_mod._rate_limit_wait(has_api_key=True)

    async def test_updates_last_request_time(self):
        import time

        cve_mod._last_request_time = 0.0
        before = time.monotonic()
        with patch("tengu.resources.cve.get_config") as mock_cfg:
            mock_cfg.return_value.cve.nvd_api_key = ""
            mock_cfg.return_value.cve.cache_path = ":memory:"
            await cve_mod._rate_limit_wait(has_api_key=False)
        assert cve_mod._last_request_time >= before


# ---------------------------------------------------------------------------
# TestLookupCve
# ---------------------------------------------------------------------------


class TestLookupCve:
    async def test_cache_hit_returns_record(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        cache = CVECache(db_path)
        record = CVERecord(
            id="CVE-2021-44228",
            description="Log4Shell",
            published="2021-12-09",
            last_modified="2021-12-15",
        )
        cache.set_cve("CVE-2021-44228", record.model_dump(mode="json"))

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            result = await lookup_cve("CVE-2021-44228")

        assert result is not None
        assert result.id == "CVE-2021-44228"
        assert result.description == "Log4Shell"

    async def test_nvd_success_returns_record(self, tmp_path):
        db_path = str(tmp_path / "nvd.db")
        cache = CVECache(db_path)
        _, mock_class = _make_httpx_mock(_make_nvd_response())

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            result = await lookup_cve("CVE-2021-44228")

        assert result is not None
        assert isinstance(result, CVERecord)
        assert result.id == "CVE-2021-44228"

    async def test_nvd_fail_fallback_to_cveorg(self, tmp_path):
        import httpx

        db_path = str(tmp_path / "fallback.db")
        cache = CVECache(db_path)

        cveorg_data = {
            "cveMetadata": {
                "cveId": "CVE-2021-44228",
                "datePublished": "2021-12-09T00:00:00",
                "dateUpdated": "2021-12-15T00:00:00",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Log4Shell from cve.org"}],
                    "references": [],
                }
            },
        }

        # NVD call raises HTTPError, CVE.org succeeds
        mock_nvd_response = MagicMock()
        mock_nvd_response.raise_for_status.side_effect = httpx.HTTPError("NVD unavailable")

        mock_cveorg_response = MagicMock()
        mock_cveorg_response.raise_for_status = MagicMock()
        mock_cveorg_response.json.return_value = cveorg_data

        call_count = 0

        async def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_nvd_response
            return mock_cveorg_response

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            result = await lookup_cve("CVE-2021-44228")

        assert result is not None
        assert result.id == "CVE-2021-44228"

    async def test_both_fail_returns_none(self, tmp_path):
        import httpx

        db_path = str(tmp_path / "bothfail.db")
        cache = CVECache(db_path)

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPError("unavailable")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            result = await lookup_cve("CVE-2021-44228")

        assert result is None

    async def test_nvd_empty_vulnerabilities_returns_none(self, tmp_path):
        db_path = str(tmp_path / "empty.db")
        cache = CVECache(db_path)
        _, mock_class = _make_httpx_mock({"vulnerabilities": []})

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            result = await lookup_cve("CVE-2021-44228")

        assert result is None


# ---------------------------------------------------------------------------
# TestSearchCves
# ---------------------------------------------------------------------------


class TestSearchCves:
    async def test_cache_hit_returns_records(self, tmp_path):
        db_path = str(tmp_path / "search_cache.db")
        cache = CVECache(db_path)
        record = CVERecord(
            id="CVE-2021-44228",
            description="Log4Shell",
            published="2021-12-09",
            last_modified="2021-12-15",
        )
        query_key = "log4j:None:None:None:20"
        cache.set_search(query_key, {"records": [record.model_dump(mode="json")]})

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            results = await search_cves(keyword="log4j")

        assert len(results) == 1
        assert results[0].id == "CVE-2021-44228"

    async def test_nvd_success_returns_records(self, tmp_path):
        db_path = str(tmp_path / "search_nvd.db")
        cache = CVECache(db_path)
        response_data = _make_nvd_response()
        _, mock_class = _make_httpx_mock(response_data)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            results = await search_cves(keyword="log4j")

        assert len(results) == 1
        assert isinstance(results[0], CVERecord)

    async def test_error_returns_empty_list(self, tmp_path):
        db_path = str(tmp_path / "search_err.db")
        cache = CVECache(db_path)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("network error"))
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            results = await search_cves(keyword="log4j")

        assert results == []

    async def test_severity_filter_included_in_params(self, tmp_path):
        db_path = str(tmp_path / "search_sev.db")
        cache = CVECache(db_path)
        captured_params: dict = {}

        async def fake_get(url, params=None, **kwargs):
            if params:
                captured_params.update(params)
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"vulnerabilities": []}
            return mock_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            await search_cves(keyword="test", severity="critical")

        assert "cvssV3Severity" in captured_params
        assert captured_params["cvssV3Severity"] == "CRITICAL"

    async def test_days_back_builds_date_range(self, tmp_path):
        db_path = str(tmp_path / "search_days.db")
        cache = CVECache(db_path)
        captured_params: dict = {}

        async def fake_get(url, params=None, **kwargs):
            if params:
                captured_params.update(params)
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"vulnerabilities": []}
            return mock_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            await search_cves(keyword="test", days_back=7)

        assert "pubStartDate" in captured_params
        assert "pubEndDate" in captured_params

    async def test_keyword_included_in_params(self, tmp_path):
        db_path = str(tmp_path / "search_kw.db")
        cache = CVECache(db_path)
        captured_params: dict = {}

        async def fake_get(url, params=None, **kwargs):
            if params:
                captured_params.update(params)
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"vulnerabilities": []}
            return mock_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_class = MagicMock(return_value=mock_ctx)

        with (
            patch("tengu.resources.cve._get_cache", return_value=cache),
            patch("tengu.resources.cve.get_config") as mock_cfg,
            patch("tengu.resources.cve._rate_limit_wait", new_callable=AsyncMock),
            patch("tengu.resources.cve.httpx.AsyncClient", mock_class),
        ):
            mock_cfg.return_value.cve.cache_ttl_hours = 24
            mock_cfg.return_value.cve.nvd_api_key = ""
            await search_cves(keyword="apache")

        assert "keywordSearch" in captured_params
        assert captured_params["keywordSearch"] == "apache"
