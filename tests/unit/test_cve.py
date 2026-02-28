"""Unit tests for CVECache and CVE parsing helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from tengu.resources.cve import CVECache, _build_headers, _parse_cveorg, _parse_nvd_cve
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
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]}
                ],
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
            {"vulnerable": True, "criteria": f"cpe:2.3:a:vendor:product{i}:*"}
            for i in range(25)
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
