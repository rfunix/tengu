"""Unit tests for CVE resource parsers and helpers."""

from __future__ import annotations

from tengu.resources.cve import _build_headers, _parse_cveorg, _parse_nvd_cve

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_nvd_cve(
    cve_id: str = "CVE-2023-1234",
    description: str = "A critical vulnerability",
    cvss_score: float = 9.8,
    severity: str = "CRITICAL",
    cwe: str = "CWE-89",
) -> dict:
    """Build a minimal NVD vuln_data dict."""
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-06-01T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": cvss_score,
                            "baseSeverity": severity,
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id}],
            "configurations": [],
        }
    }


def _make_cveorg_data(
    cve_id: str = "CVE-2023-1234",
    description: str = "Vulnerability in foo",
    published: str = "2023-01-01T00:00:00",
    updated: str = "2023-06-01T00:00:00",
) -> dict:
    """Build a minimal CVE.org API response dict."""
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "datePublished": published,
            "dateUpdated": updated,
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": description}],
                "references": [{"url": "https://example.com/advisory"}],
            }
        },
    }


# ---------------------------------------------------------------------------
# TestBuildHeaders
# ---------------------------------------------------------------------------


class TestBuildHeaders:
    def test_accept_header_always_present(self):
        headers = _build_headers("")
        assert headers["Accept"] == "application/json"

    def test_no_api_key_no_apikey_header(self):
        headers = _build_headers("")
        assert "apiKey" not in headers

    def test_api_key_adds_header(self):
        headers = _build_headers("my-secret-key")
        assert headers["apiKey"] == "my-secret-key"

    def test_returns_dict(self):
        result = _build_headers("key")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# TestParseNvdCve
# ---------------------------------------------------------------------------


class TestParseNvdCve:
    def test_returns_cve_record(self):
        from tengu.types import CVERecord

        record = _parse_nvd_cve(_make_nvd_cve())
        assert isinstance(record, CVERecord)

    def test_id_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(cve_id="CVE-2024-9999"))
        assert record.id == "CVE-2024-9999"

    def test_description_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(description="SQL injection in login form"))
        assert "SQL injection" in record.description

    def test_cvss_score_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(cvss_score=7.5))
        assert record.cvss[0].base_score == 7.5

    def test_cvss_severity_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(severity="HIGH"))
        assert record.cvss[0].severity == "HIGH"

    def test_cwe_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(cwe="CWE-79"))
        assert "CWE-79" in record.cwe_ids

    def test_reference_extracted(self):
        record = _parse_nvd_cve(_make_nvd_cve(cve_id="CVE-2023-1234"))
        assert len(record.references) >= 1

    def test_empty_metrics_gives_no_cvss(self):
        data = _make_nvd_cve()
        data["cve"]["metrics"] = {}
        record = _parse_nvd_cve(data)
        assert record.cvss == []

    def test_non_english_description_skipped(self):
        data = {
            "cve": {
                "id": "CVE-2023-0001",
                "descriptions": [{"lang": "de", "value": "Deutsch description"}],
                "published": "",
                "lastModified": "",
                "metrics": {},
                "weaknesses": [],
                "references": [],
                "configurations": [],
            }
        }
        record = _parse_nvd_cve(data)
        assert record.description == "No description available."

    def test_nvd_cwe_other_filtered(self):
        data = _make_nvd_cve()
        data["cve"]["weaknesses"] = [{"description": [{"lang": "en", "value": "NVD-CWE-Other"}]}]
        record = _parse_nvd_cve(data)
        assert "NVD-CWE-Other" not in record.cwe_ids

    def test_references_capped_at_20(self):
        data = _make_nvd_cve()
        data["cve"]["references"] = [{"url": f"https://ref{i}.com"} for i in range(30)]
        record = _parse_nvd_cve(data)
        assert len(record.references) <= 20


# ---------------------------------------------------------------------------
# TestParseCveorg
# ---------------------------------------------------------------------------


class TestParseCveorg:
    def test_returns_cve_record(self):
        from tengu.types import CVERecord

        record = _parse_cveorg(_make_cveorg_data())
        assert isinstance(record, CVERecord)

    def test_id_extracted(self):
        record = _parse_cveorg(_make_cveorg_data(cve_id="CVE-2024-5555"))
        assert record.id == "CVE-2024-5555"

    def test_description_extracted(self):
        record = _parse_cveorg(_make_cveorg_data(description="Buffer overflow in foo"))
        assert "Buffer overflow" in record.description

    def test_published_extracted(self):
        record = _parse_cveorg(_make_cveorg_data(published="2024-03-15T00:00:00"))
        assert record.published == "2024-03-15T00:00:00"

    def test_reference_extracted(self):
        record = _parse_cveorg(_make_cveorg_data())
        assert "https://example.com/advisory" in record.references

    def test_no_cvss_data(self):
        # CVE.org fallback has no CVSS
        record = _parse_cveorg(_make_cveorg_data())
        assert record.cvss == []

    def test_no_english_description_fallback(self):
        data = {
            "cveMetadata": {"cveId": "CVE-2024-0001", "datePublished": "", "dateUpdated": ""},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "fr", "value": "Desc en français"}],
                    "references": [],
                }
            },
        }
        record = _parse_cveorg(data)
        assert record.description == "No description available."

    def test_empty_data_returns_empty_record(self):
        record = _parse_cveorg({})
        assert record.id == ""
        assert record.description == "No description available."
