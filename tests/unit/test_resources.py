"""Unit tests for static JSON resources: OWASP, PTES, checklists."""

from __future__ import annotations

import pytest

from tengu.resources.checklists import get_checklist, list_checklists
from tengu.resources.owasp import get_category, get_category_checklist, get_top10_list
from tengu.resources.ptes import get_phase, get_phases_overview

# ---------------------------------------------------------------------------
# TestOwaspTop10List
# ---------------------------------------------------------------------------


class TestOwaspTop10List:
    def test_returns_dict(self):
        result = get_top10_list()
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = get_top10_list()
        assert "title" in result
        assert "version" in result
        assert "categories" in result

    def test_has_10_categories(self):
        result = get_top10_list()
        assert len(result["categories"]) == 10

    def test_each_category_has_id_and_title(self):
        result = get_top10_list()
        for cat in result["categories"]:
            assert "id" in cat
            assert "title" in cat

    def test_category_ids_are_a01_to_a10(self):
        result = get_top10_list()
        ids = [c["id"] for c in result["categories"]]
        for i in range(1, 11):
            expected = f"A{i:02d}"
            assert expected in ids

    def test_description_truncated_to_300_plus_ellipsis(self):
        result = get_top10_list()
        for cat in result["categories"]:
            if len(cat.get("description", "")) > 300:
                assert cat["description"].endswith("...")

    def test_cwe_count_is_non_negative_int(self):
        result = get_top10_list()
        for cat in result["categories"]:
            assert isinstance(cat["cwe_count"], int)
            assert cat["cwe_count"] >= 0

    def test_version_field_non_empty(self):
        result = get_top10_list()
        assert result["version"]


# ---------------------------------------------------------------------------
# TestOwaspGetCategory
# ---------------------------------------------------------------------------


class TestOwaspGetCategory:
    def test_valid_category_returns_dict(self):
        result = get_category("A01")
        assert result is not None
        assert isinstance(result, dict)

    def test_valid_category_lowercase_normalized(self):
        result = get_category("a01")
        assert result is not None
        assert result["id"] == "A01"

    def test_all_10_categories_exist(self):
        for i in range(1, 11):
            cat_id = f"A{i:02d}"
            result = get_category(cat_id)
            assert result is not None, f"{cat_id} should exist"

    def test_invalid_category_returns_none(self):
        assert get_category("A99") is None
        assert get_category("X01") is None

    def test_category_has_title(self):
        result = get_category("A01")
        assert "title" in result
        assert result["title"]

    def test_category_has_description(self):
        result = get_category("A01")
        assert "description" in result

    def test_a03_is_injection(self):
        result = get_category("A03")
        assert "Injection" in result["title"] or "injection" in result["title"].lower()


# ---------------------------------------------------------------------------
# TestOwaspGetCategoryChecklist
# ---------------------------------------------------------------------------


class TestOwaspGetCategoryChecklist:
    def test_valid_category_returns_dict(self):
        result = get_category_checklist("A01")
        assert result is not None
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = get_category_checklist("A01")
        assert "id" in result
        assert "title" in result
        assert "how_to_test" in result
        assert "tools" in result
        assert "cwe_ids" in result
        assert "references" in result

    def test_invalid_category_returns_none(self):
        assert get_category_checklist("A99") is None

    def test_how_to_test_is_list(self):
        result = get_category_checklist("A01")
        assert isinstance(result["how_to_test"], list)

    def test_cwe_ids_is_list(self):
        result = get_category_checklist("A01")
        assert isinstance(result["cwe_ids"], list)

    def test_id_matches_requested(self):
        result = get_category_checklist("A05")
        assert result["id"] == "A05"


# ---------------------------------------------------------------------------
# TestPtesGetPhasesOverview
# ---------------------------------------------------------------------------


class TestPtesGetPhasesOverview:
    def test_returns_dict(self):
        result = get_phases_overview()
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = get_phases_overview()
        assert "methodology" in result
        assert "full_name" in result
        assert "url" in result
        assert "phases" in result

    def test_has_7_phases(self):
        result = get_phases_overview()
        assert len(result["phases"]) == 7

    def test_each_phase_has_number_name_description(self):
        result = get_phases_overview()
        for phase in result["phases"]:
            assert "number" in phase
            assert "name" in phase
            assert "description" in phase

    def test_phases_numbered_1_to_7(self):
        result = get_phases_overview()
        numbers = [p["number"] for p in result["phases"]]
        assert sorted(numbers) == list(range(1, 8))

    def test_methodology_field_non_empty(self):
        result = get_phases_overview()
        assert result["methodology"]


# ---------------------------------------------------------------------------
# TestPtesGetPhase
# ---------------------------------------------------------------------------


class TestPtesGetPhase:
    def test_valid_phase_returns_dict(self):
        result = get_phase(1)
        assert result is not None
        assert isinstance(result, dict)

    def test_all_7_phases_exist(self):
        for n in range(1, 8):
            result = get_phase(n)
            assert result is not None, f"Phase {n} should exist"

    def test_invalid_phase_returns_none(self):
        assert get_phase(0) is None
        assert get_phase(8) is None
        assert get_phase(99) is None

    def test_phase_number_matches(self):
        result = get_phase(3)
        assert result["number"] == 3

    def test_phase_has_name(self):
        result = get_phase(1)
        assert "name" in result
        assert result["name"]

    def test_phase_1_is_pre_engagement(self):
        result = get_phase(1)
        assert "pre" in result["name"].lower() or "engagement" in result["name"].lower()

    def test_phase_7_is_reporting(self):
        result = get_phase(7)
        assert "report" in result["name"].lower() or "reporting" in result["name"].lower()


# ---------------------------------------------------------------------------
# TestChecklists
# ---------------------------------------------------------------------------


class TestChecklists:
    def test_list_checklists_returns_list(self):
        result = list_checklists()
        assert isinstance(result, list)

    def test_list_checklists_has_three_types(self):
        result = list_checklists()
        assert len(result) == 3

    def test_web_application_checklist_exists(self):
        result = list_checklists()
        assert "web-application" in result

    def test_api_checklist_exists(self):
        result = list_checklists()
        assert "api" in result

    def test_network_checklist_exists(self):
        result = list_checklists()
        assert "network" in result

    def test_get_checklist_web_returns_data(self):
        result = get_checklist("web-application")
        assert result is not None

    def test_get_checklist_api_returns_data(self):
        result = get_checklist("api")
        assert result is not None

    def test_get_checklist_network_returns_data(self):
        result = get_checklist("network")
        assert result is not None

    def test_invalid_checklist_returns_none(self):
        result = get_checklist("does-not-exist")
        assert result is None

    @pytest.mark.parametrize("checklist_type", ["web-application", "api", "network"])
    def test_all_checklists_return_non_empty(self, checklist_type: str):
        result = get_checklist(checklist_type)
        assert result is not None
        assert result  # non-empty dict/list
