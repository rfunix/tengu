"""Unit tests for the prompts catalog resource (prompts://list and prompts://category)."""

from __future__ import annotations

import json

from tengu.resources.prompts import (
    _CATEGORIES,
    _PROMPTS,
    get_prompts_by_category,
    get_prompts_list,
    list_categories,
)

# ---------------------------------------------------------------------------
# TestGetPromptsList
# ---------------------------------------------------------------------------


class TestGetPromptsList:
    def test_returns_dict(self) -> None:
        result = get_prompts_list()
        assert isinstance(result, dict)

    def test_has_required_keys(self) -> None:
        result = get_prompts_list()
        assert "total" in result
        assert "categories" in result
        assert "prompts" in result
        assert "by_category" in result

    def test_total_matches_prompt_count(self) -> None:
        result = get_prompts_list()
        assert result["total"] == len(result["prompts"])

    def test_total_is_positive(self) -> None:
        result = get_prompts_list()
        assert result["total"] > 0

    def test_categories_list_non_empty(self) -> None:
        result = get_prompts_list()
        assert len(result["categories"]) > 0

    def test_all_expected_categories_present(self) -> None:
        result = get_prompts_list()
        for cat in ["workflow", "recon", "vuln-assessment", "reporting", "stealth", "quick"]:
            assert cat in result["categories"]

    def test_by_category_keys_match_categories(self) -> None:
        result = get_prompts_list()
        assert set(result["by_category"].keys()) == set(result["categories"])

    def test_by_category_prompts_sum_equals_total(self) -> None:
        result = get_prompts_list()
        total_in_groups = sum(len(v) for v in result["by_category"].values())
        assert total_in_groups == result["total"]

    def test_each_prompt_has_required_fields(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            assert "name" in prompt, f"missing 'name' in {prompt}"
            assert "category" in prompt, f"missing 'category' in {prompt}"
            assert "description" in prompt, f"missing 'description' in {prompt}"
            assert "parameters" in prompt, f"missing 'parameters' in {prompt}"

    def test_prompt_names_are_non_empty_strings(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            assert isinstance(prompt["name"], str)
            assert len(prompt["name"]) > 0

    def test_prompt_descriptions_are_non_empty_strings(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            assert isinstance(prompt["description"], str)
            assert len(prompt["description"]) > 0

    def test_prompt_categories_are_valid(self) -> None:
        result = get_prompts_list()
        valid_categories = set(result["categories"])
        for prompt in result["prompts"]:
            assert prompt["category"] in valid_categories

    def test_parameters_is_list(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            assert isinstance(prompt["parameters"], list)

    def test_each_parameter_has_name_and_required(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            for param in prompt["parameters"]:
                assert "name" in param, f"param missing 'name' in {prompt['name']}"
                assert "required" in param, f"param missing 'required' in {prompt['name']}"

    def test_required_params_have_null_default(self) -> None:
        result = get_prompts_list()
        for prompt in result["prompts"]:
            for param in prompt["parameters"]:
                if param["required"]:
                    assert param["default"] is None, (
                        f"required param '{param['name']}' in '{prompt['name']}' "
                        f"should have default=None"
                    )

    def test_prompt_names_are_unique(self) -> None:
        result = get_prompts_list()
        names = [p["name"] for p in result["prompts"]]
        assert len(names) == len(set(names)), "duplicate prompt names found"

    def test_result_is_json_serialisable(self) -> None:
        result = get_prompts_list()
        serialised = json.dumps(result)
        assert len(serialised) > 0

    def test_known_prompts_present(self) -> None:
        result = get_prompts_list()
        names = {p["name"] for p in result["prompts"]}
        for expected in [
            "full_pentest",
            "quick_recon",
            "web_app_assessment",
            "osint_investigation",
            "assess_injection",
            "executive_report",
            "stealth_assessment",
            "opsec_checklist",
            "find_vulns",
            "pwn_target",
        ]:
            assert expected in names, f"expected prompt '{expected}' not found"


# ---------------------------------------------------------------------------
# TestGetPromptsByCategory
# ---------------------------------------------------------------------------


class TestGetPromptsByCategory:
    def test_returns_list_for_valid_category(self) -> None:
        result = get_prompts_by_category("workflow")
        assert isinstance(result, list)

    def test_returns_none_for_unknown_category(self) -> None:
        result = get_prompts_by_category("nonexistent")
        assert result is None

    def test_returns_none_for_empty_string(self) -> None:
        result = get_prompts_by_category("")
        assert result is None

    def test_all_results_have_correct_category(self) -> None:
        for category in _CATEGORIES:
            prompts = get_prompts_by_category(category)
            assert prompts is not None
            for prompt in prompts:
                assert prompt["category"] == category

    def test_workflow_category_non_empty(self) -> None:
        result = get_prompts_by_category("workflow")
        assert result is not None
        assert len(result) > 0

    def test_recon_category_non_empty(self) -> None:
        result = get_prompts_by_category("recon")
        assert result is not None
        assert len(result) > 0

    def test_vuln_assessment_category_non_empty(self) -> None:
        result = get_prompts_by_category("vuln-assessment")
        assert result is not None
        assert len(result) > 0

    def test_reporting_category_non_empty(self) -> None:
        result = get_prompts_by_category("reporting")
        assert result is not None
        assert len(result) > 0

    def test_stealth_category_non_empty(self) -> None:
        result = get_prompts_by_category("stealth")
        assert result is not None
        assert len(result) > 0

    def test_quick_category_non_empty(self) -> None:
        result = get_prompts_by_category("quick")
        assert result is not None
        assert len(result) > 0

    def test_all_categories_sum_equals_total(self) -> None:
        total = sum(len(get_prompts_by_category(c) or []) for c in _CATEGORIES)
        assert total == len(_PROMPTS)

    def test_full_pentest_in_workflow(self) -> None:
        result = get_prompts_by_category("workflow")
        assert result is not None
        names = {p["name"] for p in result}
        assert "full_pentest" in names

    def test_osint_investigation_in_recon(self) -> None:
        result = get_prompts_by_category("recon")
        assert result is not None
        names = {p["name"] for p in result}
        assert "osint_investigation" in names

    def test_reporting_has_seven_prompts(self) -> None:
        result = get_prompts_by_category("reporting")
        assert result is not None
        assert len(result) == 7

    def test_quick_has_nine_prompts(self) -> None:
        result = get_prompts_by_category("quick")
        assert result is not None
        assert len(result) == 9

    def test_opsec_checklist_has_no_parameters(self) -> None:
        result = get_prompts_by_category("stealth")
        assert result is not None
        opsec = next((p for p in result if p["name"] == "opsec_checklist"), None)
        assert opsec is not None
        assert opsec["parameters"] == []


# ---------------------------------------------------------------------------
# TestListCategories
# ---------------------------------------------------------------------------


class TestListCategories:
    def test_returns_list(self) -> None:
        result = list_categories()
        assert isinstance(result, list)

    def test_non_empty(self) -> None:
        result = list_categories()
        assert len(result) > 0

    def test_returns_copy(self) -> None:
        result1 = list_categories()
        result2 = list_categories()
        result1.append("extra")
        assert "extra" not in result2

    def test_all_strings(self) -> None:
        for cat in list_categories():
            assert isinstance(cat, str)
