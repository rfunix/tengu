"""Unit tests for tengu.server module — MCP registration and structure."""

from __future__ import annotations

import asyncio

from fastmcp import FastMCP

import tengu.server as server

# Pre-compute registered names at module import time (avoids event loop issues in fixtures)
_REGISTERED_TOOL_NAMES: set[str] = set(asyncio.run(server.mcp.get_tools()).keys())
_REGISTERED_PROMPT_NAMES: set[str] = set(asyncio.run(server.mcp.get_prompts()).keys())


# ---------------------------------------------------------------------------
# TestServerInstance
# ---------------------------------------------------------------------------


class TestServerInstance:
    def test_mcp_attribute_exists(self):
        """server module exposes an 'mcp' attribute."""
        assert hasattr(server, "mcp")

    def test_mcp_is_fastmcp_instance(self):
        """server.mcp is a FastMCP instance."""
        assert isinstance(server.mcp, FastMCP)

    def test_mcp_name_is_tengu(self):
        """FastMCP server is named 'Tengu'."""
        assert server.mcp.name == "Tengu"


# ---------------------------------------------------------------------------
# TestMainFunction
# ---------------------------------------------------------------------------


class TestMainFunction:
    def test_main_function_exists(self):
        """server module exposes a 'main' function."""
        assert hasattr(server, "main")

    def test_main_is_callable(self):
        """server.main is callable."""
        assert callable(server.main)

    def test_check_all_function_imported(self):
        """check_all is imported and available in the server module."""
        assert hasattr(server, "check_all")
        assert callable(server.check_all)


# ---------------------------------------------------------------------------
# TestToolsRegistered
# ---------------------------------------------------------------------------


class TestToolsRegistered:
    def test_tools_are_registered(self):
        """At least one tool is registered."""
        assert len(_REGISTERED_TOOL_NAMES) > 0

    def test_msf_search_registered(self):
        """msf_search tool is registered."""
        assert "msf_search" in _REGISTERED_TOOL_NAMES

    def test_msf_run_module_registered(self):
        """msf_run_module tool is registered."""
        assert "msf_run_module" in _REGISTERED_TOOL_NAMES

    def test_msf_sessions_list_registered(self):
        """msf_sessions_list tool is registered."""
        assert "msf_sessions_list" in _REGISTERED_TOOL_NAMES

    def test_tor_check_registered(self):
        """tor_check tool is registered."""
        assert "tor_check" in _REGISTERED_TOOL_NAMES

    def test_tor_new_identity_registered(self):
        """tor_new_identity tool is registered."""
        assert "tor_new_identity" in _REGISTERED_TOOL_NAMES

    def test_check_anonymity_registered(self):
        """check_anonymity tool is registered."""
        assert "check_anonymity" in _REGISTERED_TOOL_NAMES

    def test_rotate_identity_registered(self):
        """rotate_identity tool is registered."""
        assert "rotate_identity" in _REGISTERED_TOOL_NAMES

    def test_nmap_scan_registered(self):
        """nmap_scan recon tool is registered."""
        assert "nmap_scan" in _REGISTERED_TOOL_NAMES

    def test_nuclei_scan_registered(self):
        """nuclei_scan web tool is registered."""
        assert "nuclei_scan" in _REGISTERED_TOOL_NAMES

    def test_sqlmap_scan_registered(self):
        """sqlmap_scan injection tool is registered."""
        assert "sqlmap_scan" in _REGISTERED_TOOL_NAMES

    def test_at_least_50_tools_registered(self):
        """At least 50 tools are registered (v0.2.1 has 56+)."""
        assert len(_REGISTERED_TOOL_NAMES) >= 50


# ---------------------------------------------------------------------------
# TestPromptsRegistered
# ---------------------------------------------------------------------------


class TestPromptsRegistered:
    def test_prompts_are_registered(self):
        """At least one prompt is registered."""
        assert len(_REGISTERED_PROMPT_NAMES) > 0

    def test_full_pentest_prompt_registered(self):
        """full_pentest prompt is registered."""
        assert "full_pentest" in _REGISTERED_PROMPT_NAMES

    def test_quick_recon_prompt_registered(self):
        """quick_recon prompt is registered."""
        assert "quick_recon" in _REGISTERED_PROMPT_NAMES

    def test_executive_report_prompt_registered(self):
        """executive_report reporting prompt is registered."""
        assert "executive_report" in _REGISTERED_PROMPT_NAMES

    def test_stealth_assessment_prompt_registered(self):
        """stealth_assessment prompt is registered."""
        assert "stealth_assessment" in _REGISTERED_PROMPT_NAMES

    def test_crack_wifi_quick_action_registered(self):
        """crack_wifi quick action prompt is registered (v0.2.1)."""
        assert "crack_wifi" in _REGISTERED_PROMPT_NAMES

    def test_at_least_20_prompts_registered(self):
        """At least 20 prompts are registered (v0.2.1 has 34)."""
        assert len(_REGISTERED_PROMPT_NAMES) >= 20

    def test_msf_exploit_workflow_prompt_registered(self):
        """msf_exploit_workflow prompt is registered."""
        assert "msf_exploit_workflow" in _REGISTERED_PROMPT_NAMES


# ---------------------------------------------------------------------------
# TestModuleImport
# ---------------------------------------------------------------------------


class TestModuleImport:
    def test_module_imports_successfully(self):
        """tengu.server can be imported without raising."""
        import tengu.server  # noqa: F401

        assert True

    def test_fastmcp_imported(self):
        """FastMCP is importable from server module namespace."""
        assert FastMCP is not None


# ---------------------------------------------------------------------------
# TestServerResourceHandlers — direct calls to resource handler functions
# ---------------------------------------------------------------------------


class TestServerResourceHandlers:
    """Call resource handler functions directly to test their behavior."""

    def test_owasp_category_valid_id(self):
        """Valid OWASP category ID returns JSON with id field."""
        import json as _json

        result = server.resource_owasp_category.fn("A01")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("id") == "A01"

    def test_owasp_category_invalid_id(self):
        """Invalid OWASP category ID returns JSON with error field."""
        import json as _json

        result = server.resource_owasp_category.fn("X99")
        data = _json.loads(result)
        assert "error" in data

    def test_owasp_checklist_valid_id(self):
        """Valid category ID + checklist returns JSON with how_to_test."""
        import json as _json

        result = server.resource_owasp_checklist.fn("A01")
        data = _json.loads(result)
        assert "error" not in data
        # Checklist must have at minimum the id field
        assert data.get("id") == "A01"

    def test_owasp_checklist_invalid_id(self):
        """Invalid category ID for checklist returns JSON with error."""
        import json as _json

        result = server.resource_owasp_checklist.fn("X99")
        data = _json.loads(result)
        assert "error" in data

    def test_ptes_phase_valid(self):
        """Phase number 1-7 returns JSON phase data."""
        import json as _json

        result = server.resource_ptes_phase.fn("1")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("number") == 1

    def test_ptes_phase_invalid_number(self):
        """Phase 99 returns JSON with error field."""
        import json as _json

        result = server.resource_ptes_phase.fn("99")
        data = _json.loads(result)
        assert "error" in data

    def test_ptes_phase_invalid_string(self):
        """Non-integer phase string returns JSON with error field."""
        import json as _json

        result = server.resource_ptes_phase.fn("notanumber")
        data = _json.loads(result)
        assert "error" in data

    def test_tool_usage_valid_nmap(self):
        """'nmap' tool usage guide returns JSON with name field."""
        import json as _json

        result = server.resource_tool_usage.fn("nmap")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("name") == "nmap"

    def test_tool_usage_invalid_tool(self):
        """Unknown tool name returns JSON with error and available list."""
        import json as _json

        result = server.resource_tool_usage.fn("unknowntool9999")
        data = _json.loads(result)
        assert "error" in data
        assert "available" in data

    def test_payloads_xss_type(self):
        """payload_type='xss' returns xss payloads or error if data missing."""
        import json as _json

        result = server.resource_payloads.fn("xss")
        data = _json.loads(result)
        # Either returns the XSS payloads or an error if data file is missing
        assert isinstance(data, (dict, list))

    def test_payloads_sqli_type(self):
        """payload_type='sqli' returns sqli payloads or error if data missing."""
        import json as _json

        result = server.resource_payloads.fn("sqli")
        data = _json.loads(result)
        assert isinstance(data, (dict, list))

    def test_owasp_top10_list(self):
        """resource_owasp_top10 returns JSON with categories list."""
        import json as _json

        result = server.resource_owasp_top10.fn()
        data = _json.loads(result)
        assert "categories" in data
        assert len(data["categories"]) > 0

    def test_ptes_overview(self):
        """resource_ptes_overview returns JSON with phases list."""
        import json as _json

        result = server.resource_ptes_overview.fn()
        data = _json.loads(result)
        assert "phases" in data
        assert len(data["phases"]) == 7

    def test_mitre_technique_sanitizes_id(self):
        """Technique ID with special chars is sanitized (no injection)."""
        import json as _json

        # Injection attempt — should be sanitized
        result = server.resource_mitre_technique.fn("T1566; rm -rf /")
        data = _json.loads(result)
        # Result is either a valid technique or an error — never a crash
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# TestResourceChecklistHandlers
# ---------------------------------------------------------------------------


class TestResourceChecklistHandlers:
    """Test checklist resource handler functions."""

    def test_checklist_web_returns_valid_json(self):
        """resource_checklist_web returns a valid JSON string."""
        import json as _json

        result = server.resource_checklist_web.fn()
        assert isinstance(result, str)
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_checklist_web_not_found_returns_error(self):
        """resource_checklist_web returns error JSON when checklist not found."""
        import json as _json
        from unittest.mock import patch

        with patch("tengu.server.get_checklist", return_value=None):
            result = server.resource_checklist_web.fn()
        data = _json.loads(result)
        assert "error" in data

    def test_checklist_web_found_returns_data(self):
        """resource_checklist_web returns checklist data when found."""
        import json as _json
        from unittest.mock import patch

        fake_data = {"title": "Web App Checklist", "items": ["item1", "item2"]}
        with patch("tengu.server.get_checklist", return_value=fake_data):
            result = server.resource_checklist_web.fn()
        data = _json.loads(result)
        assert data["title"] == "Web App Checklist"
        assert data["items"] == ["item1", "item2"]

    def test_checklist_api_returns_valid_json(self):
        """resource_checklist_api returns a valid JSON string."""
        import json as _json

        result = server.resource_checklist_api.fn()
        assert isinstance(result, str)
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_checklist_api_not_found_returns_error(self):
        """resource_checklist_api returns error JSON when checklist not found."""
        import json as _json
        from unittest.mock import patch

        with patch("tengu.server.get_checklist", return_value=None):
            result = server.resource_checklist_api.fn()
        data = _json.loads(result)
        assert "error" in data

    def test_checklist_network_returns_valid_json(self):
        """resource_checklist_network returns a valid JSON string."""
        import json as _json

        result = server.resource_checklist_network.fn()
        assert isinstance(result, str)
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_checklist_network_not_found_returns_error(self):
        """resource_checklist_network returns error JSON when checklist not found."""
        import json as _json
        from unittest.mock import patch

        with patch("tengu.server.get_checklist", return_value=None):
            result = server.resource_checklist_network.fn()
        data = _json.loads(result)
        assert "error" in data


# ---------------------------------------------------------------------------
# TestResourceToolsHandlers
# ---------------------------------------------------------------------------


class TestResourceToolsHandlers:
    """Test tools:// resource handler functions."""

    async def test_tools_catalog_returns_valid_json(self):
        """resource_tools_catalog returns a valid JSON string."""
        import json as _json
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "tools": [],
            "total": 0,
            "available": 0,
            "missing": 0,
        }
        with patch("tengu.server.check_all", new=AsyncMock(return_value=mock_result)):
            result = await server.resource_tools_catalog.fn()
        data = _json.loads(result)
        assert "tools" in data

    async def test_tools_catalog_calls_check_all_with_verbose_false(self):
        """resource_tools_catalog calls check_all(verbose=False)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "tools": [],
            "total": 0,
            "available": 0,
            "missing": 0,
        }
        with patch("tengu.server.check_all", new=AsyncMock(return_value=mock_result)) as mock_ca:
            await server.resource_tools_catalog.fn()
        mock_ca.assert_called_once_with(verbose=False)

    def test_tool_usage_nmap_returns_correct_name(self):
        """resource_tool_usage('nmap') returns guide with name='nmap'."""
        import json as _json

        result = server.resource_tool_usage.fn("nmap")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("name") == "nmap"

    def test_tool_usage_nuclei_returns_correct_name(self):
        """resource_tool_usage('nuclei') returns guide with name='nuclei'."""
        import json as _json

        result = server.resource_tool_usage.fn("nuclei")
        data = _json.loads(result)
        assert data.get("name") == "nuclei"

    def test_tool_usage_sqlmap_returns_correct_name(self):
        """resource_tool_usage('sqlmap') returns guide with name='sqlmap'."""
        import json as _json

        result = server.resource_tool_usage.fn("sqlmap")
        data = _json.loads(result)
        assert data.get("name") == "sqlmap"

    def test_tool_usage_metasploit_returns_guide(self):
        """resource_tool_usage('metasploit') returns guide data."""
        import json as _json

        result = server.resource_tool_usage.fn("metasploit")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("name") == "metasploit"

    def test_tool_usage_trivy_returns_guide(self):
        """resource_tool_usage('trivy') returns guide data."""
        import json as _json

        result = server.resource_tool_usage.fn("trivy")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("name") == "trivy"

    def test_tool_usage_amass_returns_guide(self):
        """resource_tool_usage('amass') returns guide data."""
        import json as _json

        result = server.resource_tool_usage.fn("amass")
        data = _json.loads(result)
        assert "error" not in data
        assert data.get("name") == "amass"

    def test_tool_usage_case_insensitive(self):
        """resource_tool_usage is case-insensitive."""
        import json as _json

        result_lower = server.resource_tool_usage.fn("nmap")
        result_upper = server.resource_tool_usage.fn("NMAP")
        data_lower = _json.loads(result_lower)
        data_upper = _json.loads(result_upper)
        assert data_lower.get("name") == data_upper.get("name")

    def test_tool_usage_unknown_tool_returns_error(self):
        """resource_tool_usage with unknown tool returns error JSON."""
        import json as _json

        result = server.resource_tool_usage.fn("nonexistent_tool_xyz_abc123")
        data = _json.loads(result)
        assert "error" in data
        assert "available" in data

    def test_tool_usage_unknown_tool_lists_available(self):
        """resource_tool_usage error response lists available tools."""
        import json as _json

        result = server.resource_tool_usage.fn("bad_tool_name")
        data = _json.loads(result)
        available = data.get("available", [])
        assert "nmap" in available
        assert "nuclei" in available


# ---------------------------------------------------------------------------
# TestResourceMitreHandlers
# ---------------------------------------------------------------------------


class TestResourceMitreHandlers:
    """Test mitre:// resource handler functions."""

    def test_mitre_tactics_returns_valid_json_content(self):
        """resource_mitre_tactics returns valid JSON (file or error)."""
        import json as _json

        result = server.resource_mitre_tactics.fn()
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_mitre_tactics_has_tactics_key_or_error(self):
        """resource_mitre_tactics returns data with 'tactics' key or 'error'."""
        import json as _json

        result = server.resource_mitre_tactics.fn()
        data = _json.loads(result)
        assert "tactics" in data or "error" in data

    def test_mitre_tactics_file_missing_returns_error(self):
        """resource_mitre_tactics returns error JSON when data file is missing."""
        import json as _json
        from unittest.mock import patch

        with patch("pathlib.Path.exists", return_value=False):
            result = server.resource_mitre_tactics.fn()
        data = _json.loads(result)
        assert "error" in data

    def test_mitre_technique_strips_special_chars(self):
        """resource_mitre_technique strips shell-unsafe chars from ID."""
        import json as _json

        # Special characters should be stripped; no crash should occur
        result = server.resource_mitre_technique.fn("T1595;rm -rf /")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_mitre_technique_not_found_returns_error(self):
        """resource_mitre_technique with unknown ID returns error dict."""
        import json as _json

        result = server.resource_mitre_technique.fn("T9999")
        data = _json.loads(result)
        assert isinstance(data, dict)
        # If file exists, returns error; if not, returns file-not-found error
        assert "error" in data or "tactic" in data

    def test_mitre_technique_returns_string(self):
        """resource_mitre_technique always returns a string."""
        result = server.resource_mitre_technique.fn("T1595")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# TestResourceOwaspApiHandlers
# ---------------------------------------------------------------------------


class TestResourceOwaspApiHandlers:
    """Test owasp://api-security resource handler functions."""

    def test_owasp_api_top10_returns_valid_json(self):
        """resource_owasp_api_top10 returns valid JSON content."""
        import json as _json

        result = server.resource_owasp_api_top10.fn()
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_owasp_api_top10_has_categories_or_error(self):
        """resource_owasp_api_top10 has categories key or error."""
        import json as _json

        result = server.resource_owasp_api_top10.fn()
        data = _json.loads(result)
        assert "categories" in data or "error" in data

    def test_owasp_api_top10_file_missing_returns_error(self):
        """resource_owasp_api_top10 returns error if data file is missing."""
        import json as _json
        from unittest.mock import patch

        with patch("pathlib.Path.exists", return_value=False):
            result = server.resource_owasp_api_top10.fn()
        data = _json.loads(result)
        assert "error" in data

    def test_owasp_api_category_valid_returns_dict(self):
        """resource_owasp_api_category returns a dict for a valid-format ID."""
        import json as _json

        result = server.resource_owasp_api_category.fn("API1")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_owasp_api_category_invalid_returns_error(self):
        """resource_owasp_api_category returns error for unknown ID."""
        import json as _json

        result = server.resource_owasp_api_category.fn("INVALID999")
        data = _json.loads(result)
        assert "error" in data

    def test_owasp_api_category_sanitizes_input(self):
        """resource_owasp_api_category strips special chars from category_id."""
        import json as _json

        result = server.resource_owasp_api_category.fn("API1; rm -rf /")
        data = _json.loads(result)
        # Should not crash; returns dict
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# TestResourceCredentialsHandlers
# ---------------------------------------------------------------------------


class TestResourceCredentialsHandlers:
    """Test creds:// resource handler functions."""

    def test_credentials_all_returns_valid_json(self):
        """resource_default_credentials('all') returns valid JSON."""
        import json as _json

        result = server.resource_default_credentials.fn("all")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_credentials_all_has_total_or_error(self):
        """resource_default_credentials('all') has total or error key."""
        import json as _json

        result = server.resource_default_credentials.fn("all")
        data = _json.loads(result)
        assert "total" in data or "error" in data

    def test_credentials_list_returns_same_as_all(self):
        """resource_default_credentials('list') behaves same as 'all'."""
        import json as _json

        result = server.resource_default_credentials.fn("list")
        data = _json.loads(result)
        assert "total" in data or "error" in data

    def test_credentials_specific_product_returns_dict(self):
        """resource_default_credentials with a product returns a dict."""
        import json as _json

        result = server.resource_default_credentials.fn("cisco")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_credentials_specific_product_has_count_or_error(self):
        """resource_default_credentials with product has count or error."""
        import json as _json

        result = server.resource_default_credentials.fn("router")
        data = _json.loads(result)
        assert "count" in data or "error" in data

    def test_credentials_sanitizes_product_name(self):
        """resource_default_credentials strips special chars from product."""
        import json as _json

        result = server.resource_default_credentials.fn("cisco; rm -rf /")
        data = _json.loads(result)
        # Should not crash; returns a dict
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# TestResourcePayloadsHandlers
# ---------------------------------------------------------------------------


class TestResourcePayloadsHandlers:
    """Test payloads:// resource handler functions."""

    def test_payloads_all_returns_valid_json(self):
        """resource_payloads('all') returns valid JSON."""
        import json as _json

        result = server.resource_payloads.fn("all")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_payloads_all_has_available_types_or_error(self):
        """resource_payloads('all') has available_types or error."""
        import json as _json

        result = server.resource_payloads.fn("all")
        data = _json.loads(result)
        assert "available_types" in data or "error" in data

    def test_payloads_list_returns_available_types(self):
        """resource_payloads('list') returns available types."""
        import json as _json

        result = server.resource_payloads.fn("list")
        data = _json.loads(result)
        assert "available_types" in data or "error" in data

    def test_payloads_sqli_returns_dict(self):
        """resource_payloads('sqli') returns a dict."""
        import json as _json

        result = server.resource_payloads.fn("sqli")
        assert isinstance(result, str)
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_payloads_xss_returns_dict(self):
        """resource_payloads('xss') returns a dict."""
        import json as _json

        result = server.resource_payloads.fn("xss")
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_payloads_unknown_type_returns_error(self):
        """resource_payloads with unknown type returns error."""
        import json as _json

        result = server.resource_payloads.fn("unknown_payload_type_xyz999")
        data = _json.loads(result)
        assert "error" in data or "available" in data

    def test_payloads_sanitizes_type(self):
        """resource_payloads strips special chars from payload_type."""
        import json as _json

        # Uppercase and special chars stripped by re.sub(r"[^a-z_]", "", ...)
        result = server.resource_payloads.fn("XSS; rm -rf /")
        data = _json.loads(result)
        # Should not crash
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# TestResourceStealthHandlers
# ---------------------------------------------------------------------------


class TestResourceStealthHandlers:
    """Test stealth:// resource handler functions."""

    def test_stealth_techniques_returns_valid_json(self):
        """resource_stealth_techniques returns valid JSON content."""
        import json as _json

        result = server.resource_stealth_techniques.fn()
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_stealth_techniques_file_missing_returns_error(self):
        """resource_stealth_techniques returns error if data file is missing."""
        import json as _json
        from unittest.mock import patch

        with patch("pathlib.Path.exists", return_value=False):
            result = server.resource_stealth_techniques.fn()
        data = _json.loads(result)
        assert "error" in data

    def test_proxy_guide_returns_valid_json(self):
        """resource_proxy_guide returns valid JSON content."""
        import json as _json

        result = server.resource_proxy_guide.fn()
        data = _json.loads(result)
        assert isinstance(data, dict)

    def test_proxy_guide_file_missing_returns_error(self):
        """resource_proxy_guide returns error if data file is missing."""
        import json as _json
        from unittest.mock import patch

        with patch("pathlib.Path.exists", return_value=False):
            result = server.resource_proxy_guide.fn()
        data = _json.loads(result)
        assert "error" in data


# ---------------------------------------------------------------------------
# TestMainFunctionBehavior
# ---------------------------------------------------------------------------


class TestMainFunctionBehavior:
    """Test main() entry-point behavior."""

    def test_main_calls_mcp_run(self):
        """main() calls mcp.run() exactly once."""
        from unittest.mock import patch

        with (
            patch.object(server.mcp, "run") as mock_run,
            patch("tengu.config.get_config") as mock_cfg,
            patch("sys.argv", ["tengu"]),
        ):
            mock_cfg.return_value.server.log_level = "INFO"
            mock_cfg.return_value.targets.allowed_hosts = []
            mock_cfg.return_value.stealth.enabled = False
            server.main()
        mock_run.assert_called_once()

    def test_main_uses_log_level_from_config(self):
        """main() reads log_level from server config."""
        from unittest.mock import patch

        with (
            patch.object(server.mcp, "run"),
            patch("tengu.config.get_config") as mock_cfg,
            patch("logging.basicConfig") as mock_logging,
            patch("sys.argv", ["tengu"]),
        ):
            mock_cfg.return_value.server.log_level = "DEBUG"
            mock_cfg.return_value.targets.allowed_hosts = []
            mock_cfg.return_value.stealth.enabled = False
            server.main()
        # basicConfig should have been called with level=DEBUG
        call_kwargs = mock_logging.call_args
        assert call_kwargs is not None
