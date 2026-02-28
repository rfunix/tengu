"""Unit tests for tengu.server module — MCP registration and structure."""

from __future__ import annotations

import asyncio

from fastmcp import FastMCP

import tengu.server as server

# Pre-compute registered names at module import time (avoids event loop issues in fixtures)
_REGISTERED_TOOL_NAMES: set[str] = {t.name for t in asyncio.run(server.mcp.list_tools())}
_REGISTERED_PROMPT_NAMES: set[str] = {p.name for p in asyncio.run(server.mcp.list_prompts())}


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
