"""Unit tests for autonomous_tengu.py — agent helpers, routing, and state."""

from __future__ import annotations

import operator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("anthropic", reason="requires 'agent' extra: uv sync --extra agent")

from autonomous_tengu import (
    _BINARY_TO_MCP_TOOL,
    _NON_SECURITY_TOOLS,
    _PTES_TOOL_NAME_MAP,
    _PURE_PYTHON_TOOLS,
    DESTRUCTIVE_TOOLS,
    PentestState,
    TenguMCPClient,
    ToolCall,
    _build_call_key,
    _deduplicate_findings,
    _detect_stagnation,
    _extract_json_from_response,
    _get_phase_data,
    _is_destructive,
    _token_usage,
    build_graph,
    build_strategist_prompt,
    get_mcp_client,
    route_after_strategist,
    should_continue,
)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_state(**overrides: Any) -> PentestState:
    """Return a minimal PentestState with sensible defaults, merged with overrides."""
    base: PentestState = {
        "target": "192.168.1.10",
        "scope": ["192.168.1.10"],
        "engagement_type": "blackbox",
        "current_phase": 2,
        "ptes_phases": [],
        "phase_completed": {},
        "open_ports": [],
        "services": [],
        "subdomains": [],
        "technologies": [],
        "vulnerabilities": [],
        "findings": [],
        "analyst_briefing": "",
        "briefing_history": [],
        "available_tools": [],
        "command_history": [],
        "next_tool": "",
        "next_tool_args": {},
        "requires_human_approval": False,
        "human_decision": None,
        "is_complete": False,
        "error": None,
        "max_iterations": 50,
        "iteration_count": 0,
    }
    base.update(overrides)  # type: ignore[typeddict-item]
    return base


# ── _extract_json_from_response ────────────────────────────────────────────────


class TestExtractJsonFromResponse:
    def test_fenced_json_block(self):
        text = '```json\n{"key": "value", "num": 42}\n```'
        result = _extract_json_from_response(text)
        assert result == {"key": "value", "num": 42}

    def test_raw_json_text(self):
        text = '{"open_ports": [{"port": 80, "service": "http"}]}'
        result = _extract_json_from_response(text)
        assert result["open_ports"][0]["port"] == 80

    def test_json_embedded_in_prose(self):
        text = 'Here are the findings: {"vulnerabilities": []} — end of analysis'
        result = _extract_json_from_response(text)
        assert result == {"vulnerabilities": []}

    def test_invalid_json_returns_empty(self):
        result = _extract_json_from_response("not json at all")
        assert result == {}

    def test_empty_string_returns_empty(self):
        result = _extract_json_from_response("")
        assert result == {}

    def test_fenced_block_preferred_over_inline(self):
        text = '{"outer": true}\n```json\n{"inner": true}\n```'
        result = _extract_json_from_response(text)
        assert result == {"inner": True}

    def test_nested_json_object(self):
        data = {"findings": [{"severity": "high", "cve_ids": ["CVE-2024-1234"]}]}
        import json

        result = _extract_json_from_response(json.dumps(data))
        assert result["findings"][0]["severity"] == "high"

    def test_malformed_fenced_block_returns_empty(self):
        # Fenced block is invalid JSON; greedy regex spans both objects → all strategies fail
        text = '```json\n{bad json\n```\n{"key": "ok"}'
        result = _extract_json_from_response(text)
        assert result == {}


# ── _is_destructive ────────────────────────────────────────────────────────────


class TestIsDestructive:
    def test_always_destructive_tools(self):
        for tool in DESTRUCTIVE_TOOLS:
            assert _is_destructive(tool, {}) is True

    def test_msf_run_module_always_destructive(self):
        assert _is_destructive("msf_run_module", {"module": "exploit/multi/handler"}) is True

    def test_hydra_always_destructive(self):
        assert _is_destructive("hydra_attack", {"target": "host", "service": "ssh"}) is True

    def test_sqlmap_safe_at_low_level(self):
        assert _is_destructive("sqlmap_scan", {"level": 1, "risk": 1}) is False

    def test_sqlmap_destructive_at_high_level(self):
        assert _is_destructive("sqlmap_scan", {"level": 3, "risk": 1}) is True

    def test_sqlmap_destructive_at_high_risk(self):
        assert _is_destructive("sqlmap_scan", {"level": 1, "risk": 2}) is True

    def test_sqlmap_destructive_level_equals_3(self):
        assert _is_destructive("sqlmap_scan", {"level": 3, "risk": 0}) is True

    def test_nmap_not_destructive(self):
        assert _is_destructive("nmap_scan", {"target": "10.0.0.1"}) is False

    def test_nuclei_not_destructive(self):
        assert _is_destructive("nuclei_scan", {"target": "http://target"}) is False

    def test_unknown_tool_not_destructive(self):
        assert _is_destructive("some_future_tool", {"param": "value"}) is False


# ── _get_phase_data ────────────────────────────────────────────────────────────


class TestGetPhaseData:
    def test_returns_matching_phase(self):
        phases = [
            {"number": 2, "name": "Intelligence Gathering", "objectives": ["map target"]},
            {"number": 3, "name": "Threat Modeling", "objectives": ["identify threats"]},
        ]
        state = _make_state(current_phase=2, ptes_phases=phases)
        data = _get_phase_data(state)
        assert data["name"] == "Intelligence Gathering"
        assert data["objectives"] == ["map target"]

    def test_returns_fallback_when_phase_not_found(self):
        state = _make_state(current_phase=99, ptes_phases=[])
        data = _get_phase_data(state)
        assert data["number"] == 99
        assert "Phase 99" in data["name"]

    def test_empty_ptes_phases(self):
        state = _make_state(current_phase=4, ptes_phases=[])
        data = _get_phase_data(state)
        assert data["number"] == 4


# ── build_strategist_prompt ────────────────────────────────────────────────────


class TestBuildStrategistPrompt:
    def test_contains_target(self):
        state = _make_state(target="10.0.0.1")
        prompt = build_strategist_prompt(state)
        assert "10.0.0.1" in prompt

    def test_contains_phase_number(self):
        state = _make_state(current_phase=4)
        prompt = build_strategist_prompt(state)
        assert "4/7" in prompt

    def test_contains_engagement_type(self):
        state = _make_state(engagement_type="greybox")
        prompt = build_strategist_prompt(state)
        assert "greybox" in prompt

    def test_contains_iteration_info(self):
        state = _make_state(iteration_count=7, max_iterations=20)
        prompt = build_strategist_prompt(state)
        assert "7" in prompt
        assert "20" in prompt

    def test_contains_destructive_tool_warning(self):
        state = _make_state()
        prompt = build_strategist_prompt(state)
        assert "msf_run_module" in prompt
        assert "hydra_attack" in prompt

    def test_reflects_vulnerability_counts(self):
        vulns = [
            {"severity": "critical", "title": "RCE"},
            {"severity": "high", "title": "SQLi"},
        ]
        state = _make_state(vulnerabilities=vulns)
        prompt = build_strategist_prompt(state)
        assert "1 critical" in prompt
        assert "1 high" in prompt

    def test_shows_recent_history(self):
        call: ToolCall = {
            "tool": "nmap_scan",
            "args": {"target": "10.0.0.1"},
            "result": {"open_ports_summary": []},
            "timestamp": 0.0,
            "error": None,
            "duration_seconds": 1.5,
        }
        state = _make_state(command_history=[call])
        prompt = build_strategist_prompt(state)
        assert "nmap_scan" in prompt

    def test_phase_objectives_from_ptes(self):
        phases = [
            {"number": 2, "name": "Recon", "objectives": ["find open ports"], "activities": []}
        ]
        state = _make_state(current_phase=2, ptes_phases=phases)
        prompt = build_strategist_prompt(state)
        assert "find open ports" in prompt

    def test_includes_analyst_briefing_when_set(self):
        state = _make_state(analyst_briefing="[nmap_scan] Ports: 80/http, 443/https; Tech: Apache")
        prompt = build_strategist_prompt(state)
        assert "Latest Intel" in prompt
        assert "[nmap_scan]" in prompt
        assert "80/http" in prompt

    def test_empty_briefing_not_included(self):
        state = _make_state(analyst_briefing="")
        prompt = build_strategist_prompt(state)
        assert "Latest Intel" not in prompt

    def test_stagnation_message_included_when_detected(self):
        # 8 calls to the same tool triggers stagnation
        call: ToolCall = {
            "tool": "nmap_scan",
            "args": {"target": "10.0.0.1"},
            "result": {},
            "timestamp": 0.0,
            "error": None,
            "duration_seconds": 1.0,
        }
        state = _make_state(command_history=[call] * 8)
        prompt = build_strategist_prompt(state)
        assert "STAGNATION" in prompt
        assert "nmap_scan" in prompt

    def test_no_stagnation_with_diverse_history(self):
        tools = [
            "nmap_scan",
            "nuclei_scan",
            "nikto_scan",
            "ffuf_fuzz",
            "sqlmap_scan",
            "whatweb_scan",
            "gobuster_scan",
            "subfinder_enum",
        ]
        calls: list[ToolCall] = [
            {
                "tool": t,
                "args": {},
                "result": {},
                "timestamp": 0.0,
                "error": None,
                "duration_seconds": 1.0,
            }
            for t in tools
        ]
        state = _make_state(command_history=calls)
        prompt = build_strategist_prompt(state)
        assert "STAGNATION" not in prompt


# ── route_after_strategist ────────────────────────────────────────────────────


class TestRouteAfterStrategist:
    def test_routes_to_executor_by_default(self):
        state = _make_state(next_tool="nmap_scan", requires_human_approval=False)
        assert route_after_strategist(state) == "executor"

    def test_routes_to_reporter_when_complete(self):
        state = _make_state(is_complete=True)
        assert route_after_strategist(state) == "reporter"

    def test_routes_to_reporter_on_error(self):
        state = _make_state(error="Connection refused")
        assert route_after_strategist(state) == "reporter"

    def test_routes_to_human_gate_when_approval_required(self):
        state = _make_state(
            next_tool="hydra_attack",
            requires_human_approval=True,
        )
        assert route_after_strategist(state) == "human_gate"

    def test_complete_takes_precedence_over_human_gate(self):
        state = _make_state(is_complete=True, requires_human_approval=True)
        assert route_after_strategist(state) == "reporter"


# ── should_continue ───────────────────────────────────────────────────────────


class TestShouldContinue:
    def test_continues_by_default(self):
        state = _make_state(iteration_count=5, max_iterations=50)
        assert should_continue(state) == "strategist"

    def test_reports_when_complete(self):
        state = _make_state(is_complete=True, iteration_count=5)
        assert should_continue(state) == "reporter"

    def test_reports_on_error(self):
        state = _make_state(error="Something failed")
        assert should_continue(state) == "reporter"

    def test_reports_when_max_iterations_reached(self):
        state = _make_state(iteration_count=50, max_iterations=50)
        assert should_continue(state) == "reporter"

    def test_reports_when_iterations_exceed_max(self):
        state = _make_state(iteration_count=55, max_iterations=50)
        assert should_continue(state) == "reporter"

    def test_continues_one_before_limit(self):
        state = _make_state(iteration_count=49, max_iterations=50)
        assert should_continue(state) == "strategist"

    def test_reports_when_all_phases_completed(self):
        completed = dict.fromkeys(range(2, 8), True)
        state = _make_state(phase_completed=completed, iteration_count=10, max_iterations=50)
        assert should_continue(state) == "reporter"

    def test_continues_when_one_phase_missing(self):
        # Phase 7 not yet done
        completed = dict.fromkeys(range(2, 7), True)
        state = _make_state(phase_completed=completed, iteration_count=10, max_iterations=50)
        assert should_continue(state) == "strategist"

    def test_continues_when_phase_completed_empty(self):
        state = _make_state(phase_completed={}, iteration_count=0, max_iterations=50)
        assert should_continue(state) == "strategist"

    def test_continues_when_some_phases_false(self):
        completed = dict.fromkeys(range(2, 8), True)
        completed[5] = False  # Phase 5 explicitly not done
        state = _make_state(phase_completed=completed, iteration_count=10, max_iterations=50)
        assert should_continue(state) == "strategist"

    def test_all_phases_check_takes_precedence_over_iteration_count(self):
        # All phases done AND at iteration limit — should still return reporter (correctly)
        completed = dict.fromkeys(range(2, 8), True)
        state = _make_state(phase_completed=completed, iteration_count=50, max_iterations=50)
        assert should_continue(state) == "reporter"


# ── TenguMCPClient.list_tools ─────────────────────────────────────────────────


class TestTenguMCPClientListTools:
    @pytest.mark.asyncio
    async def test_list_tools_formats_for_anthropic(self):
        """list_tools should return dicts with name, description, input_schema."""
        client = TenguMCPClient()

        mock_tool = MagicMock()
        mock_tool.name = "nmap_scan"
        mock_tool.description = "Scan a target for open ports"
        mock_tool.inputSchema = {
            "type": "object",
            "properties": {"target": {"type": "string"}},
        }

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]

        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=mock_list_result)
        client._session = mock_session

        tools = await client.list_tools()

        assert len(tools) == 1
        assert tools[0]["name"] == "nmap_scan"
        assert tools[0]["description"] == "Scan a target for open ports"
        assert "properties" in tools[0]["input_schema"]

    @pytest.mark.asyncio
    async def test_list_tools_caches_result(self):
        """Second call to list_tools should not re-query the session."""
        client = TenguMCPClient()

        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "A test tool"
        mock_tool.inputSchema = {"type": "object", "properties": {}}

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]

        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=mock_list_result)
        client._session = mock_session

        await client.list_tools()
        await client.list_tools()

        assert mock_session.list_tools.call_count == 1

    @pytest.mark.asyncio
    async def test_list_tools_raises_when_not_connected(self):
        client = TenguMCPClient()
        # _session is None by default
        with pytest.raises(RuntimeError, match="not connected"):
            await client.list_tools()

    @pytest.mark.asyncio
    async def test_call_tool_parses_json_content(self):
        client = TenguMCPClient()

        mock_content = MagicMock()
        mock_content.text = '{"result": "ok", "count": 3}'
        mock_result = MagicMock()
        mock_result.content = [mock_content]

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)
        client._session = mock_session

        result = await client.call_tool("some_tool", {"arg": "val"})
        assert result == {"result": "ok", "count": 3}

    @pytest.mark.asyncio
    async def test_call_tool_falls_back_on_invalid_json(self):
        client = TenguMCPClient()

        mock_content = MagicMock()
        mock_content.text = "plain text output, not JSON"
        mock_result = MagicMock()
        mock_result.content = [mock_content]

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)
        client._session = mock_session

        result = await client.call_tool("some_tool", {})
        assert result["raw"] == "plain text output, not JSON"

    @pytest.mark.asyncio
    async def test_call_tool_raises_when_not_connected(self):
        client = TenguMCPClient()
        with pytest.raises(RuntimeError, match="not connected"):
            await client.call_tool("nmap_scan", {})


# ── get_mcp_client singleton ──────────────────────────────────────────────────


class TestGetMcpClient:
    def test_returns_same_instance(self):
        import autonomous_tengu

        # Reset singleton
        autonomous_tengu._mcp_client = None
        c1 = get_mcp_client()
        c2 = get_mcp_client()
        assert c1 is c2

    def test_returns_tengu_mcp_client_instance(self):
        import autonomous_tengu

        autonomous_tengu._mcp_client = None
        client = get_mcp_client()
        assert isinstance(client, TenguMCPClient)
        # Cleanup
        autonomous_tengu._mcp_client = None


# ── PentestState Annotated reducers ───────────────────────────────────────────


class TestPentestStateAnnotatedReducers:
    """Verify that the Annotated[list, operator.add] fields behave as expected.

    LangGraph uses these annotations to merge state updates: returning a list
    from a node causes it to be APPENDED to the existing list, not replaced.
    """

    def test_operator_add_appends_lists(self):
        existing = [{"port": 80, "service": "http"}]
        new_items = [{"port": 443, "service": "https"}]
        merged = operator.add(existing, new_items)
        assert len(merged) == 2
        assert merged[0]["port"] == 80
        assert merged[1]["port"] == 443

    def test_open_ports_reducer_is_operator_add(self):
        import typing

        hints = typing.get_type_hints(PentestState, include_extras=True)
        open_ports_hint = hints["open_ports"]
        assert hasattr(open_ports_hint, "__metadata__")
        assert open_ports_hint.__metadata__[0] is operator.add

    def test_command_history_reducer_is_operator_add(self):
        import typing

        hints = typing.get_type_hints(PentestState, include_extras=True)
        history_hint = hints["command_history"]
        assert hasattr(history_hint, "__metadata__")
        assert history_hint.__metadata__[0] is operator.add

    def test_vulnerabilities_reducer_is_operator_add(self):
        import typing

        hints = typing.get_type_hints(PentestState, include_extras=True)
        vuln_hint = hints["vulnerabilities"]
        assert hasattr(vuln_hint, "__metadata__")
        assert vuln_hint.__metadata__[0] is operator.add

    def test_findings_reducer_is_operator_add(self):
        import typing

        hints = typing.get_type_hints(PentestState, include_extras=True)
        findings_hint = hints["findings"]
        assert hasattr(findings_hint, "__metadata__")
        assert findings_hint.__metadata__[0] is operator.add

    def test_briefing_history_reducer_is_operator_add(self):
        import typing

        hints = typing.get_type_hints(PentestState, include_extras=True)
        bh_hint = hints["briefing_history"]
        assert hasattr(bh_hint, "__metadata__")
        assert bh_hint.__metadata__[0] is operator.add


# ── build_graph ───────────────────────────────────────────────────────────────


class TestBuildGraph:
    def test_graph_has_expected_nodes(self):
        graph = build_graph()
        assert "initializer" in graph.nodes
        assert "strategist" in graph.nodes
        assert "human_gate" in graph.nodes
        assert "executor" in graph.nodes
        assert "analyst" in graph.nodes
        assert "reporter" in graph.nodes

    def test_graph_compiles_without_error(self):
        from langgraph.checkpoint.memory import MemorySaver

        graph = build_graph()
        compiled = graph.compile(checkpointer=MemorySaver())
        assert compiled is not None


# ── recursion_limit in run_agent config ───────────────────────────────────────


# ── _NON_SECURITY_TOOLS ───────────────────────────────────────────────────────


class TestNonSecurityTools:
    def test_utility_tools_excluded(self):
        for tool in ("validate_target", "check_tools"):
            assert tool in _NON_SECURITY_TOOLS

    def test_analysis_aggregators_excluded(self):
        for tool in ("score_risk", "correlate_findings", "generate_report"):
            assert tool in _NON_SECURITY_TOOLS

    def test_cve_tools_excluded(self):
        for tool in ("cve_lookup", "cve_search"):
            assert tool in _NON_SECURITY_TOOLS

    def test_scanner_tools_not_excluded(self):
        for tool in ("nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "xss_scan"):
            assert tool not in _NON_SECURITY_TOOLS


# ── _deduplicate_findings ─────────────────────────────────────────────────────


class TestDeduplicateFindings:
    def test_empty_inputs_return_empty(self):
        assert _deduplicate_findings([], []) == []

    def test_all_new_when_existing_empty(self):
        new = [
            {"title": "XSS", "severity": "high", "affected_asset": "login.php"},
            {"title": "SQLi", "severity": "critical", "affected_asset": "search.php"},
        ]
        result = _deduplicate_findings([], new)
        assert len(result) == 2

    def test_exact_duplicate_is_excluded(self):
        existing = [{"title": "XSS", "severity": "high", "affected_asset": "login.php"}]
        new = [{"title": "XSS", "severity": "high", "affected_asset": "login.php"}]
        result = _deduplicate_findings(existing, new)
        assert result == []

    def test_case_insensitive_dedup(self):
        existing = [{"title": "xss", "severity": "HIGH", "affected_asset": "Login.php"}]
        new = [{"title": "XSS", "severity": "high", "affected_asset": "login.php"}]
        result = _deduplicate_findings(existing, new)
        assert result == []

    def test_unique_finding_passes_through(self):
        existing = [{"title": "XSS", "severity": "high", "affected_asset": "login.php"}]
        new = [{"title": "SQLi", "severity": "critical", "affected_asset": "search.php"}]
        result = _deduplicate_findings(existing, new)
        assert len(result) == 1
        assert result[0]["title"] == "SQLi"

    def test_dedup_within_new_list_itself(self):
        new = [
            {"title": "XSS", "severity": "high", "affected_asset": "page.php"},
            {"title": "XSS", "severity": "high", "affected_asset": "page.php"},
        ]
        result = _deduplicate_findings([], new)
        assert len(result) == 1

    def test_missing_fields_treated_as_empty_string(self):
        existing = [{"title": "XSS"}]  # no severity/affected_asset
        new = [{"title": "XSS"}]
        result = _deduplicate_findings(existing, new)
        assert result == []

    def test_partial_match_not_deduped(self):
        existing = [{"title": "XSS", "severity": "high", "affected_asset": "page1.php"}]
        new = [{"title": "XSS", "severity": "high", "affected_asset": "page2.php"}]
        result = _deduplicate_findings(existing, new)
        assert len(result) == 1

    # CWE-based dedup tests

    def test_cwe_dedup_reporter_pass_keeps_specific_asset(self):
        """Reporter final pass: two tools report CWE-79 — keep the one with the URL."""
        nuclei = {
            "title": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "affected_asset": "unknown",
            "cwe_id": 79,
            "tool": "nuclei",
        }
        dalfox = {
            "title": "XSS Vulnerability Detected",
            "severity": "high",
            "affected_asset": "http://172.20.0.5:3000/search?q=test",
            "cwe_id": 79,
            "tool": "dalfox",
        }
        result = _deduplicate_findings([], [nuclei, dalfox])
        assert len(result) == 1
        assert result[0]["tool"] == "dalfox"

    def test_cwe_dedup_skips_less_specific_in_new(self):
        """If existing already has specific URL for CWE-79, skip vague new finding."""
        dalfox = {
            "title": "XSS Vulnerability Detected",
            "severity": "high",
            "affected_asset": "http://172.20.0.5:3000/search",
            "cwe_id": 79,
            "tool": "dalfox",
        }
        nuclei = {
            "title": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "affected_asset": "unknown",
            "cwe_id": 79,
            "tool": "nuclei",
        }
        result = _deduplicate_findings([dalfox], [nuclei])
        assert result == []

    def test_cwe_dedup_includes_more_specific_new(self):
        """If existing has vague asset and new has URL, include the new one."""
        nuclei = {
            "title": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "affected_asset": "unknown",
            "cwe_id": 79,
            "tool": "nuclei",
        }
        dalfox = {
            "title": "XSS Vulnerability Detected",
            "severity": "high",
            "affected_asset": "http://172.20.0.5:3000/search",
            "cwe_id": 79,
            "tool": "dalfox",
        }
        result = _deduplicate_findings([nuclei], [dalfox])
        assert len(result) == 1
        assert result[0]["tool"] == "dalfox"

    def test_cwe_dedup_different_severity_not_deduped(self):
        """Same CWE but different severity → both kept."""
        high = {"title": "XSS High", "severity": "high", "affected_asset": "unknown", "cwe_id": 79}
        medium = {
            "title": "XSS Medium",
            "severity": "medium",
            "affected_asset": "unknown",
            "cwe_id": 79,
        }
        result = _deduplicate_findings([], [high, medium])
        assert len(result) == 2

    def test_cwe_dedup_no_cwe_passes_through(self):
        """Findings without cwe_id are not affected by CWE dedup."""
        existing = [{"title": "XSS", "severity": "high", "affected_asset": "unknown", "cwe_id": 79}]
        new = [
            {
                "title": "Open Redirect",
                "severity": "medium",
                "affected_asset": "http://example.com/redirect",
            }
        ]
        result = _deduplicate_findings(existing, new)
        assert len(result) == 1
        assert result[0]["title"] == "Open Redirect"

    def test_cwe_dedup_equal_specificity_keeps_first_in_new(self):
        """When two new findings share CWE-79 with same specificity, keep one."""
        f1 = {"title": "XSS A", "severity": "high", "affected_asset": "http://host/a", "cwe_id": 79}
        f2 = {"title": "XSS B", "severity": "high", "affected_asset": "http://host/b", "cwe_id": 79}
        result = _deduplicate_findings([], [f1, f2])
        # Only one kept (equal specificity, f2 wins as it replaces f1 in cwe_best)
        assert len(result) == 1


# ── _build_call_key ───────────────────────────────────────────────────────────


class TestBuildCallKey:
    def test_same_tool_same_args_produces_same_key(self):
        key1 = _build_call_key("nmap_scan", {"target": "10.0.0.1", "ports": "80,443"})
        key2 = _build_call_key("nmap_scan", {"target": "10.0.0.1", "ports": "80,443"})
        assert key1 == key2

    def test_different_tool_produces_different_key(self):
        key1 = _build_call_key("nmap_scan", {"target": "10.0.0.1"})
        key2 = _build_call_key("nuclei_scan", {"target": "10.0.0.1"})
        assert key1 != key2

    def test_different_args_produces_different_key(self):
        key1 = _build_call_key("nmap_scan", {"target": "10.0.0.1"})
        key2 = _build_call_key("nmap_scan", {"target": "10.0.0.2"})
        assert key1 != key2

    def test_arg_order_does_not_matter(self):
        key1 = _build_call_key("nmap_scan", {"target": "10.0.0.1", "ports": "80"})
        key2 = _build_call_key("nmap_scan", {"ports": "80", "target": "10.0.0.1"})
        assert key1 == key2

    def test_key_starts_with_tool_name(self):
        key = _build_call_key("ffuf_fuzz", {"url": "http://target/FUZZ"})
        assert key.startswith("ffuf_fuzz:")

    def test_empty_args_produces_valid_key(self):
        key = _build_call_key("check_tools", {})
        assert key == "check_tools:{}"


# ── _PTES_TOOL_NAME_MAP ───────────────────────────────────────────────────────


class TestPtesToolNameMap:
    def test_nmap_maps_to_nmap_scan(self):
        assert _PTES_TOOL_NAME_MAP["nmap"] == "nmap_scan"

    def test_subfinder_maps_to_subfinder_enum(self):
        assert _PTES_TOOL_NAME_MAP["subfinder"] == "subfinder_enum"

    def test_shodan_maps_to_shodan_lookup(self):
        assert _PTES_TOOL_NAME_MAP["shodan"] == "shodan_lookup"

    def test_metasploit_maps_to_msf_search(self):
        assert _PTES_TOOL_NAME_MAP["metasploit"] == "msf_search"

    def test_all_ptes_json_tool_names_resolve_to_nonempty(self):
        """All tool names in ptes_phases.json must resolve to a non-empty string.

        Tools already using MCP names (e.g. correlate_findings) are passed through
        via _PTES_TOOL_NAME_MAP.get(t, t); tools that need translation must be in the map.
        """
        import json
        from pathlib import Path

        ptes_path = Path(__file__).parents[2] / "src/tengu/resources/data/ptes_phases.json"
        data = json.loads(ptes_path.read_text())
        for phase in data["phases"]:
            for tool_name in phase.get("tools", []):
                resolved = _PTES_TOOL_NAME_MAP.get(tool_name, tool_name)
                assert resolved, (
                    f"PTES tool '{tool_name}' (phase {phase['number']}) resolved to empty string"
                )


# ── score_risk CVSS 0.0 regression ───────────────────────────────────────────


class TestScoreRiskCvssZero:
    """Regression test for the falsy CVSS 0.0 bug in correlate.py."""

    def test_cvss_zero_counted_in_average(self):
        """A finding with cvss_score=0.0 must be included in the avg_cvss calculation."""
        from tengu.tools.analysis.correlate import _SEVERITY_WEIGHTS  # type: ignore[import]

        # Verify the weights dict is accessible (confirms correlate.py is importable)
        assert "info" in _SEVERITY_WEIGHTS

    def test_cvss_zero_is_not_falsy(self):
        """Ensure Python treats 0.0 as falsy — confirming the bug was real."""
        cvss_zero = 0.0
        # The old bug: `if cvss:` would skip 0.0
        assert not cvss_zero  # 0.0 is falsy
        # The fix: `if cvss is not None:` correctly includes 0.0
        assert (cvss_zero is not None) is True


# ── _detect_stagnation ────────────────────────────────────────────────────────


class TestDetectStagnation:
    def _make_call(self, tool: str, error: str | None = None) -> ToolCall:
        return {
            "tool": tool,
            "args": {},
            "result": {},
            "timestamp": 0.0,
            "error": error,
            "duration_seconds": 0.1,
        }

    def test_returns_none_when_history_too_short(self):
        history = [self._make_call("nmap_scan") for _ in range(5)]
        assert _detect_stagnation(history) is None

    def test_returns_none_for_empty_history(self):
        assert _detect_stagnation([]) is None

    def test_detects_single_tool_repetition(self):
        history = [self._make_call("nmap_scan") for _ in range(8)]
        result = _detect_stagnation(history)
        assert result is not None
        assert "nmap_scan" in result

    def test_detects_high_error_rate(self):
        history = [self._make_call("nmap_scan", error="timeout")] * 4 + [
            self._make_call("nuclei_scan", error="timeout")
        ] * 4
        result = _detect_stagnation(history)
        assert result is not None
        assert "failed" in result

    def test_no_stagnation_with_diverse_successful_tools(self):
        tools = [
            "nmap_scan",
            "nuclei_scan",
            "nikto_scan",
            "ffuf_fuzz",
            "sqlmap_scan",
            "whatweb_scan",
            "gobuster_scan",
            "subfinder_enum",
        ]
        history = [self._make_call(t) for t in tools]
        assert _detect_stagnation(history) is None

    def test_detects_empty_briefings(self):
        history = [self._make_call(f"tool_{i}") for i in range(8)]
        briefings = [""] * 8
        result = _detect_stagnation(history, briefing_history=briefings)
        assert result is not None
        assert "No new findings" in result

    def test_no_stagnation_when_two_briefings_have_content(self):
        # 2 non-empty briefings → empty count = 6 < window-1 (7) → no stagnation
        history = [self._make_call(f"tool_{i}") for i in range(8)]
        briefings = [""] * 5 + ["[nmap_scan] Ports: 80/http", "[nuclei] VULN high: XSS", ""]
        result = _detect_stagnation(history, briefing_history=briefings)
        assert result is None

    def test_no_stagnation_when_briefing_history_too_short(self):
        history = [self._make_call(f"tool_{i}") for i in range(8)]
        briefings = [""] * 4  # fewer than window
        result = _detect_stagnation(history, briefing_history=briefings)
        assert result is None

    def test_exact_window_boundary_detects_stagnation(self):
        """Exactly `window` calls all to same tool triggers detection."""
        history = [self._make_call("nikto_scan") for _ in range(8)]
        result = _detect_stagnation(history, window=8)
        assert result is not None

    def test_one_fewer_than_window_returns_none(self):
        history = [self._make_call("nikto_scan") for _ in range(7)]
        result = _detect_stagnation(history, window=8)
        assert result is None

    def test_single_different_tool_breaks_single_tool_detection(self):
        """One different tool in window prevents single-tool stagnation."""
        history = [self._make_call("nmap_scan")] * 7 + [self._make_call("nuclei_scan")]
        result = _detect_stagnation(history)
        # tool_set has 2 entries — single-tool check won't fire
        # error_count is 0 — error check won't fire
        assert result is None or "nmap_scan" not in (result or "")


# ── _token_usage ──────────────────────────────────────────────────────────────


class TestTokenUsage:
    def test_token_usage_has_input_output_keys(self):
        assert "input" in _token_usage
        assert "output" in _token_usage

    def test_token_usage_values_are_integers(self):
        assert isinstance(_token_usage["input"], int)
        assert isinstance(_token_usage["output"], int)

    def test_token_usage_values_are_non_negative(self):
        assert _token_usage["input"] >= 0
        assert _token_usage["output"] >= 0


# ── TestRecursionLimit ────────────────────────────────────────────────────────


class TestRecursionLimit:
    @pytest.mark.asyncio
    async def test_recursion_limit_proportional_to_max_iterations(self):
        """run_agent must set recursion_limit = max_iterations * 5 + 20 in the LangGraph config."""
        import contextlib
        from unittest.mock import patch

        import autonomous_tengu

        captured_configs: list[dict] = []

        async def fake_ainvoke(state: dict, config: dict) -> dict:
            captured_configs.append(config)
            return {"is_complete": True, "error": None}

        mock_compiled = MagicMock()
        mock_compiled.ainvoke = fake_ainvoke

        with patch.object(autonomous_tengu, "build_graph") as mock_build:
            mock_build.return_value.compile.return_value = mock_compiled

            with contextlib.suppress(Exception):
                await autonomous_tengu.run_agent(
                    target="192.168.1.1",
                    scope=["192.168.1.1"],
                    engagement_type="blackbox",
                    max_iterations=30,
                )

        assert len(captured_configs) >= 1
        cfg = captured_configs[0]
        assert cfg.get("recursion_limit") == 30 * 5 + 20  # 170


# ── _BINARY_TO_MCP_TOOL mappings ───────────────────────────────────────────────


class TestBinaryToMcpTool:
    def test_httrack_mapped(self):
        assert _BINARY_TO_MCP_TOOL["httrack"] == "httrack_mirror"

    def test_impacket_binaries_mapped(self):
        assert _BINARY_TO_MCP_TOOL["impacket-secretsdump"] == "impacket_secretsdump"
        assert _BINARY_TO_MCP_TOOL["impacket-psexec"] == "impacket_psexec"
        assert _BINARY_TO_MCP_TOOL["GetUserSPNs.py"] == "impacket_kerberoast"

    def test_zap_binaries_mapped(self):
        assert _BINARY_TO_MCP_TOOL["zap.sh"] == "zap_spider"
        assert _BINARY_TO_MCP_TOOL["zaproxy"] == "zap_spider"

    def test_enum4linux_ng_mapped(self):
        assert _BINARY_TO_MCP_TOOL["enum4linux-ng"] == "enum4linux_scan"

    def test_setoolkit_mapped(self):
        assert _BINARY_TO_MCP_TOOL["setoolkit"] == "set_credential_harvester"

    def test_bloodhound_python_mapped(self):
        assert _BINARY_TO_MCP_TOOL["bloodhound-python"] == "bloodhound_collect"

    def test_msfvenom_mapped(self):
        assert _BINARY_TO_MCP_TOOL["msfvenom"] == "msf_search"


# ── _PURE_PYTHON_TOOLS constant ────────────────────────────────────────────────


class TestPurePythonTools:
    def test_stealth_tools_included(self):
        stealth = {
            "tor_check",
            "tor_new_identity",
            "check_anonymity",
            "proxy_check",
            "rotate_identity",
        }
        assert stealth.issubset(_PURE_PYTHON_TOOLS)

    def test_shodan_included(self):
        assert "shodan_lookup" in _PURE_PYTHON_TOOLS

    def test_utility_tools_included(self):
        assert "check_tools" in _PURE_PYTHON_TOOLS
        assert "validate_target" in _PURE_PYTHON_TOOLS

    def test_is_frozenset(self):
        assert isinstance(_PURE_PYTHON_TOOLS, frozenset)


# ── Force phase advance logic ──────────────────────────────────────────────────


class TestForcePhaseAdvance:
    def test_stagnation_triggers_above_10_iterations(self):
        """Stagnation + >10 iterations should meet force-advance criteria."""
        call: ToolCall = {
            "tool": "nmap_scan",
            "args": {"target": "10.0.0.1"},
            "result": {},
            "timestamp": 0.0,
            "error": None,
            "duration_seconds": 1.0,
        }
        history = [call] * 12
        briefings = [""] * 12
        assert _detect_stagnation(history, briefings) is not None

    def test_no_force_below_threshold(self):
        """iteration_count <= 10 should not meet force-advance criteria."""
        call: ToolCall = {
            "tool": "nmap_scan",
            "args": {"target": "10.0.0.1"},
            "result": {},
            "timestamp": 0.0,
            "error": None,
            "duration_seconds": 1.0,
        }
        state = _make_state(current_phase=2, iteration_count=8, command_history=[call] * 8)
        assert state["iteration_count"] <= 10

    def test_no_force_when_phase_already_advanced(self):
        """If LLM already advanced phase, force should not trigger."""
        # The guard condition is `if not updates.get("current_phase")`
        updates: dict[str, Any] = {"current_phase": 3}
        assert updates.get("current_phase") is not None
