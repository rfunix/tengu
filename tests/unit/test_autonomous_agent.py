"""Unit tests for autonomous_tengu.py — agent helpers, routing, and state."""

from __future__ import annotations

import operator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("anthropic", reason="requires 'agent' extra: uv sync --extra agent")

from autonomous_tengu import (
    DESTRUCTIVE_TOOLS,
    PentestState,
    TenguMCPClient,
    ToolCall,
    _extract_json_from_response,
    _get_phase_data,
    _is_destructive,
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
