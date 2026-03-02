"""Tengu Autonomous Pentest Agent — LangGraph + MCP.

Runs an autonomous penetration test against a target using the Tengu MCP server
as the execution toolset and Claude (Anthropic API) as the strategic brain.

The agent follows the PTES (Penetration Testing Execution Standard) methodology
across 7 phases, from intelligence gathering through final reporting.

Usage:
    uv run python autonomous_tengu.py <target> [options]

Examples:
    uv run python autonomous_tengu.py 192.168.1.100
    uv run python autonomous_tengu.py juice-shop --scope 172.20.0.0/24 --type blackbox
    uv run python autonomous_tengu.py 10.0.0.1 --max-iterations 30 --type greybox
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import operator
import os
import re
import sys
import time
from contextlib import AsyncExitStack
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import anthropic
from dotenv import load_dotenv
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from typing_extensions import TypedDict

# ── Constants ──────────────────────────────────────────────────────────────────

MODEL = "claude-sonnet-4-6"
MAX_HISTORY_IN_PROMPT = 5
MAX_OUTPUT_CHARS = 8000

# Tools that always require human approval before execution
DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {
        "msf_run_module",
        "msf_session_cmd",
        "hydra_attack",
        "impacket_kerberoast",
    }
)

# Tools that are conditionally destructive (require approval above certain thresholds)
CONDITIONAL_DESTRUCTIVE: frozenset[str] = frozenset({"sqlmap_scan"})


# ── TypedDicts ─────────────────────────────────────────────────────────────────


class ToolCall(TypedDict):
    """Record of a single MCP tool invocation."""

    tool: str
    args: dict[str, Any]
    result: Any
    timestamp: float
    error: str | None
    duration_seconds: float


class PentestState(TypedDict):
    """Full state of an autonomous pentest engagement."""

    # Target and engagement configuration
    target: str
    scope: list[str]
    engagement_type: str  # blackbox | greybox | whitebox

    # PTES methodology tracking
    current_phase: int  # 2-7 (phase 1 = pre-engagement, done before agent starts)
    ptes_phases: list[dict[str, Any]]  # Full phase data loaded from ptes://phase/{N}
    phase_completed: dict[int, bool]

    # Accumulated discoveries — Annotated[list, operator.add] for auto-append
    open_ports: Annotated[list[dict[str, Any]], operator.add]
    services: Annotated[list[dict[str, Any]], operator.add]
    subdomains: Annotated[list[str], operator.add]
    technologies: Annotated[list[str], operator.add]
    vulnerabilities: Annotated[list[dict[str, Any]], operator.add]
    findings: Annotated[list[dict[str, Any]], operator.add]

    # Tool tracking and execution history
    available_tools: list[str]
    command_history: Annotated[list[ToolCall], operator.add]

    # Next action to execute (set by strategist, consumed by executor)
    next_tool: str
    next_tool_args: dict[str, Any]
    requires_human_approval: bool
    human_decision: str | None

    # Termination state
    is_complete: bool
    error: str | None
    max_iterations: int
    iteration_count: int


# ── TenguMCPClient ─────────────────────────────────────────────────────────────


class TenguMCPClient:
    """Manages the lifecycle of an MCP connection to Tengu via stdio transport.

    Spawns a Tengu MCP server subprocess and communicates via stdin/stdout.
    The connection is managed through an AsyncExitStack for proper cleanup.
    """

    def __init__(self) -> None:
        self._exit_stack = AsyncExitStack()
        self._session: ClientSession | None = None
        self._tools_cache: list[dict[str, Any]] = []

    async def connect(self) -> None:
        """Spawn the Tengu MCP server via stdio and initialize the session."""
        server_params = StdioServerParameters(
            command="uv",
            args=["run", "tengu"],
        )
        read, write = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        session = ClientSession(read, write)
        self._session = await self._exit_stack.enter_async_context(session)
        await self._session.initialize()

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Call a Tengu MCP tool and return the parsed result.

        Attempts JSON parsing of text content; falls back to raw text dict.
        """
        if not self._session:
            raise RuntimeError("MCP client is not connected")
        result = await self._session.call_tool(name, args)
        for content in result.content:
            if hasattr(content, "text"):
                try:
                    return json.loads(content.text)
                except (json.JSONDecodeError, ValueError):
                    return {"text": content.text, "raw": content.text}
        return {}

    async def read_resource(self, uri: str) -> str:
        """Read a Tengu MCP resource and return its text content."""
        if not self._session:
            raise RuntimeError("MCP client is not connected")
        result = await self._session.read_resource(uri)  # type: ignore[arg-type]
        for content in result.contents:
            if hasattr(content, "text"):
                return str(content.text)
        return ""

    async def list_tools(self) -> list[dict[str, Any]]:
        """List all available Tengu tools in Anthropic API tool format.

        Returns tools formatted for direct use with the Anthropic messages API.
        Results are cached after the first call.
        """
        if self._tools_cache:
            return self._tools_cache
        if not self._session:
            raise RuntimeError("MCP client is not connected")
        result = await self._session.list_tools()
        tools = []
        for tool in result.tools:
            schema: dict[str, Any] = {"type": "object", "properties": {}}
            if tool.inputSchema:
                raw = tool.inputSchema
                schema = raw if isinstance(raw, dict) else dict(raw)
            tools.append(
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": schema,
                }
            )
        self._tools_cache = tools
        return tools

    async def disconnect(self) -> None:
        """Close the MCP session and release all resources."""
        await self._exit_stack.aclose()


# ── Singleton ──────────────────────────────────────────────────────────────────

_mcp_client: TenguMCPClient | None = None


def get_mcp_client() -> TenguMCPClient:
    """Return the module-level MCP client singleton, creating it if needed."""
    global _mcp_client  # noqa: PLW0603
    if _mcp_client is None:
        _mcp_client = TenguMCPClient()
    return _mcp_client


# ── Helper functions ───────────────────────────────────────────────────────────


def _extract_json_from_response(text: str) -> dict[str, Any]:
    """Extract a JSON object from an LLM response using multiple fallback strategies.

    Tries in order:
    1. Fenced ```json block
    2. Full text as JSON
    3. First JSON object found via regex
    """
    match = re.search(r"```json\s*\n(.*?)\n```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    return {}


def _get_phase_data(state: PentestState) -> dict[str, Any]:
    """Return the current PTES phase data dict from the loaded phases list."""
    phase_num = state["current_phase"]
    for phase in state.get("ptes_phases", []):
        if phase.get("number") == phase_num:
            return phase
    return {"number": phase_num, "name": f"Phase {phase_num}", "objectives": [], "activities": []}


def _is_destructive(tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Return True if this tool call requires human approval before execution."""
    if tool_name in DESTRUCTIVE_TOOLS:
        return True
    if tool_name in CONDITIONAL_DESTRUCTIVE:
        level = int(tool_args.get("level", 1))
        risk = int(tool_args.get("risk", 1))
        if level >= 3 or risk >= 2:
            return True
    return False


def build_strategist_prompt(state: PentestState) -> str:
    """Build the system prompt for the strategist (LLM brain) node."""
    phase_data = _get_phase_data(state)
    phase_num = state["current_phase"]
    phase_name = phase_data.get("name", f"Phase {phase_num}")

    objectives = phase_data.get("objectives", [])
    activities = phase_data.get("activities", [])
    recommended_tools = phase_data.get("tools", [])

    recent_history = state["command_history"][-MAX_HISTORY_IN_PROMPT:]
    history_lines = []
    for call in recent_history:
        args_preview = json.dumps(call["args"], default=str)[:120]
        status = f"error({call['error']})" if call.get("error") else "ok"
        history_lines.append(f"  - {call['tool']}({args_preview}) → {status}")
    history_str = "\n".join(history_lines) or "  (none yet)"

    vulns = state.get("vulnerabilities", [])
    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high_v = sum(1 for v in vulns if v.get("severity", "").lower() == "high")

    return f"""You are an autonomous penetration tester executing a {state["engagement_type"]} \
engagement following the PTES (Penetration Testing Execution Standard) methodology.

## Current Phase: {phase_num}/7 — {phase_name}

**Objectives:**
{chr(10).join(f"  - {o}" for o in objectives) or "  (see PTES documentation)"}

**Key Activities:**
{chr(10).join(f"  - {a}" for a in activities) or "  (see PTES documentation)"}

**Recommended Tools for This Phase:**
{", ".join(recommended_tools) if recommended_tools else "(select appropriate tools based on state)"}

## Current Engagement State

- **Target:** {state["target"]}
- **Scope:** {", ".join(state["scope"])}
- **Iteration:** {state["iteration_count"]}/{state["max_iterations"]}
- **Phases completed:** {sorted(k for k, v in state.get("phase_completed", {}).items() if v)}

### Discovered Assets
- Open ports: {len(state.get("open_ports", []))} \
({[f"{p.get("port")}/{p.get("protocol","tcp")}" for p in state.get("open_ports", [])[:10]]})
- Services: {[s.get("service", "?") for s in state.get("services", [])[:10]]}
- Technologies: {state.get("technologies", [])[:10]}
- Subdomains: {state.get("subdomains", [])[:10]}

### Findings
- Total vulnerabilities: {len(vulns)} ({crit} critical, {high_v} high)
- Total findings: {len(state.get("findings", []))}

## Recent Tool Calls (last {MAX_HISTORY_IN_PROMPT})
{history_str}

## Decision Instructions

1. Analyze the current state and decide the SINGLE best next tool to call
2. Prioritize tools that advance Phase {phase_num} objectives
3. Do NOT repeat tool calls with identical parameters from recent history
4. When Phase {phase_num} objectives are fully satisfied, select a tool for Phase {phase_num + 1} \
(the analyst will advance the phase counter automatically)
5. When ALL phases are complete, output text containing "PENTEST_COMPLETE" with no tool call. \
The system will generate the final report automatically.
6. Rate limit awareness: max 10 tool calls/min, 3 concurrent — pace your decisions

## Safety Notes
The following tools WILL pause for human approval:
- Always: msf_run_module, msf_session_cmd, hydra_attack, impacket_kerberoast
- Conditionally: sqlmap_scan with level>=3 or risk>=2
"""


def _print_banner(target: str, engagement_type: str, max_iterations: int) -> None:
    """Print the agent startup banner."""
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║            TENGU — Autonomous Pentest Agent              ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Target:      {target:<43} ║")
    print(f"║  Type:        {engagement_type:<43} ║")
    print(f"║  Max Iters:   {str(max_iterations):<43} ║")
    print("║  Methodology: PTES (7 phases)                            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def _print_summary(state: PentestState, risk_score: float, report_path: str) -> None:
    """Print the final engagement summary."""
    vulns = state.get("vulnerabilities", []) + state.get("findings", [])
    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high_v = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
    med = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")
    low = sum(1 for v in vulns if v.get("severity", "").lower() == "low")

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                    PENTEST COMPLETE                      ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Iterations:  {str(state.get('iteration_count', 0)):<43} ║")
    print(f"║  Open Ports:  {str(len(state.get('open_ports', []))):<43} ║")
    findings_str = f"{len(vulns)} ({crit} critical, {high_v} high, {med} medium, {low} low)"
    print(f"║  Findings:    {findings_str:<43} ║")
    if risk_score > 0:
        print(f"║  Risk Score:  {str(risk_score) + '/10':<43} ║")
    print(f"║  Report:      {report_path:<43} ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


# ── Graph Nodes ────────────────────────────────────────────────────────────────


async def initializer(state: PentestState) -> dict[str, Any]:
    """Initialize the MCP connection, load PTES phases, and validate the target.

    Runs exactly once at the start of each engagement. Connects to Tengu via
    stdio, loads all 7 PTES phases for context, discovers available tools,
    and verifies the target is in the allowlist.
    """
    print("\n[initializer] Connecting to Tengu MCP server...")
    client = get_mcp_client()

    try:
        await client.connect()
    except Exception as exc:
        print(f"[initializer] Fatal: could not connect to MCP server: {exc}")
        return {"error": str(exc), "is_complete": True}

    # Load all PTES phases with full details (objectives, activities, tools)
    print("[initializer] Loading PTES methodology phases...")
    ptes_phases: list[dict[str, Any]] = []
    for phase_num in range(1, 8):
        try:
            raw = await client.read_resource(f"ptes://phase/{phase_num}")
            if raw:
                phase_data = json.loads(raw)
                if isinstance(phase_data, dict) and "number" in phase_data:
                    ptes_phases.append(phase_data)
        except Exception:
            pass

    # Discover available tools — filter to only those actually installed on the system
    print("[initializer] Discovering available tools...")
    available_tool_names: list[str] = []
    try:
        tools = await client.list_tools()
        all_tool_names = {t["name"] for t in tools}

        # check_tools returns which external binaries are actually installed
        check_result = await client.call_tool("check_tools", {})
        installed = {
            t["name"]
            for t in check_result.get("tools", [])
            if t.get("available")
        }
        # Pure-Python tools (correlate, score_risk, etc.) have no binary — always available
        pure_python = {
            "check_tools", "validate_target", "correlate_findings", "score_risk",
            "cve_lookup", "cve_search", "generate_report", "analyze_headers",
            "test_cors", "dns_enumerate", "whois_lookup", "hash_identify",
            "graphql_security_check",
        }
        available_tool_names = sorted(
            all_tool_names & (installed | pure_python)
        )
        missing = sorted(all_tool_names - set(available_tool_names))
        print(f"[initializer] {len(available_tool_names)} tools available, "
              f"{len(missing)} not installed (skipped)")
    except Exception as exc:
        print(f"[initializer] Warning: tool discovery failed: {exc}")

    # Validate target is in allowlist
    print(f"[initializer] Validating target: {state['target']}")
    try:
        val_result = await client.call_tool("validate_target", {"target": state["target"]})
        if isinstance(val_result, dict) and val_result.get("allowed") is False:
            reason = val_result.get("reason", "not in allowlist")
            return {
                "error": f"Target {state['target']} is not allowed: {reason}",
                "is_complete": True,
            }
    except Exception as exc:
        print(f"[initializer] Warning: target validation failed ({exc}) — continuing")

    print(
        f"[initializer] Ready — {len(available_tool_names)} tools available, "
        f"{len(ptes_phases)} PTES phases loaded"
    )

    return {
        "ptes_phases": ptes_phases,
        "available_tools": available_tool_names,
        "current_phase": 2,
        "phase_completed": {},
        "requires_human_approval": False,
        "human_decision": None,
    }


async def strategist(state: PentestState) -> dict[str, Any]:
    """LLM brain: analyze current state and decide the next tool to execute.

    Uses Claude via the Anthropic API with Tengu's MCP tools passed as native
    tool definitions. Parses the response for a tool_use block and checks if
    the selected tool requires human approval.
    """
    if state.get("is_complete") or state.get("error"):
        return {}

    client = get_mcp_client()
    anthropic_client = anthropic.Anthropic()

    phase_data = _get_phase_data(state)
    phase_num = state["current_phase"]
    phase_name = phase_data.get("name", f"Phase {phase_num}")

    print(f"\n── PHASE {phase_num}/7: {phase_name} {'─' * (50 - len(phase_name))}")
    print("[strategist] Analyzing state and deciding next action...")

    try:
        all_tools = await client.list_tools()
        # Filter to only tools confirmed available in the initializer
        available = set(state.get("available_tools", []))
        tools = [t for t in all_tools if not available or t["name"] in available]
    except Exception as exc:
        return {"error": f"Failed to list tools: {exc}", "is_complete": True}

    system_prompt = build_strategist_prompt(state)
    user_message = (
        f"Target: {state['target']}\n"
        f"Current PTES phase: {phase_num} ({phase_name})\n"
        f"Iteration {state['iteration_count']} of {state['max_iterations']}.\n"
        f"Decide the next action. Call exactly one tool, or output PENTEST_COMPLETE."
    )

    try:
        response = anthropic_client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=system_prompt,
            tools=tools,
            messages=[{"role": "user", "content": user_message}],
        )
    except Exception as exc:
        return {"error": f"Anthropic API error in strategist: {exc}", "is_complete": True}

    for block in response.content:
        if block.type == "tool_use":
            tool_name = block.name
            tool_args = block.input if isinstance(block.input, dict) else {}
            requires_approval = _is_destructive(tool_name, tool_args)

            print(f"[strategist] Decision: {tool_name}({json.dumps(tool_args, default=str)[:100]})")
            if requires_approval:
                print(f"[strategist] ⚠ {tool_name} requires human approval")

            return {
                "next_tool": tool_name,
                "next_tool_args": tool_args,
                "requires_human_approval": requires_approval,
                "human_decision": None,
            }

        if block.type == "text" and "PENTEST_COMPLETE" in block.text:
            print("[strategist] All phases complete — triggering final report")
            return {"is_complete": True}

    # No tool selected and no completion signal — trigger report
    print("[strategist] No tool decision made — triggering report")
    return {"is_complete": True}


async def human_gate(state: PentestState) -> Command[Any]:
    """Pause execution and request human approval for destructive tool calls.

    Uses LangGraph's interrupt() to pause the graph. The caller resumes with
    Command(resume=True/False) after obtaining user consent.

    Returns:
        Command routing to "executor" (approved) or "strategist" (rejected).
    """
    tool_name = state["next_tool"]
    tool_args = state["next_tool_args"]

    # interrupt() pauses execution — the value is returned when graph is resumed
    decision = interrupt(
        {
            "tool": tool_name,
            "args": tool_args,
            "target": state["target"],
            "message": (
                f"Tool '{tool_name}' requires human approval before execution. "
                f"This tool may modify data or cause irreversible changes on the target."
            ),
        }
    )

    approved = decision is True or (
        isinstance(decision, str) and decision.strip().lower() in ("y", "yes")
    )

    if approved:
        print(f"\n[human_gate] Approved — executing {tool_name}")
        return Command(goto="executor")

    print(f"\n[human_gate] Rejected — skipping {tool_name}")
    return Command(
        goto="strategist",
        update={
            "requires_human_approval": False,
            "human_decision": "rejected",
            "next_tool": "",
            "next_tool_args": {},
        },
    )


async def executor(state: PentestState) -> dict[str, Any]:
    """Execute the MCP tool selected by the strategist.

    Calls the tool via the Tengu MCP client, records the result and metadata
    in command_history (using the Annotated reducer for auto-append), and
    increments the iteration counter.
    """
    tool_name = state["next_tool"]
    tool_args = state["next_tool_args"]

    print(f"[executor] Calling {tool_name}({json.dumps(tool_args, default=str)[:80]})")
    client = get_mcp_client()
    start = time.monotonic()
    error: str | None = None
    result: Any = {}

    try:
        result = await client.call_tool(tool_name, tool_args)
    except Exception as exc:
        error = str(exc)
        print(f"[executor] Error: {error}")
        result = {"error": error}

    duration = time.monotonic() - start
    call: ToolCall = {
        "tool": tool_name,
        "args": tool_args,
        "result": result,
        "timestamp": time.time(),
        "error": error,
        "duration_seconds": round(duration, 2),
    }

    return {
        "command_history": [call],  # Annotated[list, operator.add] — appends automatically
        "iteration_count": state["iteration_count"] + 1,
        "requires_human_approval": False,
        "human_decision": None,
    }


async def analyst(state: PentestState) -> dict[str, Any]:
    """Analyze the last tool output and extract structured findings.

    Uses Claude to parse arbitrary tool output and extract structured data:
    open ports, services, technologies, vulnerabilities, and findings.
    Also determines whether the current PTES phase objectives have been met.
    """
    if not state["command_history"]:
        return {}

    last_call = state["command_history"][-1]
    tool_name = last_call["tool"]
    raw_result = last_call["result"]

    result_str = json.dumps(raw_result, default=str)[:MAX_OUTPUT_CHARS]
    print(f"[analyst] Analyzing {tool_name} output ({len(result_str)} chars)...")

    anthropic_client = anthropic.Anthropic()
    analysis_prompt = f"""You are analyzing the output of a penetration testing tool to extract \
structured intelligence for an ongoing engagement.

**Tool executed:** {tool_name}
**Target:** {state["target"]}
**Current PTES Phase:** {state["current_phase"]}

**Tool Output:**
{result_str}

Extract data from the output and return a JSON object with ONLY the keys that have actual data.
Omit keys where the tool found nothing relevant.

{{
  "open_ports": [],      // list of {{"port": int, "protocol": str, "service": str, "version": str}}
  "services": [],        // list of {{"service": str, "port": int, "banner": str}}
  "subdomains": [],      // list of subdomain strings
  "technologies": [],    // list of "Technology/version" strings
  "vulnerabilities": [], // list of {{"title": str, "severity": str, "description": str, \
"cve_ids": [], "owasp_category": str}}
  "findings": [],        // list of {{"title": str, "severity": str, "description": str, \
"affected_asset": str, "evidence": str, "tool": "{tool_name}"}}
  "should_advance_phase": false  // true ONLY if current phase {state["current_phase"]} \
objectives are fully satisfied
}}

Respond with ONLY the JSON object. No explanation, no markdown fences."""

    try:
        response = anthropic_client.messages.create(
            model=MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": analysis_prompt}],
        )
        text = response.content[0].text if response.content else ""
        data = _extract_json_from_response(text)
    except Exception as exc:
        print(f"[analyst] Analysis error: {exc}")
        data = {}

    updates: dict[str, Any] = {}

    if data.get("open_ports"):
        count = len(data["open_ports"])
        print(f"[analyst] Extracted {count} open port(s)")
        updates["open_ports"] = data["open_ports"]

    if data.get("services"):
        updates["services"] = data["services"]

    if data.get("subdomains"):
        updates["subdomains"] = data["subdomains"]

    if data.get("technologies"):
        updates["technologies"] = data["technologies"]

    if data.get("vulnerabilities"):
        count = len(data["vulnerabilities"])
        print(f"[analyst] Extracted {count} vulnerability/vulnerabilities")
        updates["vulnerabilities"] = data["vulnerabilities"]

    if data.get("findings"):
        count = len(data["findings"])
        print(f"[analyst] Extracted {count} finding(s)")
        updates["findings"] = data["findings"]

    # Advance PTES phase if current objectives are satisfied
    if data.get("should_advance_phase"):
        cp = state["current_phase"]
        completed = {**state.get("phase_completed", {}), cp: True}
        updates["phase_completed"] = completed
        if cp < 7:
            updates["current_phase"] = cp + 1
            print(f"[analyst] Phase {cp} complete → Phase {cp + 1}")
        else:
            print("[analyst] Phase 7 (Reporting) complete — all phases covered")

    return updates


async def reporter(state: PentestState) -> dict[str, Any]:
    """Generate the final pentest report using Tengu analysis tools.

    Calls correlate_findings → score_risk → generate_report in sequence,
    then prints the engagement summary and marks the run as complete.
    """
    print("\n── PHASE 7: Reporting ──────────────────────────────────────────────")
    print("[reporter] Generating final pentest report...")

    client = get_mcp_client()
    all_findings = state.get("vulnerabilities", []) + state.get("findings", [])
    risk_score = 0.0
    report_path = (
        f"output/pentest-{state['target'].replace('/', '_')}"
        f"-{datetime.now().strftime('%Y-%m-%d')}.md"
    )

    # Step 1: Correlate findings
    if all_findings:
        try:
            print(f"[reporter] Correlating {len(all_findings)} findings...")
            await client.call_tool("correlate_findings", {"findings": all_findings})
        except Exception as exc:
            print(f"[reporter] correlate_findings error: {exc}")

    # Step 2: Score risk
    try:
        print("[reporter] Calculating risk score...")
        risk_raw = await client.call_tool(
            "score_risk",
            {
                "findings": all_findings
                or [{"title": "No findings identified", "severity": "info"}],
                "context": f"{state['engagement_type']} engagement against {state['target']}",
            },
        )
        if isinstance(risk_raw, dict):
            risk_score = float(risk_raw.get("overall_risk_score", 0.0))
    except Exception as exc:
        print(f"[reporter] score_risk error: {exc}")

    # Step 3: Generate the report
    try:
        print("[reporter] Generating markdown report...")
        tools_used = list({call["tool"] for call in state.get("command_history", [])})
        date_range = datetime.now().strftime("%Y-%m-%d")

        await client.call_tool(
            "generate_report",
            {
                "client_name": state["target"],
                "engagement_type": state["engagement_type"],
                "scope": state["scope"],
                "engagement_dates": date_range,
                "findings": all_findings,
                "executive_summary": (
                    f"Automated {state['engagement_type']} penetration test conducted against "
                    f"{state['target']} using the Tengu autonomous agent. "
                    f"{len(all_findings)} findings identified across {state['iteration_count']} "
                    f"tool executions over {state['current_phase'] - 1} PTES phases."
                ),
                "report_type": "full",
                "output_format": "markdown",
                "output_path": report_path,
                "tools_used": tools_used,
            },
        )
        print(f"[reporter] Report saved to {report_path}")
    except Exception as exc:
        print(f"[reporter] generate_report error: {exc}")

    _print_summary(state, risk_score, report_path)
    return {"is_complete": True}


# ── Routing Functions ──────────────────────────────────────────────────────────


def route_after_strategist(state: PentestState) -> str:
    """Route after strategist: reporter | human_gate | executor."""
    if state.get("is_complete") or state.get("error"):
        return "reporter"
    if state.get("requires_human_approval"):
        return "human_gate"
    return "executor"


def should_continue(state: PentestState) -> str:
    """Route after analyst: reporter | strategist."""
    if state.get("error"):
        return "reporter"
    if state.get("is_complete"):
        return "reporter"

    # All PTES phases covered — go to reporter without waiting for LLM signal
    completed = state.get("phase_completed", {})
    if all(completed.get(p) for p in range(2, 8)):
        print("\n[agent] All PTES phases (2–7) completed — triggering final report")
        return "reporter"

    if state.get("iteration_count", 0) >= state.get("max_iterations", 50):
        print(
            f"\n[agent] Maximum iterations ({state['max_iterations']}) reached "
            "— triggering final report"
        )
        return "reporter"
    return "strategist"


# ── Graph Builder ──────────────────────────────────────────────────────────────


def build_graph() -> StateGraph:
    """Build and return the LangGraph pentest agent graph (uncompiled)."""
    builder: StateGraph = StateGraph(PentestState)

    builder.add_node("initializer", initializer)
    builder.add_node("strategist", strategist)
    builder.add_node("human_gate", human_gate)
    builder.add_node("executor", executor)
    builder.add_node("analyst", analyst)
    builder.add_node("reporter", reporter)

    builder.add_edge(START, "initializer")
    builder.add_edge("initializer", "strategist")
    builder.add_conditional_edges("strategist", route_after_strategist)
    builder.add_edge("executor", "analyst")
    builder.add_conditional_edges("analyst", should_continue)
    builder.add_edge("reporter", END)

    return builder


# ── Main Runner ────────────────────────────────────────────────────────────────


async def run_agent(
    target: str,
    scope: list[str],
    engagement_type: str,
    max_iterations: int,
) -> None:
    """Compile and run the autonomous pentest graph, handling human-in-the-loop interrupts."""
    initial_state: PentestState = {
        "target": target,
        "scope": scope,
        "engagement_type": engagement_type,
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
        "max_iterations": max_iterations,
        "iteration_count": 0,
    }

    # Ensure output directory exists
    Path("output").mkdir(exist_ok=True)

    graph = build_graph().compile(checkpointer=MemorySaver())
    config: dict[str, Any] = {
        "configurable": {"thread_id": f"pentest-{target}-{int(time.time())}"},
        "recursion_limit": max_iterations * 5 + 20,
    }

    result: Any = await graph.ainvoke(initial_state, config)

    # Handle human-in-the-loop interrupts in a loop
    while isinstance(result, dict) and result.get("__interrupt__"):
        interrupts = result["__interrupt__"]
        interrupt_obj = interrupts[0]
        interrupt_data = (
            interrupt_obj.value if hasattr(interrupt_obj, "value") else interrupt_obj
        )

        print("\n" + "═" * 64)
        print("  HUMAN APPROVAL REQUIRED")
        print("═" * 64)
        print(f"  Tool:    {interrupt_data.get('tool', 'unknown')}")
        args_formatted = json.dumps(interrupt_data.get("args", {}), indent=4)
        for line in args_formatted.splitlines():
            print(f"  {line}")
        print(f"  Target:  {interrupt_data.get('target', target)}")
        print(f"  Warning: {interrupt_data.get('message', 'This action may be irreversible.')}")
        print("═" * 64)

        try:
            answer = input("Approve? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
            print("n")

        approved = answer in ("y", "yes")
        result = await graph.ainvoke(Command(resume=approved), config)

    if isinstance(result, dict) and result.get("error"):
        print(f"\n[error] Agent terminated with error: {result['error']}")


async def main() -> None:
    """Parse CLI arguments and launch the autonomous pentest agent."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="autonomous_tengu",
        description="Tengu Autonomous Pentest Agent — LangGraph + Tengu MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="Target IP address, hostname, or URL to pentest",
    )
    parser.add_argument(
        "--scope",
        nargs="+",
        default=None,
        metavar="HOST",
        help="In-scope targets (IPs, CIDRs, hostnames). Defaults to target.",
    )
    parser.add_argument(
        "--type",
        dest="engagement_type",
        choices=["blackbox", "greybox", "whitebox"],
        default="blackbox",
        help="Engagement type (default: blackbox)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum number of tool calls before forcing a report (default: 50)",
    )
    args = parser.parse_args()

    # Validate required environment variable
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[error] ANTHROPIC_API_KEY is not set.")
        print("        Create a .env file with ANTHROPIC_API_KEY=sk-ant-... or export it.")
        sys.exit(1)

    scope = args.scope or [args.target]
    _print_banner(args.target, args.engagement_type, args.max_iterations)

    try:
        answer = input("Confirm pentest start? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        sys.exit(0)

    if answer not in ("y", "yes"):
        print("Aborted.")
        sys.exit(0)

    print()
    client = get_mcp_client()
    try:
        await run_agent(args.target, scope, args.engagement_type, args.max_iterations)
    finally:
        with contextlib.suppress(Exception):  # anyio cancel-scope errors on shutdown are non-fatal
            await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
