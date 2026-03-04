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

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_TIMEOUT_MINUTES = 60
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

# Tools that do not produce security findings (utility-only or post-analysis aggregators).
# The analyst skips these — their output contains synthetic/aggregated data, not raw scan results.
_NON_SECURITY_TOOLS: frozenset[str] = frozenset({
    "validate_target",
    "check_tools",
    "correlate_findings",
    "score_risk",
    "generate_report",
    "cve_lookup",
    "cve_search",
})

# Map PTES JSON tool names to actual MCP tool function names
_PTES_TOOL_NAME_MAP: dict[str, str] = {
    "nmap": "nmap_scan",
    "subfinder": "subfinder_enum",
    "amass": "amass_enum",
    "shodan": "shodan_lookup",
    "theHarvester": "theharvester_scan",
    "nuclei": "nuclei_scan",
    "nikto": "nikto_scan",
    "sqlmap": "sqlmap_scan",
    "sslyze": "ssl_tls_check",
    "dalfox": "xss_scan",
    "metasploit": "msf_search",
    "hydra": "hydra_attack",
    "searchsploit": "searchsploit_query",
    "bloodhound": "bloodhound_collect",
    "john": "hash_crack",
    "hashcat": "hash_crack",
    "mimikatz": "impacket_secretsdump",
    "recon-ng": "theharvester_scan",  # closest Tengu equivalent
}

# Map check_tools binary names → MCP tool function names.
# check_tools returns binary names (e.g. "nmap") but MCP tools have different
# names (e.g. "nmap_scan"). Without this mapping the initializer intersection
# produces an empty set and the strategist only sees pure-Python tools.
_BINARY_TO_MCP_TOOL: dict[str, str] = {
    "nmap": "nmap_scan",
    "masscan": "masscan_scan",
    "subfinder": "subfinder_enum",
    "amass": "amass_enum",
    "dnsrecon": "dnsrecon_scan",
    "subjack": "subjack_check",
    "gowitness": "gowitness_screenshot",
    "katana": "katana_crawl",
    "httpx": "httpx_probe",
    "snmpwalk": "snmpwalk_scan",
    "rustscan": "rustscan_scan",
    "nuclei": "nuclei_scan",
    "nikto": "nikto_scan",
    "ffuf": "ffuf_fuzz",
    "sslyze": "ssl_tls_check",
    "gobuster": "gobuster_scan",
    "wpscan": "wpscan_scan",
    "testssl.sh": "testssl_check",
    "wafw00f": "wafw00f_scan",
    "feroxbuster": "feroxbuster_scan",
    "sqlmap": "sqlmap_scan",
    "dalfox": "xss_scan",
    "commix": "commix_scan",
    "crlfuzz": "crlfuzz_scan",
    "msfconsole": "msf_search",
    "searchsploit": "searchsploit_query",
    "hydra": "hydra_attack",
    "john": "hash_crack",
    "hashcat": "hash_crack",
    "cewl": "cewl_generate",
    "theharvester": "theharvester_scan",
    "whatweb": "whatweb_scan",
    "dnstwist": "dnstwist_scan",
    "trufflehog": "trufflehog_scan",
    "gitleaks": "gitleaks_scan",
    "trivy": "trivy_scan",
    "arjun": "arjun_discover",
    "enum4linux": "enum4linux_scan",
    "nxc": "nxc_enum",
    "bloodhound": "bloodhound_collect",
    "responder": "responder_capture",
    "smbmap": "smbmap_scan",
    "aircrack-ng": "aircrack_scan",
    "checkov": "checkov_scan",
    "httrack": "httrack_mirror",
    "theHarvester": "theharvester_scan",
    "msfvenom": "msf_search",
    "zap.sh": "zap_spider",
    "zaproxy": "zap_spider",
    "scout": "scoutsuite_scan",
    "prowler": "prowler_scan",
    "enum4linux-ng": "enum4linux_scan",
    "GetUserSPNs.py": "impacket_kerberoast",
    "impacket-secretsdump": "impacket_secretsdump",
    "impacket-psexec": "impacket_psexec",
    "impacket-wmiexec": "impacket_wmiexec",
    "impacket-smbclient": "impacket_smbclient",
    "bloodhound-python": "bloodhound_collect",
    "setoolkit": "set_credential_harvester",
}

_MAX_DUPLICATE_SKIPS = 3

_PURE_PYTHON_TOOLS: frozenset[str] = frozenset({
    "check_tools", "validate_target", "correlate_findings", "score_risk",
    "cve_lookup", "cve_search", "generate_report", "analyze_headers",
    "test_cors", "dns_enumerate", "whois_lookup", "hash_identify",
    "graphql_security_check",
    "tor_check", "tor_new_identity", "check_anonymity",
    "proxy_check", "rotate_identity",
    "shodan_lookup",
})


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

    # Analyst intel feed — updated after each analysis cycle
    analyst_briefing: str  # Compact summary of latest findings, fed into strategist prompt
    briefing_history: Annotated[list[str], operator.add]  # All briefings for stagnation detection

    # Tool tracking and execution history
    available_tools: list[str]
    command_history: Annotated[list[ToolCall], operator.add]

    # Next action to execute (set by strategist, consumed by executor)
    next_tool: str
    next_tool_args: dict[str, Any]
    requires_human_approval: bool
    human_decision: str | None

    # Model configuration
    model: str
    max_tokens: int

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


_NEGATIVE_FINDING_PATTERNS = (
    # Negative scan results
    "no vulnerabilities detected",
    "no vulnerabilities found",
    "no exploits found",
    "not vulnerable",
    "no injectable",
    "no issues found",
    # Tool errors / scan failures
    "scan timeout",
    "scan failed",
    "tool execution failed",
    "unsupported source",
    # Scan limitations — operational notes, not security findings
    "not authorized",
    "401 unauthorized",
    "not fully tested",
    "not properly tested",
    "parameter encoding issue",
    "parameter detection failure",
    "not present within",
    "authentication bypass - 401",
    # Negative injection results
    "no sql injection detected",
    "no injection detected",
    "injection not detected",
    "does not seem to be injectable",
    "injection not confirmed",
)


def _is_negative_finding(finding: dict[str, Any]) -> bool:
    """Return True for findings that represent negative scan results (nothing found)."""
    title = (finding.get("title") or "").lower()
    return any(pattern in title for pattern in _NEGATIVE_FINDING_PATTERNS)


def _asset_specificity(finding: dict[str, Any]) -> int:
    """Score how specific the affected_asset is. Higher = more specific."""
    asset = (finding.get("affected_asset") or "").lower().strip()
    if not asset or asset == "unknown":
        return 0
    if asset.startswith("http"):
        return 2
    return 1


def _deduplicate_findings(
    existing: list[dict[str, Any]],
    new: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return only findings from `new` not already in `existing`.

    Primary dedup key: (title_lower, severity_lower, affected_asset_lower).
    Secondary dedup key: (cwe_id, severity_lower) — prevents the same
    vulnerability reported by different tools (e.g. nuclei + dalfox both
    finding CWE-79) from appearing multiple times. When CWE collision occurs,
    the finding with the more specific asset (URL > hostname > "unknown") wins.
    """
    # Stage 1: primary dedup against existing (exact key match)
    seen: set[tuple[str, str, str]] = set()
    for f in existing:
        seen.add((
            (f.get("title") or "").lower().strip(),
            (f.get("severity") or "").lower().strip(),
            (f.get("affected_asset") or "").lower().strip(),
        ))

    candidates: list[dict[str, Any]] = []
    for f in new:
        key = (
            (f.get("title") or "").lower().strip(),
            (f.get("severity") or "").lower().strip(),
            (f.get("affected_asset") or "").lower().strip(),
        )
        if key not in seen:
            seen.add(key)
            candidates.append(f)

    # Stage 2: CWE-based dedup
    # Build best asset score per (cwe_id, severity) already in existing
    existing_cwe: dict[tuple[int, str], int] = {}
    for f in existing:
        cwe = f.get("cwe_id")
        if cwe is None:
            continue
        try:
            cwe_key = (int(cwe), (f.get("severity") or "").lower().strip())
            score = _asset_specificity(f)
            if score > existing_cwe.get(cwe_key, -1):
                existing_cwe[cwe_key] = score
        except (ValueError, TypeError):
            pass

    # Group candidates by (cwe_id, severity), keeping most specific per group
    cwe_best: dict[tuple[int, str], dict[str, Any]] = {}
    no_cwe: list[dict[str, Any]] = []
    for f in candidates:
        cwe = f.get("cwe_id")
        if cwe is None:
            no_cwe.append(f)
            continue
        try:
            cwe_key = (int(cwe), (f.get("severity") or "").lower().strip())
        except (ValueError, TypeError):
            no_cwe.append(f)
            continue
        current_best = cwe_best.get(cwe_key)
        if current_best is None or _asset_specificity(f) > _asset_specificity(current_best):
            cwe_best[cwe_key] = f

    # Accept CWE-keyed candidates only if they are more specific than existing
    cwe_winners: list[dict[str, Any]] = [
        f
        for cwe_key, f in cwe_best.items()
        if _asset_specificity(f) > existing_cwe.get(cwe_key, -1)
    ]

    return no_cwe + cwe_winners


def _build_call_key(tool: str, args: dict[str, Any]) -> str:
    """Build a stable string key for a (tool, args) pair to detect duplicate calls."""
    significant = {k: str(v)[:100] for k, v in sorted(args.items())}
    return f"{tool}:{json.dumps(significant, sort_keys=True)}"


def _detect_stagnation(
    history: list[ToolCall],
    briefing_history: list[str] | None = None,
    window: int = 8,
) -> str | None:
    """Detect if the agent is stuck in an unproductive loop.

    Checks the last `window` tool calls for three patterns:
    1. All calls to the same tool (no diversity).
    2. High error rate (>= half of calls failed).
    3. No new findings in recent calls (all briefings empty).

    Returns a human-readable stagnation message, or None if no stagnation detected.
    """
    if len(history) < window:
        return None
    recent = history[-window:]
    tool_set = {c["tool"] for c in recent}
    if len(tool_set) == 1:
        return f"Last {window} calls all to {tool_set.pop()} — try different tools"
    error_count = sum(1 for c in recent if c.get("error"))
    if error_count >= window // 2:
        return f"{error_count}/{window} recent calls failed — change approach"
    if briefing_history is not None and len(briefing_history) >= window:
        recent_briefings = briefing_history[-window:]
        empty = sum(1 for b in recent_briefings if not b)
        if empty >= window - 1:
            return f"No new findings in last {window} calls — consider advancing phase"
    return None


_RETRYABLE_STATUS_CODES = {429, 529}
_API_MAX_RETRIES = 8
_API_RETRY_BASE_DELAY = 5.0  # seconds
_API_RETRY_MAX_DELAY = 60.0  # cap per attempt (seconds)
_token_usage: dict[str, int] = {"input": 0, "output": 0}
_agent_start_time: float = 0.0


def _is_transient_api_error(exc: Exception) -> bool:
    """Return True if the exception is a transient error worth retrying.

    Covers Cloudflare bot challenges (HTML response body), connection errors,
    and standard rate-limit / overload status codes.
    """
    if isinstance(exc, anthropic.APIStatusError):
        if exc.status_code in _RETRYABLE_STATUS_CODES:
            return True
        # Cloudflare challenges come back as 403/503 with an HTML body
        body = str(exc)
        return "<!DOCTYPE html>" in body or "just a moment" in body.lower()
    # Network-level failures (timeout, DNS, connection reset) are always retryable
    return isinstance(exc, (anthropic.APIConnectionError, anthropic.APITimeoutError))


async def _call_api_with_retry(
    client: anthropic.Anthropic,
    **kwargs: Any,
) -> anthropic.types.Message:
    """Call the Anthropic API, retrying on transient errors with exponential backoff.

    Retries on: rate-limit (429), overload (529), connection errors, timeouts,
    and Cloudflare bot challenges (HTML response body instead of JSON).
    Backoff: 5s, 10s, 20s, 40s, 80s.
    """
    for attempt in range(_API_MAX_RETRIES):
        try:
            response = client.messages.create(**kwargs)
            _token_usage["input"] += response.usage.input_tokens
            _token_usage["output"] += response.usage.output_tokens
            return response
        except Exception as exc:
            if not _is_transient_api_error(exc) or attempt == _API_MAX_RETRIES - 1:
                raise
            delay = min(_API_RETRY_BASE_DELAY * (2**attempt), _API_RETRY_MAX_DELAY)
            status = getattr(exc, "status_code", "conn")
            print(
                f"[api] Transient error (HTTP {status}) — "
                f"retrying in {delay:.0f}s (attempt {attempt + 1}/{_API_MAX_RETRIES})"
            )
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")  # pragma: no cover


def build_strategist_prompt(state: PentestState) -> str:
    """Build the system prompt for the strategist (LLM brain) node."""
    phase_data = _get_phase_data(state)
    phase_num = state["current_phase"]
    phase_name = phase_data.get("name", f"Phase {phase_num}")

    objectives = phase_data.get("objectives", [])
    activities = phase_data.get("activities", [])
    recommended_tools_raw = phase_data.get("tools", [])
    recommended_tools = [_PTES_TOOL_NAME_MAP.get(t, t) for t in recommended_tools_raw]

    all_history = state["command_history"]
    recent_history = all_history[-MAX_HISTORY_IN_PROMPT:]
    older_calls = all_history[:-MAX_HISTORY_IN_PROMPT]

    history_lines = []
    for call in recent_history:
        args_preview = json.dumps(call["args"], default=str)[:120]
        status = f"error({call['error']})" if call.get("error") else "ok"
        history_lines.append(f"  - {call['tool']}({args_preview}) → {status}")
    history_str = "\n".join(history_lines) or "  (none yet)"

    older_summary = ""
    if older_calls:
        older_summary = (
            "\n\n**All prior tools used (complete history):** "
            + ", ".join(c["tool"] for c in older_calls)
        )

    vulns = state.get("vulnerabilities", [])
    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high_v = sum(1 for v in vulns if v.get("severity", "").lower() == "high")

    prompt = f"""You are an autonomous penetration tester executing a {state["engagement_type"]} \
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
{history_str}{older_summary}

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

    briefing = state.get("analyst_briefing", "")
    if briefing:
        prompt += f"\n## Latest Intel\n{briefing}\n"

    stagnation = _detect_stagnation(state["command_history"], state.get("briefing_history"))
    if stagnation:
        print(f"[strategist] STAGNATION: {stagnation}")
        prompt += f"\n## \u26a0 STAGNATION DETECTED\n{stagnation}\n"

    return prompt


def _print_banner(
    target: str,
    engagement_type: str,
    max_iterations: int,
    model: str,
    max_tokens: int,
    timeout_minutes: int,
) -> None:
    """Print the agent startup banner."""
    timeout_label = f"{timeout_minutes}m" if timeout_minutes > 0 else "unlimited"
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║            TENGU — Autonomous Pentest Agent              ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Target:      {target:<43} ║")
    print(f"║  Type:        {engagement_type:<43} ║")
    print(f"║  Max Iters:   {str(max_iterations):<43} ║")
    print(f"║  Model:       {model:<43} ║")
    print(f"║  Max Tokens:  {str(max_tokens):<43} ║")
    print(f"║  Timeout:     {timeout_label:<43} ║")
    print("║  Methodology: PTES (7 phases)                            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def _print_summary(state: PentestState, risk_score: float, report_path: str) -> None:
    """Print the final engagement summary."""
    vulns = _deduplicate_findings(
        [], state.get("vulnerabilities", []) + state.get("findings", [])
    )
    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high_v = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
    med = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")
    low = sum(1 for v in vulns if v.get("severity", "").lower() == "low")

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                    PENTEST COMPLETE                      ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Iterations:  {str(state.get('iteration_count', 0)):<43} ║")

    # Phases completed
    completed_phases = sorted(k for k, v in state.get("phase_completed", {}).items() if v)
    phases_str = ", ".join(str(p) for p in completed_phases) if completed_phases else "none"
    print(f"║  Phases:      {phases_str:<43} ║")

    # Termination reason
    if state.get("error"):
        term = f"error: {state['error'][:35]}"
    elif all(state.get("phase_completed", {}).get(p) for p in range(2, 8)):
        term = "all phases completed"
    elif state.get("iteration_count", 0) >= state.get("max_iterations", 50):
        term = "max iterations reached"
    else:
        term = "agent decided complete"
    print(f"║  Terminated:  {term:<43} ║")

    # Total duration
    if _agent_start_time > 0:
        elapsed = time.monotonic() - _agent_start_time
        mins, secs = divmod(int(elapsed), 60)
        print(f"║  Duration:    {f'{mins}m {secs}s':<43} ║")

    print(f"║  Open Ports:  {str(len(state.get('open_ports', []))):<43} ║")
    findings_str = f"{len(vulns)} ({crit} critical, {high_v} high, {med} medium, {low} low)"
    print(f"║  Findings:    {findings_str:<43} ║")
    if risk_score > 0:
        print(f"║  Risk Score:  {str(risk_score) + '/10':<43} ║")
    total_tokens = _token_usage["input"] + _token_usage["output"]
    if total_tokens > 0:
        tokens_str = (
            f"{total_tokens:,} ({_token_usage['input']:,} in, {_token_usage['output']:,} out)"
        )
        print(f"║  Tokens:      {tokens_str:<43} ║")
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

        # check_tools returns binary names (e.g. "nmap") but MCP tools use different
        # names (e.g. "nmap_scan"). Translate using _BINARY_TO_MCP_TOOL so the
        # intersection with all_tool_names (MCP names) produces the correct result.
        check_result = await client.call_tool("check_tools", {})
        installed: set[str] = set()
        for t in check_result.get("tools", []):
            if t.get("available"):
                binary = t["name"]
                mcp_name = _BINARY_TO_MCP_TOOL.get(binary, binary)
                installed.add(mcp_name)
        # Pure-Python tools (correlate, score_risk, etc.) have no binary — always available
        pure_python = set(_PURE_PYTHON_TOOLS)
        available_tool_names = sorted(
            all_tool_names & (installed | pure_python)
        )
        missing = sorted(all_tool_names - set(available_tool_names))
        print(f"[initializer] {len(available_tool_names)} tools available, "
              f"{len(missing)} not installed (skipped)")
        if available_tool_names:
            print(f"[initializer] Available: {', '.join(available_tool_names[:15])}")
        if missing:
            print(f"[initializer] Missing:   {', '.join(sorted(missing)[:5])}")
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

    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 50)
    print(f"\n── PHASE {phase_num}/7: {phase_name} {'─' * (50 - len(phase_name))}")
    print(f"[strategist] Iteration {iteration}/{max_iter} — Analyzing state...")

    try:
        all_tools = await client.list_tools()
        # Filter to only tools confirmed available in the initializer
        available = set(state.get("available_tools", []))
        if not available:
            print("[strategist] WARNING: available_tools is empty — using all tools as fallback")
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

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    consecutive_skips = 0
    history_keys = {_build_call_key(c["tool"], c["args"]) for c in state.get("command_history", [])}

    while True:
        try:
            response = await _call_api_with_retry(
                anthropic_client,
                model=state.get("model", DEFAULT_MODEL),
                max_tokens=state.get("max_tokens", DEFAULT_MAX_TOKENS),
                system=system_prompt,
                tools=tools,
                messages=messages,
            )
        except Exception as exc:
            return {"error": f"Anthropic API error in strategist: {exc}", "is_complete": True}

        is_duplicate = False
        for block in response.content:
            if block.type == "text" and "PENTEST_COMPLETE" not in block.text:
                reasoning = block.text.strip()[:200]
                if reasoning:
                    print(f"[strategist] LLM reasoning: {reasoning}")
            if block.type == "tool_use":
                tool_name = block.name
                tool_args = block.input if isinstance(block.input, dict) else {}
                call_key = _build_call_key(tool_name, tool_args)

                if call_key in history_keys:
                    consecutive_skips += 1
                    print(
                        f"[strategist] Duplicate call detected: {tool_name} "
                        f"(skip {consecutive_skips}/{_MAX_DUPLICATE_SKIPS})"
                    )
                    if consecutive_skips >= _MAX_DUPLICATE_SKIPS:
                        print(
                            f"[strategist] {_MAX_DUPLICATE_SKIPS} consecutive duplicate calls "
                            "— forcing completion"
                        )
                        return {"is_complete": True}
                    # The API requires every tool_use block to be followed by a tool_result.
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": (
                                    "SKIPPED: This tool call is a duplicate — identical "
                                    "arguments were already used in a previous iteration."
                                ),
                            },
                            {
                                "type": "text",
                                "text": (
                                    f"That exact call ({tool_name} with those arguments) was "
                                    "already executed. Choose a DIFFERENT tool or use DIFFERENT "
                                    "arguments to advance the pentest."
                                ),
                            },
                        ],
                    })
                    is_duplicate = True
                    break

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

        if is_duplicate:
            continue

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
    rejected_call: ToolCall = {
        "tool": tool_name,
        "args": tool_args,
        "result": "rejected_by_human",
        "timestamp": time.monotonic(),
        "error": "Human approval denied — tool skipped",
        "duration_seconds": 0.0,
    }
    return Command(
        goto="strategist",
        update={
            "requires_human_approval": False,
            "human_decision": "rejected",
            "next_tool": "",
            "next_tool_args": {},
            "command_history": [rejected_call],
            "iteration_count": state["iteration_count"] + 1,
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
    status_msg = f"error: {error}" if error else "ok"
    print(f"[executor] {tool_name} completed in {duration:.1f}s [{status_msg}]")
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

    # Skip calls that were rejected by human_gate — no output to analyze
    if raw_result == "rejected_by_human":
        print(f"[analyst] Skipping rejected call: {tool_name}")
        return {}

    # Fix 2: Skip utility tools — they produce no security findings
    if tool_name in _NON_SECURITY_TOOLS:
        print(f"[analyst] Skipping analysis for utility tool: {tool_name}")
        return {}

    result_str = json.dumps(raw_result, default=str)[:MAX_OUTPUT_CHARS]
    print(f"[analyst] Analyzing {tool_name} output ({len(result_str)} chars)...")

    anthropic_client = anthropic.Anthropic()
    analysis_prompt = f"""Analyze the output of a penetration testing tool and extract structured data.

**Tool:** {tool_name}
**Target:** {state["target"]}
**Phase:** {state["current_phase"]}

**Output:**
{result_str}

Return a JSON object with ONLY keys that have actual data:
{{
  "open_ports": [{{"port": int, "protocol": str, "service": str, "version": str}}],
  "services": [{{"service": str, "port": int, "banner": str}}],
  "subdomains": [str],
  "technologies": [str],
  "vulnerabilities": [{{
    "title": str, "severity": "critical"|"high"|"medium"|"low"|"info",
    "description": str, "cve_ids": [str], "owasp_category": str,
    "cvss_score": float, "cwe_id": int|null, "impact": str, "remediation_short": str
  }}],
  "findings": [{{
    "title": str, "severity": "critical"|"high"|"medium"|"low"|"info",
    "description": str, "affected_asset": str, "evidence": str,
    "tool": "{tool_name}", "cvss_score": float, "cwe_id": int|null,
    "impact": str, "steps_to_reproduce": [str],
    "remediation_short": str, "remediation_long": str, "owasp_category": str
  }}],
  "should_advance_phase": bool,
  "strategic_notes": str
}}

OWASP category — set on every finding where applicable (never leave blank for these):
- Injection (SQLi, XSS, command injection, SSTI) → "A03:2021 - Injection"
- Missing/weak TLS, cleartext transmission → "A02:2021 - Cryptographic Failures"
- CORS wildcard, missing headers, verbose errors, exposed admin → "A05:2021 - Security Misconfiguration"
- Auth bypass, weak session, JWT issues → "A07:2021 - Identification and Authentication Failures"
- Known CVE in library or component → "A06:2021 - Vulnerable and Outdated Components"
- IDOR, path traversal, privilege escalation → "A01:2021 - Broken Access Control"
- SSRF → "A10:2021 - Server-Side Request Forgery"

CVSS severity scale: critical=9.0-10.0, high=7.0-8.9, medium=4.0-6.9, low=0.1-3.9, info=0.0.
Severity rules:
- Open port or accessible service alone = INFO (0.0), never CRITICAL or HIGH.
- Elevate to HIGH/CRITICAL only when exploitation is confirmed (e.g., sqlmap confirmed injectable, XSS payload executed, auth bypassed).
- Consolidate findings with the same root cause, endpoint, and tool into a single finding — do not create duplicates.
- Exclude scan limitations (401 auth errors, parameter encoding failures, tool not-found errors) — these are not security findings.

Respond with ONLY the JSON."""

    try:
        response = await _call_api_with_retry(
            anthropic_client,
            model=state.get("model", DEFAULT_MODEL),
            max_tokens=state.get("max_tokens", DEFAULT_MAX_TOKENS),
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
        new_vulns = _deduplicate_findings(state.get("vulnerabilities", []), data["vulnerabilities"])
        skipped = len(data["vulnerabilities"]) - len(new_vulns)
        if new_vulns:
            print(f"[analyst] Extracted {len(new_vulns)} vulnerability/vulnerabilities ({skipped} duplicates skipped)")
            updates["vulnerabilities"] = new_vulns
        else:
            print(f"[analyst] All {len(data['vulnerabilities'])} vulnerabilities were duplicates — skipped")

    if data.get("findings"):
        new_findings = _deduplicate_findings(state.get("findings", []), data["findings"])
        skipped = len(data["findings"]) - len(new_findings)
        if new_findings:
            print(f"[analyst] Extracted {len(new_findings)} finding(s) ({skipped} duplicates skipped)")
            updates["findings"] = new_findings
        else:
            print(f"[analyst] All {len(data['findings'])} findings were duplicates — skipped")

    # Generate analyst briefing for the strategist's next decision
    briefing_parts: list[str] = []
    if data.get("open_ports"):
        ports_str = ", ".join(
            f"{p['port']}/{p.get('service', '?')}" for p in data["open_ports"][:5]
        )
        briefing_parts.append(f"Ports: {ports_str}")
    if data.get("vulnerabilities"):
        for v in data["vulnerabilities"][:3]:
            briefing_parts.append(f"VULN [{v.get('severity', '?')}]: {v.get('title', '?')}")
    if data.get("findings"):
        for f_item in data["findings"][:3]:
            briefing_parts.append(
                f"FINDING [{f_item.get('severity', '?')}]: {f_item.get('title', '?')}"
            )
    if data.get("technologies"):
        briefing_parts.append(f"Tech: {', '.join(str(t) for t in data['technologies'][:5])}")
    if data.get("strategic_notes"):
        briefing_parts.append(f"Note: {data['strategic_notes']}")
    briefing = f"[{tool_name}] " + "; ".join(briefing_parts) if briefing_parts else ""
    updates["analyst_briefing"] = briefing
    updates["briefing_history"] = [briefing]  # Annotated[list, operator.add] — appends
    if briefing:
        print(f"[analyst] Briefing: {briefing[:200]}")
    total_v = len(state.get("vulnerabilities", [])) + len(updates.get("vulnerabilities", []))
    total_f = len(state.get("findings", [])) + len(updates.get("findings", []))
    print(f"[analyst] Totals: {total_v} vulns, {total_f} findings, "
          f"{len(state.get('open_ports', []))} ports")

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

    # Force phase advancement when stagnating for too long
    if not updates.get("current_phase") and state["current_phase"] < 7:
        cp = state["current_phase"]
        stagnation_msg = _detect_stagnation(
            state["command_history"], state.get("briefing_history")
        )
        if stagnation_msg and state.get("iteration_count", 0) > 10:
            completed = {**state.get("phase_completed", {}), cp: True}
            updates["phase_completed"] = completed
            updates["current_phase"] = cp + 1
            print(f"[analyst] FORCED phase advance: {cp} -> {cp + 1} "
                  f"(stagnation at iteration {state.get('iteration_count', 0)})")

    return updates


async def reporter(state: PentestState) -> dict[str, Any]:
    """Generate the final pentest report using Tengu analysis tools.

    Calls correlate_findings → score_risk → generate_report in sequence,
    then prints the engagement summary and marks the run as complete.
    """
    print("\n── PHASE 7: Reporting ──────────────────────────────────────────────")
    print("[reporter] Generating final pentest report...")

    client = get_mcp_client()
    all_findings = _deduplicate_findings(
        [], state.get("vulnerabilities", []) + state.get("findings", [])
    )
    # Strip negative findings ("no vulnerabilities found", etc.) from the report
    before = len(all_findings)
    all_findings = [f for f in all_findings if not _is_negative_finding(f)]
    dropped = before - len(all_findings)
    if dropped:
        print(f"[reporter] Filtered {dropped} negative finding(s) from report")
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

        crit_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")
        med_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "medium")
        if crit_count or high_count:
            posture = "requires immediate remediation"
        elif med_count:
            posture = "presents moderate risk requiring attention"
        else:
            posture = "presents low overall risk"
        conclusion = (
            f"The {state['engagement_type']} penetration test of {state['target']} identified "
            f"{len(all_findings)} finding(s) across {state['current_phase'] - 1} PTES phases "
            f"using {len(tools_used)} tools. "
            f"The overall security posture {posture}. "
            f"Immediate remediation is recommended for all Critical and High severity findings "
            f"as detailed in the Remediation Roadmap."
        )

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
                "conclusion": conclusion,
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
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES,
    auto_approve_destructive: bool = False,
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
        "max_iterations": max_iterations,
        "iteration_count": 0,
        "model": model,
        "max_tokens": max_tokens,
    }

    # Ensure output directory exists
    Path("output").mkdir(exist_ok=True)

    graph = build_graph().compile(checkpointer=MemorySaver())
    config: dict[str, Any] = {
        "configurable": {"thread_id": f"pentest-{target}-{int(time.time())}"},
        "recursion_limit": max_iterations * 5 + 20,
    }

    global _agent_start_time
    _agent_start_time = time.monotonic()
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

        if auto_approve_destructive:
            print("[human_gate] Auto-approved via --auto-approve-destructive flag")
            approved = True
        elif not sys.stdin.isatty():
            print(
                "[human_gate] Non-interactive stdin — skipping destructive tool. "
                "Use --auto-approve-destructive to auto-approve in background runs."
            )
            approved = False
        else:
            try:
                answer = input("Approve? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[human_gate] Input interrupted — rejecting.")
                approved = False
            else:
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
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model to use for strategist and analyst (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Max tokens per API call (default: {DEFAULT_MAX_TOKENS})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_MINUTES,
        metavar="MINUTES",
        help="Total execution timeout in minutes; 0 = unlimited (default: 60)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the interactive confirmation prompt (required for non-interactive/Docker runs)",
    )
    parser.add_argument(
        "--auto-approve-destructive",
        action="store_true",
        help="Auto-approve destructive tools (sqlmap, msf, hydra) without prompting. "
        "Use only in trusted automated environments.",
    )
    args = parser.parse_args()

    # Validate required environment variable
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[error] ANTHROPIC_API_KEY is not set.")
        print("        Create a .env file with ANTHROPIC_API_KEY=sk-ant-... or export it.")
        sys.exit(1)

    scope = args.scope or [args.target]
    _print_banner(
        args.target,
        args.engagement_type,
        args.max_iterations,
        args.model,
        args.max_tokens,
        args.timeout,
    )

    if not args.yes:
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
        coro = run_agent(
            args.target,
            scope,
            args.engagement_type,
            args.max_iterations,
            model=args.model,
            max_tokens=args.max_tokens,
            timeout_minutes=args.timeout,
            auto_approve_destructive=args.auto_approve_destructive,
        )
        if args.timeout > 0:
            try:
                await asyncio.wait_for(coro, timeout=args.timeout * 60)
            except TimeoutError:
                print(f"\n[timeout] Agent exceeded {args.timeout}m limit. Stopping.")
        else:
            await coro
    finally:
        with contextlib.suppress(Exception):  # anyio cancel-scope errors on shutdown are non-fatal
            await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
