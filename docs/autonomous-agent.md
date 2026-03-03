# Autonomous Pentest Agent

Tengu includes an optional autonomous agent (`autonomous_tengu.py`) that runs a
full penetration test without human intervention at every step. You give it a
target, it follows the PTES methodology across 7 phases, and at the end it
produces a complete report.

This document explains how the agent works internally.

---

## The Three Layers

The agent is built on three distinct layers, each with a clear responsibility:

| Layer | Technology | Responsibility |
|-------|-----------|----------------|
| **Orchestration** | LangGraph | Controls the flow — which node runs, when, and in what order |
| **Reasoning** | Claude (Anthropic API) | Decides what to do next and interprets tool output |
| **Execution** | Tengu MCP server | Runs the actual pentesting tools (Nmap, Nuclei, SQLMap, etc.) |

Think of it this way: **LangGraph is the skeleton, Claude is the brain, Tengu is
the hands.**

---

## The State Machine

The agent is modelled as a **directed graph of nodes**. Each node is an async
function that receives the current engagement state, does some work, and returns
updates to that state.

```
START
  │
  ▼
initializer ──────────────────────────────────────────────────────────┐
  │                                                                    │
  ▼                                                                    │
strategist ◄──────────────────────────────────────────┐               │
  │                                                   │               │
  ├─── (destructive tool?) ──► human_gate             │               │
  │         │ approved                                │               │
  │         ▼                                         │               │
  └─────► executor                                    │               │
              │                                       │               │
              ▼                                       │               │
           analyst ──── (more phases?) ───────────────┘               │
              │                                                        │
              └──── (all phases done / max iterations?) ──► reporter ──┘
                                                               │
                                                              END
```

The loop `strategist → executor → analyst → strategist` repeats until one of
three conditions is met:

- The strategist signals `PENTEST_COMPLETE`
- The analyst confirms all PTES phases (2–7) are satisfied
- The iteration counter reaches the configured maximum

---

## Nodes in Detail

### `initializer`

Runs **once** at the start of the engagement.

1. Spawns the Tengu MCP server as a subprocess (via stdio transport)
2. Loads all 7 PTES phases from the `ptes://phase/{N}` MCP resources — these
   define objectives, activities, and recommended tools for each phase
3. Calls `check_tools` to discover which external binaries are actually installed
   on the system, so the strategist never tries to call a tool that is not there
4. Calls `validate_target` to confirm the target is in the Tengu allowlist
5. Returns the initial engagement context into the shared state

### `strategist`

The **LLM brain** of the agent.

Calls Claude (model configurable via `TENGU_AGENT_MODEL`, default `claude-sonnet-4-6`) via the Anthropic API, passing:
- A system prompt with the current PTES phase objectives, recent tool call
  history, and a snapshot of all discoveries so far (open ports, services,
  vulnerabilities, etc.)
- All available Tengu tools formatted as native Anthropic tool definitions

Claude responds with a `tool_use` block naming the next tool to call and its
arguments, or with the text `PENTEST_COMPLETE` when all objectives are satisfied.

The strategist then checks whether the chosen tool is destructive (Metasploit,
Hydra, Kerberoasting, etc.) and routes accordingly.

### `human_gate`

Handles **human-in-the-loop** for dangerous operations.

Uses LangGraph's `interrupt()` primitive to **pause the graph** and surface the
pending action to the operator. The graph is frozen in memory (via `MemorySaver`)
until a `Command(resume=True/False)` is received.

- If approved → routes to `executor`
- If rejected → routes back to `strategist` with the tool marked as skipped

Tools that always require approval:

```python
DESTRUCTIVE_TOOLS = {
    "msf_run_module",
    "msf_session_cmd",
    "hydra_attack",
    "impacket_kerberoast",
}
```

`sqlmap_scan` is conditionally destructive — it requires approval only when
called with `level >= 3` or `risk >= 2`.

### `executor`

Calls the tool chosen by the strategist through the **Tengu MCP client**.

The MCP client communicates with the Tengu server over stdin/stdout, just like
any other MCP client (Claude Desktop, Claude Code, etc.). The result is stored
in `command_history` — a LangGraph state field typed as
`Annotated[list, operator.add]`, which means each executor run **appends** its
entry rather than replacing the list.

### `analyst`

Extracts **structured intelligence** from raw tool output.

Calls Claude with the raw JSON output of the last tool and asks it to extract:

- Open ports and service banners
- Detected technologies and versions
- Subdomains
- Vulnerabilities (with severity, CVE IDs, OWASP category)
- General findings (with affected asset and evidence)
- Whether the current PTES phase objectives are now satisfied

When the analyst determines that a phase is complete, it increments
`current_phase` in the shared state, advancing the engagement to the next phase
automatically.

### `reporter`

Runs **once** at the end of the engagement.

Calls three Tengu tools in sequence:

1. `correlate_findings` — identifies attack chains and compound risks across all
   findings collected throughout the engagement
2. `score_risk` — calculates an overall CVSS-based risk score
3. `generate_report` — produces a full markdown report saved to `output/`

---

## Sequence Diagram

The diagram below shows the temporal interaction between participants across the
three stages of a full engagement run.

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Main
    participant Graph
    participant Claude
    participant Tengu

    %% ── Stage 1: Initialisation ──────────────────────────────────────────────
    Note over User,Tengu: Stage 1 — Initialisation

    User->>Main: autonomous_tengu.py <target> [flags]
    Main->>User: Display target, scope, model, confirm? [y/N]
    User->>Main: y
    Main->>Graph: run_agent(target, config)
    Graph->>Tengu: Spawn MCP server (stdio transport)
    Tengu-->>Graph: MCP session ready

    loop Load PTES phases 1–7
        Graph->>Tengu: ptes://phase/{N}
        Tengu-->>Graph: phase objectives + recommended tools
    end

    Graph->>Tengu: check_tools()
    Tengu-->>Graph: installed tools list
    Graph->>Tengu: validate_target(target)
    Tengu-->>Graph: target confirmed in allowlist

    %% ── Stage 2: Main reasoning loop ─────────────────────────────────────────
    Note over User,Tengu: Stage 2 — Main Reasoning Loop

    loop Until PENTEST_COMPLETE or max_iterations reached
        Graph->>Claude: system prompt (phase objectives, history, discoveries)<br/>+ tool definitions
        Claude-->>Graph: tool_use { tool_name, arguments }

        alt Normal tool (non-destructive)
            Graph->>Tengu: call tool_name(arguments)
            Tengu-->>Graph: tool result (JSON)
            Graph->>Claude: raw tool result
            Claude-->>Graph: extracted findings, phase complete?
            Note right of Graph: analyst updates state;<br/>phase advances if complete
        else Destructive tool (msf_run_module, hydra_attack, etc.)
            Graph->>User: ⚠ Approval required<br/>tool: tool_name<br/>args: arguments
            User->>Graph: approve / reject

            alt Approved
                Graph->>Tengu: call tool_name(arguments)
                Tengu-->>Graph: tool result (JSON)
                Graph->>Claude: raw tool result
                Claude-->>Graph: extracted findings
            else Rejected
                Note right of Graph: tool marked as skipped;<br/>strategist picks next action
            end
        end
    end

    %% ── Stage 3: Reporting ───────────────────────────────────────────────────
    Note over User,Tengu: Stage 3 — Reporting

    Graph->>Tengu: correlate_findings(all_findings)
    Tengu-->>Graph: attack chains + compound risks
    Graph->>Tengu: score_risk(findings)
    Tengu-->>Graph: overall CVSS risk score
    Graph->>Tengu: generate_report(engagement_data)
    Tengu-->>Graph: report saved to output/
    Graph-->>Main: engagement complete
    Main-->>User: Report path + summary
```

---

## Shared State

All nodes read from and write to a single `PentestState` TypedDict. LangGraph
merges the dicts returned by each node into the shared state after every step.

Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `current_phase` | `int` | Current PTES phase (2–7) |
| `open_ports` | `list` | Accumulated open ports (auto-appended) |
| `vulnerabilities` | `list` | Accumulated vulnerabilities (auto-appended) |
| `findings` | `list` | Accumulated findings (auto-appended) |
| `command_history` | `list` | Every tool call with args, result, and duration |
| `next_tool` | `str` | Tool chosen by the strategist for the next step |
| `requires_human_approval` | `bool` | Whether the next tool needs human sign-off |
| `is_complete` | `bool` | Signals all nodes to route toward the reporter |

Fields typed as `Annotated[list, operator.add]` are **append-only** — each node
adds to them rather than overwriting, so findings accumulate across the entire
engagement.

---

## Memory and Resumability

The graph is compiled with `MemorySaver`:

```python
graph = build_graph().compile(checkpointer=MemorySaver())
```

This gives two benefits:

1. **Human-in-the-loop interrupts** — the graph state is checkpointed before
   pausing, so it can be resumed exactly where it left off after the operator
   approves or rejects a destructive action.

2. **Crash recovery** — if the agent is interrupted unexpectedly, the state is
   preserved in memory for the duration of the process.

---

## Running the Agent

```bash
# Basic blackbox pentest
uv run python autonomous_tengu.py 192.168.1.100

# With explicit scope and engagement type
uv run python autonomous_tengu.py juice-shop \
    --scope 172.20.0.0/24 \
    --type greybox

# Limit iterations (default: 50)
uv run python autonomous_tengu.py 10.0.0.1 --max-iterations 30

# Cost-optimised run (cheaper model, lower token cap, 15-minute hard stop)
uv run python autonomous_tengu.py 10.0.0.1 \
    --model claude-haiku-4-5 \
    --max-tokens 1024 \
    --timeout 15
```

Requirements:

- `ANTHROPIC_API_KEY` set in environment or `.env` file
- Tengu server runnable via `uv run tengu` (the agent spawns it automatically)
- Target present in `tengu.toml` `[targets].allowed_hosts`

---

## Cost Control

Three parameters let you tune the cost/capability trade-off:

| CLI flag | Env var | Default | Effect |
|---|---|---|---|
| `--model` | `TENGU_AGENT_MODEL` | `claude-sonnet-4-6` | Claude model used by strategist and analyst |
| `--max-tokens` | `TENGU_AGENT_MAX_TOKENS` | `2048` | Max tokens per API call |
| `--timeout` | `TENGU_AGENT_TIMEOUT` | `60` | Total runtime limit in minutes (`0` = unlimited) |

Via Docker / Make:

```bash
# Cheap and fast
make docker-agent-haiku   # claude-haiku-4-5, max_tokens=1024

# Default (balanced)
make docker-agent-sonnet  # claude-sonnet-4-6, max_tokens=4096
```

Or override ad-hoc:

```bash
TENGU_AGENT_MODEL=claude-haiku-4-5 TENGU_AGENT_TIMEOUT=30 make docker-agent
```

---

## Why LangGraph Instead of a Simple Loop

A plain `while True` loop would work for the happy path, but LangGraph provides
three things that are difficult to replicate cleanly:

1. **Interrupt and resume** — `interrupt()` freezes the entire graph state and
   lets external code inject a decision before continuing. Implementing this
   correctly with a raw loop requires significant bookkeeping.

2. **Conditional routing** — edges between nodes can be functions, making the
   control flow explicit, testable, and easy to extend with new nodes.

3. **State reducers** — `Annotated[list, operator.add]` fields accumulate data
   across many iterations without any manual list management in node code.
