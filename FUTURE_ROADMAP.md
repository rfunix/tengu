# Tengu — Strategic Roadmap V0.5 to V2.0

## Context

Tengu is a pentesting MCP server (80 tools, 20 resources, 35 prompts) running in a Kali Linux Docker container. Key technical debt: no plugin system (165+ manual imports in `server.py`), unused `ToolExecutor` base class (80 tools duplicate ~20 lines of boilerplate), zero state persistence, and the LangGraph agent (`autonomous_tengu.py`) is a disconnected standalone script.

This roadmap addresses: (1) modern Red Teaming gaps, (2) autonomous agent evolution, (3) infrastructure/isolation, (4) intelligent Resource usage by AI.

---

## Dependency Graph

```
V0.5:  [3] standalone    [4] standalone    [5] standalone    [6] standalone    [7] standalone
       [1] ──▶ [2]
       [8] standalone

V1.0:  [1] ──▶ [9] ──▶ [10] ──▶ [11]
                        [10] ──▶ [12]
       [9,10] ──▶ [13]
       [14] standalone

V1.5:  [1,2] ──▶ [15]    [16] standalone    [9] ──▶ [18]
       [17] standalone    [19] standalone    [20] standalone

V2.0:  [9,10,11] ──▶ [21]    [9,10] ──▶ [22]    [15] ──▶ [23]    [9,22] ──▶ [24]
```

---

## V0.5 — Quick Wins (4–6 weeks)

### 1. `@tengu_tool` decorator — Eliminate boilerplate [Effort: L | Priority: P0]

**Problem:** All 80 tools repeat the same ~20-line security pipeline manually. `ToolExecutor` in `src/tengu/executor/base.py` exists but is unused.

**Implementation steps:**

1. Read `src/tengu/executor/base.py` to understand the existing `ToolExecutor` abstract class
2. Read `src/tengu/tools/recon/nmap.py` as the canonical example of the repeated boilerplate pattern (lines ~20-45: `get_config()`, `get_audit_logger()`, `make_allowlist_from_config()`, `allowlist.check()`, `rate_limited()`, `audit.log_tool_call()`)
3. Create a new decorator function in `src/tengu/executor/base.py`:

```python
from functools import wraps
from tengu.security.sanitizer import sanitize_target
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.rate_limiter import rate_limited
from tengu.security.audit import get_audit_logger
from tengu.config import get_config

def tengu_tool(tool_name: str, requires_target: bool = True):
    """Decorator that wraps a tool function with the full security pipeline."""
    def decorator(func):
        @wraps(func)
        async def wrapper(ctx, target: str = "", **kwargs):
            cfg = get_config()
            audit = get_audit_logger()
            if requires_target:
                target = sanitize_target(target)
                allowlist = make_allowlist_from_config()
                allowlist.check(target)
            async with rate_limited(tool_name):
                await audit.log_tool_call(tool_name, {"target": target, **kwargs})
                try:
                    result = await func(ctx, target=target, cfg=cfg, **kwargs)
                    await audit.log_tool_call(tool_name, {"target": target}, result="success")
                    return result
                except Exception as e:
                    await audit.log_tool_call(tool_name, {"target": target}, result="error", error=str(e))
                    raise
        wrapper._tengu_tool_name = tool_name
        return wrapper
    return decorator
```

4. Refactor `src/tengu/tools/recon/nmap.py` first as a proof-of-concept
5. Run `pytest tests/unit/tools/recon/test_nmap.py` to verify no regressions
6. Progressively refactor remaining 82 tools (batched by category)
7. Run full test suite: `pytest tests/unit/ tests/security/ --cov --cov-fail-under=80`

**Files to modify:**
- `src/tengu/executor/base.py` — Add `tengu_tool` decorator
- `src/tengu/tools/recon/nmap.py` — First refactor target
- All other 82 tool files in `src/tengu/tools/*/`

**Acceptance criteria:**
- All 80 tools use `@tengu_tool`
- No manual calls to `get_config()`, `make_allowlist_from_config()`, `rate_limited()`, `audit.log_tool_call()`
- `pytest tests/unit/ tests/security/` passes (2562+ tests)
- `ruff check src/` and `mypy src/` pass

---

### 2. Auto-registration of tools via discovery [Effort: M | Priority: P0]

**Problem:** `server.py` has 165+ manual import lines and ~60 `mcp.tool()` registration lines.

**Implementation steps:**

1. Read `src/tengu/server.py` to understand current registration pattern
2. Create `src/tengu/tools/registry.py`:

```python
import importlib
import pkgutil
from pathlib import Path

def discover_tools(tools_package="tengu.tools"):
    """Scan tools/ directory and return all functions decorated with @tengu_tool."""
    tools = []
    package = importlib.import_module(tools_package)
    package_path = Path(package.__file__).parent

    for importer, modname, ispkg in pkgutil.walk_packages(
        [str(package_path)], prefix=f"{tools_package}."
    ):
        module = importlib.import_module(modname)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if callable(attr) and hasattr(attr, "_tengu_tool_name"):
                tools.append(attr)
    return tools

def register_all_tools(mcp):
    """Register all discovered tools with the MCP server."""
    for tool_func in discover_tools():
        mcp.tool()(tool_func)
```

3. Replace all imports and `mcp.tool()` calls in `server.py` with `register_all_tools(mcp)`

**Files to modify:**
- New: `src/tengu/tools/registry.py`
- `src/tengu/executor/base.py` — `_tengu_tool_name` attribute
- `src/tengu/server.py` — Replace 165+ imports

**Acceptance criteria:**
- `server.py` has no manual tool imports
- All 80 tools auto-discovered and registered
- Adding a new tool requires only creating the file — no `server.py` edit

**Dependency:** Item 1

---

### 3. Allowlist deny-all-by-default [Effort: S | Priority: P0]

**Problem:** `src/tengu/security/allowlist.py` allows any target when `allowed_hosts` is empty.

**Implementation steps:**

1. Read `src/tengu/security/allowlist.py` — find the `check()` method
2. Add `strict_mode: bool = True` to `TenguConfig`
3. When `self._allowed` is empty and `strict_mode=True`, raise `AllowlistError`
4. Update `tengu.toml` example to document `strict_mode`
5. Update tests in `tests/unit/security/test_allowlist.py`

**Files to modify:**
- `src/tengu/security/allowlist.py`
- `src/tengu/config.py`
- `tengu.toml`
- `tests/unit/security/test_allowlist.py`

**Acceptance criteria:**
- Empty allowlist + `strict_mode=True` → raises error
- Empty allowlist + `strict_mode=False` → warns and allows (backward compatible)

---

### 4. Essential Cloud/K8s tools [Effort: M | Priority: P1]

**Tools to add:**

| Tool | Binary | File |
|---|---|---|
| kube-hunter | `kube-hunter` | `src/tengu/tools/cloud/kube_hunter.py` |
| kubeaudit | `kubeaudit` | `src/tengu/tools/cloud/kubeaudit.py` |
| enumerate-iam | `enumerate-iam.py` | `src/tengu/tools/cloud/enumerate_iam.py` |
| cloudfox | `cloudfox` | `src/tengu/tools/cloud/cloudfox.py` |

**Files to modify:**
- New: 4 tool files in `src/tengu/tools/cloud/`
- `src/tengu/executor/registry.py` — 4 new entries
- `Dockerfile`, `scripts/install-tools.sh`
- New: tests in `tests/unit/tools/cloud/`

---

### 5. Linux post-exploitation tools [Effort: S | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/tools/postexploit/` directory
2. `linpeas.py` — Wrapper for `linpeas.sh`
3. `les.py` — Wrapper for `linux-exploit-suggester.sh`
4. Add to registry and Dockerfile
5. Write unit tests

**Files to modify:**
- New: `src/tengu/tools/postexploit/__init__.py`, `linpeas.py`, `les.py`
- `src/tengu/executor/registry.py`
- `Dockerfile`
- New: `tests/unit/tools/postexploit/`

---

### 6. Persistent rate limiter [Effort: M | Priority: P1]

**Implementation steps:**

1. Read `src/tengu/security/rate_limiter.py`
2. Add `aiosqlite` to `pyproject.toml`
3. Add SQLite persistence: `~/.tengu/rate_limiter.db`
4. Add `rate_limiter_db_path` to config
5. Update tests

**Files to modify:**
- `src/tengu/security/rate_limiter.py`
- `src/tengu/config.py`
- `pyproject.toml`
- `tests/unit/security/test_rate_limiter.py`

---

### 7. Initial integration tests [Effort: M | Priority: P2]

**Implementation steps:**

1. Create `tests/integration/conftest.py` with Docker + Juice Shop fixtures
2. Create 5 integration test files (nmap, nuclei, trivy, subfinder, sqlmap)
3. Add `docker-compose.test.yml`
4. Add `make test-integration`
5. Add `.github/workflows/integration.yml` (weekly, not every PR)

**Files to modify:**
- New: `tests/integration/conftest.py`, 5 test files
- New: `docker-compose.test.yml`
- `Makefile`
- New: `.github/workflows/integration.yml`

---

### 8. GitHub Actions — Phase 1: Individual tools in CI/CD [Effort: M | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/cli.py` — CLI entrypoint for CI
2. Add `[project.scripts]` entry in `pyproject.toml`
3. Create GitHub Actions in `.github/actions/`: `secrets-scan`, `iac-scan`, `container-scan`, `dependency-audit`, `web-headers`
4. Add `Dockerfile` stage `tengu:ci`
5. Create `src/tengu/reporting/sarif.py` for SARIF output

**Files to modify:**
- New: `src/tengu/cli.py`
- New: `src/tengu/reporting/sarif.py`
- `pyproject.toml`
- New: `.github/actions/*/action.yml` (5 actions)
- `Dockerfile`

---

## V1.0 — The Agent Era (2–3 months)

### 9. State persistence with SQLite [Effort: XL | Priority: P0]

**Implementation steps:**

1. Create `src/tengu/storage/` module: `db.py`, `models.py`, `repository.py`
2. Schema: `engagements`, `scan_results`, `findings`, `agent_state` tables
3. SQLite with WAL mode + foreign keys
4. Update `@tengu_tool` to optionally save results
5. Add `StorageConfig` to config

**Files to modify:**
- New: `src/tengu/storage/__init__.py`, `db.py`, `models.py`, `repository.py`
- `src/tengu/config.py`
- `src/tengu/executor/base.py`
- `pyproject.toml` — Add `aiosqlite>=0.20`
- New: `tests/unit/storage/`

**Dependency:** Item 1

---

### 10. LangGraph integration into MCP Server [Effort: XL | Priority: P0]

**Implementation steps:**

1. Extract from `autonomous_tengu.py` into `src/tengu/agent/`:
   - `state.py` — `PentestState` TypedDict
   - `nodes.py` — All node functions (call tools directly, not via MCP stdio)
   - `graph.py` — `build_graph()`
   - `memory.py` — `SqliteSaver` checkpointer
2. Register 4 new MCP tools: `agent_start_pentest`, `agent_status`, `agent_approve`, `agent_stop`
3. Move `langgraph` to core dependencies

**Files to modify:**
- New: `src/tengu/agent/__init__.py`, `state.py`, `nodes.py`, `graph.py`, `memory.py`
- `src/tengu/server.py`
- `autonomous_tengu.py` — Thin wrapper
- `pyproject.toml`
- New: `tests/unit/agent/`

**Dependency:** Item 9

---

### 11. Long-term memory for campaigns [Effort: L | Priority: P1]

**Implementation steps:**

1. Add `target_knowledge` and `technique_history` tables to storage
2. Create `src/tengu/agent/memory.py` with `get_target_knowledge`, `save_target_knowledge`, `get_technique_history`, `build_memory_context`
3. Enrich `_strategist()` node with memory context
4. Save knowledge in `_analyst()` node after each analysis

**Files to modify:**
- `src/tengu/storage/db.py`
- `src/tengu/storage/repository.py`
- New: `src/tengu/agent/memory.py`
- `src/tengu/agent/nodes.py`

**Dependencies:** Items 9 and 10

---

### 12. Resources for real-time AI decision-making [Effort: M | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/agent/resource_advisor.py`
2. `get_relevant_resources(context)` — returns OWASP checklists, default credentials, MITRE techniques based on current findings and phase
3. Modify `_strategist()` to call `get_relevant_resources(state)` and append to prompt

**Files to modify:**
- New: `src/tengu/agent/resource_advisor.py`
- `src/tengu/agent/nodes.py`
- New: `tests/unit/agent/test_resource_advisor.py`

**Dependency:** Item 10

---

### 13. GitHub Actions — Phase 2: Autonomous agent in CI/CD [Effort: L | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/agent/ci_mode.py` — `CIConfig` with `human_gate_enabled=False`, SARIF output
2. Create `.github/actions/security-gate/action.yml`
3. Create `src/tengu/agent/ci_runner.py`
4. Create `scheduled-pentest` and `pr-security-review` actions

**Files to modify:**
- New: `src/tengu/agent/ci_mode.py`, `ci_runner.py`
- New: `.github/actions/security-gate/action.yml`
- New: `.github/actions/scheduled-pentest/action.yml`
- New: `.github/actions/pr-security-review/action.yml`

**Dependencies:** Items 9 and 10

---

### 14. Human gate in MCP flow [Effort: M | Priority: P0]

**Implementation steps:**

1. Create `src/tengu/security/human_gate.py` with `DESTRUCTIVE_TOOLS`, `CONDITIONALLY_DESTRUCTIVE`, `requires_approval()`
2. Update `@tengu_tool` to check human gate before execution
3. Return `{"status": "approval_required", ...}` for destructive tools
4. Add `destructive_tools` config for customization

**Files to modify:**
- New: `src/tengu/security/human_gate.py`
- `src/tengu/executor/base.py`
- `src/tengu/config.py`
- New: `tests/unit/security/test_human_gate.py`

---

## V1.5 — Advanced Platform (4–6 months)

### 15. Dynamic plugin architecture [Effort: XL | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/plugins/`: `interface.py` (TenguPlugin Protocol), `loader.py` (entry_points discovery), `validator.py`
2. Use `importlib.metadata.entry_points(group="tengu.plugins")`
3. Add `[plugins]` section to `tengu.toml`
4. Update `registry.py` to discover plugin tools
5. Create example plugin in `examples/tengu-plugin-example/`

**Files to modify:**
- New: `src/tengu/plugins/__init__.py`, `interface.py`, `loader.py`, `validator.py`
- `src/tengu/tools/registry.py`
- `src/tengu/config.py`
- New: `examples/tengu-plugin-example/`

**Dependencies:** Items 1 and 2

---

### 16. Per-tool container isolation [Effort: XL | Priority: P0]

**Implementation steps:**

1. Create `src/tengu/executor/isolated.py` with `IsolationProfile` dataclass and `TOOL_PROFILES`
2. `run_isolated()` — runs tool binary in ephemeral Docker container with `--read-only`, memory limits, `--tmpfs`
3. Add `isolation_enabled: bool = False` to config (opt-in)
4. Create `docker/tool-runner.Dockerfile`

**Files to modify:**
- New: `src/tengu/executor/isolated.py`
- `src/tengu/executor/base.py`
- `src/tengu/config.py`
- New: `docker/tool-runner.Dockerfile`
- `docker-compose.yml`

---

### 17. Real-time threat intelligence [Effort: L | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/intelligence/kev.py` — CISA KEV feed client with caching
2. Create `src/tengu/intelligence/greynoise.py` — GreyNoise API client
3. Register new resources: `intel://cisa-kev`, `intel://greynoise/{ip}`
4. Enrich `correlate_findings` with active exploitation context

**Files to modify:**
- New: `src/tengu/intelligence/__init__.py`, `kev.py`, `greynoise.py`
- `src/tengu/server.py`
- `src/tengu/tools/analysis/correlate.py`

---

### 18. Advanced correlation with attack graphs [Effort: XL | Priority: P2]

**Implementation steps:**

1. Create `src/tengu/resources/data/attack_chains.json` with 50+ MITRE ATT&CK chains
2. Create `src/tengu/analysis/attack_graph.py`: graph structure, path finding, cumulative risk scoring
3. Update `correlate.py` to use attack graph engine

**Files to modify:**
- New: `src/tengu/analysis/attack_graph.py`
- `src/tengu/resources/data/attack_chains.json`
- `src/tengu/tools/analysis/correlate.py`

**Dependency:** Item 9

---

### 19. Compliance reporting (LGPD/GDPR) [Effort: L | Priority: P1]

**Implementation steps:**

1. Create mapping files: `lgpd_mapping.json`, `gdpr_mapping.json`
2. Create Jinja2 template `compliance_report.md.j2`
3. Add `report_type="compliance"` to `generate_report()`
4. Register resources: `compliance://lgpd`, `compliance://gdpr`

**Files to modify:**
- New: `src/tengu/resources/data/lgpd_mapping.json`, `gdpr_mapping.json`
- New: `src/tengu/tools/reporting/templates/compliance_report.md.j2`
- `src/tengu/tools/reporting/generate.py`
- `src/tengu/server.py`

---

### 20. Tamper-evident audit log [Effort: S | Priority: P0]

**Implementation steps:**

1. Add SHA-256 hash chain to each audit record (`prev_hash`, `hash` fields)
2. Create `scripts/verify-audit-log.py` to verify chain integrity
3. Write tests for hash chain integrity

**Files to modify:**
- `src/tengu/security/audit.py`
- New: `scripts/verify-audit-log.py`
- `tests/unit/security/test_audit.py`

---

## V2.0 — Ecosystem (6–12 months)

### 21. Multi-agent architecture [Effort: XL | Priority: P1]

**Implementation steps:**

1. Create specialist agents in `src/tengu/agent/specialists/`:
   - `web.py` — WebAgent (nuclei, sqlmap, ffuf, zap, wpscan)
   - `infra.py` — InfraAgent (nmap, masscan, hydra, nxc, impacket)
   - `cloud.py` — CloudAgent (scoutsuite, prowler, kube-hunter, cloudfox)
   - `recon.py` — ReconAgent (subfinder, amass, shodan, theHarvester)
2. Create `src/tengu/agent/orchestrator.py` — meta-strategist with parallel execution
3. Register `multi_agent_start` and `multi_agent_status` MCP tools

**Files to modify:**
- New: `src/tengu/agent/specialists/` — 4 modules
- New: `src/tengu/agent/orchestrator.py`
- `src/tengu/server.py`

**Dependencies:** Items 9, 10, 11

---

### 22. Monitoring dashboard [Effort: XL | Priority: P2]

**Implementation steps:**

1. Create `src/tengu/dashboard/` with FastAPI/HTMX routes, templates, WebSocket handler
2. Pages: main dashboard (agent status + findings stream), findings table, human gate approvals
3. Mount alongside MCP endpoints in `server.py`

**Files to modify:**
- New: `src/tengu/dashboard/` — Full module
- `src/tengu/server.py`

**Dependencies:** Items 9, 10

---

### 23. Plugin marketplace [Effort: XL | Priority: P2]

**Implementation steps:**

1. Community plugin registry at GitHub (JSON index)
2. CLI commands: `tengu plugin search`, `tengu plugin install`, `tengu plugin list`
3. Plugin validation: GPG signature verification, sandbox testing
4. Update `src/tengu/cli.py` with plugin subcommands

**Dependency:** Item 15

---

### 24. Enterprise features — RBAC and multi-tenant [Effort: XL | Priority: P1]

**Implementation steps:**

1. Create `src/tengu/auth/`: `jwt.py`, `rbac.py`, `middleware.py`, `models.py`
2. Define role→tool mappings: `viewer`, `junior_pentester`, `senior_pentester`, `admin`
3. Add auth middleware to MCP server
4. Add users/roles tables to SQLite storage
5. Optional OIDC/SAML integration

**Files to modify:**
- New: `src/tengu/auth/` — Full auth module
- `src/tengu/storage/db.py`
- `src/tengu/server.py`

**Dependencies:** Items 9, 22

---

## Verification Checklist

| Version | Verification |
|---------|-------------|
| **V0.5** | `pytest tests/unit/ tests/security/` (2562+ tests pass) · `ruff check src/` · `mypy src/` clean · New cloud tools tested against lab |
| **V1.0** | Full cycle: `agent_start_pentest` → `agent_status` → `agent_approve` → restart server → verify state recovery |
| **V1.5** | Install external plugin via `tengu plugin install` · Verify container isolation · Generate LGPD compliance report |
| **V2.0** | Multi-agent pentest with parallel Web+Infra agents · Dashboard real-time streaming |

---

## Item Summary

| # | Title | Version | Effort | Priority |
|---|-------|---------|--------|----------|
| 1 | `@tengu_tool` decorator | V0.5 | L | P0 |
| 2 | Auto-registration via discovery | V0.5 | M | P0 |
| 3 | Allowlist deny-all-by-default | V0.5 | S | P0 |
| 4 | Essential Cloud/K8s tools | V0.5 | M | P1 |
| 5 | Linux post-exploitation tools | V0.5 | S | P1 |
| 6 | Persistent rate limiter | V0.5 | M | P1 |
| 7 | Initial integration tests | V0.5 | M | P2 |
| 8 | GitHub Actions Phase 1 | V0.5 | M | P1 |
| 9 | State persistence with SQLite | V1.0 | XL | P0 |
| 10 | LangGraph integration | V1.0 | XL | P0 |
| 11 | Long-term memory for campaigns | V1.0 | L | P1 |
| 12 | Resources for AI decision-making | V1.0 | M | P1 |
| 13 | GitHub Actions Phase 2 | V1.0 | L | P1 |
| 14 | Human gate in MCP flow | V1.0 | M | P0 |
| 15 | Dynamic plugin architecture | V1.5 | XL | P1 |
| 16 | Per-tool container isolation | V1.5 | XL | P0 |
| 17 | Real-time threat intelligence | V1.5 | L | P1 |
| 18 | Attack graphs correlation | V1.5 | XL | P2 |
| 19 | Compliance reporting LGPD/GDPR | V1.5 | L | P1 |
| 20 | Tamper-evident audit log | V1.5 | S | P0 |
| 21 | Multi-agent architecture | V2.0 | XL | P1 |
| 22 | Monitoring dashboard | V2.0 | XL | P2 |
| 23 | Plugin marketplace | V2.0 | XL | P2 |
| 24 | Enterprise RBAC multi-tenant | V2.0 | XL | P1 |
