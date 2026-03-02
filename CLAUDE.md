# CLAUDE.md — Tengu MCP Server

This file is the primary guide for AI assistants (Claude Code and others) working on
the Tengu codebase. Read it in full before making any changes.

---

## Project Overview

**Tengu** is a Model Context Protocol (MCP) server that exposes professional
pentesting tools to AI assistants through a clean, secure interface.

| Property        | Value                                             |
|----------------|---------------------------------------------------|
| Framework       | FastMCP 2.0+                                      |
| Python          | 3.12+                                             |
| Package manager | `uv` (full path: `/Users/rfunix/.local/bin/uv`)   |
| Validation      | Pydantic v2                                       |
| Logging         | structlog (JSON, structured)                      |
| Entry point     | `src/tengu/server.py` → `FastMCP("Tengu")`        |
| Config file     | `tengu.toml` at project root                      |
| Test suite      | 1931+ tests, 0 lint errors |
| Tools           | 63 MCP tools                                      |
| Resources       | 20 MCP resources                                  |
| Prompts         | 34 MCP prompts                                    |

---

## Architecture

### Request Flow

Every tool invocation follows this mandatory pipeline — no exceptions:

```
Claude (MCP Client)
       │
       ▼
  FastMCP layer          ← receives JSON-RPC call
       │
       ▼
1. sanitizer             ← tengu/security/sanitizer.py
   - Validate input formats (IP, hostname, CIDR, URL, port spec, etc.)
   - Strip/reject shell metacharacters: [;&|`$<>(){}\[\]!\\\'\"\\r\\n]
   - Raise InvalidInputError on any violation
       │
       ▼
2. allowlist             ← tengu/security/allowlist.py
   - Extract hostname from target
   - Check against blocked_hosts (always wins)
   - Check against allowed_hosts (must match if non-empty)
   - Raise TargetNotAllowedError on denial
       │
       ▼
3. rate_limiter          ← tengu/security/rate_limiter.py
   - Sliding window (60s) per tool
   - Concurrent slot limit per tool
   - Raise RateLimitError if either limit is exceeded
       │
       ▼
4. audit logger          ← tengu/security/audit.py
   - Write JSON audit record to logs/tengu-audit.log
   - Redact sensitive parameters (password, token, key, etc.)
   - Log tool name, target, params, result, duration
       │
       ▼
5. executor              ← tengu/executor/process.py
   - asyncio.create_subprocess_exec (NEVER shell=True)
   - Resolve tool path via shutil.which
   - Enforce timeout
   - Return (stdout, stderr, returncode)
       │
       ▼
  Output parser          ← per-tool parsing function
  (XML, JSON, JSONL, plain text)
       │
       ▼
  Return dict to Claude
```

### Module Map

```
src/tengu/
├── server.py              # FastMCP instance + tool/resource/prompt registration
├── config.py              # TenguConfig Pydantic model, load_config(), get_config()
├── types.py               # Shared Pydantic models (Host, Port, Finding, ScanResult, ...)
├── exceptions.py          # Custom exception hierarchy (TenguError subclasses)
│
├── security/
│   ├── sanitizer.py       # sanitize_target, sanitize_url, sanitize_port_spec,
│   │                      # sanitize_repo_url, sanitize_docker_image, sanitize_proxy_url
│   ├── allowlist.py       # TargetAllowlist, make_allowlist_from_config()
│   ├── rate_limiter.py    # SlidingWindowRateLimiter, rate_limited context manager
│   └── audit.py           # AuditLogger, get_audit_logger(), _redact_sensitive()
│
├── executor/
│   ├── process.py         # run_command(), stream_command() — NO shell=True
│   ├── registry.py        # check_all(), check_tool_async(), resolve_tool_path()
│   └── base.py            # (future: base executor class)
│
├── stealth/               # Stealth layer — Tor/proxy, UA rotation, timing jitter
│   ├── layer.py           # StealthLayer singleton, inject_proxy_flags()
│   ├── config.py          # StealthConfig Pydantic model
│   ├── timing.py          # Jitter utilities (random sleep ranges)
│   ├── user_agents.py     # UA rotation pool
│   └── http_client.py     # create_http_client() — httpx with proxy + UA injection
│
├── tools/
│   ├── utility.py         # check_tools, validate_target
│   ├── recon/             # nmap, masscan, subfinder, dns, whois, amass, dnsrecon,
│   │                      # subjack, gowitness, httrack
│   ├── web/               # nuclei, nikto, ffuf, headers, cors, ssl_tls, gobuster,
│   │                      # wpscan, testssl
│   ├── osint/             # theharvester, shodan, whatweb
│   ├── injection/         # sqlmap, xss
│   ├── exploit/           # metasploit (msf_search, msf_module_info, msf_run_module,
│   │                      # msf_sessions_list), searchsploit
│   ├── bruteforce/        # hydra, hash_tools (hash_crack, hash_identify), cewl
│   ├── proxy/             # zap (zap_spider, zap_active_scan, zap_get_alerts)
│   ├── analysis/          # correlate (correlate_findings, score_risk), cve_tools,
│   │                      # reporting (generate_report)
│   ├── secrets/           # trufflehog, gitleaks
│   ├── container/         # trivy
│   ├── cloud/             # scoutsuite
│   ├── api/               # arjun, graphql_security_check
│   ├── ad/                # enum4linux, nxc, impacket (impacket_kerberoast)
│   ├── wireless/          # aircrack
│   ├── iac/               # checkov
│   └── stealth/           # tor_check, tor_new_identity, check_anonymity,
│                          # proxy_check, rotate_identity
│
├── resources/
│   ├── owasp.py           # get_top10_list, get_category, get_category_checklist
│   ├── ptes.py            # get_phases_overview, get_phase
│   ├── checklists.py      # get_checklist (web-application, api, network)
│   ├── cve.py             # CVE lookup helpers
│   └── data/              # Static JSON: OWASP, PTES, checklists, MITRE ATT&CK,
│                          # OWASP API Top 10, default creds, payloads, stealth techniques
│
└── prompts/
    ├── pentest_workflow.py # full_pentest, quick_recon, web_app_assessment
    ├── vuln_assessment.py  # assess_injection, assess_access_control, assess_crypto, assess_misconfig
    ├── report_prompts.py   # executive_report, technical_report, full_pentest_report,
    │                       # remediation_plan, finding_detail, risk_matrix, retest_report
    ├── advanced_workflows.py # osint_investigation, stealth_assessment, opsec_checklist,
    │                         # api_security_assessment, ad_assessment, container_assessment,
    │                         # cloud_assessment, bug_bounty_workflow, compliance_assessment,
    │                         # wireless_assessment
    └── quick_actions.py    # crack_wifi, explore_url, go_stealth, find_secrets,
                            # map_network, hunt_subdomains, find_vulns, pwn_target
```

---

## Stealth Layer

The stealth layer (`src/tengu/stealth/`) provides optional anonymization and evasion
capabilities. It is enabled via `tengu.toml` and is fully transparent to tool code —
tools do not need to check whether stealth mode is active.

### Configuration

```toml
[stealth]
enabled = true

[stealth.proxy]
enabled = true
url = "socks5h://127.0.0.1:9050"   # Tor SOCKS5 proxy
```

### What the Stealth Layer Does

| Capability | Module | Details |
|------------|--------|---------|
| Proxy injection | `layer.py` → `inject_proxy_flags()` | Appends proxy CLI flags to tool argument lists |
| User agent rotation | `user_agents.py` | Rotates realistic browser UA strings per request |
| Timing jitter | `timing.py` | Random sleep ranges between requests to evade rate detection |
| HTTP client | `http_client.py` | Returns an `httpx.AsyncClient` pre-configured with proxy + UA |

### Proxy Flag Injection (per tool)

| Tool | Flag injected |
|------|---------------|
| nmap | `--proxies` |
| nuclei | `-proxy` |
| ffuf | `-x` |
| sqlmap | `--proxy` |
| subfinder | `--proxy` |
| nikto | `-useproxy` |
| gobuster | `--proxy` |
| wpscan | `--proxy` |
| curl (internal) | `-x` |
| httpx (internal) | `proxies=` kwarg |

### HTTP Tools

`analyze_headers` and `test_cors` use `stealth.create_http_client()` automatically
when stealth mode is enabled — no special handling required in tool code.

### Stealth Tools (MCP-exposed)

Five tools expose stealth controls to the AI:

| Tool | Description |
|------|-------------|
| `tor_check` | Verify Tor connectivity and exit node IP |
| `tor_new_identity` | Signal Tor to rotate the exit node |
| `check_anonymity` | Comprehensive anonymity posture check |
| `proxy_check` | Verify proxy reachability and IP leak status |
| `rotate_identity` | Rotate proxy/UA and request a new Tor identity |

---

## Development Workflow

All common tasks are in the `Makefile`. Run `make help` to see all targets.

```bash
# Setup
make install-dev        # Install Python deps + dev extras (pytest, ruff, mypy)
make install-tools      # Install external pentesting tools via scripts/install-tools.sh
make setup              # Alias for install-dev

# Code quality
make lint               # ruff check src/ tests/
make format             # ruff format src/ tests/
make typecheck          # mypy src/ (strict mode)
make check              # lint + typecheck

# Testing
make test               # unit + security tests (fast, no external tools needed)
make test-unit          # tests/unit/ only
make test-security      # tests/security/ only (74 command injection tests)
make test-integration   # tests/integration/ (requires tools installed)
make test-all           # all tests
make coverage           # pytest --cov, generates htmlcov/index.html

# Running
make run                # uv run tengu (stdio transport)
make run-sse            # uv run tengu --transport sse
make run-dev            # TENGU_LOG_LEVEL=DEBUG uv run tengu
make inspect            # npx @modelcontextprotocol/inspector uv run tengu

# Direct run commands (without make)
# /Users/rfunix/.local/bin/uv run pytest tests/ -q
# /Users/rfunix/.local/bin/uv run ruff check src/ tests/
# /Users/rfunix/.local/bin/uv run tengu
# TENGU_HOST=0.0.0.0 uv run tengu --transport sse   # SSE for remote clients (e.g. Kali)

# Diagnostics
make doctor             # check which pentest tools are installed

# Cleanup
make clean              # remove dist/, .pytest_cache/, htmlcov/, __pycache__/
```

---

## Code Conventions

### Language
- All source code, comments, docstrings, variable names, and test names: **English only**.
- All user-facing error messages: English.
- This CLAUDE.md and project docs: English.

### Style
- Line limit: **100 characters** (ruff enforces this).
- All files start with `from __future__ import annotations`.
- Type annotations on every function parameter and return value.
- Mypy strict mode — no `type: ignore` unless absolutely necessary (always add a comment).
- Ruff rules: E, F, I, N, W, UP, B, C4, PTH, SIM.

### Pydantic v2
- Use `model_validate()`, `model_dump()`, not `parse_obj()`, `dict()`.
- Use `Field(default_factory=...)` for mutable defaults.
- Validators use `@field_validator(..., mode="before")` decorator.

### Logging
- Never use `print()` or `logging.info()` directly in tool code.
- Always use `structlog.get_logger(__name__)` at module level.
- Pass context as keyword arguments: `logger.info("msg", key=value, ...)`.
- Do not log sensitive values (passwords, tokens, API keys).

### Async
- Tool functions are `async def`.
- Use `await ctx.report_progress(current, total, message)` to report scan progress.
- Use `asyncio.create_subprocess_exec` (via `run_command`), never `subprocess.run` or `shell=True`.

---

## Security Rules (NON-NEGOTIABLE)

These rules are absolute. No PR that violates them will be accepted.

### Rule 1 — NEVER use shell=True
```python
# WRONG — shell injection vulnerability
proc = subprocess.run(f"nmap {target}", shell=True)

# CORRECT — arguments as a list, no shell interpretation
stdout, stderr, rc = await run_command(["nmap", "-sT", "-p", ports, target])
```

### Rule 2 — Always sanitize inputs before use
```python
# WRONG — using raw user input
args = ["nmap", target]

# CORRECT — sanitize first, then use
target = sanitize_target(target)  # raises InvalidInputError if malicious
args = ["nmap", target]
```

### Rule 3 — Always check the allowlist before scanning
```python
# WRONG — scanning without allowlist check
await run_command(["nmap", target])

# CORRECT — check allowlist first
allowlist = make_allowlist_from_config()
allowlist.check(target)  # raises TargetNotAllowedError if not allowed
await run_command(["nmap", target])
```

### Rule 4 — Always write an audit log entry
```python
# Every tool call must have at least two audit entries:
audit = get_audit_logger()
await audit.log_tool_call("mytool", target, params, result="started")
# ... run tool ...
await audit.log_tool_call("mytool", target, params, result="completed", duration_seconds=dur)
# OR on failure:
await audit.log_tool_call("mytool", target, params, result="failed", error=str(exc))
```

### Rule 5 — Always rate limit active scan tools
```python
async with rate_limited("mytool"):
    stdout, stderr, rc = await run_command(args)
```
Analysis tools (correlate, score_risk) and pure-Python tools do not need rate limiting.

### Rule 6 — Redact sensitive data
- Never log or return raw passwords, tokens, or API keys.
- The audit logger's `_redact_sensitive()` handles common keys automatically.
- Add any new sensitive parameter names to `_SENSITIVE_KEYS` in `audit.py`.

---

## How to Add a New Tool

Follow these 8 steps exactly. Use `nmap_scan` as the canonical reference.

### Step 1 — Create the tool file
Place it in the appropriate category subdirectory:
```
src/tengu/tools/<category>/<toolname>.py
```

### Step 2 — Write the function signature
```python
from __future__ import annotations

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target  # pick appropriate sanitizers

logger = structlog.get_logger(__name__)


async def my_tool(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    option: str = "default",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
```

### Step 3 — Write a complete docstring
Include Args and Returns sections. FastMCP uses the docstring as the tool description
shown to the AI. Clear, detailed docstrings improve tool usage accuracy.

### Step 4 — Sanitize all inputs
```python
target = sanitize_target(target)
# use other sanitizers from security/sanitizer.py as appropriate
```

### Step 5 — Check the allowlist
```python
allowlist = make_allowlist_from_config()
try:
    allowlist.check(target)
except Exception as exc:
    await audit.log_target_blocked("my_tool", target, str(exc))
    raise
```

### Step 6 — Build the argument list safely
```python
cfg = get_config()
tool_path = resolve_tool_path("mytoolexe", cfg.tools.paths.mytool)
effective_timeout = timeout or cfg.tools.defaults.scan_timeout

args = [tool_path, "--option", option, target]
# Never concatenate strings into a single command
```

### Step 7 — Execute with rate limiting and audit logging
```python
await ctx.report_progress(0, 100, f"Starting my_tool on {target}...")

async with rate_limited("my_tool"):
    start = time.monotonic()
    await audit.log_tool_call("my_tool", target, params, result="started")

    try:
        stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
    except Exception as exc:
        await audit.log_tool_call("my_tool", target, params, result="failed", error=str(exc))
        raise

    duration = time.monotonic() - start

await audit.log_tool_call("my_tool", target, params, result="completed", duration_seconds=duration)
await ctx.report_progress(100, 100, "Complete")
```

### Step 8 — Register in server.py
```python
# In server.py, add the import:
from tengu.tools.category.my_tool import my_tool

# And register:
mcp.tool()(my_tool)
```

### Annotated Example (nmap_scan)

```python
async def nmap_scan(
    ctx: Context,              # FastMCP context — provides report_progress
    target: str,               # Raw user input — sanitized in step 1
    ports: str = "1-1024",
    scan_type: ScanType = "connect",
    timing: str = "T3",
    os_detection: bool = False,
    scripts: str = "",
    timeout: int | None = None,
) -> dict:
    """Scan a target for open ports..."""

    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "ports": ports, ...}

    # Step 1: Sanitize
    target = sanitize_target(target)
    ports = sanitize_port_spec(ports)

    # Step 2: Allowlist
    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nmap", target, str(exc))
        raise

    # Step 3: Resolve tool path
    tool_path = resolve_tool_path("nmap", cfg.tools.paths.nmap)

    # Step 4: Build args (list only, no shell)
    args = [tool_path, *_SCAN_TYPE_FLAGS[scan_type], f"-{timing}", "-p", ports, "-oX", "-"]
    if os_detection:
        args.append("-O")
    args.append(target)

    # Step 5: Execute with rate limiting + audit
    await ctx.report_progress(0, 100, f"Starting nmap scan on {target}...")

    async with rate_limited("nmap"):
        start = time.monotonic()
        await audit.log_tool_call("nmap", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("nmap", target, params, result="failed", error=str(exc))
            raise
        duration = time.monotonic() - start

    # Step 6: Parse and return
    hosts = _parse_nmap_xml(stdout)
    await audit.log_tool_call("nmap", target, params, result="completed", duration_seconds=duration)
    await ctx.report_progress(100, 100, "Scan complete")

    return {
        "tool": "nmap",
        "target": target,
        "hosts": [h.model_dump() for h in hosts],
        ...
    }
```

---

## How to Add a New Resource

Resources provide read-only reference data (OWASP, PTES, checklists, etc.).

1. Create or update the data source in `src/tengu/resources/`.
2. Register the resource in `server.py` using the `@mcp.resource("scheme://path")` decorator.
3. The function must return a `str` (typically `json.dumps(data, indent=2)`).
4. Use meaningful URI schemes:  `owasp://`, `ptes://`, `checklist://`, `tools://`.

```python
@mcp.resource("myscheme://path/{param}")
def resource_my_data(param: str) -> str:
    """Description shown to the AI about this resource."""
    data = get_my_data(param)
    if not data:
        return json.dumps({"error": f"Not found: {param}"})
    return json.dumps(data, indent=2)
```

---

## How to Add a New Prompt

Prompts are guided workflow templates that the AI expands with real tool calls.

1. Add the function to the appropriate file in `src/tengu/prompts/`.
2. The function must return a `str` (the prompt text).
3. Include `Args:` docstring — FastMCP uses them to expose the prompt's parameters.
4. Register in `server.py`: `mcp.prompt()(my_prompt_function)`.

```python
def my_workflow(target: str, option: str = "default") -> str:
    """One-line description of what this workflow does.

    Args:
        target: The system or URL to assess.
        option: Workflow variant (default, thorough, quick).
    """
    return f"""Perform a {option} assessment of {target}.

1. Use `validate_target` to confirm {target} is in scope.
2. Use `check_tools` to verify required tools are installed.
...
"""
```

---

## Common Pitfalls

1. **Forgetting `from __future__ import annotations`** — Required in every file.
   Without it, PEP 604 union types (`X | Y`) break on Python 3.12.

2. **Using `subprocess.run` instead of `run_command`** — Never. Always use
   `tengu.executor.process.run_command()`.

3. **Passing user input directly to args** — Always sanitize first.
   `args = ["nmap", user_input]` is wrong. `args = ["nmap", sanitize_target(user_input)]`.

4. **Forgetting the allowlist check** — Every tool that accepts a `target` parameter
   must call `allowlist.check(target)` before executing.

5. **Missing audit log entries** — Every active scan needs both a "started" and a
   "completed"/"failed" audit entry.

6. **Returning Pydantic models directly** — FastMCP cannot serialize Pydantic objects.
   Always call `.model_dump()` or build plain dicts.

7. **Hardcoding tool paths** — Always use `resolve_tool_path(name, cfg.tools.paths.name)`.
   Users set custom paths in `tengu.toml`.

8. **Not rate limiting** — All external process tools must use `async with rate_limited(tool_name)`.

9. **Type annotation gaps** — Mypy strict mode requires complete annotations.
   `dict` and `list` without subscripts need `# type: ignore[type-arg]` until FastMCP
   supports generic contexts.

10. **Modifying `_config` singleton directly in tests** — Use `reset_config()` from
    `tengu.config` to reset state between tests.

---

## File Organization

```
tengu/
├── CLAUDE.md              ← You are here
├── CHANGELOG.md
├── Makefile
├── pyproject.toml
├── tengu.toml             ← Runtime configuration
├── uv.lock
├── README.md
│
├── src/tengu/             ← All Python source
├── tests/
│   ├── unit/              ← Fast tests, no external tools
│   ├── security/          ← Command injection, input validation tests
│   └── integration/       ← Tests requiring real tools installed
│
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── tool-development-guide.md
│   ├── configuration-reference.md
│   ├── deployment-guide.md
│   ├── api-reference.md
│   └── contributing.md
│
├── logs/                  ← Audit logs (gitignored)
└── scripts/
    └── install-tools.sh   ← External tool installer
```
