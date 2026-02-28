# Tengu Architecture

## System Overview

Tengu is a **Model Context Protocol (MCP) server** that acts as a secure intermediary
between an AI assistant (Claude) and industry-standard penetration testing tools.

The MCP protocol carries JSON-RPC 2.0 messages over stdio (or SSE for remote use).
Tengu implements three MCP primitives:

| Primitive | Count | Purpose |
|-----------|-------|---------|
| Tools     | 56    | Active operations: scanning, exploitation, analysis, stealth |
| Resources | 19    | Read-only reference data: OWASP, PTES, MITRE ATT&CK, checklists, payloads |
| Prompts   | 34    | Guided workflow templates for complex engagements |

---

## Request Flow

Every tool invocation passes through a mandatory 5-layer security pipeline
before any external process is executed.

```mermaid
sequenceDiagram
    participant C as Claude (MCP Client)
    participant F as FastMCP Layer
    participant S as Sanitizer
    participant A as Allowlist
    participant R as Rate Limiter
    participant AU as Audit Logger
    participant E as Executor
    participant T as External Tool

    C->>F: JSON-RPC tool call
    F->>S: raw parameters
    S-->>F: InvalidInputError (if malicious)
    S->>A: sanitized target
    A-->>F: TargetNotAllowedError (if blocked)
    A->>R: approved target
    R-->>F: RateLimitError (if exceeded)
    R->>AU: acquire token
    AU->>E: log "started"
    E->>T: asyncio.create_subprocess_exec
    T-->>E: stdout, stderr, returncode
    E->>AU: log "completed" / "failed"
    AU->>F: structured result dict
    F-->>C: JSON-RPC response
```

---

## Component Dependency Diagram

```mermaid
graph TD
    SERVER["server.py<br/>(FastMCP instance)"]

    subgraph TOOLS["Tools Layer"]
        RECON["recon/<br/>nmap, masscan, subfinder, dns, whois,<br/>amass, dnsrecon, subjack, gowitness"]
        WEB["web/<br/>nuclei, nikto, ffuf, headers, cors,<br/>ssl_tls, gobuster, wpscan, testssl"]
        OSINT["osint/<br/>theharvester, shodan, whatweb"]
        INJ["injection/<br/>sqlmap, xss"]
        EXP["exploit/<br/>metasploit, searchsploit"]
        BRF["bruteforce/<br/>hydra, hash_tools, cewl"]
        PRX["proxy/<br/>zap"]
        ANA["analysis/<br/>correlate, cve_tools"]
        REP["reporting/<br/>generate"]
        SEC["secrets/<br/>trufflehog, gitleaks"]
        CONT["container/<br/>trivy"]
        CLD["cloud/<br/>scoutsuite"]
        API["api/<br/>arjun, graphql"]
        AD["ad/<br/>enum4linux, nxc, impacket"]
        WLS["wireless/<br/>aircrack"]
        IAC["iac/<br/>checkov"]
        STL["stealth/<br/>tor_check, tor_new_identity,<br/>check_anonymity, proxy_check, rotate_identity"]
        UTL["utility.py<br/>check_tools, validate_target"]
    end

    subgraph SECURITY["Security Layer"]
        SAN["sanitizer.py"]
        ALL["allowlist.py"]
        RLM["rate_limiter.py"]
        AUD["audit.py"]
    end

    subgraph STEALTH["Stealth Layer"]
        SLYR["layer.py<br/>StealthLayer, inject_proxy_flags"]
        SCFG["config.py<br/>StealthConfig"]
        STIM["timing.py<br/>jitter utilities"]
        SUA["user_agents.py<br/>UA rotation"]
        SHTP["http_client.py<br/>create_http_client"]
    end

    subgraph EXECUTOR["Executor Layer"]
        PROC["process.py<br/>run_command, stream_command"]
        REG["registry.py<br/>resolve_tool_path, check_all"]
    end

    subgraph CONFIG["Config Layer"]
        CFG["config.py<br/>TenguConfig (Pydantic v2)"]
    end

    subgraph DATA["Data Layer"]
        TYPES["types.py<br/>Shared Pydantic models"]
        EXCEP["exceptions.py<br/>TenguError hierarchy"]
    end

    SERVER --> TOOLS
    TOOLS --> SECURITY
    TOOLS --> EXECUTOR
    TOOLS --> CONFIG
    TOOLS --> TYPES
    TOOLS --> STEALTH
    STEALTH --> CONFIG
    SECURITY --> CONFIG
    SECURITY --> EXCEP
    EXECUTOR --> EXCEP
    CONFIG --> EXCEP
```

---

## Tool Categories and Coverage

56 tools across 17 categories as of v0.2.1.

```mermaid
graph LR
    subgraph RECON["Reconnaissance (9)"]
        N["nmap_scan"]
        M["masscan_scan"]
        SF["subfinder_enum"]
        DNS["dns_enumerate"]
        W["whois_lookup"]
        AM["amass_enum"]
        DR["dnsrecon_scan"]
        SJ["subjack_check"]
        GW["gowitness_screenshot"]
    end

    subgraph WEB["Web Scanning (9)"]
        NUC["nuclei_scan"]
        NIK["nikto_scan"]
        FFU["ffuf_fuzz"]
        HDR["analyze_headers"]
        CRS["test_cors"]
        SSL["ssl_tls_check"]
        GOB["gobuster_scan"]
        WPS["wpscan_scan"]
        TSS["testssl_check"]
    end

    subgraph OSINT["OSINT (3)"]
        THV["theharvester_scan"]
        SHO["shodan_lookup"]
        WW["whatweb_scan"]
    end

    subgraph INJ["Injection (2)"]
        SQL["sqlmap_scan"]
        XSS["xss_scan"]
    end

    subgraph EXP["Exploitation (5)"]
        MSS["msf_search"]
        MSI["msf_module_info"]
        MSR["msf_run_module"]
        MSSL["msf_sessions_list"]
        SEX["searchsploit_query"]
    end

    subgraph BRF["Bruteforce (4)"]
        HYD["hydra_attack"]
        HCR["hash_crack"]
        HID["hash_identify"]
        CEW["cewl_generate"]
    end

    subgraph PRX["Proxy (3)"]
        ZSP["zap_spider"]
        ZAS["zap_active_scan"]
        ZAL["zap_get_alerts"]
    end

    subgraph ANA["Analysis (4)"]
        COR["correlate_findings"]
        SCR["score_risk"]
        CVL["cve_lookup"]
        CVS["cve_search"]
    end

    subgraph REP["Reporting (1)"]
        GEN["generate_report"]
    end

    subgraph SEC["Secrets (2)"]
        TRF["trufflehog_scan"]
        GLK["gitleaks_scan"]
    end

    subgraph CONT["Container (1)"]
        TRV["trivy_scan"]
    end

    subgraph CLD["Cloud (1)"]
        SCT["scoutsuite_scan"]
    end

    subgraph API["API Security (2)"]
        ARJ["arjun_discover"]
        GQL["graphql_security_check"]
    end

    subgraph AD["Active Directory (3)"]
        E4L["enum4linux_scan"]
        NXC["nxc_enum"]
        IMP["impacket_kerberoast"]
    end

    subgraph WLS["Wireless (1)"]
        AIR["aircrack_scan"]
    end

    subgraph IAC["IaC Security (1)"]
        CHK["checkov_scan"]
    end

    subgraph STL["Stealth (5)"]
        TOR["tor_check"]
        TNI["tor_new_identity"]
        CHK2["check_anonymity"]
        PRC["proxy_check"]
        ROT["rotate_identity"]
    end

    subgraph UTL["Utility (2)"]
        CT["check_tools"]
        VT["validate_target"]
    end
```

---

## Stealth Layer Architecture

The stealth layer (`src/tengu/stealth/`) is an optional, transparent anonymization
subsystem enabled via `tengu.toml`. Tool code does not need to check whether stealth
mode is active — the layer intercepts at the argument-building and HTTP-client levels.

### Data Flow with Stealth Enabled

```
Tool function builds args list
        │
        ▼
StealthLayer.inject_proxy_flags(tool_name, args)
        │                               │
        │  stealth disabled             │  stealth + proxy enabled
        │  (returns args unchanged)     ▼
        │                     args += ["--proxies", "socks5h://127.0.0.1:9050"]
        │                     (flag varies by tool — see table below)
        ▼
timing.jitter_sleep()          ← random sleep to break timing fingerprints
        │
        ▼
run_command(args)              ← executor layer (unchanged)
```

For HTTP-based tools (`analyze_headers`, `test_cors`):

```
stealth.create_http_client()
        │
        ▼
httpx.AsyncClient(
    proxies={"all://": proxy_url},
    headers={"User-Agent": user_agents.next()},
)
```

### Proxy Flag Injection per Tool

| Tool | CLI flag appended |
|------|-------------------|
| nmap | `--proxies <url>` |
| nuclei | `-proxy <url>` |
| ffuf | `-x <url>` |
| sqlmap | `--proxy <url>` |
| subfinder | `--proxy <url>` |
| nikto | `-useproxy <url>` |
| gobuster | `--proxy <url>` |
| wpscan | `--proxy <url>` |
| curl (internal) | `-x <url>` |
| httpx (internal) | `proxies=` kwarg |

---

## Design Decisions

### Why FastMCP?

FastMCP is the official Python SDK for building MCP servers. It provides:
- Automatic JSON-RPC serialization/deserialization
- Tool registration via simple function decoration (`mcp.tool()`)
- Resource registration via URI templates (`@mcp.resource("scheme://path/{param}")`)
- Prompt registration (`mcp.prompt()`)
- Progress reporting via `ctx.report_progress(current, total, message)`
- Both stdio and SSE transport support

The alternative — implementing the MCP protocol directly — would require thousands
of lines of boilerplate and introduce correctness risks in the protocol layer.

### Why No shell=True?

`shell=True` passes the command string to `/bin/sh -c`, which interprets shell
metacharacters. An attacker who can inject characters like `;`, `|`, `$()`, or
backticks into a parameter can execute arbitrary commands.

`asyncio.create_subprocess_exec()` passes arguments directly to `execve()` as an
argument vector. The kernel never invokes a shell, so shell metacharacters in
arguments have no special meaning. This is a complete class of vulnerability
eliminated by design.

Even though Tengu also sanitizes all inputs (defense in depth), the no-shell rule
is the primary and unconditional protection.

### Why Pydantic v2?

- Runtime validation of all configuration values on startup
- Automatic error messages for invalid config
- Type-safe model serialization/deserialization via `model_dump()` and `model_validate()`
- Field validators for complex constraints (e.g., ensuring `allowed_hosts` is always a list)
- Used consistently for all data structures: config, tool results, finding models

### Why structlog?

- Structured JSON log output — every log entry is machine-parseable
- Context binding (`logger.bind(target=x, tool=y)`) avoids repeating context in every call
- Compatible with the standard `logging` module for library compatibility
- The audit log is also JSONL — tools like `jq` can query it directly

### Why a Sliding Window Rate Limiter?

The sliding window algorithm (vs. fixed window) prevents burst-at-boundary attacks
where an attacker makes N calls at the end of window 1 and N more at the start of
window 2, effectively doubling the rate.

The in-memory implementation is intentional — Tengu is designed for single-server
deployments where Redis would be unnecessary overhead. If multi-server deployments
are needed, the `SlidingWindowRateLimiter` class can be replaced with a Redis-backed
implementation without changing any tool code.

### Why SQLite for CVE Cache?

- No additional infrastructure (no Redis, no PostgreSQL)
- Survives server restarts (unlike in-memory dict)
- Fast enough for lookup-heavy workloads (CVE IDs are primary keys)
- Simple to inspect and debug with standard SQLite tools
- 24-hour TTL prevents stale CVE data

---

## Module Map with Descriptions

| Module | Description |
|--------|-------------|
| `server.py` | FastMCP server instance. Imports and registers all 56 tools, 19 resources, and 34 prompts. Contains the `main()` entry point. |
| `config.py` | Loads `tengu.toml` with `tomllib`, applies env var overrides, returns a `TenguConfig` singleton. Contains default blocked hosts list. |
| `types.py` | All shared Pydantic v2 models: network scan models (`Host`, `Port`, `ScanResult`), web models (`SecurityHeader`, `CORSResult`, `SSLResult`), finding models (`Finding`, `Evidence`), report models (`PentestReport`, `RiskMatrix`), CVE models (`CVERecord`, `CVSSMetrics`), tool status models (`ToolStatus`, `ToolsCheckResult`). |
| `exceptions.py` | Custom exception hierarchy rooted at `TenguError`. Each exception carries structured data (tool name, target, returncode, etc.) for programmatic handling. |
| `security/sanitizer.py` | Input validation functions for every parameter type, including `sanitize_repo_url`, `sanitize_docker_image`, `sanitize_proxy_url` added in v0.2.1. All functions raise `InvalidInputError` on invalid input. Never mutates input silently — either returns the sanitized value or raises. |
| `security/allowlist.py` | `TargetAllowlist` class with `check(target)` method. Supports CIDR, exact hostname, and wildcard patterns. Blocklist always evaluated before allowlist. |
| `security/rate_limiter.py` | `SlidingWindowRateLimiter` with per-tool call time tracking and concurrent slot counting. `rate_limited` is an async context manager for clean usage. |
| `security/audit.py` | `AuditLogger` writes append-only JSONL records to `logs/tengu-audit.log`. Async write with `asyncio.Lock` to prevent interleaving. `_redact_sensitive()` removes secrets before logging. |
| `executor/process.py` | `run_command()` — runs a command, returns `(stdout, stderr, returncode)`. `stream_command()` — async generator yielding output lines. Both use `asyncio.create_subprocess_exec`, never `shell=True`. |
| `executor/registry.py` | `check_all()` — discovers all tools in `_TOOL_CATALOG` and returns `ToolsCheckResult`. `resolve_tool_path()` — returns configured or auto-detected tool path. |
| `stealth/layer.py` | `StealthLayer` singleton. `inject_proxy_flags(tool_name, args)` appends proxy CLI flags for 10 supported tools when stealth mode is enabled. |
| `stealth/config.py` | `StealthConfig` Pydantic model loaded from `[stealth]` section in `tengu.toml`. |
| `stealth/timing.py` | Jitter utilities: configurable random sleep ranges to break inter-request timing fingerprints. |
| `stealth/user_agents.py` | Rotating pool of realistic browser user-agent strings. |
| `stealth/http_client.py` | `create_http_client()` — returns `httpx.AsyncClient` pre-configured with proxy and user-agent when stealth is enabled. Used by `analyze_headers` and `test_cors`. |
| `tools/utility.py` | `check_tools` and `validate_target` — the two utility MCP tools used to diagnose setup and pre-validate targets. |
| `tools/recon/nmap.py` | `nmap_scan` — the canonical reference tool implementation. Includes XML output parsing via `xml.etree.ElementTree`. |
| `tools/osint/` | OSINT tools added in v0.2.0: `theharvester_scan`, `shodan_lookup`, `whatweb_scan`. |
| `tools/secrets/` | Secret scanning tools added in v0.2.0: `trufflehog_scan`, `gitleaks_scan`. |
| `tools/container/` | Container security tool added in v0.2.0: `trivy_scan`. |
| `tools/cloud/` | Cloud security tool added in v0.2.0: `scoutsuite_scan`. |
| `tools/api/` | API security tools added in v0.2.0: `arjun_discover`, `graphql_security_check`. |
| `tools/ad/` | Active Directory tools added in v0.2.0: `enum4linux_scan`, `nxc_enum`, `impacket_kerberoast`. |
| `tools/wireless/` | Wireless security tool added in v0.2.0: `aircrack_scan`. |
| `tools/iac/` | IaC security tool added in v0.2.0: `checkov_scan`. |
| `tools/stealth/` | MCP-exposed stealth control tools added in v0.2.1: `tor_check`, `tor_new_identity`, `check_anonymity`, `proxy_check`, `rotate_identity`. |
| `tools/analysis/correlate.py` | `correlate_findings` — identifies attack chains by matching OWASP categories across findings. `score_risk` — CVSS-weighted risk scoring with context multipliers. |
| `tools/analysis/reporting/generate.py` | `generate_report` — Jinja2-based report rendering. Supports Markdown, HTML, and PDF (via WeasyPrint). |
| `resources/owasp.py` | OWASP Top 10:2025 and OWASP API Security Top 10 data access. Data stored in `resources/data/`. |
| `resources/ptes.py` | PTES 7-phase methodology data. Data stored in `resources/data/ptes_phases.json`. |
| `resources/checklists.py` | Web application, API, and network pentest checklists. |
| `resources/mitre.py` | MITRE ATT&CK tactic and technique data added in v0.2.0. |
| `resources/data/` | Static JSON data files: OWASP Top 10, OWASP API Top 10, PTES phases, checklists, MITRE ATT&CK, default credentials, security payloads, stealth techniques. |
| `prompts/pentest_workflow.py` | Workflow prompts: `full_pentest` (7 PTES phases), `quick_recon` (7-step fast recon), `web_app_assessment` (OWASP OTG). |
| `prompts/vuln_assessment.py` | Focused assessment prompts: injection, access control, cryptography, misconfiguration. |
| `prompts/report_prompts.py` | Report prompts: executive, technical, full, remediation plan, finding detail, risk matrix, retest. |
| `prompts/advanced_workflows.py` | Advanced prompts added in v0.2.0: osint_investigation, stealth_assessment, opsec_checklist, api_security_assessment, ad_assessment, container_assessment, cloud_assessment, bug_bounty_workflow, compliance_assessment, wireless_assessment. |
| `prompts/quick_actions.py` | Quick action prompts added in v0.2.1: crack_wifi, explore_url, go_stealth, find_secrets, map_network, hunt_subdomains, find_vulns, pwn_target. |
