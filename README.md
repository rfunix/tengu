# Tengu — Pentesting MCP Server

[![CI](https://github.com/rfunix/tengu/actions/workflows/ci.yml/badge.svg)](https://github.com/rfunix/tengu/actions/workflows/ci.yml)

Tengu is an MCP (Model Context Protocol) server that provides an intelligent abstraction layer over industry-standard penetration testing tools (Metasploit, Nmap, Nuclei, SQLMap, Dalfox, Hydra, OWASP ZAP, and more).

## Quick Start

```bash
# Install Python dependencies
make install-dev

# Install external pentesting tools
make install-tools

# Run the MCP server (stdio transport)
make run

# Open MCP Inspector for interactive testing
make inspect

# Check which tools are installed
make doctor
```

## Architecture

```
tengu/
├── src/tengu/
│   ├── server.py          # FastMCP entry point — registers all tools/resources/prompts
│   ├── config.py          # Configuration (tengu.toml + env vars)
│   ├── types.py           # Shared Pydantic models
│   ├── security/          # Sanitizer, allowlist, rate limiter, audit logger
│   ├── executor/          # Safe async subprocess execution (never shell=True)
│   ├── tools/             # MCP Tools (recon, web, injection, exploit, brute, proxy, analysis, reporting)
│   ├── resources/         # MCP Resources (OWASP, PTES, CWE, CVE, checklists)
│   └── prompts/           # MCP Prompts (pentest workflows, reporting)
```

## Configuration

Copy `.env.example` to `.env` and edit `tengu.toml`:

```toml
[targets]
# REQUIRED: Add your authorized targets before running any scan
allowed_hosts = ["example.com", "192.168.1.0/24"]
```

## Tools

### Reconnaissance
`nmap_scan`, `masscan_scan`, `subfinder_enum`, `dns_enumerate`, `whois_lookup`

### Web Scanning
`nuclei_scan`, `nikto_scan`, `ffuf_fuzz`, `analyze_headers`, `test_cors`, `ssl_tls_check`

### Injection Testing
`sqlmap_scan`, `xss_scan`

### Exploitation
`msf_search`, `msf_module_info`, `msf_run_module`, `msf_sessions_list`, `searchsploit_query`

### Brute Force
`hydra_attack`, `hash_crack`, `hash_identify`

### Proxy
`zap_spider`, `zap_active_scan`, `zap_get_alerts`

### Analysis & Reporting
`correlate_findings`, `score_risk`, `cve_search`, `cve_lookup`, `generate_report`, `check_tools`, `validate_target`

## Security

- **No shell=True — ever.** All subprocess calls use `asyncio.create_subprocess_exec` with argument lists.
- **Allowlist enforcement.** Every scan validates the target against `tengu.toml [targets].allowed_hosts`.
- **Input sanitization.** All inputs are validated against strict patterns before reaching executors.
- **Audit logging.** Every tool invocation is logged to `./logs/tengu-audit.log` in JSON format.
- **Rate limiting.** Configurable limits prevent accidental DoS (default: 10 scans/min, 3 concurrent).

## Legal Notice

Tengu is designed for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.
