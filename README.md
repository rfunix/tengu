# Tengu — Pentesting MCP Server

<p align="center">
  <img src="assets/Tengu.png" alt="Tengu" width="480"/>
</p>

<p align="center">
  <strong>From recon to report — AI-assisted pentesting in one command.</strong>
</p>

<p align="center">
  <a href="https://asciinema.org/a/ZdvkN5ZHOynmfjTO">
    <img src="https://asciinema.org/a/ZdvkN5ZHOynmfjTO.svg" alt="Tengu demo" width="800"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/rfunix/tengu/actions/workflows/ci.yml"><img src="https://github.com/rfunix/tengu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP"></a>
  <img src="https://img.shields.io/badge/tools-57-orange.svg" alt="Tools">
  <img src="https://img.shields.io/badge/version-0.2.1-brightgreen.svg" alt="Version">
</p>

---

**Tengu** is an MCP server that turns Claude into a penetration testing copilot. It orchestrates 57 security tools — from Nmap to Metasploit — with built-in safety controls, audit logging, and professional reporting.

- **What is it?** An MCP server that connects Claude to industry-standard pentest tools
- **Why use it?** Automates recon and scanning while keeping the human in control of exploits
- **Who is it for?** Pentesters, red teamers, security students, and consulting firms

### Key Features

- **57 Tools** — Nmap, Metasploit, SQLMap, Nuclei, Hydra, Burp-compatible ZAP, and more
- **AI-Orchestrated** — Claude decides the next tool based on previous findings
- **Safety First** — Allowlist, rate limiting, audit logs, and human-in-the-loop for destructive actions
- **Auto Reports** — Correlate findings and generate professional pentest reports (MD/HTML/PDF)
- **34 Workflows** — Pre-built prompts for full pentest, web app, AD, cloud, and more
- **19 Resources** — Built-in OWASP Top 10, MITRE ATT&CK, PTES, and pentest checklists
- **Stealth Layer** — Optional Tor/SOCKS5 proxy routing, UA rotation, and timing jitter

---

## Quick Start

### Docker (Recommended)

The fastest way to get Tengu running — no manual tool installation required.

```bash
git clone https://github.com/rfunix/tengu.git && cd tengu
docker compose up -d
```

Connect Claude Code to the running server:

```bash
claude mcp add --transport sse tengu http://localhost:8000/sse
```

**With lab targets (Juice Shop + DVWA):**

```bash
docker compose --profile lab up -d
```

**With Metasploit + ZAP + labs:**

```bash
docker compose --profile exploit --profile proxy --profile lab up -d
```

**Image tiers** — choose the right size for your use case:

| Tier | Size | MCP Tools | Use case |
|------|------|-----------|----------|
| `minimal` | ~480MB | 17 | Lightweight analysis, CVE research, reporting |
| `core` | ~7GB | 47 | Full pentest toolkit (default) |
| `full` | ~8GB | 57 | Everything + AD, wireless, stealth/OPSEC |

```bash
TENGU_TIER=minimal docker compose build   # lightweight
TENGU_TIER=core    docker compose build   # default
TENGU_TIER=full    docker compose build   # everything
```

**Scan custom targets** without editing files:

```bash
TENGU_ALLOWED_HOSTS="192.168.1.0/24,10.0.0.0/8" docker compose up -d
```

> **All tiers include all 34 prompts and 19 resources** — only the binary tools differ.

<details>
<summary>Manual Install (without Docker)</summary>

**Prerequisites:** Python 3.12+, [`uv`](https://github.com/astral-sh/uv), Kali Linux (recommended)

```bash
git clone https://github.com/rfunix/tengu.git && cd tengu

# Install Python dependencies
uv sync

# Install external pentesting tools (Kali/Debian)
make install-tools

# Run the MCP server (stdio transport)
uv run tengu
```

Connect Claude Code:

```bash
claude mcp add --scope user tengu -- uv run --directory /path/to/tengu tengu
```

Configure allowed targets in `tengu.toml`:

```toml
[targets]
allowed_hosts = ["192.168.1.0/24", "example.com"]
```

For Claude Desktop, VM/SSE remote setup, and advanced configurations, see [docs/deployment-guide.md](docs/deployment-guide.md).

</details>

---

## Tool Catalog

> `minimal` (17 tools, ~480MB) · `core` (47 tools, ~7GB, default) · `full` (57 tools, ~8GB)
> Build with: `TENGU_TIER=<tier> docker compose build`. All tiers include all 34 prompts and 19 resources.

| Category | Tools | Count |
|----------|-------|-------|
| Reconnaissance | Nmap, Masscan, Amass, Subfinder, theHarvester, WhatWeb, Gowitness, HTTrack | 8 |
| Web Scanning | Nikto, Nuclei, FFUF, Gobuster, WPScan, Arjun, OWASP ZAP | 7 |
| SSL / TLS | sslyze, testssl.sh, HTTP headers analysis, CORS tester | 4 |
| DNS | DNS Enumerate, DNSRecon, Subjack, WHOIS | 4 |
| Injection Testing | SQLMap, Dalfox (XSS), GraphQL Security Check | 3 |
| Brute Force | Hydra, John the Ripper, Hashcat, CeWL | 4 |
| Exploitation | Metasploit (search, info, run, sessions), SearchSploit | 5 |
| OSINT | theHarvester, Shodan, WHOIS | 3 |
| Secrets & Code | TruffleHog, Gitleaks | 2 |
| Container & Cloud | Trivy, Checkov, ScoutSuite | 3 |
| Active Directory | NetExec, Enum4linux, Impacket Kerberoast | 3 |
| Wireless | aircrack-ng / airodump-ng | 1 |
| Anonymity & Stealth | Tor check/rotate, proxy check, identity rotation | 5 |
| Analysis & Reporting | Finding correlation, CVSS risk scoring, report generation | 3 |
| CVE Intelligence | CVE lookup (NVD), CVE search by keyword/product/severity | 2 |
| Utility | Tool checker, target validator | 2 |

<details>
<summary>Full tool list (57 tools)</summary>

### Reconnaissance
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning and service/OS detection |
| `masscan_scan` | High-speed port scanner for large networks |
| `subfinder_enum` | Passive subdomain enumeration |
| `amass_enum` | Attack surface mapping and DNS brute-force |
| `dnsrecon_scan` | DNS recon (zone transfer, brute-force, PTR) |
| `dns_enumerate` | DNS record enumeration (A, MX, NS, TXT, SOA…) |
| `whois_lookup` | WHOIS domain and IP lookup |
| `subjack_check` | Subdomain takeover detection |
| `gowitness_screenshot` | Web screenshot capture for documentation |
| `httrack_mirror` | Full website mirror for offline analysis and forensics |

### Web Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Template-based vulnerability scanner (CVEs, misconfigs) |
| `nikto_scan` | Web server misconfiguration and outdated software scanner |
| `ffuf_fuzz` | Directory, parameter, and vhost fuzzing |
| `gobuster_scan` | Directory, DNS, and vhost brute-force |
| `wpscan_scan` | WordPress vulnerability scanner |
| `testssl_check` | Comprehensive SSL/TLS configuration analysis |
| `analyze_headers` | HTTP security headers analysis and grading |
| `test_cors` | CORS misconfiguration detection |
| `ssl_tls_check` | SSL/TLS certificate and cipher check (sslyze) |

### OSINT
| Tool | Description |
|------|-------------|
| `theharvester_scan` | Email, subdomain, and host enumeration from public sources |
| `shodan_lookup` | Shodan host and asset search |
| `whatweb_scan` | Web technology fingerprinting (CMS, WAF, frameworks) |

### Injection Testing
| Tool | Description |
|------|-------------|
| `sqlmap_scan` | Automated SQL injection detection and exploitation |
| `xss_scan` | XSS detection via Dalfox |
| `graphql_security_check` | GraphQL introspection, batching, depth limit, field suggestions |
| `arjun_discover` | Hidden HTTP parameter discovery |

### Exploitation
| Tool | Description |
|------|-------------|
| `msf_search` | Search Metasploit modules |
| `msf_module_info` | Get detailed Metasploit module information |
| `msf_run_module` | Execute a Metasploit module (requires explicit confirmation) |
| `msf_sessions_list` | List active Metasploit sessions |
| `searchsploit_query` | Search Exploit-DB offline database |

### Brute Force
| Tool | Description |
|------|-------------|
| `hydra_attack` | Network login brute-force (SSH, FTP, HTTP, SMB…) |
| `hash_crack` | Dictionary hash cracking (Hashcat / John the Ripper) |
| `hash_identify` | Hash type identification |
| `cewl_generate` | Custom wordlist generation from a target website |

### Proxy / DAST
| Tool | Description |
|------|-------------|
| `zap_spider` | OWASP ZAP web spider |
| `zap_active_scan` | OWASP ZAP active vulnerability scan |
| `zap_get_alerts` | Retrieve ZAP scan findings |

### Secrets & Code Analysis
| Tool | Description |
|------|-------------|
| `trufflehog_scan` | Leaked secrets detection in git repositories |
| `gitleaks_scan` | Credential scanning in git history |

### Container Security
| Tool | Description |
|------|-------------|
| `trivy_scan` | Vulnerability scanning for Docker images, IaC, and SBOM |

### Cloud Security
| Tool | Description |
|------|-------------|
| `scoutsuite_scan` | Cloud security audit (AWS, Azure, GCP) |

### Active Directory
| Tool | Description |
|------|-------------|
| `enum4linux_scan` | SMB/NetBIOS enumeration |
| `nxc_enum` | Active Directory enumeration via NetExec |
| `impacket_kerberoast` | Kerberoasting with Impacket GetUserSPNs |

### Wireless
| Tool | Description |
|------|-------------|
| `aircrack_scan` | Passive wireless network scan (airodump-ng) |

### IaC Security
| Tool | Description |
|------|-------------|
| `checkov_scan` | IaC misconfiguration scan (Terraform, K8s, Dockerfile) |

### Stealth / OPSEC
| Tool | Description |
|------|-------------|
| `tor_check` | Verify Tor connectivity and exit node IP |
| `tor_new_identity` | Request new Tor circuit (NEWNYM) |
| `check_anonymity` | Check exposed IP, DNS leaks, and anonymity level |
| `proxy_check` | Validate proxy latency, exit IP, and anonymity type |
| `rotate_identity` | Rotate Tor circuit and User-Agent simultaneously |

### Analysis & Utility
| Tool | Description |
|------|-------------|
| `check_tools` | Verify which external tools are installed |
| `validate_target` | Validate target against allowlist |
| `correlate_findings` | Correlate findings across multiple scans |
| `score_risk` | CVSS-based risk scoring |
| `cve_lookup` | CVE details from NVD (CVSS, CWE, affected products) |
| `cve_search` | Search CVEs by keyword, product, or severity |
| `generate_report` | Generate Markdown/HTML/PDF pentest report |

</details>

---

## Workflows & Prompts (34)

Pre-built workflow templates that guide Claude through complete engagements.

| Category | Prompts |
|----------|---------|
| **Pentest workflows** | `full_pentest`, `quick_recon`, `web_app_assessment` |
| **Vulnerability assessment** | `assess_injection`, `assess_access_control`, `assess_crypto`, `assess_misconfig` |
| **OSINT** | `osint_investigation` |
| **Reports** | `executive_report`, `technical_report`, `full_pentest_report`, `finding_detail`, `risk_matrix`, `remediation_plan`, `retest_report` |
| **Stealth/OPSEC** | `stealth_assessment`, `opsec_checklist` |
| **Specialized** | `ad_assessment`, `api_security_assessment`, `container_assessment`, `cloud_assessment`, `wireless_assessment`, `bug_bounty_workflow`, `compliance_assessment` |
| **Quick actions** | `explore_url`, `map_network`, `hunt_subdomains`, `find_vulns`, `find_secrets`, `go_stealth`, `crack_wifi`, `pwn_target` |

---

## Built-in Resources (19)

Static reference data loaded by Claude during engagements.

| URI | Content |
|-----|---------|
| `owasp://top10/2025` | OWASP Top 10:2025 full list |
| `owasp://top10/2025/{A01..A10}` | Per-category details + testing checklist |
| `owasp://api-security/top10` | OWASP API Security Top 10 (2023) |
| `owasp://api-security/top10/{API1..API10}` | Per-category details |
| `ptes://phases` | PTES 7-phase methodology overview |
| `ptes://phase/{1..7}` | Phase details (objectives, tools, deliverables) |
| `checklist://web-application` | Web app pentest checklist (OWASP Testing Guide) |
| `checklist://api` | API pentest checklist |
| `checklist://network` | Network infrastructure checklist |
| `mitre://attack/tactics` | MITRE ATT&CK Enterprise tactics + techniques |
| `mitre://attack/technique/{T1xxx}` | Technique detail by ID |
| `creds://defaults/{product}` | Default credentials database |
| `tools://catalog` | Live tool availability status |
| `tools://{tool}/usage` | Usage guide for nmap, nuclei, sqlmap, metasploit, trivy, amass |

---

## Architecture

```
┌─────────────┐     MCP      ┌─────────────────┐    subprocess    ┌─────────────────┐
│   Claude    │◄────────────►│     Tengu        │─────────────────►│  Nmap, SQLMap,  │
│  (Desktop / │  stdio/SSE   │   MCP Server     │  (never shell=T) │  Metasploit...  │
│   Code)     │              │                  │                  └─────────────────┘
└─────────────┘              └────────┬─────────┘
                                      │
                               Every tool call passes through:
                                      │
                             ┌────────▼─────────┐
                             │  Safety Pipeline  │
                             │                  │
                             │  1. sanitizer    │  ← strip metacharacters, validate format
                             │  2. allowlist    │  ← check target against tengu.toml
                             │  3. rate_limiter │  ← sliding window + concurrent slots
                             │  4. audit logger │  ← JSON log to ./logs/tengu-audit.log
                             └──────────────────┘
```

---

## Safety by Design

Tengu is built as a **force multiplier for human pentesters**, not an autonomous attack tool.

| Control | Description |
|---------|-------------|
| **Target Allowlist** | Only pre-approved targets in `tengu.toml` are ever scanned |
| **Input Sanitization** | All inputs are validated against strict patterns before reaching any tool |
| **Rate Limiting** | Sliding window + concurrent slot limits prevent accidental DoS |
| **Audit Logging** | Every tool invocation logged to `./logs/tengu-audit.log` in JSON format |
| **Human-in-the-Loop** | `msf_run_module`, `hydra_attack`, and `impacket_kerberoast` require explicit confirmation |
| **No shell=True — ever** | All subprocess calls use `asyncio.create_subprocess_exec` |

---

## Practice Lab

Set up isolated vulnerable targets for safe, legal testing.

```
┌─────────────────────┐         LAN          ┌──────────────────────┐
│  Host (Mac/Windows) │◄────────────────────►│  Kali Linux VM       │
│                     │  Claude → SSE :8000  │                      │
│  Docker containers  │                      │  Tengu MCP Server    │
│  :3000  Juice Shop  │◄────────────────────►│  nmap, sqlmap,       │
│  :80    DVWA        │  Tengu scans targets │  nuclei, hydra...    │
│  :5013  DVGA        │                      │                      │
└─────────────────────┘                      └──────────────────────┘
         ▲
         │ Claude Code (MCP client)
```

**Start with Docker Compose** (simplest — runs Tengu + lab targets on one machine):

```bash
docker compose --profile lab up -d
```

**Or run lab targets individually on your host:**

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop      # OWASP Juice Shop
docker run -d -p 80:80 vulnerables/web-dvwa            # DVWA
docker run -d -p 5013:5013 dolevf/dvga                 # DVGA (GraphQL)
docker run -d -p 2121:21 -p 2222:22 tleemcjr/metasploitable2
```

Then ask Claude:

```
Do a full pentest on http://192.168.86.30:3000
```

Claude chains tools automatically: `validate_target` → `whatweb` → `nmap` → `nikto` →
`nuclei` → `sqlmap` → `correlate_findings` → `generate_report`

For step-by-step Kali VM setup, SSE transport configuration, and remote client connection,
see [docs/deployment-guide.md](docs/deployment-guide.md).

---

## Configuration Reference

```toml
[targets]
# REQUIRED: Only these hosts will be scanned
allowed_hosts = ["192.168.1.0/24", "example.com"]
blocked_hosts = []  # Always blocked, even if in allowed_hosts

[stealth]
enabled = false  # Route traffic through Tor/proxy

[stealth.proxy]
enabled = false
url = "socks5h://127.0.0.1:9050"

[osint]
shodan_api_key = ""  # Required for shodan_lookup

[tools.defaults]
scan_timeout = 300   # seconds
```

See [docs/configuration-reference.md](docs/configuration-reference.md) for the full reference.

---

## Development

```bash
make install-dev    # Install Python deps + dev extras
make test           # Run unit + security tests
make lint           # ruff check
make typecheck      # mypy strict
make check          # lint + typecheck
make coverage       # pytest --cov
make inspect        # Open MCP Inspector
make doctor         # Check which pentest tools are installed
```

Tengu has 1931+ tests covering unit logic, security (command injection, input validation), and integration scenarios. See [CLAUDE.md](CLAUDE.md) for the full contributor guide.

---

## Legal Notice

Tengu is designed for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. The authors accept no liability for misuse.
