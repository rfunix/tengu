# Tengu — Pentesting MCP Server

<p align="center">
  <img src="assets/Tengu.png" alt="Tengu" width="480"/>
</p>

<p align="center">
  <strong>From recon to report — AI-assisted pentesting in one command.</strong>
</p>

<p align="center">
  <video src="docs/tengu-demo.mp4" autoplay loop muted playsinline width="800"></video>
</p>

<p align="center">
  <a href="https://github.com/rfunix/tengu/actions/workflows/ci.yml"><img src="https://github.com/rfunix/tengu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP"></a>
  <img src="https://img.shields.io/badge/tools-56-orange.svg" alt="Tools">
  <img src="https://img.shields.io/badge/version-0.2.0-brightgreen.svg" alt="Version">
</p>

---

**Tengu** is an MCP server that turns Claude into a penetration testing copilot. It orchestrates 56 security tools — from Nmap to Metasploit — with built-in safety controls, audit logging, and professional reporting.

- **What is it?** An MCP server that connects Claude to industry-standard pentest tools
- **Why use it?** Automates recon and scanning while keeping the human in control of exploits
- **Who is it for?** Pentesters, red teamers, security students, and consulting firms

### Key Features

- **56 Tools** — Nmap, Metasploit, SQLMap, Nuclei, Hydra, Burp-compatible ZAP, and more
- **AI-Orchestrated** — Claude decides the next tool based on previous findings
- **Safety First** — Allowlist, rate limiting, audit logs, and human-in-the-loop for destructive actions
- **Auto Reports** — Correlate findings and generate professional pentest reports (MD/HTML/PDF)
- **26 Workflows** — Pre-built prompts for full pentest, web app, AD, cloud, and more
- **19 Resources** — Built-in OWASP Top 10, MITRE ATT&CK, PTES, and pentest checklists
- **Stealth Layer** — Optional Tor/SOCKS5 proxy routing, UA rotation, and timing jitter

---

## Quick Start

### Prerequisites

- Python 3.11+
- [`uv`](https://github.com/astral-sh/uv) package manager
- Kali Linux (recommended) or any Linux with security tools

### Install & Run

```bash
git clone https://github.com/rfunix/tengu.git
cd tengu

# Install Python dependencies
uv sync

# Install external pentesting tools (Kali/Debian)
make install-tools

# Run the MCP server (stdio transport)
uv run tengu
```

### Connect to Claude Code

```bash
claude mcp add --scope user tengu -- uv run --directory /path/to/tengu tengu
```

Or add manually to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tengu", "tengu"]
    }
  }
}
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tengu", "tengu"]
    }
  }
}
```

### Remote / VM Setup (SSE Transport)

Run Tengu on a remote machine (e.g. Kali Linux in a VM):

```bash
uv run tengu --transport sse --host 0.0.0.0 --port 8000
```

Then connect from your host:

```json
{
  "mcpServers": {
    "tengu": {
      "url": "http://<kali-ip>:8000/sse"
    }
  }
}
```

### Configure Targets

Edit `tengu.toml` before running any scan — only listed targets will be accepted:

```toml
[targets]
allowed_hosts = ["192.168.1.0/24", "example.com"]
```

---

## Tool Catalog

| Category | Tools | Count |
|----------|-------|-------|
| Reconnaissance | Nmap, Masscan, Amass, Subfinder, theHarvester, WhatWeb, Gowitness | 7 |
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
<summary>Full tool list (56 tools)</summary>

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

### API Security
| Tool | Description |
|------|-------------|
| `arjun_discover` | Hidden HTTP parameter discovery |
| `graphql_security_check` | GraphQL security testing |

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

## Pre-built Workflows (26 Prompts)

Tengu includes guided workflows that automatically chain multiple tools:

| Workflow | Description |
|----------|-------------|
| `full_pentest` | Complete engagement: recon → scanning → exploitation → reporting |
| `quick_recon` | Fast passive reconnaissance and asset discovery |
| `web_app_assessment` | OWASP Top 10 focused web application testing |
| `api_security_assessment` | REST and GraphQL API security review |
| `active_directory_audit` | AD enumeration, Kerberoasting, lateral movement paths |
| `cloud_security_review` | AWS/Azure/GCP misconfiguration audit |
| `container_assessment` | Docker image, IaC, and registry security review |
| `osint_investigation` | Passive OSINT from public sources |
| `stealth_assessment` | Anonymized testing via Tor + jitter |
| `bug_bounty_workflow` | Optimized workflow for bug bounty programs |
| `compliance_assessment` | Compliance-focused security review |
| `wireless_assessment` | Wireless network security testing |
| `find_secrets` | Detect leaked credentials in repos and code |
| `hunt_subdomains` | Comprehensive subdomain discovery |
| … and 12 more | Reporting, remediation, individual finding workflows |

---

## Knowledge Resources (19)

Built-in reference data available to Claude during testing:

| Resource | Description |
|----------|-------------|
| OWASP Top 10 (2021) | Full category descriptions and testing checklists |
| OWASP API Top 10 | API-specific vulnerability reference |
| MITRE ATT&CK | Adversary tactics, techniques, and procedures |
| PTES Methodology | Penetration Testing Execution Standard phases |
| Web App Checklist | Comprehensive web application test checklist |
| API Checklist | REST/GraphQL security checklist |
| Network Checklist | Network penetration testing checklist |
| CWE Top 25 | Most dangerous software weaknesses |
| Default Credentials | Common default credentials database |
| Payloads | Common payloads for injection testing |
| Stealth Techniques | OPSEC and evasion reference |

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

Set up isolated vulnerable targets for safe, legal testing:

```bash
# DVWA — classic web vulnerabilities
docker run -d -p 80:80 vulnerables/web-dvwa

# OWASP Juice Shop — OWASP Top 10
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVGA — GraphQL vulnerabilities
docker run -d -p 5013:5013 dolevf/dvga

# Metasploitable 2 — network services
docker run -d -p 2121:21 -p 2222:22 -p 8180:8080 tleemcjr/metasploitable2
```

Then allow them in `tengu.toml`:

```toml
[targets]
allowed_hosts = ["127.0.0.1", "localhost"]
```

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
