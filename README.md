# Tengu — Pentesting MCP Server

<p align="center">
  <img src="assets/Tengu.png" alt="Tengu" width="480"/>
</p>

[![CI](https://github.com/rfunix/tengu/actions/workflows/ci.yml/badge.svg)](https://github.com/rfunix/tengu/actions/workflows/ci.yml)

Tengu is an MCP (Model Context Protocol) server that provides an intelligent abstraction layer over industry-standard penetration testing tools. Integrates with Claude Code and Claude Desktop to enable AI-assisted pentesting workflows.

**v0.2.0** — 56 tools · 19 resources · 26 prompts

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

## Claude Code Integration

```json
// ~/.claude/settings.json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tengu", "tengu"]
    }
  }
}
```

For remote use (e.g. Kali Linux via UTM):

```json
{
  "mcpServers": {
    "tengu": {
      "url": "http://<kali-ip>:8000/sse"
    }
  }
}
```

## Tools (56)

### Reconnaissance
| Tool | Description |
|---|---|
| `nmap_scan` | Port scanning and service/OS detection |
| `masscan_scan` | High-speed port scanner |
| `subfinder_enum` | Passive subdomain enumeration |
| `amass_enum` | Attack surface mapping and DNS brute-force |
| `dnsrecon_scan` | DNS reconnaissance (zone transfer, brute-force, PTR) |
| `dns_enumerate` | DNS record enumeration |
| `whois_lookup` | WHOIS domain and IP lookup |
| `subjack_check` | Subdomain takeover detection |
| `gowitness_screenshot` | Web screenshot capture for documentation |

### Web Scanning
| Tool | Description |
|---|---|
| `nuclei_scan` | Template-based vulnerability scanner |
| `nikto_scan` | Web server misconfiguration scanner |
| `ffuf_fuzz` | Web fuzzer for directories, parameters, and vhosts |
| `gobuster_scan` | Directory, DNS, and vhost brute-force |
| `wpscan_scan` | WordPress vulnerability scanner |
| `testssl_check` | SSL/TLS configuration analysis |
| `analyze_headers` | HTTP security headers analysis |
| `test_cors` | CORS misconfiguration detection |
| `ssl_tls_check` | SSL/TLS certificate and cipher check |

### OSINT
| Tool | Description |
|---|---|
| `theharvester_scan` | Email, subdomain, and host enumeration from public sources |
| `shodan_lookup` | Shodan host and asset search |
| `whatweb_scan` | Web technology fingerprinting (CMS, WAF, frameworks) |

### Injection Testing
| Tool | Description |
|---|---|
| `sqlmap_scan` | Automated SQL injection detection and exploitation |
| `xss_scan` | Cross-site scripting detection (Dalfox) |

### Exploitation
| Tool | Description |
|---|---|
| `msf_search` | Search Metasploit modules |
| `msf_module_info` | Get detailed module information |
| `msf_run_module` | Execute a Metasploit module |
| `msf_sessions_list` | List active Metasploit sessions |
| `searchsploit_query` | Search Exploit-DB (offline) |

### Brute Force
| Tool | Description |
|---|---|
| `hydra_attack` | Network login brute-force |
| `hash_crack` | Hash cracking (Hashcat/John) |
| `hash_identify` | Hash type identification |
| `cewl_generate` | Custom wordlist generation from a target website |

### Proxy / DAST
| Tool | Description |
|---|---|
| `zap_spider` | OWASP ZAP web spider |
| `zap_active_scan` | OWASP ZAP active vulnerability scan |
| `zap_get_alerts` | Retrieve ZAP scan findings |

### Secrets & Code Analysis
| Tool | Description |
|---|---|
| `trufflehog_scan` | Leaked secrets detection in git repositories |
| `gitleaks_scan` | Credential scanning in git history |

### Container Security
| Tool | Description |
|---|---|
| `trivy_scan` | Vulnerability scanning for Docker images, IaC, and SBOM |

### Cloud Security
| Tool | Description |
|---|---|
| `scoutsuite_scan` | Cloud security audit (AWS, Azure, GCP) |

### API Security
| Tool | Description |
|---|---|
| `arjun_discover` | Hidden HTTP parameter discovery |
| `graphql_security_check` | GraphQL introspection, batching, depth limit, field suggestions |

### Active Directory
| Tool | Description |
|---|---|
| `enum4linux_scan` | SMB/NetBIOS enumeration |
| `nxc_enum` | Active Directory enumeration via NetExec (multi-protocol) |
| `impacket_kerberoast` | Kerberoasting with Impacket GetUserSPNs |

### Wireless
| Tool | Description |
|---|---|
| `aircrack_scan` | Passive wireless network scan (airodump-ng) |

### IaC Security
| Tool | Description |
|---|---|
| `checkov_scan` | Infrastructure-as-Code misconfiguration scan (Terraform, K8s, Docker) |

### Stealth / OPSEC
| Tool | Description |
|---|---|
| `tor_check` | Verify Tor connectivity and exit node IP |
| `tor_new_identity` | Request new Tor circuit (NEWNYM) |
| `check_anonymity` | Check exposed IP, DNS leaks, and anonymity level |
| `proxy_check` | Validate proxy latency, exit IP, and anonymity type |
| `rotate_identity` | Rotate Tor circuit and User-Agent simultaneously |

### Utility
| Tool | Description |
|---|---|
| `check_tools` | Verify which external tools are installed |
| `validate_target` | Validate target against allowlist |
| `correlate_findings` | Correlate findings across multiple scans |
| `score_risk` | CVSS-based risk scoring |
| `cve_lookup` | CVE details lookup |
| `cve_search` | Search CVEs by keyword or product |
| `generate_report` | Generate HTML/PDF pentest report |

## Architecture

```
src/tengu/
├── server.py          # FastMCP entry point — registers all tools/resources/prompts
├── config.py          # Configuration (tengu.toml + env vars)
├── types.py           # Shared Pydantic models
├── security/          # Sanitizer, allowlist, rate limiter, audit logger
├── executor/          # Safe async subprocess execution (never shell=True)
├── stealth/           # Tor/proxy injection, UA rotation, timing jitter, DoH
├── tools/             # 56 MCP tools across 16 categories
├── resources/         # 19 MCP resources (OWASP, PTES, MITRE ATT&CK, payloads, creds)
└── prompts/           # 26 MCP prompts (pentest workflows, reporting)
```

Every tool request passes through: `sanitizer → allowlist → rate_limiter → audit → executor`

## Configuration

Edit `tengu.toml`:

```toml
[targets]
# REQUIRED: Add authorized targets before running any scan
allowed_hosts = ["example.com", "192.168.1.0/24"]

[stealth]
enabled = false  # Enable Tor/proxy routing

[stealth.proxy]
enabled = false
type = "socks5"
host = "127.0.0.1"
port = 9050

[osint]
shodan_api_key = ""  # Required for shodan_lookup
```

## Security

- **No shell=True — ever.** All subprocess calls use `asyncio.create_subprocess_exec`.
- **Allowlist enforcement.** Every scan validates the target against `tengu.toml [targets].allowed_hosts`.
- **Input sanitization.** All inputs are validated against strict patterns before reaching executors.
- **Audit logging.** Every tool invocation is logged to `./logs/tengu-audit.log` in JSON format.
- **Rate limiting.** Configurable limits prevent accidental DoS (default: 10 scans/min, 3 concurrent).

## Legal Notice

Tengu is designed for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.
