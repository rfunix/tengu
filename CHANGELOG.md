# Changelog

All notable changes to Tengu are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Tengu uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] — Expanded Tool Coverage

### Added

**Reconnaissance Tools (4 new MCP tools)**
- `katana_crawl` — fast web crawler for link discovery and endpoint mapping
- `httpx_probe` — HTTP probe for status codes, tech stack, and redirect following
- `snmpwalk_scan` — SNMP enumeration and MIB walking for network device discovery
- `rustscan_scan` — ultra-fast port scanning (finds open ports, hands off to Nmap for detail)

**Web Scanning Tools (2 new MCP tools)**
- `wafw00f_scan` — Web Application Firewall detection and fingerprinting
- `feroxbuster_scan` — fast, recursive content discovery via brute-force

**OSINT Tools (1 new MCP tool)**
- `dnstwist_scan` — domain permutation and typosquatting detection

**Injection Tools (2 new MCP tools)**
- `commix_scan` — automated command injection detection and exploitation
- `crlfuzz_scan` — CRLF injection fuzzing for header injection vulnerabilities

**Cloud Security Tools (1 new MCP tool)**
- `prowler_scan` — AWS/GCP/Azure security best practices and compliance audit (CIS, GDPR, HIPAA, SOC2)

**Active Directory Tools (7 new MCP tools)**
- `impacket_secretsdump` — remote SAM/LSA/NTDS secrets dump via Impacket (requires explicit confirmation)
- `impacket_psexec` — remote command execution via SMB PsExec-style (requires explicit confirmation)
- `impacket_wmiexec` — remote command execution via WMI (requires explicit confirmation)
- `impacket_smbclient` — SMB share enumeration and file access
- `bloodhound_collect` — BloodHound AD data collection (SharpHound/bloodhound-python)
- `responder_capture` — LLMNR/NBT-NS/MDNS poisoning for credential capture (requires explicit confirmation)
- `smbmap_scan` — SMB share enumeration and access testing

**Social Engineering Tools (3 new MCP tools)**
- `set_credential_harvester` — clone a website and capture credentials via SET (authorized phishing simulations only; requires explicit human confirmation)
- `set_qrcode_attack` — generate a QR code pointing to a target URL for physical social engineering assessments
- `set_payload_generator` — generate social engineering payloads (PowerShell alphanumeric, reverse, HTA) for authorized red team engagements; requires explicit human confirmation

**Prompts (3 new MCP prompts)**
- `social_engineering_assessment` — structured social engineering assessment workflow covering phishing, pretexting, and physical access
- `msf_exploit_workflow` — step-by-step Metasploit module selection, configuration, and execution workflow
- `save_report` — save a pentest report to the Docker output volume for the built-in report viewer

---

## [0.2.1] — Quality and Stealth

### Added

**Stealth Tools (5 new MCP tools)**
- `tor_check` — verify Tor connectivity and retrieve current exit node IP
- `tor_new_identity` — signal Tor control port to rotate the exit circuit
- `check_anonymity` — comprehensive anonymity posture check (Tor, proxy, DNS, WebRTC)
- `proxy_check` — verify proxy reachability and detect IP leak conditions
- `rotate_identity` — rotate proxy/user-agent and request a new Tor identity atomically

**Quick Action Prompts (9 new prompts in `src/tengu/prompts/quick_actions.py`)**
- `crack_wifi` — guided Wi-Fi capture and offline WPA/WPA2 crack workflow
- `explore_url` — rapid single-URL web assessment
- `go_stealth` — configure and verify stealth posture before an engagement
- `find_secrets` — scan repositories and file systems for leaked credentials
- `map_network` — fast network discovery and service fingerprinting
- `hunt_subdomains` — passive and active subdomain enumeration workflow
- `find_vulns` — template-based vulnerability sweep across a target
- `pwn_target` — full exploitation workflow with post-exploitation checklist
- `msf_exploit_workflow` — step-by-step Metasploit module selection, configuration, and execution workflow

### Improved

- **Test coverage**: 1931 tests across 73 test files, 90%+ overall coverage
- **Lint**: 0 ruff errors across all source and test files; strict type annotations
  enforced throughout
- **Reporting**: `generate_report` with Jinja2 templates supporting Markdown, HTML,
  and PDF (WeasyPrint) output formats
- **Sanitizer**: added `sanitize_repo_url`, `sanitize_docker_image`,
  `sanitize_proxy_url` to `security/sanitizer.py`
- **Mock patterns**: standardized async mock patterns across the test suite
  (`asyncio_mode = "auto"`, `AsyncMock` for context managers, direct patching of
  synchronous helpers called via `run_in_executor`)

---

## [0.2.0] — Extended Tool Coverage

### Added

**OSINT Tools (3 new MCP tools)**
- `theharvester_scan` — email, hostname, and employee data harvesting from public sources
- `shodan_lookup` — Shodan host lookup with service fingerprinting and CVE correlation
- `whatweb_scan` — web technology fingerprinting (CMS, framework, server, libraries)

**Secrets Scanning Tools (2 new MCP tools)**
- `trufflehog_scan` — entropy-based secret scanning for repositories and filesystems
- `gitleaks_scan` — Git history secret scanning with SARIF output

**Container Security Tool (1 new MCP tool)**
- `trivy_scan` — container image and filesystem vulnerability scanning (CVE + misconfig)

**Cloud Security Tool (1 new MCP tool)**
- `scoutsuite_scan` — multi-cloud security posture assessment (AWS, GCP, Azure)

**API Security Tools (2 new MCP tools)**
- `arjun_discover` — HTTP parameter discovery for API endpoints
- `graphql_security_check` — GraphQL introspection, injection, and authorization testing

**Active Directory Tools (3 new MCP tools)**
- `enum4linux_scan` — SMB enumeration: shares, users, groups, password policy
- `nxc_enum` — NetExec (formerly CrackMapExec) credential testing and enumeration
- `impacket_kerberoast` — Kerberoasting: request and extract service ticket hashes

**Wireless Tool (1 new MCP tool)**
- `aircrack_scan` — Wi-Fi monitor mode capture and offline WPA/WPA2 cracking

**IaC Security Tool (1 new MCP tool)**
- `checkov_scan` — Terraform, CloudFormation, Kubernetes, Dockerfile static analysis

**Additional Recon Tools (4 new MCP tools)**
- `amass_enum` — active/passive subdomain enumeration with graph-based ASN mapping
- `dnsrecon_scan` — DNS record enumeration, zone transfer, and brute-force
- `subjack_check` — subdomain takeover detection across dangling DNS entries
- `gowitness_screenshot` — headless browser screenshots for discovered web targets

**Additional Web Tools (3 new MCP tools)**
- `gobuster_scan` — directory, DNS, and virtual host brute-forcing
- `wpscan_scan` — WordPress vulnerability and plugin enumeration
- `testssl_check` — comprehensive TLS/SSL configuration testing

**Additional Bruteforce Tool (1 new MCP tool)**
- `cewl_generate` — custom wordlist generation from web page content

**Resources (8 new MCP resources)**
- `mitre://attack/tactics` — MITRE ATT&CK Enterprise tactic list
- `mitre://attack/technique/{id}` — technique detail by ID (e.g. T1059)
- `owasp://api-security/top10` — OWASP API Security Top 10 list
- `owasp://api-security/top10/{id}` — API security category detail (API1–API10)
- `creds://defaults/{product}` — default credential database for common products
- `payloads://{type}` — curated payload lists by type (xss, sqli, lfi, ssti, etc.)
- `stealth://techniques` — reference guide for operational security techniques
- `stealth://proxy-guide` — step-by-step proxy and Tor configuration guide

**Prompts (10 new MCP prompts)**
- `osint_investigation` — structured open-source intelligence gathering workflow
- `stealth_assessment` — full engagement with stealth/anonymization controls active
- `opsec_checklist` — operational security pre-engagement checklist
- `api_security_assessment` — OWASP API Security Top 10 assessment workflow
- `ad_assessment` — Active Directory enumeration and attack path workflow
- `container_assessment` — container image and runtime security assessment
- `cloud_assessment` — cloud infrastructure security posture review
- `bug_bounty_workflow` — scope-aware bug bounty hunting workflow
- `compliance_assessment` — compliance-mapped assessment (PCI-DSS, ISO 27001, NIST)
- `wireless_assessment` — Wi-Fi reconnaissance, capture, and cracking workflow

**Stealth Layer (`src/tengu/stealth/`)**
- `layer.py` — `StealthLayer` singleton with `inject_proxy_flags()` for 10 tools
- `config.py` — `StealthConfig` Pydantic model loaded from `tengu.toml`
- `timing.py` — configurable random sleep ranges for inter-request jitter
- `user_agents.py` — realistic browser UA rotation pool
- `http_client.py` — `create_http_client()` returning `httpx.AsyncClient` with proxy
  and user-agent pre-configured

**CVE Infrastructure**
- SQLite-backed CVE cache with 24-hour TTL
- NVD API v2.0 as primary source with CVE.org as fallback
- `cve_lookup` and `cve_search` tools wired to the cache layer

---

## [0.1.0] — 2026-02-28

Initial release of Tengu — a FastMCP-based MCP server providing an intelligent
abstraction layer over industry-standard pentesting tools.

### Added

#### Core Infrastructure
- FastMCP 2.0+ server instance (`FastMCP("Tengu")`) registered in `src/tengu/server.py`
- Pydantic v2 configuration model (`TenguConfig`) with `tengu.toml` parsing and
  environment variable overrides (`TENGU_CONFIG_PATH`, `TENGU_LOG_LEVEL`, `NVD_API_KEY`)
- Structured logging via `structlog` with JSON output and ISO timestamps
- Custom exception hierarchy: `TenguError`, `TargetNotAllowedError`, `ToolNotFoundError`,
  `ToolExecutionError`, `ScanTimeoutError`, `RateLimitError`, `InvalidInputError`,
  `ConfigError`, `MetasploitConnectionError`, `ZAPConnectionError`
- Shared Pydantic models in `types.py`: `Port`, `Host`, `ScanResult`, `SubdomainResult`,
  `DNSRecord`, `DNSResult`, `WhoisResult`, `SecurityHeader`, `HeaderAnalysisResult`,
  `CORSResult`, `SSLResult`, `Evidence`, `Finding`, `PentestReport`, `RiskMatrix`,
  `CVSSMetrics`, `CVERecord`, `ToolStatus`, `ToolsCheckResult`

#### Security Layer (5 layers, mandatory pipeline)
- **Sanitizer** (`security/sanitizer.py`): `sanitize_target`, `sanitize_url`,
  `sanitize_domain`, `sanitize_cidr`, `sanitize_port_spec`, `sanitize_wordlist_path`,
  `sanitize_hash`, `sanitize_cve_id`, `sanitize_free_text`, `sanitize_scan_type`,
  `sanitize_severity`. Shell metacharacter reject list: `[;&|` + "`$<>(){}[]!\\'\"\\r\\n]`
- **Allowlist** (`security/allowlist.py`): `TargetAllowlist` with CIDR, wildcard,
  and exact hostname matching. Default blocked hosts: localhost, metadata endpoints,
  `*.gov`, `*.mil`, `*.edu`
- **Rate limiter** (`security/rate_limiter.py`): `SlidingWindowRateLimiter` with
  per-tool sliding window and concurrent slot tracking. `rate_limited` async context manager
- **Audit logger** (`security/audit.py`): `AuditLogger` writes append-only JSONL audit
  records. Sensitive parameter redaction for: password, passwd, secret, token, key,
  api_key, passlist, credentials
- **Executor** (`executor/process.py`): `run_command()` and `stream_command()` using
  `asyncio.create_subprocess_exec` exclusively. Absolute path resolution via `shutil.which`

#### 29 MCP Tools

**Utility (2)**
- `check_tools` — catalog of all supported external tools with install status and versions
- `validate_target` — validate a target against sanitizer and allowlist rules

**Reconnaissance (5)**
- `nmap_scan` — port scan with service/version detection, OS fingerprinting, NSE scripts;
  XML output parsing into structured `Host` and `Port` objects
- `masscan_scan` — high-speed SYN port scanning for large CIDR ranges
- `subfinder_enum` — passive subdomain enumeration via subfinder
- `dns_enumerate` — DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) via dnspython
- `whois_lookup` — WHOIS registration data including registrar, dates, nameservers

**Web Scanning (6)**
- `nuclei_scan` — template-based vulnerability scanning with JSONL output parsing;
  supports severity filters, template paths, and tag filters
- `nikto_scan` — web server vulnerability and misconfiguration scanning
- `ffuf_fuzz` — directory and endpoint fuzzing with wordlist support
- `analyze_headers` — HTTP security header analysis with A+/F grading
- `test_cors` — CORS misconfiguration detection (origin reflection, credential leakage)
- `ssl_tls_check` — SSL/TLS configuration analysis via sslyze; detects weak protocols
  and cipher suites

**Injection (2)**
- `sqlmap_scan` — automated SQL injection detection (level 1-5, risk 1-3, DBMS auto-detect)
- `xss_scan` — Cross-Site Scripting detection via dalfox

**Exploitation (5)**
- `msf_search` — search Metasploit module database via RPC
- `msf_module_info` — get detailed module information and options
- `msf_run_module` — execute a Metasploit module (requires explicit human authorization)
- `msf_sessions_list` — list active Metasploit sessions
- `searchsploit_query` — query Exploit-DB offline mirror via searchsploit

**Bruteforce (3)**
- `hydra_attack` — network authentication brute force via Hydra
- `hash_crack` — offline hash cracking via John the Ripper or Hashcat
- `hash_identify` — identify hash type from format patterns

**Proxy (3)**
- `zap_spider` — OWASP ZAP passive spider for web application mapping
- `zap_active_scan` — OWASP ZAP active vulnerability scanning
- `zap_get_alerts` — retrieve ZAP scan alerts with risk levels

**Analysis (4)**
- `correlate_findings` — cross-tool finding correlation; identifies attack chains
  (SQLi→Data Exfiltration, BAC→Privilege Escalation, XSS→Session Hijacking, etc.)
- `score_risk` — CVSS-weighted risk scoring with context multipliers (external/internal)
- `cve_lookup` — look up a specific CVE by ID via NVD API with local SQLite cache
- `cve_search` — search CVEs by keyword with severity filtering

**Reporting (1)**
- `generate_report` — generate professional pentest reports in Markdown, HTML, or PDF
  using Jinja2 templates; supports full, executive, technical, finding, and risk_matrix
  report types

#### 11 MCP Resources
- `owasp://top10/2025` — OWASP Top 10:2025 full category list
- `owasp://top10/2025/{category_id}` — category details (A01–A10)
- `owasp://top10/2025/{category_id}/checklist` — testing checklist per category
- `ptes://phases` — PTES methodology all 7 phases overview
- `ptes://phase/{phase_number}` — PTES phase details (objectives, activities, tools)
- `checklist://web-application` — OWASP Testing Guide web app checklist
- `checklist://api` — OWASP API Security Top 10 checklist
- `checklist://network` — network infrastructure pentest checklist
- `tools://catalog` — live catalog of all tools with install status
- `tools://{tool_name}/usage` — usage guide for nmap, nuclei, sqlmap, metasploit

#### 14 MCP Prompts

**Workflow (3)**
- `full_pentest` — complete PTES-guided 7-phase penetration test workflow
- `quick_recon` — rapid 7-step reconnaissance assessment
- `web_app_assessment` — OWASP Testing Guide web application assessment workflow

**Vulnerability Assessment (4)**
- `assess_injection` — focused injection testing (SQL, XSS, command, SSTI)
- `assess_access_control` — broken access control and IDOR testing
- `assess_crypto` — cryptographic failures and SSL/TLS assessment
- `assess_misconfig` — security misconfiguration testing

**Reporting (7)**
- `executive_report` — C-level executive summary prompt
- `technical_report` — detailed technical findings documentation
- `full_pentest_report` — complete report generation workflow
- `remediation_plan` — prioritized remediation roadmap (by risk, effort, or quick-wins)
- `finding_detail` — individual vulnerability documentation
- `risk_matrix` — 5x5 risk matrix visualization prompt
- `retest_report` — remediation verification report

#### Testing
- 141 tests across unit, security, and integration suites
- 74 command injection tests covering SHELL_INJECTION_PAYLOADS and PATH_TRAVERSAL_PAYLOADS
  across all sanitizer functions
- 0 lint errors (ruff)
- 0 type errors (mypy strict)

#### Tooling
- `Makefile` with targets: install, install-dev, install-tools, setup, lint, format,
  typecheck, check, test, test-unit, test-security, test-integration, test-all,
  coverage, run, run-sse, run-dev, inspect, doctor, clean
- `scripts/install-tools.sh` for automated external tool installation
- `uv` as the package manager with `uv.lock` for reproducible installs

---

[0.3.0]: https://github.com/rfunix/tengu/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/rfunix/tengu/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rfunix/tengu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rfunix/tengu/releases/tag/v0.1.0
