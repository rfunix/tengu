# API Reference

Complete reference for all 57 tools, 19 resources, and 34 prompts in Tengu.

All tools require the target to be in the `[targets].allowed_hosts` allowlist
configured in `tengu.toml`, unless explicitly noted otherwise.

> **Note**: This document covers all tool categories. The core 29 tools from v0.1.0
> are fully documented below with parameter tables and example responses. The 27 tools
> added in v0.2.0 and v0.2.1 are listed in the [v0.2 Tools](#v02-tools) section
> at the end of this document. Resources added in v0.2.0 are included in the
> [Resources](#resources) section.

---

## Tools

### Utility Tools

#### `check_tools`

Check which external pentesting tools are installed and available on the system.

**Parameters**: None

**Returns**:
```json
{
  "summary": {
    "total": 21,
    "available": 15,
    "missing": 6
  },
  "tools": [
    {
      "name": "nmap",
      "category": "recon",
      "available": true,
      "path": "/usr/bin/nmap",
      "version": "Nmap 7.95 ( https://nmap.org )"
    }
  ],
  "missing_tools": ["nuclei", "ffuf"],
  "install_hint": "Run 'make install-tools' to install missing tools."
}
```

---

#### `validate_target`

Validate whether a target is allowed for scanning (sanitizer + allowlist check).

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | `str` | Yes | IP address, hostname, CIDR, or URL to validate |

**Returns**:
```json
{
  "target": "192.168.1.1",
  "sanitized": "192.168.1.1",
  "valid": true,
  "allowed": true,
  "reason": "Target is allowed and ready for scanning."
}
```

---

### Reconnaissance Tools

#### `nmap_scan`

Scan a target for open ports, services, and versions using Nmap. Parses Nmap XML output
into structured `Host` and `Port` objects.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | IP, hostname, CIDR, or URL |
| `ports` | `str` | `"1-1024"` | Port spec: `"80"`, `"22-443"`, `"22,80,443"`, `"1-65535"` |
| `scan_type` | `str` | `"connect"` | `syn` (root), `connect`, `udp`, `version`, `ping`, `fast` |
| `timing` | `str` | `"T3"` | Nmap timing: `T0` (paranoid) to `T5` (insane) |
| `os_detection` | `bool` | `false` | Enable OS fingerprinting (requires root/sudo) |
| `scripts` | `str` | `""` | Comma-separated NSE scripts (e.g. `"http-title,ssl-cert"`) |
| `timeout` | `int\|null` | config | Override scan timeout in seconds |

**Returns**:
```json
{
  "tool": "nmap",
  "target": "192.168.1.1",
  "command": "nmap -sT -T3 -p 1-1024 -oX - 192.168.1.1",
  "duration_seconds": 12.4,
  "hosts_found": 1,
  "hosts": [
    {
      "address": "192.168.1.1",
      "hostname": "router.local",
      "os": "Linux 4.x",
      "status": "up",
      "ports": [
        {
          "number": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "nginx 1.24.0"
        }
      ]
    }
  ],
  "open_ports_summary": [
    {"host": "192.168.1.1", "port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24.0"}
  ],
  "raw_output": "<?xml ..."
}
```

---

#### `masscan_scan`

High-speed TCP SYN port scan for large networks. Requires root/sudo. Much faster
than Nmap for initial port discovery on large CIDR ranges.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | IP, CIDR range, or hostname |
| `ports` | `str` | `"1-1024"` | Port specification |
| `rate` | `int` | `1000` | Packets per second (higher = faster, noisier) |
| `timeout` | `int\|null` | config | Override scan timeout |

**Returns**:
```json
{
  "tool": "masscan",
  "target": "192.168.1.0/24",
  "duration_seconds": 8.2,
  "hosts_found": 5,
  "open_ports": [
    {"ip": "192.168.1.1", "port": 80, "protocol": "tcp"},
    {"ip": "192.168.1.1", "port": 443, "protocol": "tcp"}
  ],
  "raw_output": "..."
}
```

---

#### `subfinder_enum`

Passive subdomain enumeration using multiple public sources (DNS, certificate
transparency, web archives). Does not send requests to the target.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | `str` | required | Root domain to enumerate |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "subfinder",
  "domain": "example.com",
  "duration_seconds": 15.3,
  "subdomains_found": 42,
  "subdomains": ["www.example.com", "api.example.com", "dev.example.com"],
  "raw_output": "..."
}
```

---

#### `dns_enumerate`

Enumerate DNS records for a domain using dnspython. Queries A, AAAA, MX, NS, TXT,
CNAME, and SOA records.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | `str` | required | Domain to enumerate |
| `record_types` | `list[str]\|null` | all types | DNS record types to query |
| `resolver` | `str` | system | DNS resolver IP (e.g. `"8.8.8.8"`) |

**Returns**:
```json
{
  "tool": "dns_enumerate",
  "domain": "example.com",
  "duration_seconds": 2.1,
  "records": [
    {"name": "example.com", "record_type": "A", "value": "93.184.216.34", "ttl": 3600},
    {"name": "example.com", "record_type": "MX", "value": "10 mail.example.com", "ttl": 3600}
  ],
  "record_count": 12
}
```

---

#### `whois_lookup`

WHOIS registration lookup for a domain or IP address.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | Domain name or IP address |

**Returns**:
```json
{
  "tool": "whois",
  "target": "example.com",
  "registrar": "IANA",
  "creation_date": "1992-01-01",
  "expiration_date": "2024-01-01",
  "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
  "status": ["clientDeleteProhibited"],
  "emails": ["abuse@iana.org"],
  "org": "Internet Assigned Numbers Authority",
  "country": "US",
  "raw": "..."
}
```

---

### Web Scanning Tools

#### `nuclei_scan`

Scan a target with Nuclei's community vulnerability template library. Supports
severity filtering, tag filtering, and specific template selection. Parses JSONL output.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL to scan (http:// or https://) |
| `templates` | `list[str]\|null` | all | Template paths/dirs: `["cves/", "misconfiguration/"]` |
| `severity` | `list[str]\|null` | config | Filter by severity: `["medium", "high", "critical"]` |
| `tags` | `list[str]\|null` | none | Filter by tags: `["sqli", "xss", "rce", "cve"]` |
| `exclude_tags` | `list[str]\|null` | none | Tags to exclude: `["dos", "fuzz"]` |
| `rate_limit` | `int` | `150` | Max requests/second (1–1000) |
| `timeout` | `int\|null` | config | Override scan timeout |

**Returns**:
```json
{
  "tool": "nuclei",
  "target": "https://example.com",
  "duration_seconds": 120.5,
  "findings_count": 3,
  "severity_breakdown": {"medium": 1, "high": 2},
  "findings": [
    {
      "template_id": "cve-2021-44228",
      "template_name": "Apache Log4j RCE",
      "severity": "critical",
      "description": "...",
      "matched_url": "https://example.com/api",
      "cve_ids": ["CVE-2021-44228"],
      "cvss_score": 10.0,
      "tags": ["cve", "rce", "log4j"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    }
  ]
}
```

---

#### `nikto_scan`

Scan a web server for known vulnerabilities, misconfigurations, outdated software,
and dangerous files using Nikto.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL or host:port |
| `port` | `int\|null` | from URL | Target port (if not in URL) |
| `ssl` | `bool` | `false` | Force SSL/TLS |
| `timeout` | `int\|null` | config | Override scan timeout |

**Returns**:
```json
{
  "tool": "nikto",
  "target": "https://example.com",
  "duration_seconds": 45.2,
  "findings_count": 7,
  "findings": [
    {
      "id": "999970",
      "message": "The anti-clickjacking X-Frame-Options header is not present.",
      "uri": "/",
      "method": "GET"
    }
  ],
  "raw_output": "+ ..."
}
```

---

#### `ffuf_fuzz`

Directory and endpoint fuzzing using ffuf. Discovers hidden files, directories,
API endpoints, and virtual hosts.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL with `FUZZ` placeholder: `"https://example.com/FUZZ"` |
| `wordlist` | `str\|null` | config | Path to wordlist file |
| `extensions` | `list[str]\|null` | none | File extensions: `[".php", ".bak", ".old"]` |
| `method` | `str` | `"GET"` | HTTP method |
| `headers` | `dict\|null` | none | Additional HTTP headers |
| `filter_status` | `list[int]\|null` | none | Filter out these status codes |
| `timeout` | `int\|null` | config | Override scan timeout |

**Returns**:
```json
{
  "tool": "ffuf",
  "target": "https://example.com/FUZZ",
  "duration_seconds": 30.1,
  "results_count": 5,
  "results": [
    {
      "input": "admin",
      "url": "https://example.com/admin",
      "status": 200,
      "length": 4521,
      "words": 189,
      "lines": 78
    }
  ]
}
```

---

#### `analyze_headers`

Analyze HTTP security headers for a URL. Checks for presence and correct configuration
of security headers and assigns a grade (A+ to F).

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | required | Full URL to analyze (http:// or https://) |
| `follow_redirects` | `bool` | `true` | Follow HTTP redirects |

**Returns**:
```json
{
  "tool": "analyze_headers",
  "url": "https://example.com",
  "score": 65,
  "grade": "C",
  "headers": [
    {
      "name": "Strict-Transport-Security",
      "value": "max-age=31536000; includeSubDomains",
      "present": true,
      "score": "pass",
      "recommendation": null
    },
    {
      "name": "Content-Security-Policy",
      "value": null,
      "present": false,
      "score": "fail",
      "recommendation": "Add a Content-Security-Policy header to prevent XSS."
    }
  ]
}
```

Headers checked: `Strict-Transport-Security`, `Content-Security-Policy`,
`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`, `X-XSS-Protection`.

---

#### `test_cors`

Test a URL for CORS (Cross-Origin Resource Sharing) misconfigurations, including
origin reflection, null origin acceptance, and credential leakage.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | required | URL to test |
| `origin` | `str` | `"https://evil.com"` | Origin to use in CORS test requests |

**Returns**:
```json
{
  "tool": "test_cors",
  "url": "https://example.com/api",
  "vulnerable": true,
  "issues": [
    "Origin reflection: server reflects any origin in Access-Control-Allow-Origin",
    "Credentials allowed: Access-Control-Allow-Credentials: true"
  ],
  "allow_origin": "https://evil.com",
  "allow_credentials": true
}
```

---

#### `ssl_tls_check`

Analyze SSL/TLS configuration using sslyze. Checks for weak protocols (SSLv2/3,
TLS 1.0/1.1), weak cipher suites, certificate validity, and known vulnerabilities.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | required | Hostname or IP to check |
| `port` | `int` | `443` | TLS port |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "ssl_tls_check",
  "host": "example.com",
  "port": 443,
  "certificate_valid": true,
  "certificate_expiry": "2025-12-31",
  "protocols": ["TLSv1.2", "TLSv1.3"],
  "weak_protocols": [],
  "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
  "vulnerabilities": [],
  "grade": "A+"
}
```

---

### Injection Tools

#### `sqlmap_scan`

Automated SQL injection detection using sqlmap. Tests for error-based, union-based,
blind, time-based, and stacked query injection.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | required | URL to test (include parameters: `?id=1`) |
| `method` | `str` | `"GET"` | HTTP method (`GET`, `POST`) |
| `data` | `str` | `""` | POST data (e.g. `"user=admin&pass=test"`) |
| `level` | `int` | `1` | Test level 1–5 (higher = more thorough, noisier) |
| `risk` | `int` | `1` | Risk level 1–3 (higher = heavier tests) |
| `dbms` | `str` | `""` | Target DBMS: `mysql`, `postgresql`, `mssql`, `oracle` |
| `timeout` | `int\|null` | config | Override scan timeout |

**Returns**:
```json
{
  "tool": "sqlmap",
  "target": "https://example.com/search?q=test",
  "duration_seconds": 89.4,
  "vulnerable": true,
  "findings": [
    {
      "parameter": "q",
      "type": "boolean-based blind",
      "title": "AND boolean-based blind - WHERE or HAVING clause",
      "payload": "q=test' AND 1=1-- -"
    }
  ],
  "raw_output": "..."
}
```

---

#### `xss_scan`

Cross-Site Scripting detection using dalfox. Tests for reflected, stored, and
DOM-based XSS vulnerabilities.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | required | URL to test |
| `method` | `str` | `"GET"` | HTTP method |
| `data` | `str` | `""` | POST body data |
| `cookies` | `str` | `""` | Cookie string for authenticated testing |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "xss_scan",
  "target": "https://example.com/search?q=test",
  "duration_seconds": 45.2,
  "vulnerable": true,
  "findings": [
    {
      "type": "Reflected XSS",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "evidence": "...",
      "poc": "https://example.com/search?q=<script>alert(1)</script>"
    }
  ]
}
```

---

### Exploitation Tools

#### `msf_search`

Search the Metasploit module database for exploits, auxiliary modules, and payloads.
Requires Metasploit RPC to be running (`msfrpcd`).

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | `str` | required | Search query (e.g. `"apache log4j"`, `"CVE-2021-44228"`) |
| `type` | `str` | `"exploit"` | Module type: `exploit`, `auxiliary`, `payload`, `post` |

**Returns**:
```json
{
  "tool": "msf_search",
  "query": "log4j",
  "modules": [
    {
      "name": "exploit/multi/http/log4shell_header_injection",
      "fullname": "exploit/multi/http/log4shell_header_injection",
      "rank": "excellent",
      "disclosure_date": "2021-12-09",
      "description": "Log4Shell - Remote Code Execution"
    }
  ],
  "count": 1
}
```

---

#### `msf_module_info`

Get detailed information about a specific Metasploit module including required options.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `module_name` | `str` | required | Full module path: `"exploit/multi/http/..."` |

**Returns**:
```json
{
  "tool": "msf_module_info",
  "module": "exploit/multi/http/log4shell_header_injection",
  "name": "Log4Shell Header Injection",
  "description": "...",
  "rank": "excellent",
  "options": {
    "RHOSTS": {"type": "string", "required": true, "description": "Target host"},
    "RPORT": {"type": "integer", "required": false, "default": 80}
  }
}
```

---

#### `msf_run_module`

Execute a Metasploit module. **Requires explicit human authorization** — this tool
performs active exploitation. Do not run without written authorization.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `module_name` | `str` | required | Full module path |
| `options` | `dict` | `{}` | Module options: `{"RHOSTS": "10.0.0.1", "RPORT": 8080}` |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "msf_run_module",
  "module": "exploit/multi/http/log4shell_header_injection",
  "status": "completed",
  "result": "...",
  "session_id": 1
}
```

---

#### `msf_sessions_list`

List all active Metasploit sessions (Meterpreter, shell, etc.).

**Parameters**: None

**Returns**:
```json
{
  "tool": "msf_sessions_list",
  "sessions": [
    {
      "id": 1,
      "type": "meterpreter",
      "target": "192.168.1.100",
      "platform": "linux",
      "arch": "x64"
    }
  ],
  "count": 1
}
```

---

#### `searchsploit_query`

Search the Exploit-DB offline mirror for known exploits matching a query.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | `str` | required | Search query (software name, CVE, etc.) |
| `strict` | `bool` | `false` | Strict title matching only |

**Returns**:
```json
{
  "tool": "searchsploit",
  "query": "apache 2.4",
  "results": [
    {
      "title": "Apache 2.4.49 - Path Traversal & Remote Code Execution",
      "path": "webapps/50383.py",
      "type": "remote",
      "date": "2021-10-07",
      "edb_id": 50383
    }
  ],
  "count": 5
}
```

---

### Bruteforce Tools

#### `hydra_attack`

Network authentication brute force using Hydra. Supports SSH, FTP, HTTP, RDP,
SMB, MySQL, PostgreSQL, and many other protocols.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | Target host or IP |
| `service` | `str` | required | Protocol: `ssh`, `ftp`, `http-get`, `http-post-form`, `rdp`, `smb` |
| `username` | `str` | `""` | Single username (or empty to use wordlist) |
| `userlist` | `str` | `""` | Path to username wordlist |
| `password` | `str` | `""` | Single password (or empty to use wordlist) |
| `passlist` | `str` | `""` | Path to password wordlist |
| `port` | `int\|null` | service default | Target port |
| `threads` | `int` | `4` | Parallel threads |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "hydra",
  "target": "192.168.1.10",
  "service": "ssh",
  "duration_seconds": 120.5,
  "credentials_found": [
    {"username": "admin", "password": "password123"}
  ],
  "attempts": 1500
}
```

---

#### `hash_crack`

Offline hash cracking using John the Ripper or Hashcat with wordlist or brute-force mode.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hash_value` | `str` | required | Hash to crack (hex string) |
| `hash_type` | `str` | `""` | Hash type: `md5`, `sha1`, `sha256`, `bcrypt`, etc. |
| `wordlist` | `str` | config | Path to wordlist |
| `tool` | `str` | `"john"` | Tool to use: `john`, `hashcat` |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "hash_crack",
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "hash_type": "md5",
  "cracked": true,
  "password": "password",
  "duration_seconds": 2.1
}
```

---

#### `hash_identify`

Identify the type of a hash based on its format and length characteristics.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hash_value` | `str` | required | Hash string to identify |

**Returns**:
```json
{
  "tool": "hash_identify",
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "possible_types": [
    {"name": "MD5", "confidence": "high", "length": 32},
    {"name": "MD4", "confidence": "medium", "length": 32}
  ],
  "most_likely": "MD5"
}
```

---

### Proxy Tools

#### `zap_spider`

Spider a web application with OWASP ZAP to discover all pages, forms, and links.
Requires ZAP to be running in daemon mode.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL to spider |
| `zap_url` | `str` | `"http://127.0.0.1:8080"` | ZAP API URL |
| `api_key` | `str` | `""` | ZAP API key (if configured) |
| `max_depth` | `int` | `5` | Maximum spider depth |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "zap_spider",
  "target": "https://example.com",
  "duration_seconds": 45.8,
  "urls_found": 127,
  "urls": ["https://example.com/", "https://example.com/login", "..."]
}
```

---

#### `zap_active_scan`

Run OWASP ZAP active vulnerability scan against a previously spidered target.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL to scan |
| `zap_url` | `str` | `"http://127.0.0.1:8080"` | ZAP API URL |
| `api_key` | `str` | `""` | ZAP API key |
| `scan_policy` | `str` | `"Default Policy"` | ZAP scan policy name |
| `timeout` | `int\|null` | config | Override timeout |

**Returns**:
```json
{
  "tool": "zap_active_scan",
  "target": "https://example.com",
  "scan_id": "1",
  "status": "completed",
  "progress": 100,
  "duration_seconds": 300.2
}
```

---

#### `zap_get_alerts`

Retrieve vulnerability alerts from OWASP ZAP after spidering and/or active scanning.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `zap_url` | `str` | `"http://127.0.0.1:8080"` | ZAP API URL |
| `api_key` | `str` | `""` | ZAP API key |
| `risk_level` | `str` | `""` | Filter by risk: `High`, `Medium`, `Low`, `Informational` |
| `base_url` | `str` | `""` | Filter alerts to this base URL |

**Returns**:
```json
{
  "tool": "zap_get_alerts",
  "alerts_count": 12,
  "severity_breakdown": {"High": 2, "Medium": 5, "Low": 5},
  "alerts": [
    {
      "alert": "SQL Injection",
      "risk": "High",
      "confidence": "High",
      "url": "https://example.com/search",
      "parameter": "q",
      "description": "...",
      "solution": "...",
      "reference": "...",
      "cweid": "89",
      "wascid": "19"
    }
  ]
}
```

---

### Analysis Tools

#### `correlate_findings`

Correlate findings from multiple tools to identify attack chains and compound risks.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `findings` | `list[dict]` | required | Findings from any Tengu tools. Each should have: `severity`, `owasp_category`, `cve_ids`, `tool`, `affected_asset` |

**Returns**:
```json
{
  "tool": "correlate_findings",
  "findings_analyzed": 15,
  "severity_breakdown": {"critical": 1, "high": 4, "medium": 8, "low": 2},
  "tools_used": ["nmap", "nuclei", "sqlmap"],
  "owasp_categories_present": ["A03", "A05", "A07"],
  "attack_chains_identified": [
    {
      "name": "SQL Injection → Data Exfiltration",
      "description": "...",
      "severity": "critical",
      "relevant_owasp_categories": ["A03"]
    }
  ],
  "exploitable_findings_count": 3,
  "high_risk_assets": [
    {"asset": "https://example.com/api", "finding_count": 4, "highest_severity": "high"}
  ],
  "overall_risk_score": 7.8,
  "risk_rating": "HIGH",
  "remediation_priority": [
    {"priority": 1, "title": "SQL Injection in /search", "severity": "high", "recommended_timeframe": "0-30 days"}
  ]
}
```

**Detected Attack Chains**:
- SQL Injection → Data Exfiltration (A03)
- Broken Access Control → Privilege Escalation (A01 + A07)
- Outdated Components → Known CVE Exploitation (A06)
- Misconfiguration → Information Disclosure (A05)
- XSS → Session Hijacking (A03 + A07)
- SSRF → Internal Network Access (A10)

---

#### `score_risk`

Calculate a comprehensive risk score from a list of findings.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `findings` | `list[dict]` | required | Findings list (same format as `correlate_findings`) |
| `context` | `str` | `""` | Engagement context affecting multipliers: `"external-facing e-commerce"`, `"internal HR system"` |

Context keywords:
- `"external"`, `"internet"`, `"public"` → multiplier 1.2 (higher risk)
- `"internal"`, `"intranet"`, `"vpn"` → multiplier 0.9 (lower risk)

**Returns**:
```json
{
  "tool": "score_risk",
  "findings_count": 15,
  "overall_risk_score": 7.2,
  "risk_rating": "HIGH",
  "average_cvss": 6.8,
  "severity_distribution": {"critical": 1, "high": 4, "medium": 8, "low": 2},
  "risk_matrix": {"critical": 1, "high": 4, "medium": 8, "low": 2, "info": 0},
  "context_applied": "external-facing e-commerce",
  "context_multiplier": 1.2
}
```

---

#### `cve_lookup`

Look up a specific CVE by ID using the NVD API with local SQLite caching.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cve_id` | `str` | required | CVE identifier: `"CVE-2024-1234"` |

**Returns**:
```json
{
  "tool": "cve_lookup",
  "id": "CVE-2021-44228",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 allows...",
  "published": "2021-12-10",
  "last_modified": "2023-05-12",
  "cvss": [
    {
      "version": "3.1",
      "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "base_score": 10.0,
      "severity": "CRITICAL"
    }
  ],
  "cwe_ids": ["CWE-502"],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  "affected_products": ["apache:log4j:2.0-beta9"],
  "exploit_available": true,
  "metasploit_module": "exploit/multi/http/log4shell_header_injection"
}
```

---

#### `cve_search`

Search CVEs by keyword with optional severity filtering.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | `str` | required | Search keyword (software name, technology, etc.) |
| `severity` | `list[str]\|null` | all | Filter by CVSS severity: `["high", "critical"]` |
| `max_results` | `int` | `10` | Maximum results to return |

**Returns**:
```json
{
  "tool": "cve_search",
  "query": "apache struts",
  "results_count": 5,
  "cves": [
    {
      "id": "CVE-2017-5638",
      "description": "...",
      "published": "2017-03-11",
      "cvss_score": 10.0,
      "severity": "CRITICAL"
    }
  ]
}
```

---

### Reporting Tools

#### `generate_report`

Generate a professional penetration test report using Jinja2 templates.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client_name` | `str` | required | Client or organization name |
| `engagement_type` | `str` | `"blackbox"` | `blackbox`, `greybox`, `whitebox` |
| `scope` | `list[str]\|null` | `[]` | Targets in scope |
| `exclusions` | `list[str]\|null` | `[]` | Excluded targets |
| `engagement_dates` | `str` | `""` | e.g. `"2026-02-01 to 2026-02-15"` |
| `findings` | `list[dict]\|null` | `[]` | Findings from scan tools |
| `executive_summary` | `str` | `""` | Executive summary text |
| `conclusion` | `str` | `""` | Report conclusion text |
| `report_type` | `str` | `"full"` | `full`, `executive`, `technical`, `finding`, `risk_matrix` |
| `output_format` | `str` | `"markdown"` | `markdown`, `html`, `pdf` |
| `output_path` | `str` | `""` | Save path (if empty, returns content inline) |
| `tools_used` | `list[str]\|null` | `[]` | Tool names used in engagement |

**Returns**:
```json
{
  "tool": "generate_report",
  "report_type": "full",
  "output_format": "markdown",
  "client_name": "Acme Corp",
  "findings_count": 15,
  "risk_score": 7.2,
  "risk_rating": "HIGH",
  "output_path": "./reports/Acme_Corp_pentest_report.md",
  "content": "# Penetration Test Report\n..."
}
```

---

## v0.2 Tools

The following 27 tools were added in v0.2.0 and v0.2.1. All follow the same security
pipeline: sanitizer → allowlist → rate_limiter → audit → executor.

### OSINT Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `theharvester_scan` | Harvest emails, hostnames, and employee data from public sources (Google, Bing, LinkedIn, Hunter.io, etc.) |
| `shodan_lookup` | Shodan host intelligence: open ports, banners, CVEs, geolocation, organization |
| `whatweb_scan` | Web technology fingerprinting: CMS, framework, server software, JavaScript libraries |

### Secrets Scanning Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `trufflehog_scan` | Entropy-based and pattern-based secret scanning for Git repositories and local filesystems |
| `gitleaks_scan` | Git history scanning for leaked credentials with SARIF output and configurable rule sets |

### Container Security Tool (v0.2.0)

| Tool | Description |
|------|-------------|
| `trivy_scan` | Container image and filesystem vulnerability scanning: OS packages, language libraries, misconfigurations |

### Cloud Security Tool (v0.2.0)

| Tool | Description |
|------|-------------|
| `scoutsuite_scan` | Multi-cloud security posture assessment for AWS, GCP, and Azure environments |

### API Security Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `arjun_discover` | HTTP parameter discovery for REST API endpoints using heuristics and wordlists |
| `graphql_security_check` | GraphQL introspection enumeration, injection testing, and authorization bypass detection |

### Active Directory Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `enum4linux_scan` | SMB/CIFS enumeration: shares, users, groups, password policy via enum4linux-ng |
| `nxc_enum` | NetExec (CrackMapExec successor) for credential testing, SMB enumeration, and lateral movement |
| `impacket_kerberoast` | Kerberoasting: request service tickets for SPN accounts and extract hashes for offline cracking |

### Wireless Tool (v0.2.0)

| Tool | Description |
|------|-------------|
| `aircrack_scan` | Wi-Fi interface management, WPA/WPA2 handshake capture, and offline dictionary cracking |

### IaC Security Tool (v0.2.0)

| Tool | Description |
|------|-------------|
| `checkov_scan` | Static analysis of Terraform, CloudFormation, Kubernetes manifests, Helm charts, and Dockerfiles |

### Additional Recon Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `amass_enum` | Active and passive subdomain enumeration with ASN mapping and graph-based relationship discovery |
| `dnsrecon_scan` | DNS record enumeration, zone transfer attempts, and subdomain brute-force |
| `subjack_check` | Subdomain takeover detection by identifying dangling CNAME and NS records |
| `gowitness_screenshot` | Headless Chromium screenshots of discovered web targets for visual triage |
| `httrack_mirror` | Full website mirror for offline content analysis, JS secret hunting, and forensic snapshots |

#### `httrack_mirror`

Downloads a full website locally (HTML, JS, CSS, images) for offline inspection. Useful for
forensic snapshots, hunting secrets hardcoded in compiled JS bundles, and mapping application
structure without continuous active interaction.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | URL of the site to mirror (e.g. `http://example.com`) |
| `depth` | `int` | `2` | Crawl depth 1–5 (capped at 5) |
| `output_dir` | `str` | `"/tmp/httrack"` | Local directory to save the mirror (must be under `/tmp/` or `/home/`) |
| `max_size` | `int` | `100` | Max download size in MB (capped at 500) |
| `include_assets` | `bool` | `true` | Download CSS/JS/images; set `false` for HTML/JS only |
| `timeout` | `int\|null` | config | Override scan timeout in seconds |

**Returns**:
```json
{
  "tool": "httrack",
  "target": "http://example.com",
  "output_dir": "/tmp/httrack",
  "depth": 2,
  "max_size_mb": 100,
  "include_assets": true,
  "pages_downloaded": 42,
  "total_files": 137,
  "total_size_mb": 18.3,
  "duration_seconds": 34.5,
  "file_types": {"html": 42, "js": 51, "css": 14, "png": 30},
  "interesting_findings": [
    "Found potential API key in config.js",
    "Found development note in app.js"
  ],
  "command": "httrack http://example.com -O /tmp/httrack -r2 ...",
  "raw_output": "..."
}
```

**Notes**:
- Requires `httrack` installed (`apt install httrack` / `brew install httrack`).
- `interesting_findings` auto-scans HTML/JS for patterns: `api_key`, `secret`, `token`, `TODO/FIXME`, HTML comments with env hints, and internal URL references.
- Use `include_assets=false` to skip images/CSS and focus on code files only.
- Use `depth=1` for single-page apps (SPAs load all JS on the first request).

---

### Additional Web Tools (v0.2.0)

| Tool | Description |
|------|-------------|
| `gobuster_scan` | Directory, DNS subdomain, and virtual host brute-forcing |
| `wpscan_scan` | WordPress vulnerability, plugin, theme, and user enumeration |
| `testssl_check` | Comprehensive TLS/SSL configuration and vulnerability testing (POODLE, BEAST, ROBOT, etc.) |

### Additional Bruteforce Tool (v0.2.0)

| Tool | Description |
|------|-------------|
| `cewl_generate` | Custom wordlist generation by spidering a web target and extracting unique words |

### Stealth Control Tools (v0.2.1)

| Tool | Description |
|------|-------------|
| `tor_check` | Verify Tor connectivity and retrieve the current exit node IP address |
| `tor_new_identity` | Signal Tor control port to rotate the exit circuit and obtain a new IP |
| `check_anonymity` | Comprehensive anonymity posture check: Tor status, proxy, DNS leaks, WebRTC |
| `proxy_check` | Verify proxy reachability and detect IP leak conditions |
| `rotate_identity` | Rotate proxy/user-agent combination and request a new Tor identity atomically |

---

## Resources

Resources provide read-only reference data. Access via their URI.

### v0.1.0 Resources (11)

| URI | Description | Returns |
|-----|-------------|---------|
| `owasp://top10/2025` | OWASP Top 10:2025 full list | JSON array of all 10 categories |
| `owasp://top10/2025/{category_id}` | Category details (A01–A10) | JSON object with name, description, examples, references |
| `owasp://top10/2025/{category_id}/checklist` | Testing checklist for a category | JSON object with checklist items |
| `ptes://phases` | PTES methodology overview | JSON array of all 7 phases |
| `ptes://phase/{phase_number}` | Phase details (1–7) | JSON object with objectives, activities, tools, deliverables |
| `checklist://web-application` | Web app pentest checklist | JSON checklist (OWASP Testing Guide) |
| `checklist://api` | API pentest checklist | JSON checklist (OWASP API Security Top 10) |
| `checklist://network` | Network infrastructure checklist | JSON checklist |
| `tools://catalog` | Live tool availability catalog | JSON array of all tools with install status |
| `tools://{tool_name}/usage` | Usage guide for a tool | JSON guide with examples and options |

### v0.2.0 Resources (8)

| URI | Description | Returns |
|-----|-------------|---------|
| `mitre://attack/tactics` | MITRE ATT&CK Enterprise tactic list | JSON array of all tactics |
| `mitre://attack/technique/{id}` | Technique detail by ID (e.g. `T1059`) | JSON object with name, description, subtechniques, mitigations |
| `owasp://api-security/top10` | OWASP API Security Top 10 list | JSON array of all 10 API security categories |
| `owasp://api-security/top10/{id}` | API security category detail (API1–API10) | JSON object with name, description, examples, prevention |
| `creds://defaults/{product}` | Default credential database entry for a product | JSON object with username/password pairs |
| `payloads://{type}` | Curated payload list by type | JSON array of payload strings |
| `stealth://techniques` | Reference guide for operational security techniques | JSON object with technique descriptions |
| `stealth://proxy-guide` | Step-by-step proxy and Tor configuration guide | JSON object with configuration steps |

### `tools://{tool_name}/usage` Available Guides

- `tools://nmap/usage`
- `tools://nuclei/usage`
- `tools://sqlmap/usage`
- `tools://metasploit/usage`

### `payloads://{type}` Available Types

- `payloads://xss`
- `payloads://sqli`
- `payloads://lfi`
- `payloads://ssti`
- `payloads://xxe`
- `payloads://open-redirect`

### OWASP Category IDs (A01–A10)

| ID | Category (2025) |
|----|----------------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery (SSRF) |

---

## Prompts

Prompts are guided workflow templates that return a string prompt for Claude to execute.

### Workflow Prompts

#### `full_pentest`

Complete PTES-guided 7-phase penetration test workflow.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `target` | `str` | required | Primary target (IP, domain, URL, or CIDR) |
| `scope` | `str` | `"full"` | `web`, `network`, `api`, `full` |
| `engagement_type` | `str` | `"blackbox"` | `blackbox`, `greybox`, `whitebox` |

---

#### `quick_recon`

Rapid 7-step reconnaissance workflow: validate → whois → dns → subdomains →
nmap → headers → ssl.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `target` | `str` | required | Target host, IP, or domain |

---

#### `web_app_assessment`

OWASP Testing Guide web application assessment: headers → cors → ssl →
ffuf → nuclei → nikto → sqlmap → xss → correlate → score.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `url` | `str` | required | Target URL (http:// or https://) |
| `authenticated` | `bool` | `false` | Whether testing with authentication |

---

### Vulnerability Assessment Prompts

#### `assess_injection`

Focused injection testing workflow.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `url` | `str` | required | Target URL |
| `injection_type` | `str` | `"sql"` | `sql`, `xss`, `command`, `ssti` |

---

#### `assess_access_control`

Broken Access Control and IDOR testing workflow.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `url` | `str` | required | Target URL |

---

#### `assess_crypto`

Cryptographic failures and SSL/TLS assessment workflow.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `host` | `str` | required | Target hostname |

---

#### `assess_misconfig`

Security misconfiguration testing workflow.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `target` | `str` | required | Target host or URL |

---

### Reporting Prompts

#### `executive_report`

Generate a C-level executive summary (business language, no technical jargon).

| Argument | Type | Description |
|----------|------|-------------|
| `findings` | `list[dict]` | Findings list |
| `client_name` | `str` | Client organization name |
| `engagement_date` | `str` | Assessment date |

---

#### `technical_report`

Generate detailed technical findings documentation for a security team audience.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `findings` | `list[dict]` | required | Findings list |
| `client_name` | `str` | required | Client name |
| `scope` | `list[str]` | required | Scope list |
| `methodology` | `str` | `"PTES"` | Methodology used |

---

#### `full_pentest_report`

Generate a complete report using the `generate_report` tool.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `findings` | `list[dict]` | required | All findings |
| `client_name` | `str` | required | Client name |
| `scope` | `list[str]` | required | In-scope targets |
| `rules_of_engagement` | `str` | required | ROE description |
| `methodology` | `str` | `"PTES"` | Methodology |
| `engagement_dates` | `str` | `""` | Date range |

---

#### `remediation_plan`

Generate a prioritized remediation roadmap with timelines.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `findings` | `list[dict]` | required | Findings to remediate |
| `priority` | `str` | `"risk"` | Sort order: `risk`, `effort`, `quick-wins` |

---

#### `finding_detail`

Document a single vulnerability in professional finding format (TENGU-YYYY-NNN).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `vulnerability` | `str` | required | Vulnerability name |
| `target` | `str` | required | Affected target |
| `evidence` | `str` | `""` | Evidence description |
| `cvss_vector` | `str` | `""` | CVSS vector string |

---

#### `risk_matrix`

Generate a 5x5 risk matrix visualization with OWASP coverage and asset risk profiles.

| Argument | Type | Description |
|----------|------|-------------|
| `findings` | `list[dict]` | All findings for matrix |

---

#### `retest_report`

Compare original findings against retest results to measure remediation effectiveness.

| Argument | Type | Description |
|----------|------|-------------|
| `original_findings` | `list[dict]` | Original assessment findings |
| `retest_results` | `list[dict]` | Retest verification results |

---

### Advanced Workflow Prompts (v0.2.0)

| Prompt | Description | Key Arguments |
|--------|-------------|---------------|
| `osint_investigation` | Structured OSINT gathering workflow using theharvester, shodan, and whatweb | `target: str` |
| `stealth_assessment` | Full engagement with stealth layer active (Tor + proxy + UA rotation) | `target: str`, `scope: str` |
| `opsec_checklist` | Pre-engagement operational security checklist: anonymity, logging, detection risk | `engagement_type: str` |
| `api_security_assessment` | OWASP API Security Top 10 assessment using arjun, graphql_security_check, nuclei | `url: str`, `api_type: str` |
| `ad_assessment` | Active Directory enumeration and attack path analysis: enum4linux, nxc, kerberoast | `target: str`, `domain: str` |
| `container_assessment` | Container image and runtime security assessment using trivy and checkov | `image: str` |
| `cloud_assessment` | Cloud infrastructure security posture review using scoutsuite | `provider: str`, `profile: str` |
| `bug_bounty_workflow` | Scope-aware bug bounty hunting with program-specific constraints | `target: str`, `program_scope: str` |
| `compliance_assessment` | Compliance-mapped assessment with findings tagged to PCI-DSS, ISO 27001, or NIST controls | `target: str`, `framework: str` |
| `wireless_assessment` | Wi-Fi reconnaissance, WPA handshake capture, and offline cracking workflow | `interface: str`, `target_ssid: str` |

### Quick Action Prompts (v0.2.1)

| Prompt | Description | Key Arguments |
|--------|-------------|---------------|
| `crack_wifi` | Capture a WPA/WPA2 handshake and run an offline dictionary attack | `interface: str`, `bssid: str`, `wordlist: str` |
| `explore_url` | Rapid single-URL web assessment: headers, cors, ssl, ffuf, nuclei | `url: str` |
| `go_stealth` | Configure and verify stealth posture before starting an engagement | `proxy_url: str` |
| `find_secrets` | Scan repositories and file systems for leaked API keys, tokens, and passwords | `target: str` |
| `map_network` | Fast network discovery and service fingerprinting with nmap and masscan | `cidr: str` |
| `hunt_subdomains` | Passive and active subdomain enumeration with takeover detection | `domain: str` |
| `find_vulns` | Template-based vulnerability sweep using nuclei across a target | `target: str`, `severity: str` |
| `pwn_target` | Full exploitation workflow: recon → vuln scan → exploit → post-exploitation checklist | `target: str` |
