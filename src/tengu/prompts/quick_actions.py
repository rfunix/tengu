"""Quick action prompts — practical task-oriented workflows."""

from __future__ import annotations


def crack_wifi(ssid: str, interface: str = "wlan0") -> str:
    """WiFi password cracking workflow for a specific SSID.

    Args:
        ssid: Target WiFi network name (SSID).
        interface: Wireless interface (must support monitor mode).

    WARNING: Only use on networks you own or have explicit written authorization.
    """
    return f"""# Crack WiFi: {ssid}

## LEGAL WARNING
Unauthorized wireless testing violates the Computer Fraud and Abuse Act (CFAA)
and equivalent laws worldwide. Only test networks you OWN or have EXPLICIT
WRITTEN AUTHORIZATION to test. You are solely responsible for your actions.

## Step 1 — Enable Monitor Mode
```bash
sudo airmon-ng check kill
sudo airmon-ng start {interface}
# Monitor interface: {interface}mon
```

## Step 2 — Passive Scan (Find BSSID and Channel)
1. `aircrack_scan(interface="{interface}mon", scan_time=30)` — identify "{ssid}" BSSID and channel
2. Note the BSSID (MAC address) and channel number of "{ssid}"

## Step 3 — Targeted Capture (Specific Channel)
3. Lock to the target channel and capture handshake:
   `aircrack_scan(interface="{interface}mon", scan_time=120)` — filter on channel
4. To force handshake: deauthenticate a connected client (requires root):
   ```bash
   sudo aireplay-ng --deauth 5 -a <BSSID> {interface}mon
   ```

## Step 4 — Crack the Handshake
5. `hash_crack(hash="<handshake.cap>", mode="hashcat", wordlist="/usr/share/wordlists/rockyou.txt")`
   - If rockyou fails, try: `cewl_generate(url="https://{ssid.lower().replace(" ", "")}.com")` for custom wordlist

## Step 5 — Check WPS Vulnerability
6. If WPS is enabled on "{ssid}":
   - WPS Pixie-Dust is often faster than handshake cracking
   - Use Reaver: `reaver -i {interface}mon -b <BSSID> -vv -K 1`
   - WPS PIN brute-force (slow): `reaver -i {interface}mon -b <BSSID> -vv`

## Step 6 — PMKID Attack (No Client Needed)
7. Alternative if no clients are connected:
   ```bash
   sudo hcxdumptool -i {interface}mon -o capture.pcapng --enable_status=1
   sudo hcxpcapngtool -o hash.hc22000 capture.pcapng
   ```
   Then: `hash_crack(hash="hash.hc22000", mode="hashcat")`

## Cleanup
```bash
sudo airmon-ng stop {interface}mon
sudo systemctl start NetworkManager
```

## Common Attack Vectors
- **WPA2-PSK weak passphrase** — rockyou.txt wordlist (most common)
- **WPS enabled** — Pixie-Dust attack (instant on vulnerable APs)
- **WPA3 downgrade** — force WPA2 handshake via rogue AP
- **PMKID** — no client deauth needed, captures from AP beacon"""


def explore_url(url: str, depth: str = "normal") -> str:
    """Full exploration of a specific URL — recon, tech fingerprint, vulnerabilities.

    Args:
        url: Target URL to explore (e.g. https://example.com).
        depth: Scan depth — "quick" (headers + tech), "normal" (+ fuzzing + scan),
               "deep" (+ sqlmap + xss).
    """
    return f"""# Explore URL: {url}

## Depth: {depth.upper()}

## Phase 1 — Headers and TLS (always)
1. `analyze_headers(url="{url}")` — check security headers (CSP, HSTS, X-Frame-Options, etc.)
2. `test_cors(url="{url}")` — test CORS misconfiguration (wildcard origins, credentials)
3. `ssl_tls_check(host="{
        url.split("//")[-1].split("/")[0]
    }")` — TLS version, cipher suites, certificate chain
{"" if depth == "quick" else ""}
## Phase 2 — Technology Fingerprint (always)
4. `whatweb_scan(url="{url}")` — detect CMS, frameworks, server version, JavaScript libraries
5. Based on detected tech, check for CMS-specific vulnerabilities:
   - WordPress: `wpscan_scan(url="{url}")`
   - Testssl: `testssl_check(host="{url.split("//")[-1].split("/")[0]}")`
{
        '''
## Phase 3 — Directory and File Fuzzing (normal + deep)
6. `ffuf_fuzz(url="{url}/FUZZ", wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt")` — hidden paths
7. `gobuster_scan(url="{url}", mode="dir")` — directory brute-force (parallel confirmation)
8. Look for: admin panels, backup files (.bak, .old), config files, API endpoints

## Phase 4 — Vulnerability Scanning (normal + deep)
9. `nuclei_scan(target="{url}", severity=["medium","high","critical"])` — known CVEs and misconfigs
10. `nikto_scan(url="{url}")` — web server misconfigurations, dangerous files
'''
        if depth in ("normal", "deep")
        else ""
    }
{
        f'''
## Phase 5 — Injection Testing (deep only)
11. `sqlmap_scan(url="{url}", level=1, risk=1)` — SQL injection (safe mode)
12. `xss_scan(url="{url}")` — reflected and stored XSS
13. `arjun_discover(url="{url}")` — discover hidden parameters
14. Test discovered parameters for SSRF, LFI, SSTI

## Phase 6 — API and GraphQL (deep only)
15. Check for GraphQL: `graphql_security_check(url="{url}/graphql")`
16. `arjun_discover(url="{url}/api")` — API parameter discovery

## Phase 7 — Offline Content Analysis (deep only)
17. `httrack_mirror(target="{url}", depth=2, include_assets=False)` — mirror HTML/JS for offline inspection
    - Review `interesting_findings` in the result: hardcoded API keys, credentials, dev comments, internal URLs
    - The mirrored JS bundle captures secrets that never appear in git repos (compiled/minified frontend code)
    - Output dir: /tmp/httrack — search with `grep -r -e api_key -e secret -e token /tmp/httrack/`
'''
        if depth == "deep"
        else ""
    }
## Scoring
- After all scans: `score_risk(findings=[...])` — prioritize by CVSS
- `correlate_findings(findings=[...])` — identify attack chains

## Quick Reference
| Depth | Tools Used |
|-------|-----------|
| quick | analyze_headers, test_cors, ssl_tls_check, whatweb_scan |
| normal | + ffuf_fuzz, gobuster_scan, nuclei_scan, nikto_scan |
| deep | + sqlmap_scan, xss_scan, arjun_discover, graphql_security_check, httrack_mirror |"""


def go_stealth(proxy_url: str = "") -> str:
    """Activate stealth mode: Tor, proxy, User-Agent rotation, timing jitter, DNS-over-HTTPS.

    Args:
        proxy_url: Optional proxy URL to use (e.g. socks5://127.0.0.1:9050 for Tor).
                   Leave empty to use Tor default.
    """
    proxy_line = proxy_url if proxy_url else "socks5://127.0.0.1:9050"
    return f"""# Go Stealth

## Step 1 — Configure tengu.toml
Edit your `tengu.toml` to enable all stealth layers:

```toml
[stealth]
enabled = true
timing_jitter = true
jitter_min_ms = 500
jitter_max_ms = 3000
user_agent_rotation = true

[stealth.proxy]
enabled = true
url = "{proxy_line}"
verify_ssl = false

[stealth.dns]
use_doh = true
doh_server = "https://cloudflare-dns.com/dns-query"
```

## Step 2 — Verify Tor Connectivity
1. `tor_check()` — confirm Tor daemon is running and reachable
   - If Tor is not running: `sudo systemctl start tor`
   - Verify Tor version: `tor --version`

## Step 3 — Validate Anonymity
2. `check_anonymity()` — confirm your real IP is hidden
   - Check: exit node IP, DNS leak, WebRTC leak
   - Target: all checks should return Tor exit node, NOT your real IP

## Step 4 — Validate Proxy
3. `proxy_check(proxy_url="{proxy_line}")` — test proxy connectivity and latency
   - Acceptable latency: < 5 seconds for Tor

## Step 5 — First Identity Rotation
4. `rotate_identity()` — request new Tor circuit (new exit node)
5. `check_anonymity()` — confirm IP changed after rotation

## Step 6 — Operational Checklist
- [ ] Tor is running (`tor_check()` passes)
- [ ] Real IP is hidden (`check_anonymity()` shows exit node)
- [ ] DNS resolves through DoH (no DNS leaks)
- [ ] Proxy is functional (`proxy_check()` passes)
- [ ] User-Agent rotation enabled in tengu.toml
- [ ] Timing jitter configured (500–3000ms)
- [ ] Identity rotated at session start

## Step 7 — During Operations
- Rotate identity between targets: `tor_new_identity()`
- Re-check anonymity periodically: `check_anonymity()`
- Auto-rotate every N requests: configure `[stealth] rotate_every = 10` in tengu.toml

## OPSEC Notes
- Tor exit nodes may be blocked by some targets — use bridge relays if needed
- High-jitter timing reduces correlation attacks but slows scans significantly
- Never mix stealth and non-stealth sessions (compartmentalize)
- Avoid large file transfers over Tor (slow + bandwidth costs)
- Check `stealth://techniques` resource for advanced OPSEC techniques"""


def find_secrets(target: str, scan_type: str = "git") -> str:
    """Find leaked credentials and secrets in git repositories or filesystems.

    Args:
        target: Git repo URL, local path, or GitHub organization/user to scan.
        scan_type: Scan type — "git" (local/remote repo), "filesystem" (local path),
                   "github" (GitHub org or user repos).
    """
    return f"""# Find Secrets: {target}

## Scan Type: {scan_type.upper()}

## Phase 1 — Deep Scan with TruffleHog (verified secrets)
1. `trufflehog_scan(target="{target}", scan_type="{scan_type}")` — scan with secret verification
   - TruffleHog attempts to VERIFY secrets against APIs (AWS, GitHub, Stripe, etc.)
   - Verified secrets = active credentials, highest priority
   - Unverified secrets = potential matches, need manual review

## Phase 2 — Fast Pattern Scan with Gitleaks
2. `gitleaks_scan(target="{target}")` — regex-based scan for secret patterns
   - Faster than TruffleHog, no API verification
   - Covers: API keys, tokens, passwords, private keys, connection strings
   - Scans full git history, not just current state

## Phase 3 — Triage Results

### Verified Secrets (Critical — Act Immediately)
- Revoke and rotate ALL verified credentials BEFORE reporting
- Check AWS CloudTrail / GitHub audit log for unauthorized use
- Document: what was exposed, for how long, what data was accessible

### Unverified Secrets (High — Manual Review)
- Test each manually: try the credential against the target service
- Look for: AWS_ACCESS_KEY, GITHUB_TOKEN, STRIPE_KEY, DATABASE_URL, JWT_SECRET
- Prioritize by service criticality and exposure duration

### Historical Commits
- Even deleted secrets in git history are recoverable
- Recommend: git history rewrite (BFG Repo-Cleaner) after remediation
- All historic commits with secrets are considered compromised

## Phase 4 — Expand Search
{
        '''
- For GitHub orgs: enumerate all repos first, then scan each
- Check: GitHub Actions secrets, environment variables in CI/CD
- Look for: `.env` files committed by accident, hardcoded credentials in test files
'''
        if scan_type == "github"
        else ""
    }
- Search for additional secret locations:
  - `ffuf_fuzz(url="<target-url>/FUZZ", wordlist="...")` — exposed `.env`, `.git`, config files
  - Check: `/.git/config`, `/.env`, `/config.json`, `/appsettings.json`

## Phase 5 — Web Frontend Secret Hunting
If the target has a web interface, many apps bundle secrets into compiled/minified JavaScript
that never appear in git history. Mirror the site to capture what's actually served:

- `httrack_mirror(target="<target-web-url>", depth=2, include_assets=False)` — download all HTML/JS
  - Check `interesting_findings` in the result for automatic pattern matches
  - Manual sweep: `grep -r -e api_key -e apiKey -e secret -e token -e password -e Authorization /tmp/httrack/`
  - Look for: React/Vue/Angular config objects, webpack bundle exports, inline `<script>` blocks
  - Use `depth=1` for SPAs (single-page apps load everything on the first page)

## Severity Reference
| Finding | Severity | Action |
|---------|----------|--------|
| Active AWS/GCP key | Critical | Revoke immediately |
| GitHub personal token | Critical | Revoke immediately |
| DB connection string | High | Rotate password |
| API key (unverified) | High | Test and rotate |
| Private key (PEM) | High | Rotate all certs |
| Generic password | Medium | Rotate if active |
| Historical only | Medium | Rewrite git history |"""


def map_network(network: str) -> str:
    """Full network mapping — active hosts, ports, services, OS fingerprinting.

    Args:
        network: Target network in CIDR notation (e.g. 192.168.1.0/24)
                 or IP range (e.g. 192.168.1.1-254).
    """
    return f"""# Map Network: {network}

## Phase 1 — Fast Host Discovery (Masscan)
1. `masscan_scan(target="{network}", ports="0-65535", rate=1000)` — rapid port sweep
   - Masscan is 1000x faster than Nmap for large ranges
   - Output: list of open ports per host
   - Rate 1000 = balanced (increase for speed, decrease for stealth)

## Phase 2 — Service Detection (Nmap)
2. `nmap_scan(target="{network}", scan_type="version", timing="T4")` — service fingerprint
   - Focuses on hosts/ports found by Masscan
   - Detects: service versions, software, potential CVEs
3. `nmap_scan(target="{network}", scan_type="syn", ports="1-1024,8080,8443,8888")` — top ports
   - OS fingerprinting: add `-O` flag if root access available

## Phase 3 — DNS Reverse Resolution
4. `dns_enumerate(domain="{network.split("/")[0]}", record_types=["PTR"])` — reverse DNS
   - Maps IPs to hostnames for target context
   - Reveals internal naming conventions (dev-, prod-, db-, etc.)

## Phase 4 — Analyze Attack Surface

### Host Classification (from scan results)
- **Domain Controllers**: ports 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (GC)
- **Web Servers**: ports 80, 443, 8080, 8443, 8888
- **Databases**: ports 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB)
- **Remote Access**: ports 22 (SSH), 3389 (RDP), 5900 (VNC), 5985 (WinRM)
- **Email**: ports 25 (SMTP), 110 (POP3), 143 (IMAP), 993, 995
- **Network Devices**: SNMP 161, Telnet 23, Cisco 443/8443

### Priority Targets
5. `cve_search(query="<detected-software> <version>")` — check CVEs for found services
6. `searchsploit_query(query="<service> <version>")` — available exploits

## Attack Surface Summary Template
```
Network: {network}
Live Hosts: <count>
Open Ports: <total>

High-Value Targets:
- <IP>: <service> <version> — <risk>
- <IP>: <service> <version> — <risk>

Recommended Next Steps:
- [ ] Enumerate SMB shares: nxc_enum()
- [ ] Test default credentials: hydra_attack()
- [ ] Check for unpatched CVEs: cve_lookup()
```"""


def hunt_subdomains(domain: str) -> str:
    """Aggressive subdomain enumeration combining multiple tools for maximum coverage.

    Args:
        domain: Target root domain to enumerate (e.g. example.com).
    """
    return f"""# Hunt Subdomains: {domain}

## Phase 1 — Passive Enumeration (No Direct Contact)
1. `subfinder_enum(domain="{domain}")` — aggregate from passive sources
   - Sources: CertSpotter, crt.sh, HackerTarget, SecurityTrails, Shodan, VirusTotal
   - No direct DNS queries to target
   - Fast, stealthy, broad coverage

## Phase 2 — Active Enumeration
2. `amass_enum(domain="{domain}", mode="active")` — active DNS enumeration
   - DNS brute-force, zone transfer attempts, certificate scraping
   - More thorough than passive, generates DNS queries
3. `dnsrecon_scan(domain="{domain}")` — DNS brute-force and zone walk
   - Wordlist-based subdomain brute-force
   - Checks: zone transfers (AXFR), wildcard DNS, DNSSEC

## Phase 3 — Consolidate and Deduplicate
4. Merge all results from steps 1-3:
   - Remove duplicates
   - Filter out wildcards (*.{domain})
   - Sort by subdomain pattern (api., dev., staging., admin., etc.)

### High-Value Patterns to Prioritize
- `admin.{domain}`, `portal.{domain}`, `dashboard.{domain}` — admin interfaces
- `api.{domain}`, `api-v2.{domain}`, `graphql.{domain}` — APIs
- `dev.{domain}`, `staging.{domain}`, `test.{domain}` — non-production (often less secure)
- `vpn.{domain}`, `remote.{domain}`, `citrix.{domain}` — remote access
- `mail.{domain}`, `owa.{domain}`, `autodiscover.{domain}` — email services
- `jira.{domain}`, `confluence.{domain}`, `jenkins.{domain}` — internal tools

## Phase 4 — Subdomain Takeover Check
5. `subjack_check(domain="{domain}")` — check for dangling DNS (subdomain takeover)
   - Dangling CNAME pointing to unclaimed cloud resource = takeover opportunity
   - Services to check: GitHub Pages, S3, Heroku, Netlify, Azure, Fastly

## Phase 5 — Visual Reconnaissance
6. `gowitness_screenshot(targets=["<subdomain-list>"])` — screenshot all live subdomains
   - Quickly identifies login panels, admin interfaces, interesting apps
   - Prioritize investigation based on screenshots

## Phase 6 — Expand Attack Surface
7. For each interesting subdomain found:
   - `explore_url(url="https://<subdomain>", depth="quick")` — quick recon
   - `nuclei_scan(target="https://<subdomain>", severity=["high","critical"])` — fast vuln check

## Output Template
```
Domain: {domain}
Total Subdomains Found: <count>
Live (HTTP/HTTPS): <count>
Takeover Candidates: <count>

Top Targets:
1. <subdomain> — <reason>
2. <subdomain> — <reason>
```"""


def find_vulns(target: str) -> str:
    """Quickly find vulnerabilities in a target (IP, domain, or URL).

    Args:
        target: Target IP address, domain name, or URL to assess.
    """
    return f"""# Find Vulns: {target}

## Phase 1 — Port and Service Discovery
1. `nmap_scan(target="{target}", scan_type="version", timing="T4", ports="1-1024,1433,3306,3389,5432,5900,8080,8443,8888,27017")` — service fingerprint
   - Detect software versions for CVE matching
   - Note: service name, version, and any Nmap NSE script output

## Phase 2 — Known Vulnerability Scan
2. `nuclei_scan(target="{target}", severity=["medium","high","critical"])` — template-based vuln scan
   - Checks: CVEs, misconfigurations, exposures, default credentials
   - Templates: cves/, misconfiguration/, technologies/, exposures/
3. For web targets additionally:
   - `nikto_scan(url="http://{target}")` — web server misconfigs
   - `analyze_headers(url="http://{target}")` — missing security headers

## Phase 3 — CVE Lookup by Software
4. For each service found in Phase 1:
   `cve_search(query="<software> <version>")` — search NVD for CVEs
   - Focus on: CVSS >= 7.0, RCE, authentication bypass, privilege escalation
   - Check: `cve_lookup(cve_id="CVE-XXXX-XXXXX")` for specific CVE details

## Phase 4 — Exploit Availability
5. `searchsploit_query(query="<software> <version>")` — check Exploit-DB
6. `msf_search(query="<software>")` — Metasploit module availability
   - Prioritize: exploits with high reliability, low complexity
   - Check: public PoC on GitHub if searchsploit has no results

## Phase 5 — Prioritization

### Critical (Exploit Now — with authorization)
- CVSS >= 9.0 + public exploit available + service exposed
- RCE, authentication bypass, SQLi leading to data exfiltration

### High (Exploit Next)
- CVSS >= 7.0 + Metasploit module or PoC available
- Privilege escalation, SSRF with internal access

### Medium (Document and Report)
- CVSS 4.0-6.9 or limited exploit complexity
- Information disclosure, weak configurations

## Next Steps
- Exploit critical findings: `pwn_target(target="{target}", cve="CVE-XXXX-XXXXX")`
- Generate findings report: `generate_report(findings=[...])`
- Score overall risk: `score_risk(findings=[...])`"""


def pwn_target(target: str, cve: str) -> str:
    """Guided exploitation workflow for a specific CVE against an authorized target.

    Args:
        target: Target IP or hostname (must be in tengu.toml allowlist).
        cve: CVE identifier to exploit (e.g. CVE-2021-44228).

    WARNING: Only use against systems you own or have explicit written authorization to test.
    Human confirmation is REQUIRED before executing any exploit module.
    """
    return f"""# Pwn Target: {target} via {cve}

## LEGAL WARNING
This workflow executes active exploits against {target}.
Only proceed if you have EXPLICIT WRITTEN AUTHORIZATION.
Unauthorized exploitation is a criminal offense in all jurisdictions.
**A human must confirm before running msf_run_module.**

## Step 1 — CVE Intelligence Gathering
1. `cve_lookup(cve_id="{cve}")` — get full CVE details
   - CVSS score and vector
   - Affected products and versions
   - Patch availability
   - Known weaponized versions in the wild

## Step 2 — Confirm Target is Vulnerable
2. `nmap_scan(target="{target}", scan_type="version")` — verify exact software version
   - Confirm the target runs the vulnerable version
   - Do NOT proceed if version is patched
3. `nuclei_scan(target="{target}")` — check for {cve}-specific templates
   - Safe detection without exploitation
   - Confirm vulnerability without triggering IDS

## Step 3 — Find Public Exploits
4. `searchsploit_query(query="{cve}")` — search Exploit-DB
   - Note exploit type: RCE, PoC, DoS, local, remote
   - Download and review exploit code BEFORE running
5. `msf_search(query="{cve}")` — find Metasploit modules
   - Note module path (e.g. exploit/multi/handler/...)

## Step 4 — Module Details
6. `msf_module_info(module="<module-path-from-step-5>")` — review module options
   - Required options: RHOSTS, RPORT, LHOST, LPORT, payload
   - Check reliability rating and rank (Excellent > Great > Good > Normal)
   - Review required vs optional parameters

## Step 5 — ⚠️ HUMAN CONFIRMATION REQUIRED ⚠️
```
STOP — Before proceeding, confirm:
[ ] Target {target} is in tengu.toml allowlist
[ ] Written authorization obtained for {target}
[ ] CVE {cve} confirmed applicable to target version
[ ] Exploitation scope approved (what actions are allowed post-exploitation)
[ ] Incident response team notified (if required by rules of engagement)
[ ] Safe exploitation time window confirmed
```

**Type CONFIRM to proceed to exploitation.**

## Step 6 — Execute Exploit (After Human Confirmation)
7. `msf_run_module(module="<module>", options={{"RHOSTS": "{target}", "LHOST": "<your-ip>"}})` — run exploit
   - Monitor output carefully
   - Stop immediately if unexpected behavior occurs

## Step 7 — Post-Exploitation (Authorized Scope Only)
8. `msf_sessions_list()` — list active sessions
9. Document: what access was gained, what data is accessible
10. Do NOT exceed authorized scope — document findings and exit cleanly

## Step 8 — Cleanup and Report
11. Close all sessions after documenting evidence
12. `generate_report(findings=[...])` — create exploitation evidence report
13. `finding_detail(...)` — document full technical details

## Abort Conditions
- Stop immediately if: unexpected systems accessed, data outside scope found,
  IDS/WAF triggers excessive alerts, session becomes unstable"""
