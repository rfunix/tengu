# Tengu Demo Script — 10–15 min

**Audience:** Security Director
**Target:** OWASP Juice Shop (`http://juice-shop:3000`)
**Environment:** Docker Compose local (`--profile lab`)
**Mode:** Clean Claude Code session with Tengu via MCP

---

## Pre-Demo (before entering the room)

```bash
# Start the environment
make docker-lab

# Confirm everything is up
docker compose ps

# Verify Juice Shop is reachable (juice-shop is internal to the Docker network)
docker exec $(docker compose ps -q tengu) curl -s http://juice-shop:3000/ | grep -o "OWASP Juice Shop"
```

**`tengu.toml` — add the target to the allowlist:**
```toml
[targets]
allowed_hosts = ["juice-shop", "172.20.0.5"]
```

---

## Phase 0 — Setup (~1 min)

**What to show:** scope control, available tooling.

**Prompt:**
```
Check which pentesting tools are installed and validate that juice-shop is an allowed target.
```

Claude calls `check_tools` and `validate_target` — lists available tools and confirms the target is in the allowlist before any action.

> **Talking point:** "Before any scan, Tengu validates scope. Zero action outside the authorized target."

---

## Phase 1 — Discovery + Vulnerabilities (~5 min)

**What to show:** Claude orchestrating a full pentest with a single prompt.

**Prompt:**
```
Use find_vulns on juice-shop
```

Claude follows the `find_vulns` prompt workflow:
1. `nmap_scan` — port scan + service fingerprint (port 3000/tcp open, Node.js)
2. `nuclei_scan` — CVE templates and misconfigurations (severity: medium, high, critical)
3. `nikto_scan` — web server misconfigurations
4. `analyze_headers` — missing security headers (CSP, HSTS, X-Frame-Options)
5. `cve_search` — CVEs for the detected Node.js/Express stack
6. `searchsploit_query` — publicly available exploits

Among the findings, nuclei/nikto flags the `/rest/products/search` endpoint as suspicious.

> **Talking point:** "One prompt. Claude fired 6 tools in sequence, correlated the results, and delivered prioritized findings by severity."

---

## Phase 2 — SQLi: Exploitation + Dump (~6 min)

**What to show:** moving from finding to exploitation with a natural language prompt.

**Prompt:**
```
The endpoint /rest/products/search?q=test looks injectable. Confirm the SQLi and dump the Users table — email, password, role.
```

Claude calls:
1. `sqlmap_scan` on `http://juice-shop:3000/rest/products/search?q=test` — **UNION SQLi confirmed** (SQLite, 9 columns, parameter `q`)
2. `sqlmap_scan` with `--dump` on the `Users` table → 22 users with email, MD5 hash, and role

Output:
```
admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 | admin
jim@juice-sh.op   | e541ca7ecf72b8d1286474fc613e5e45 | customer
...
[22 rows total]
```

> **Talking point:** "From finding to data exfiltration in one message. No manual commands."

---

## Phase 3 — Hash Crack (~2 min)

**What to show:** real impact — from hash to plaintext password.

**Prompt:**
```
Identify and crack this hash from the admin account: 0192023a7bbd73250516f069df18b500
```

Claude calls:
1. `hash_identify` → MD5 confirmed
2. `hash_crack` with rockyou → **`admin123`** in ~3 seconds

> **Talking point:** "admin@juice-sh.op / admin123. Full access to the admin panel. The full cycle — discovery, exploitation, exfiltration, password cracking — driven by natural language."

---

## Wrap-up (~1 min, if time allows)

**Prompt:**
```
Generate an executive summary report of all findings from this assessment.
```

Claude calls `generate_report` with the accumulated findings and delivers a structured report with severity ratings, CVSS scores, and remediation recommendations.

---

## Timing Reference

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 0. Setup | ~1 min | 1 min |
| 1. find_vulns | ~5 min | 6 min |
| 2. SQLi + Dump | ~6 min | 12 min |
| 3. Hash Crack | ~2 min | 14 min |
| Buffer / Q&A | ~1 min | 15 min |

---

## Quick Troubleshooting

**`sqlmap` does not detect injection:**
Increase the level directly in the prompt:
```
Run sqlmap_scan on http://juice-shop:3000/rest/products/search?q=test with level=5 and risk=3
```

**`Target not allowed` on start:**
```bash
TENGU_ALLOWED_HOSTS=juice-shop,172.20.0.5 docker compose up -d
```

**Claude cannot see Tengu tools:**
Check in Claude Code: `/mcp` → should show `tengu (connected)`

**`hash_crack` does not find the password:**
```bash
docker exec <tengu-container> ls /usr/share/wordlists/rockyou.txt
```

---

## Pre-Demo Checklist

- [ ] `docker compose --profile lab up -d` running
- [ ] `tengu.toml` with `allowed_hosts = ["juice-shop", "172.20.0.5"]`
- [ ] `http://juice-shop:3000` accessible in the browser
- [ ] Claude Code: `/mcp` shows `tengu (connected)`
- [ ] Clean session open (`claude` in a new window)
