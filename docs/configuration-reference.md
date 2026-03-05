# Configuration Reference

Tengu is configured via `tengu.toml` at the project root. Configuration is parsed
at startup using Pydantic v2 models with full validation. Missing optional fields
fall back to safe defaults.

---

## Configuration Priority

```
Environment variables  (highest priority)
        ↓
tengu.toml values
        ↓
Pydantic model defaults  (lowest priority)
```

---

## Complete tengu.toml Reference

```toml
# =============================================================================
# [server] — Core server settings
# =============================================================================
[server]

# Server name shown in MCP client discovery
name = "Tengu"

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
# Override with TENGU_LOG_LEVEL environment variable
log_level = "INFO"

# Path to the append-only JSONL audit log file
# Supports ~ expansion. Parent directories are created automatically.
audit_log_path = "./logs/tengu-audit.log"


# =============================================================================
# [targets] — Scope enforcement
# =============================================================================
[targets]

# Hosts/CIDRs allowed as scan targets.
# ALL scan tools check this before executing.
# Supported formats:
#   - Exact hostname:    "example.com"
#   - Wildcard:         "*.example.com"
#   - Single IP:        "192.168.1.1"
#   - CIDR range:       "192.168.1.0/24", "10.0.0.0/8"
#
# If empty, a warning is logged but scanning is not blocked.
# Set this for any production or lab use.
allowed_hosts = []

# Additional hosts to block (merged with built-in defaults).
# Built-in blocked (always active):
#   localhost, 127.0.0.1, ::1, 0.0.0.0, 169.254.169.254,
#   metadata.google.internal, *.gov, *.mil, *.edu
blocked_hosts = []


# =============================================================================
# [tools.paths] — External tool binary paths
# =============================================================================
[tools.paths]

# Leave empty ("") to auto-detect via PATH.
# Set to absolute path if the tool is installed in a non-standard location.
nmap = ""
masscan = ""
nuclei = ""
nikto = ""
ffuf = ""
subfinder = ""
sqlmap = ""
dalfox = ""         # XSS scanner (dalfox)
hydra = ""
john = ""
hashcat = ""
searchsploit = ""

# Metasploit RPC endpoint (not a binary path)
# Format: "https://HOST:PORT"
# Start RPC with: msfrpcd -P PASSWORD -a 127.0.0.1
metasploit_rpc = "https://127.0.0.1:55553"

# Social Engineering Toolkit (SET) — used by set_credential_harvester,
# set_qrcode_attack, set_payload_generator
setoolkit = ""


# =============================================================================
# [tools.defaults] — Default tool parameters
# =============================================================================
[tools.defaults]

# Default Nmap timing template (T0–T5)
# T0 = paranoid (slowest), T3 = balanced (default), T5 = insane (fastest)
nmap_timing = "T3"

# Default Nuclei severity filter
# Valid values: "info", "low", "medium", "high", "critical"
nuclei_severity = ["medium", "high", "critical"]

# Maximum scan duration in seconds (applied to all tool executions)
# Tools exceeding this timeout are killed with SIGKILL
scan_timeout = 600

# Default wordlist for ffuf_fuzz and directory fuzzing
# Change to your preferred wordlist or a larger SecLists wordlist
wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"


# =============================================================================
# [stealth] — Optional anonymization and evasion layer
# =============================================================================
[stealth]

# Set to true to enable the stealth layer (proxy routing, UA rotation, jitter)
enabled = false

[stealth.proxy]

# Enable proxy routing for supported tools (nmap, nuclei, ffuf, etc.)
enabled = false

# Proxy type: socks5, socks4, http, https
type = "socks5"

# Proxy host and port
host = "127.0.0.1"
port = 9050

[stealth.wrapper]

# Wrapper mode: none, proxychains, torsocks
# Wraps tool process with a proxy wrapper for tools that don't support native proxy flags
mode = "none"

[stealth.timing]

# Enable timing jitter between requests
enabled = false

# Minimum jitter delay in milliseconds
min_delay_ms = 100

# Maximum jitter delay in milliseconds
max_delay_ms = 3000

# Random variation percentage applied to delay (0-100)
jitter_percent = 30

[stealth.user_agent]

# Enable User-Agent rotation
enabled = false

# Rotate User-Agent every N requests
rotate_every = 10

# Browser type: chrome, firefox, safari, edge, random
browser_type = "random"

[stealth.dns]

# Enable DNS privacy (route DNS through Tor or DoH)
enabled = false

# DNS method: system, doh, tor
method = "system"

# DNS-over-HTTPS resolver URL (used when method = "doh")
doh_url = "https://cloudflare-dns.com/dns-query"


# =============================================================================
# [rate_limiting] — Abuse prevention
# =============================================================================
[rate_limiting]

# Maximum scan invocations per tool per 60-second sliding window
max_scans_per_minute = 10

# Maximum simultaneous scans per tool
max_concurrent_scans = 3


# =============================================================================
# [cve] — CVE database settings
# =============================================================================
[cve]

# NVD API key for higher rate limits (optional).
# Without a key: 5 requests/30s. With a key: 50 requests/30s.
# Get a key at: https://nvd.nist.gov/developers/request-an-api-key
# Override with NVD_API_KEY environment variable
nvd_api_key = ""

# SQLite cache database path (~ is expanded)
cache_path = "~/.tengu/cve_cache.db"

# Cache TTL in hours. CVE records older than this are refreshed from NVD.
cache_ttl_hours = 24
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TENGU_CONFIG_PATH` | Absolute path to `tengu.toml`. Overrides the default (`./tengu.toml`). | `/opt/tengu/tengu.toml` |
| `TENGU_LOG_LEVEL` | Log level. Overrides `[server].log_level`. | `DEBUG` |
| `TENGU_ALLOWED_HOSTS` | Comma-separated allowed hosts/CIDRs. Overrides `[targets].allowed_hosts`. | `192.168.1.0/24,10.0.0.0/8` |
| `NVD_API_KEY` | NVD API key for CVE lookups. Overrides `[cve].nvd_api_key`. | `your-key-here` |
| `TENGU_SHODAN_API_KEY` | Shodan API key for `shodan_lookup`. | `your-key-here` |

Environment variables take precedence over `tengu.toml` values.

---

## Example Configurations

### Minimal Lab Setup (single target)

```toml
[targets]
allowed_hosts = ["192.168.1.0/24"]

[tools.defaults]
scan_timeout = 300
```

### Bug Bounty Program (multiple subdomains)

```toml
[targets]
allowed_hosts = [
    "*.example.com",
    "*.api.example.com",
    "203.0.113.0/24",   # example IP range from scope doc
]
blocked_hosts = [
    "internal.example.com",   # explicitly excluded by program rules
    "legacy.example.com",
]

[tools.defaults]
nuclei_severity = ["low", "medium", "high", "critical"]
nmap_timing = "T2"   # polite timing for production environment
scan_timeout = 900

[rate_limiting]
max_scans_per_minute = 5   # conservative for production target
max_concurrent_scans = 2
```

### Internal Network Audit

```toml
[targets]
allowed_hosts = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

[tools.defaults]
nmap_timing = "T4"   # faster timing acceptable for internal network
scan_timeout = 1200
wordlist_path = "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt"

[rate_limiting]
max_scans_per_minute = 20
max_concurrent_scans = 5

[cve]
nvd_api_key = "your-nvd-api-key-here"
cache_ttl_hours = 12
```

### Kali VM (pre-installed tools, custom paths)

```toml
[server]
log_level = "DEBUG"
audit_log_path = "/opt/tengu/logs/tengu-audit.log"

[targets]
allowed_hosts = ["192.168.56.0/24"]   # host-only network

[tools.paths]
# Most tools are in PATH on Kali, leave empty for auto-detection
# Custom path example for a non-standard install:
nuclei = "/opt/tools/nuclei"
wordlist_path = "/usr/share/wordlists/dirb/common.txt"

[tools.defaults]
scan_timeout = 1800   # allow longer scans for thorough testing
```

---

## Pydantic Models Reference

The configuration is parsed into the following Pydantic v2 model hierarchy:

### `TenguConfig`

The root configuration model. Accessed via `get_config()` which returns a singleton.

```python
class TenguConfig(BaseModel):
    server: ServerConfig
    targets: TargetsConfig
    tools: ToolsConfig      # contains paths and defaults
    rate_limiting: RateLimitingConfig
    cve: CVEConfig
    stealth: StealthConfig = Field(default_factory=StealthConfig)

    @property
    def effective_blocked_hosts(self) -> list[str]:
        """Built-in defaults + user-configured blocked hosts (deduplicated)."""
```

### `ServerConfig`

```python
class ServerConfig(BaseModel):
    name: str = "Tengu"
    log_level: str = "INFO"
    audit_log_path: str = "./logs/tengu-audit.log"
```

### `TargetsConfig`

```python
class TargetsConfig(BaseModel):
    allowed_hosts: list[str] = []
    blocked_hosts: list[str] = []
```

### `ToolPathsConfig`

```python
class ToolPathsConfig(BaseModel):
    nmap: str = ""
    masscan: str = ""
    nuclei: str = ""
    nikto: str = ""
    ffuf: str = ""
    subfinder: str = ""
    sqlmap: str = ""
    dalfox: str = ""
    hydra: str = ""
    john: str = ""
    hashcat: str = ""
    searchsploit: str = ""
    metasploit_rpc: str = "https://127.0.0.1:55553"
```

### `ToolDefaultsConfig`

```python
class ToolDefaultsConfig(BaseModel):
    nmap_timing: str = "T3"
    nuclei_severity: list[str] = ["medium", "high", "critical"]
    scan_timeout: int = 600
    wordlist_path: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
```

### `ToolsConfig`

```python
class ToolsConfig(BaseModel):
    paths: ToolPathsConfig = Field(default_factory=ToolPathsConfig)
    defaults: ToolDefaultsConfig = Field(default_factory=ToolDefaultsConfig)
```

### `RateLimitingConfig`

```python
class RateLimitingConfig(BaseModel):
    max_scans_per_minute: int = 10
    max_concurrent_scans: int = 3
```

### `CVEConfig`

```python
class CVEConfig(BaseModel):
    nvd_api_key: str = ""
    cache_path: str = "~/.tengu/cve_cache.db"
    cache_ttl_hours: int = 24
```

### `StealthConfig`

```python
class StealthProxyConfig(BaseModel):
    enabled: bool = False
    type: str = "socks5h"
    host: str = "127.0.0.1"
    port: int = 9050

    @property
    def url(self) -> str:
        """Construct proxy URL from fields (e.g. socks5h://127.0.0.1:9050)."""
        return f"{self.type}://{self.host}:{self.port}"


class StealthTimingConfig(BaseModel):
    min_delay: float = 0.5
    max_delay: float = 3.0


class StealthUserAgentConfig(BaseModel):
    rotate: bool = True


class StealthConfig(BaseModel):
    enabled: bool = False
    proxy: StealthProxyConfig = Field(default_factory=StealthProxyConfig)
    timing: StealthTimingConfig = Field(default_factory=StealthTimingConfig)
    user_agent: StealthUserAgentConfig = Field(default_factory=StealthUserAgentConfig)
```

---

## Accessing Configuration in Tool Code

```python
from tengu.config import get_config

cfg = get_config()  # returns cached singleton, parsed once at startup

# Access values
tool_path = cfg.tools.paths.nmap                    # "" if not configured
timeout = cfg.tools.defaults.scan_timeout           # 600 (default)
allowed = cfg.targets.allowed_hosts                 # list[str]
rpc_url = cfg.tools.paths.metasploit_rpc            # "https://127.0.0.1:55553"

# Effective blocked hosts (built-in + user-configured)
blocked = cfg.effective_blocked_hosts               # list[str]
```

### Resetting the Config Singleton (for tests)

```python
from tengu.config import reset_config

def teardown_function():
    reset_config()  # clears the singleton so the next test gets a fresh config
```

---

## Validation and Error Handling

If `tengu.toml` contains invalid TOML syntax, Tengu raises `ConfigError` at startup
with the file path and parse error message.

If `tengu.toml` is missing, Tengu logs a warning and uses all defaults. This allows
running without any configuration file for quick testing.

If a field has the wrong type (e.g., `max_scans_per_minute = "ten"`), Pydantic raises
a `ValidationError` with a clear message indicating the field and expected type.
