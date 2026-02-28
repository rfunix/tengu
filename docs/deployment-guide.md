# Deployment Guide

This guide covers installation, configuration, and integration of Tengu with
MCP clients (Claude Code, Claude Desktop) and the MCP Inspector.

---

## Prerequisites

### Python Environment

| Requirement | Minimum Version | Notes |
|------------|----------------|-------|
| Python | 3.12+ | Required for `tomllib` (stdlib) and PEP 604 union types |
| uv | Latest | Package manager. Install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

### External Pentesting Tools

Tools are optional at install time — Tengu starts without them and reports missing
tools via `check_tools`. Install only what you need for your engagement type.

| Tool | Category | Required By |
|------|----------|------------|
| nmap | recon | `nmap_scan` |
| masscan | recon | `masscan_scan` |
| subfinder | recon | `subfinder_enum` |
| nuclei | web | `nuclei_scan` |
| nikto | web | `nikto_scan` |
| ffuf | web | `ffuf_fuzz` |
| sqlmap | injection | `sqlmap_scan` |
| dalfox | injection | `xss_scan` |
| hydra | bruteforce | `hydra_attack` |
| john | bruteforce | `hash_crack` |
| hashcat | bruteforce | `hash_crack` |
| searchsploit | exploit | `searchsploit_query` |
| msfconsole / msfvenom | exploit | `msf_*` tools |
| zaproxy / zap.sh | proxy | `zap_*` tools |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/tengu-project/tengu.git
cd tengu
```

### 2. Install Python Dependencies

```bash
# Install runtime dependencies only
uv sync

# Install runtime + development dependencies (tests, lint, types)
uv sync --extra dev

# Install all extras (reporting = Jinja2+WeasyPrint, metasploit = pymetasploit3)
uv sync --all-extras
```

### 3. Install External Tools

```bash
# Install all supported external tools
make install-tools

# Or install by category
make install-tools-recon    # nmap, masscan, subfinder
make install-tools-web      # nuclei, nikto, ffuf, sslyze
```

### 4. Configure Tengu

Copy and edit the default configuration:

```bash
cp tengu.toml tengu.toml.bak   # keep a backup
```

At minimum, configure `allowed_hosts` with your engagement scope:

```toml
[targets]
allowed_hosts = ["192.168.1.0/24", "*.example.com"]
```

### 5. Verify the Installation

```bash
# Check Python dependencies and tool availability
make doctor

# Run the test suite
make test
```

---

## Claude Code Configuration

> **Important:** Claude Code reads MCP server configuration from **`~/.claude.json`**, not
> from `~/.claude/settings.json`. The recommended way to register servers is via the
> `claude mcp add` CLI — it writes to the correct file automatically.

### Basic Configuration (stdio transport)

Use the `claude mcp add` command with `--scope user` to register Tengu globally
(available in all projects):

```bash
claude mcp add --scope user tengu \
  uv -- run --directory /absolute/path/to/tengu tengu
```

Or manually set environment variables:

```bash
claude mcp add --scope user \
  --env TENGU_CONFIG_PATH=/absolute/path/to/tengu/tengu.toml \
  tengu \
  uv -- run --directory /absolute/path/to/tengu tengu
```

The command writes an entry like this to `~/.claude.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/tengu", "tengu"],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml"
      }
    }
  }
}
```

Replace `/absolute/path/to/tengu` with the actual absolute path to your clone.

### With NVD API Key

```bash
claude mcp add --scope user \
  --env TENGU_CONFIG_PATH=/absolute/path/to/tengu/tengu.toml \
  --env NVD_API_KEY=your-nvd-api-key-here \
  tengu \
  uv -- run --directory /absolute/path/to/tengu tengu
```

### With Debug Logging

```bash
claude mcp add --scope user \
  --env TENGU_CONFIG_PATH=/absolute/path/to/tengu/tengu.toml \
  --env TENGU_LOG_LEVEL=DEBUG \
  tengu \
  uv -- run --directory /absolute/path/to/tengu tengu
```

### Useful CLI Commands

```bash
claude mcp list                 # list all registered MCP servers
claude mcp remove tengu         # remove a server
claude mcp get tengu            # show details for a specific server
```

After adding a server, restart Claude Code or open a new session for it to connect.

---

## Claude Desktop Configuration

Claude Desktop reads MCP configuration from:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

> **Important:** Claude Desktop validates that a `command` field is present. It does **not**
> accept a bare `url` field for remote servers — that schema fails validation at startup.

### Local (stdio) — Tengu running on the same machine

```json
{
  "mcpServers": {
    "tengu": {
      "command": "/absolute/path/to/uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/tengu",
        "tengu"
      ],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml"
      }
    }
  }
}
```

Use the full path to `uv` (find it with `which uv`) to avoid PATH issues.

### Remote (SSE) — Tengu running on a Kali VM

See the [SSE Mode section](#sse-mode-macos-host--kali-vm) below for the full setup.
In short: create a wrapper script and point Claude Desktop at it.

Restart Claude Desktop after editing the config file.

---

## MCP Inspector

The MCP Inspector provides an interactive web UI for testing tools, resources,
and prompts without needing an AI client.

```bash
make inspect
# equivalent to:
npx @modelcontextprotocol/inspector uv run tengu
```

The inspector opens at `http://localhost:5173`. You can:
- Browse all registered tools, resources, and prompts
- Call tools with custom parameters and inspect the JSON response
- Read resources and see their content
- Expand prompts with test arguments

---

## SSE Transport (Remote Connections)

The SSE (Server-Sent Events) transport allows the MCP server to run on a different
host than the client. This is useful for running Tengu on a Kali Linux VM while
Claude Code runs on a macOS host.

### Start Tengu in SSE Mode

On the Kali VM:

```bash
make run-sse
# equivalent to:
uv run tengu --transport sse
# default: http://0.0.0.0:8000
```

### Configure Claude Code for SSE

On the macOS host, use `claude mcp add` with `--transport sse`:

```bash
claude mcp add --transport sse --scope user tengu http://KALI_VM_IP:8000/sse
```

Replace `KALI_VM_IP` with the actual IP of your Kali VM (e.g., `192.168.64.5`
for UTM, `192.168.56.101` for VirtualBox host-only).

This writes the following entry to `~/.claude.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "type": "sse",
      "url": "http://KALI_VM_IP:8000/sse"
    }
  }
}
```

> **Note:** Do not edit `~/.claude/settings.json` to add MCP servers — that file
> is for other Claude Code settings. The `mcpServers` key there is ignored for
> MCP registration. Always use `claude mcp add` or edit `~/.claude.json` directly.

---

## Example Workflows

After connecting Claude Code to Tengu, use these prompts to start an engagement.

### Quick Recon

```
Use the quick_recon prompt with target="192.168.1.1"
```

This triggers a 7-step workflow: validate_target → whois_lookup → dns_enumerate →
subfinder_enum → nmap_scan → analyze_headers → ssl_tls_check

### Web Application Assessment

```
Use the web_app_assessment prompt with url="https://example.com"
```

This triggers: analyze_headers → test_cors → ssl_tls_check → ffuf_fuzz →
nuclei_scan → nikto_scan → sqlmap_scan → xss_scan → correlate_findings → score_risk

### Full Penetration Test

```
Use the full_pentest prompt with target="example.com", scope="full", engagement_type="blackbox"
```

This triggers the complete 7-phase PTES workflow.

---

## Kali Linux Quickstart

Kali Linux is the recommended platform for running Tengu in a penetration testing lab.

### Install uv on Kali

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc   # or source ~/.zshrc
uv --version
```

### Clone and Setup Tengu

```bash
sudo mkdir -p /opt/tengu
sudo chown $USER:$USER /opt/tengu
git clone https://github.com/tengu-project/tengu.git /opt/tengu
cd /opt/tengu
make setup          # installs Python dependencies
make install-tools  # installs any missing pentesting tools
```

### Configure for Kali

```bash
cat > /opt/tengu/tengu.toml << 'EOF'
[server]
log_level = "INFO"
audit_log_path = "/opt/tengu/logs/tengu-audit.log"

[targets]
# Configure your lab network
allowed_hosts = ["192.168.56.0/24"]

[tools.defaults]
scan_timeout = 1800
wordlist_path = "/usr/share/wordlists/dirb/common.txt"
EOF
```

### Verify Tool Availability

```bash
make doctor
```

### Tools Pre-Installed on Kali

The following tools are available via `apt` on Kali Linux (2025.1+) and are installed
automatically by `make install-tools`:

| Tool | Package | Tengu Usage |
|------|---------|------------|
| nmap | `nmap` | `nmap_scan` |
| masscan | `masscan` | `masscan_scan` |
| subfinder | `subfinder` | `subfinder_enum` |
| amass | `amass` | `amass_enum` |
| dnsrecon | `dnsrecon` | `dnsrecon_scan` |
| sqlmap | `sqlmap` | `sqlmap_scan` |
| nikto | `nikto` | `nikto_scan` |
| ffuf | `ffuf` | `ffuf_fuzz` |
| nuclei | `nuclei` | `nuclei_scan` |
| gobuster | `gobuster` | `gobuster_scan` |
| wpscan | `wpscan` | `wpscan_scan` |
| gitleaks | `gitleaks` | `gitleaks_scan` |
| trivy | `trivy` | `trivy_scan` |
| zaproxy | `zaproxy` | `zap_*` tools |
| arjun | `arjun` | `arjun_discover` |
| enum4linux-ng | `enum4linux-ng` | `enum4linux_scan` |
| nxc | `nxc` | `nxc_enum` |
| impacket-scripts | `impacket-scripts` | `impacket_kerberoast` |
| hydra | `hydra` | `hydra_attack` |
| john | `john` | `hash_crack` |
| hashcat | `hashcat` | `hash_crack` |
| cewl | `cewl` | `cewl_generate` |
| msfconsole | `metasploit-framework` | `msf_*` tools |
| searchsploit | `exploitdb` | `searchsploit_query` |
| theHarvester | `theharvester` | `theharvester_scan` |
| whatweb | `whatweb` | `whatweb_scan` |
| aircrack-ng | `aircrack-ng` | `aircrack_scan` |
| tor | `tor` | stealth tools |
| torsocks | `torsocks` | stealth tools |
| proxychains4 | `proxychains4` | stealth tools |
| golang | `golang` | (required for Go-based tools) |

### Tools That Need Special Installation on Kali

Run `./scripts/install-tools.sh --all` to handle all of the below automatically.

**testssl.sh** — Kali installs the binary as `testssl` (no `.sh`); a symlink is required:
```bash
sudo apt install -y testssl.sh
sudo ln -sf /usr/bin/testssl /usr/local/bin/testssl.sh
```

**trufflehog** — `go install` fails (replace directives); use the official install script:
```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sudo sh -s -- -b /usr/local/bin
```

**dalfox, gowitness, subjack** — Go tools not yet in apt:
```bash
go install github.com/hahwul/dalfox/v2@latest
go install github.com/sensepost/gowitness@latest
go install github.com/haccer/subjack@latest
# Symlink to /usr/local/bin so they are in PATH for all sessions:
for bin in dalfox gowitness subjack; do
    sudo ln -sf "$HOME/go/bin/$bin" "/usr/local/bin/$bin"
done
```

**checkov, ScoutSuite, prowler** — pip installs to `~/.local/bin`; symlinks needed:
```bash
pip3 install --break-system-packages checkov scoutsuite prowler
sudo ln -sf ~/.local/bin/checkov /usr/local/bin/checkov
sudo ln -sf ~/.local/bin/scout   /usr/local/bin/scout
sudo ln -sf ~/.local/bin/prowler /usr/local/bin/prowler
```

**GetUserSPNs.py** — Kali installs it as `impacket-GetUserSPNs`; create a shim:
```bash
sudo ln -sf /usr/bin/impacket-GetUserSPNs /usr/local/bin/GetUserSPNs.py
```

**zap.sh** — Tengu also checks for `zap.sh`; symlink `zaproxy`:
```bash
sudo ln -sf /usr/bin/zaproxy /usr/local/bin/zap.sh
```

**WeasyPrint** (for PDF report generation):
```bash
sudo apt install -y python3-weasyprint libpango-1.0-0 libpangocairo-1.0-0
# Then install the Python extra:
uv sync --extra reporting
```

### SSE Mode: macOS Host → Kali VM

This setup lets Claude Code on your macOS machine use Tengu running on Kali.

**On Kali VM:**

```bash
# Configure the allowed hosts for your lab network
# (edit /opt/tengu/tengu.toml first)

# Start Tengu in SSE mode
cd /opt/tengu
uv run tengu --transport sse --host 0.0.0.0 --port 8000
```

**On macOS host**, register the SSE server via CLI:

```bash
claude mcp add --transport sse --scope user tengu http://KALI_VM_IP:8000/sse
```

This writes to `~/.claude.json`. Verify with `claude mcp list`.

**For Claude Desktop**, create a wrapper script and point the config at it.
Claude Desktop uses a restricted `PATH` (`/usr/local/bin`, `/opt/homebrew/bin`,
`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) so tools managed by `fnm`, `nvm`, or
`pyenv` are not found. The wrapper injects the correct `PATH` before running `mcp-remote`.

**Step 1 — Create the wrapper script:**

```bash
cat > ~/.local/bin/tengu-mcp-bridge << 'EOF'
#!/bin/bash
# Inject the fnm node path so Claude Desktop can find node/npx
export PATH="/Users/<you>/.local/share/fnm/node-versions/<version>/installation/bin:$PATH"
exec npx -y mcp-remote http://KALI_VM_IP:8000/sse --allow-http
EOF
chmod +x ~/.local/bin/tengu-mcp-bridge
```

Find your Node.js stable path with:
```bash
readlink -f $(which npx)
# example: /Users/you/.local/share/fnm/node-versions/v20.20.0/installation/lib/node_modules/npm/bin/npx-cli.js
# → use the bin/ sibling directory: /Users/you/.local/share/fnm/node-versions/v20.20.0/installation/bin
```

> **Note:** `--allow-http` is required because `mcp-remote` blocks non-HTTPS URLs
> that are not `localhost` by default.

**Step 2 — Configure Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tengu": {
      "command": "/Users/<you>/.local/bin/tengu-mcp-bridge",
      "args": []
    }
  }
}
```

**Step 3 — Restart Claude Desktop.** The `tengu` server should appear as connected.

**Verify the wrapper works** (simulates Claude Desktop's restricted PATH):
```bash
env -i PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  ~/.local/bin/tengu-mcp-bridge
# expected: "Proxy established successfully between local STDIO and remote SSEClientTransport"
```

**UTM network setup** (macOS — recommended for Apple Silicon):
1. UTM assigns the VM an IP automatically via its built-in NAT
2. Find the VM IP inside Kali: `ip addr show` — look for the `192.168.x.x` address
3. Use that IP in the commands above
4. The Mac host can reach the VM directly (no port forwarding needed for NAT)

**VirtualBox network setup** (host-only adapter):
1. Go to VirtualBox → File → Host Network Manager
2. Create a host-only network (e.g., `192.168.56.0/24`)
3. Add a host-only adapter to your Kali VM
4. Configure Kali's `/etc/network/interfaces` or use NetworkManager:
   ```bash
   sudo dhclient eth1   # adjust interface name as needed
   ```

**VMware Fusion network setup**:
1. Use VMnet1 (Host-Only) or VMnet8 (NAT)
2. Note the VM's IP from `ip addr show`
3. Use that IP in the commands above

---

## Troubleshooting

### "Tool not found" errors

```bash
# Check which tools are missing
make doctor

# Install missing tools
make install-tools

# Or install manually and verify PATH
which nmap nuclei ffuf sqlmap

# If tool is in a non-standard location, set path in tengu.toml:
# [tools.paths]
# nmap = "/usr/local/bin/nmap"
```

### "Target not in allowlist" errors

```bash
# Check your tengu.toml configuration
grep -A5 "\[targets\]" tengu.toml

# Add the target to allowed_hosts in tengu.toml
# Example:
# [targets]
# allowed_hosts = ["192.168.1.0/24"]

# Then restart the MCP server (restart Claude Code or run /mcp reload)
```

### Rate limit errors

```bash
# Check current rate limiting config
grep -A3 "\[rate_limiting\]" tengu.toml

# Increase limits for intensive testing (use responsibly):
# [rate_limiting]
# max_scans_per_minute = 20
# max_concurrent_scans = 5
```

### MCP server not appearing in Claude Code

1. Confirm the server is registered: `claude mcp list`
   - If empty, the server was not added to `~/.claude.json` — run `claude mcp add` (see above)
   - Do **not** add `mcpServers` to `~/.claude/settings.json` — that key is ignored for MCP
2. For SSE servers: verify the remote server is reachable:
   ```bash
   curl -I http://KALI_VM_IP:8000/sse   # should return HTTP 200 with text/event-stream
   ```
3. For stdio servers: verify the path in `--directory` exists: `ls /absolute/path/to/tengu`
4. Test Tengu starts manually: `cd /path/to/tengu && uv run tengu`
5. Check for errors: `TENGU_LOG_LEVEL=DEBUG uv run tengu`
6. In Claude Code, run `/mcp` to see server status and error messages
7. Open a new Claude Code session after adding the server — changes to `~/.claude.json`
   are picked up on session start

### Metasploit RPC connection failures

```bash
# Start Metasploit RPC daemon
msfrpcd -P your_password -a 127.0.0.1 -p 55553 -S

# Verify it is running
netstat -tlnp | grep 55553

# Set the password in environment (Tengu reads MSF_RPC_PASSWORD)
export MSF_RPC_PASSWORD="your_password"
```

### OWASP ZAP connection failures

```bash
# Start ZAP in daemon mode
zaproxy -daemon -host 127.0.0.1 -port 8080 -config api.key=your_api_key

# Verify ZAP is running
curl http://127.0.0.1:8080/JSON/core/view/version/?apikey=your_api_key

# Set the API key in tengu.toml (future config option) or environment
```

### Audit log growing too large

```bash
# Rotate the audit log manually (safe — Tengu appends, so the new file is used)
mv logs/tengu-audit.log logs/tengu-audit-$(date +%Y%m%d).log

# Or set up logrotate
cat > /etc/logrotate.d/tengu << 'EOF'
/opt/tengu/logs/tengu-audit.log {
    weekly
    rotate 52
    compress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Scan timeouts

```bash
# Increase the global timeout in tengu.toml
# [tools.defaults]
# scan_timeout = 1800   # 30 minutes

# Or pass timeout explicitly in the tool call:
# nmap_scan(target="...", timeout=3600)
```
