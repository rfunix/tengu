# Tengu — Pentesting MCP Server
# Multi-stage build with tool tiers: minimal | core (default) | full
#
# Usage:
#   docker build .                              # core tier (~2GB)
#   docker build --build-arg TENGU_TIER=minimal # ~400MB, Python-only tools
#   docker build --build-arg TENGU_TIER=full    # ~3GB, all tools including AD/wireless

ARG TENGU_TIER=core

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1 — builder: Python deps + Go tools
# ══════════════════════════════════════════════════════════════════════════════
FROM kalilinux/kali-rolling AS builder

ARG TENGU_TIER

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl git ca-certificates golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/root/.cargo/bin:${PATH}"

# Install Go tools BEFORE Python deps so Go cache survives uv.lock changes
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

RUN mkdir -p /root/go/bin && \
    if [ "$TENGU_TIER" = "core" ] || [ "$TENGU_TIER" = "full" ]; then \
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
        go install github.com/ffuf/ffuf/v2@latest && \
        go install github.com/hahwul/dalfox/v2@latest && \
        go install github.com/sensepost/gowitness@latest && \
        go install github.com/haccer/subjack@latest && \
        go install github.com/projectdiscovery/katana/cmd/katana@latest && \
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
        go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
        go install github.com/lc/crlfuzz@latest; \
    fi && \
    if [ "$TENGU_TIER" = "full" ]; then \
        go install github.com/evilsocket/sovereign@latest 2>/dev/null || true; \
    fi

# Cache Python dependencies separately from source code
# README.md is required by hatchling (referenced in pyproject.toml)
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra agent --extra metasploit

# Copy application source (invalidates only on src/ changes, not on dep changes)
COPY . /app

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2 — runtime: Kali base + apt tools by tier
# ══════════════════════════════════════════════════════════════════════════════
FROM kalilinux/kali-rolling AS runtime

ARG TENGU_TIER
ENV TENGU_TIER=${TENGU_TIER}

# ── Minimal tier: Python-only tools (~400MB) ────────────────────────────────
# Tools available: analyze_headers, test_cors, ssl_tls_check, dns_enumerate,
# whois_lookup, hash_identify, correlate_findings, score_risk, cve_lookup,
# generate_report, graphql_security_check, checkov
RUN if [ "$TENGU_TIER" = "minimal" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            python3 curl ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# ── Core tier: Essential pentesting tools (~2GB, default) ──────────────────
# rustscan: not in Kali apt — installed via Go binary or skipped (masscan covers this)
# dnstwist: python3-dnstwist is the correct apt package name
RUN if [ "$TENGU_TIER" = "core" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            python3 curl ca-certificates \
            nmap masscan nikto sqlmap gobuster wpscan whatweb \
            hydra john hashcat \
            seclists testssl.sh dnsrecon theharvester cewl exploitdb httrack \
            gitleaks trivy chromium \
            amass \
            wafw00f feroxbuster snmp python3-dnstwist \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# ── Full tier: All tools including AD, wireless, stealth (~3GB) ─────────────
# rustscan: not in Kali apt — use masscan as alternative
# bloodhound: GUI app (not the python collector); bloodhound-python via pip below
# prowler: pip-only, installed below
RUN if [ "$TENGU_TIER" = "full" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            python3 python3-pip curl ca-certificates \
            nmap masscan nikto sqlmap gobuster wpscan whatweb \
            hydra john hashcat \
            seclists testssl.sh dnsrecon theharvester cewl exploitdb httrack \
            gitleaks trivy chromium \
            amass \
            wafw00f feroxbuster snmp python3-dnstwist \
            enum4linux-ng netexec impacket-scripts \
            commix smbmap responder \
            aircrack-ng \
            tor torsocks proxychains4 socat \
            arjun \
        && python3 -m pip install --break-system-packages bloodhound-python prowler \
        && rm -rf /var/lib/apt/lists/* /root/.cache/pip; \
    fi

# ── Copy uv and Python virtualenv from builder ──────────────────────────────
COPY --from=builder /root/.local/bin/uv /root/.local/bin/uv
COPY --from=builder /root/.local/bin/uvx /root/.local/bin/uvx
COPY --from=builder /app/.venv /app/.venv

# ── Copy Go binaries from builder (core and full tiers) ─────────────────────
COPY --from=builder /root/go/bin/ /usr/local/bin/

# ── Copy application source ──────────────────────────────────────────────────
COPY --from=builder /app /app

# ── Copy Docker-specific configuration ──────────────────────────────────────
COPY docker/tengu.toml /app/tengu.toml
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/entrypoint-agent.sh /entrypoint-agent.sh
RUN chmod +x /entrypoint.sh /entrypoint-agent.sh

# ── Runtime environment ──────────────────────────────────────────────────────
ENV PATH="/root/.local/bin:/usr/local/bin:${PATH}"
ENV TENGU_CONFIG_PATH=/app/tengu.toml
ENV PYTHONUNBUFFERED=1

WORKDIR /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=3 \
    CMD /bin/sh -c "curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://localhost:8000/sse | grep -q 200"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
