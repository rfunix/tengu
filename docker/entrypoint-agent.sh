#!/usr/bin/env bash
# Tengu Docker Entrypoint — Autonomous Agent Mode
#
# Environment variables:
#   ANTHROPIC_API_KEY       (required) Anthropic API key for Claude
#   TENGU_AGENT_TARGET      (required) Target IP, hostname, or URL
#   TENGU_AGENT_SCOPE       (optional) Comma-separated scope. Defaults to TENGU_AGENT_TARGET
#   TENGU_AGENT_TYPE        (optional) blackbox | greybox | whitebox. Default: blackbox
#   TENGU_AGENT_MAX_ITER    (optional) Max tool iterations. Default: 50
#   TENGU_AGENT_MODEL       (optional) Claude model ID. Default: claude-sonnet-4-6
#   TENGU_AGENT_MAX_TOKENS  (optional) Max tokens per API call. Default: 2048
#   TENGU_AGENT_TIMEOUT     (optional) Total timeout in minutes; 0=unlimited. Default: 60
set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────────
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ── Banner ──────────────────────────────────────────────────────────────────────
echo -e "${BLUE}"
echo "  ████████╗███████╗███╗   ██╗ ██████╗ ██╗   ██╗"
echo "     ██╔══╝██╔════╝████╗  ██║██╔════╝ ██║   ██║"
echo "     ██║   █████╗  ██╔██╗ ██║██║  ███╗██║   ██║"
echo "     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║   ██║"
echo "     ██║   ███████╗██║ ╚████║╚██████╔╝╚██████╔╝"
echo "     ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝"
echo "  Autonomous Pentest Agent — Docker"
echo -e "${NC}"

# ── Ensure required directories ─────────────────────────────────────────────────
mkdir -p /app/logs /app/output

# ── Validate required environment variables ─────────────────────────────────────
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "${RED}[error]${NC} ANTHROPIC_API_KEY is not set."
    echo -e "        Create a .env file with ANTHROPIC_API_KEY=sk-ant-... or pass -e ANTHROPIC_API_KEY=..."
    exit 1
fi

if [[ -z "${TENGU_AGENT_TARGET:-}" ]]; then
    echo -e "${RED}[error]${NC} TENGU_AGENT_TARGET is not set."
    echo -e "        Set TENGU_AGENT_TARGET=<ip-or-hostname> in your .env file."
    exit 1
fi

# ── Apply TENGU_ALLOWED_HOSTS override ─────────────────────────────────────────
if [[ -n "${TENGU_ALLOWED_HOSTS:-}" ]]; then
    echo -e "${YELLOW}[config]${NC} TENGU_ALLOWED_HOSTS override: ${TENGU_ALLOWED_HOSTS}"
fi

# ── Update Nuclei templates (best-effort, skip if offline) ─────────────────────
if command -v nuclei &>/dev/null; then
    echo -e "${BLUE}[nuclei]${NC} Updating templates..."
    nuclei -update-templates -silent 2>/dev/null && \
        echo -e "${GREEN}[nuclei]${NC} Templates updated" || \
        echo -e "${YELLOW}[nuclei]${NC} Template update skipped (offline?)"
fi

# ── Resolve agent parameters ────────────────────────────────────────────────────
TARGET="${TENGU_AGENT_TARGET}"
SCOPE="${TENGU_AGENT_SCOPE:-${TARGET}}"
TYPE="${TENGU_AGENT_TYPE:-blackbox}"
MAX_ITER="${TENGU_AGENT_MAX_ITER:-50}"
MODEL="${TENGU_AGENT_MODEL:-claude-sonnet-4-6}"
MAX_TOKENS="${TENGU_AGENT_MAX_TOKENS:-2048}"
TIMEOUT="${TENGU_AGENT_TIMEOUT:-60}"

# Convert comma-separated scope to --scope args
SCOPE_ARGS=()
IFS=',' read -ra SCOPE_ITEMS <<< "${SCOPE}"
for item in "${SCOPE_ITEMS[@]}"; do
    item="${item// /}"  # trim whitespace
    if [[ -n "$item" ]]; then
        SCOPE_ARGS+=("$item")
    fi
done

echo ""
echo -e "${GREEN}[agent]${NC} Starting autonomous pentest:"
echo -e "  Target:      ${TARGET}"
echo -e "  Scope:       ${SCOPE}"
echo -e "  Type:        ${TYPE}"
echo -e "  Max Iters:   ${MAX_ITER}"
echo -e "  Model:       ${MODEL}"
echo -e "  Max Tokens:  ${MAX_TOKENS}"
echo -e "  Timeout:     ${TIMEOUT}m"
echo ""

# ── Launch autonomous agent ──────────────────────────────────────────────────────
exec uv run python /app/autonomous_tengu.py \
    "${TARGET}" \
    --scope "${SCOPE_ARGS[@]}" \
    --type "${TYPE}" \
    --max-iterations "${MAX_ITER}" \
    --model "${MODEL}" \
    --max-tokens "${MAX_TOKENS}" \
    --timeout "${TIMEOUT}" \
    --yes
