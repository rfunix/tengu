#!/usr/bin/env bash
# record-demo.sh — Automated asciinema recording of Tengu + Claude Code pentesting Juice Shop
#
# Usage:  ./scripts/record-demo.sh [output.cast]
# Re-run: safe to re-execute; overwrites the previous cast and kills old tmux sessions.
#
# Architecture:
#   1. preflight_checks()   — verify dependencies and Docker lab
#   2. setup_tmux_session() — fresh 149×40 tmux session
#   3. run_full_demo()      — background driver: types prompts via tmux send-keys
#   4. asciinema rec        — foreground recorder; terminates when tmux detaches

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

CAST_FILE="${1:-/Users/rfunix/dev/tengu/docs/tengu-demo-claude-code.cast}"
TMUX_SESSION="tengu-demo"
TERM_COLS=149
TERM_ROWS=40

# Typing simulation delays (seconds)
TYPING_DELAY_MIN=0.03
TYPING_DELAY_MAX=0.08
TYPING_DELAY_SPACE=0.12
TYPING_DELAY_PUNCT=0.20   # commas, periods, etc.

# Phase timeouts (seconds) — generous to accommodate slow tool runs
TIMEOUT_LANG=30
TIMEOUT_PHASE0=120
TIMEOUT_PHASE1=420
TIMEOUT_PHASE2=480
TIMEOUT_PHASE3=180
TIMEOUT_REPORT=120

ASCIINEMA_IDLE_LIMIT=5

# Prompts — mirror docs/demo-script.md exactly
PROMPT_LANG="Always respond in English for this entire session. Do not use Portuguese."
PROMPT_PHASE0="Check which pentesting tools are installed and validate that juice-shop is an allowed target."
PROMPT_PHASE1="Use find_vulns on juice-shop"
PROMPT_PHASE2="The endpoint /rest/products/search?q=test looks injectable. Confirm the SQLi and dump the Users table — email, password, role."
PROMPT_PHASE3="Identify and crack this hash from the admin account: 0192023a7bbd73250516f069df18b500"
PROMPT_REPORT="Generate an executive summary report of all findings from this assessment."

# ─── Logging helpers (stderr only — invisible to asciinema) ──────────────────

log_info()  { echo "[INFO]  $*" >&2; }
log_step()  { echo "[STEP]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# ─── Utility: type text character by character via tmux ──────────────────────
#
# Uses python3 for sub-millisecond random sleep because `sleep` on macOS only
# accepts integer seconds without GNU coreutils.

type_text() {
    local text="$1"
    local i char

    for (( i=0; i<${#text}; i++ )); do
        char="${text:$i:1}"

        # Send one character literally (--  prevents - being parsed as a flag)
        tmux send-keys -t "$TMUX_SESSION" -l -- "$char"

        # Variable delay based on character type
        case "$char" in
            ' ')
                python3 -c "import time; time.sleep($TYPING_DELAY_SPACE)"
                ;;
            ','|'.'|'!'|'?'|':'|';'|'—')
                python3 -c "
import time, random
time.sleep(random.uniform($TYPING_DELAY_PUNCT, $TYPING_DELAY_PUNCT + 0.05))
"
                ;;
            *)
                python3 -c "
import time, random
time.sleep(random.uniform($TYPING_DELAY_MIN, $TYPING_DELAY_MAX))
"
                ;;
        esac
    done
}

send_enter() {
    tmux send-keys -t "$TMUX_SESSION" Enter
    sleep 0.5
}

type_and_send() {
    local text="$1"
    type_text "$text"
    sleep 0.5
    send_enter
}

# ─── Wait for Claude Code ❯ prompt ───────────────────────────────────────────
#
# Polls tmux capture-pane every 2s.  Requires 2 consecutive clean matches to
# avoid false positives from partial renders or spinner frames.
#
# Claude Code uses ❯ (U+276F) as its REPL prompt.
# Spinner characters: ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ (Braille block)
# Activity words:     Running, thinking, Calling, Executing, Processing

wait_for_claude_prompt() {
    local timeout="${1:-60}"
    local elapsed=0
    local poll_interval=2
    local consecutive_matches=0
    local required_matches=2
    # Target the first pane explicitly — avoids "can't find pane: <session>" on macOS tmux
    local pane_target="${TMUX_SESSION}:0.0"

    log_info "Waiting for Claude prompt (timeout: ${timeout}s)…"

    while (( elapsed < timeout )); do
        local pane_text
        pane_text=$(tmux capture-pane -t "$pane_target" -p -S -5 2>/dev/null || true)

        # Use python3 for Unicode-safe detection (BSD grep on macOS lacks -P).
        local has_prompt=false
        local is_busy=false

        if python3 -c "
import sys
text = sys.stdin.read()
sys.exit(0 if '\u276f' in text else 1)
" <<< "$pane_text" 2>/dev/null; then
            has_prompt=true
        fi

        if python3 -c "
import sys
text = sys.stdin.read()
spinners = '\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2817\u280f'
busy_words = ['Running', 'thinking', 'Calling', 'Executing', 'Processing']
found = any(c in text for c in spinners) or any(w in text for w in busy_words)
sys.exit(0 if found else 1)
" <<< "$pane_text" 2>/dev/null; then
            is_busy=true
        fi

        if $has_prompt && ! $is_busy; then
            (( consecutive_matches++ )) || true
            log_info "  Match ${consecutive_matches}/${required_matches} (${elapsed}s elapsed)"
            if (( consecutive_matches >= required_matches )); then
                log_info "  Claude prompt stable — proceeding."
                return 0
            fi
        else
            consecutive_matches=0
        fi

        sleep "$poll_interval"
        (( elapsed += poll_interval )) || true
    done

    log_error "Timed out waiting for Claude prompt after ${timeout}s."
    log_error "Last pane content:"
    tmux capture-pane -t "$pane_target" -p -S -20 >&2 || true
    return 1
}

# ─── Preflight checks ─────────────────────────────────────────────────────────

preflight_checks() {
    log_step "Running preflight checks…"

    local missing=()

    for cmd in tmux asciinema claude python3 docker; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        log_error "Missing required commands: ${missing[*]}"
        exit 1
    fi

    # Docker daemon running?
    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running. Start Docker Desktop and retry."
        exit 1
    fi

    # juice-shop container up?
    local juice_shop_id
    juice_shop_id=$(docker compose -f /Users/rfunix/dev/tengu/docker-compose.yml ps -q juice-shop 2>/dev/null || true)
    if [[ -z "$juice_shop_id" ]]; then
        log_error "juice-shop container is not running."
        log_error "Run: cd /Users/rfunix/dev/tengu && make docker-lab"
        exit 1
    fi

    # tengu container running?
    local tengu_running
    tengu_running=$(docker compose -f /Users/rfunix/dev/tengu/docker-compose.yml ps -q tengu 2>/dev/null || true)
    if [[ -z "$tengu_running" ]]; then
        log_error "tengu container is not running. Start the lab first."
        exit 1
    fi

    # Juice Shop reachable from inside the Docker network?
    # Use docker compose exec (service name lookup) and check HTTP 200 status only.
    local http_status
    http_status=$(docker compose -f /Users/rfunix/dev/tengu/docker-compose.yml \
        exec -T tengu \
        curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://juice-shop:3000/ \
        2>/dev/null || true)
    if [[ "$http_status" != "200" ]]; then
        log_error "Juice Shop is not reachable at http://juice-shop:3000/ (HTTP status: '${http_status}')."
        log_error "Ensure the lab is running: make docker-lab"
        exit 1
    fi

    # tengu.toml has juice-shop in allowed_hosts?
    # Also sync the config into the running container (it bakes the toml at image build time).
    local toml="/Users/rfunix/dev/tengu/tengu.toml"
    if ! grep -q "juice-shop" "$toml"; then
        log_error "tengu.toml does not list 'juice-shop' in [targets].allowed_hosts."
        log_error "Add: allowed_hosts = [\"juice-shop\", \"172.20.0.5\"]"
        exit 1
    fi

    # Push the local tengu.toml into the running container so the server picks up
    # the updated allowed_hosts (the image bakes an older copy at build time).
    local container_name="tengu-tengu-1"
    log_info "Syncing tengu.toml into container '${container_name}'…"
    if docker cp "$toml" "${container_name}:/app/tengu.toml" 2>/dev/null; then
        log_info "Config copied. Restarting ${container_name} to reload…"
        docker restart "$container_name" >/dev/null
        # Wait for the container to become healthy again (up to 30s)
        local waited=0
        while (( waited < 30 )); do
            local state
            state=$(docker inspect --format '{{.State.Health.Status}}' "$container_name" 2>/dev/null || true)
            if [[ "$state" == "healthy" ]]; then
                log_info "Container healthy."
                break
            fi
            sleep 2
            (( waited += 2 )) || true
        done
    else
        log_error "Could not copy tengu.toml into container '${container_name}'."
        log_error "Is the container name correct? Run: docker ps --format '{{.Names}}'"
        exit 1
    fi

    log_info "Preflight OK."
}

# ─── tmux session setup ───────────────────────────────────────────────────────

setup_tmux_session() {
    log_step "Setting up tmux session '${TMUX_SESSION}'…"

    # Kill any leftover session from a previous run
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    sleep 0.5

    # Create a fresh session (detached, specific geometry, 256-colour, no status bar)
    tmux new-session -d \
        -s "$TMUX_SESSION" \
        -x "$TERM_COLS" \
        -y "$TERM_ROWS" \
        -e "TERM=tmux-256color"

    tmux set-option -t "$TMUX_SESSION" status off

    # Navigate to the project root and clear the screen
    tmux send-keys -t "$TMUX_SESSION" "cd /Users/rfunix/dev/tengu && clear" Enter
    sleep 1

    log_info "tmux session ready."
}

# ─── Cleanup trap ────────────────────────────────────────────────────────────

cleanup() {
    log_info "Cleaning up…"
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
}

# ─── Demo phases ─────────────────────────────────────────────────────────────

run_phase() {
    local name="$1"
    local prompt="$2"
    local timeout="$3"

    log_step "=== ${name} ==="
    sleep 3  # brief pause between phases for visual breathing room
    type_and_send "$prompt"
    wait_for_claude_prompt "$timeout"
}

run_full_demo() {
    # Give asciinema a moment to attach to the tmux session
    sleep 3

    log_step "Starting Claude Code…"
    type_and_send "claude --dangerously-skip-permissions"
    wait_for_claude_prompt 30

    # ── Prompt 0: Force English ─────────────────────────────────────────────
    # The user's ~/.claude/CLAUDE.md instructs Claude to respond in pt-BR.
    # This prompt overrides that preference so the recording is in English.
    log_step "Setting language to English…"
    run_phase "Language Override" "$PROMPT_LANG" "$TIMEOUT_LANG"

    # ── Phase 0: Setup ──────────────────────────────────────────────────────
    run_phase "Phase 0 — Setup" "$PROMPT_PHASE0" "$TIMEOUT_PHASE0"

    # ── Phase 1: find_vulns ─────────────────────────────────────────────────
    run_phase "Phase 1 — Discovery" "$PROMPT_PHASE1" "$TIMEOUT_PHASE1"

    # ── Phase 2: SQLi + Dump ────────────────────────────────────────────────
    run_phase "Phase 2 — SQLi Exploitation" "$PROMPT_PHASE2" "$TIMEOUT_PHASE2"

    # ── Phase 3: Hash Identification + Cracking ─────────────────────────────
    run_phase "Phase 3 — Hash Crack" "$PROMPT_PHASE3" "$TIMEOUT_PHASE3"

    # ── Wrap-up: Executive Report ───────────────────────────────────────────
    run_phase "Wrap-up — Report" "$PROMPT_REPORT" "$TIMEOUT_REPORT"

    # ── End session ─────────────────────────────────────────────────────────
    log_step "Demo complete. Exiting Claude Code and detaching tmux…"
    sleep 2
    type_and_send "/exit"
    sleep 3

    # Detach — this causes asciinema to stop recording
    tmux detach-client -s "$TMUX_SESSION" 2>/dev/null || true
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    trap cleanup EXIT

    log_step "Tengu Demo Recorder"
    log_step "Output: ${CAST_FILE}"
    log_step "Session: ${TMUX_SESSION} (${TERM_COLS}×${TERM_ROWS})"

    preflight_checks
    setup_tmux_session

    # Start the demo driver in the background (waits for asciinema to attach)
    run_full_demo &
    local driver_pid=$!

    log_step "Starting asciinema recording…"
    log_step "(Recording will stop automatically when the demo completes.)"

    asciinema rec \
        --overwrite \
        --title "Tengu + Claude Code — Pentesting Juice Shop" \
        --idle-time-limit "$ASCIINEMA_IDLE_LIMIT" \
        --command "tmux attach-session -t ${TMUX_SESSION}" \
        "${CAST_FILE}"

    # Wait for the driver to finish (it should already be done)
    wait "$driver_pid" 2>/dev/null || true

    log_step "Recording saved to: ${CAST_FILE}"
    log_step "Play back with:  asciinema play ${CAST_FILE}"
    log_step "Convert to GIF:  agg ${CAST_FILE} docs/tengu-demo.gif"
}

main "$@"
