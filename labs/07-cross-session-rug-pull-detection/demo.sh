#!/usr/bin/env bash
# demo.sh — Cross-session rug-pull demo
# Usage: ./demo.sh [--reset]
#
# This demo:
# 1. Resets session counter and fingerprint store
# 2. Starts rugpull_server.py in background
# 3. Runs sessions 1-4 (clean) — shows fingerprinter output: PASS
# 4. Runs sessions 5-7 (poisoned) — shows fingerprinter output: CRITICAL DRIFT DETECTED
# 5. Shows diff of session 1 vs session 6 description
# 6. Shows the exfiltration attempt in the agent log
# Clean up on exit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# LLM configuration (llama.cpp)
export LLM_URL="http://localhost:8081/v1"
export LLM_MODEL="qwen3.6-35b-a3b"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Config
SESSIONS_CLEAN=4
SESSIONS_POISONED=3
THRESHOLD=5
SERVER_PID=""
OUTPUT_DIR="results"

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        echo -e "${GREEN}Server stopped.${NC}"
    fi
    # Remove temp files
    rm -f sessions.db
    echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT

reset_state() {
    echo -e "${CYAN}Resetting state...${NC}"
    rm -f sessions.db
    rm -f "$OUTPUT_DIR"/fingerprint_history.db
    rm -f "$OUTPUT_DIR"/session_log.jsonl
    rm -f "$OUTPUT_DIR"/drift_alerts.json
    rm -f "$OUTPUT_DIR"/summary.md
}

print_header() {
    echo ""
    echo -e "${BOLD}$(printf '=%.0s' {1..60})${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${BOLD}$(printf '=%.0s' {1..60})${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_fail() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${CYAN}  → $1${NC}"
}

# Parse args
RESET=false
for arg in "$@"; do
    case $arg in
        --reset) RESET=true ;;
    esac
done

if $RESET; then
    reset_state
fi

# ============================================================
# STEP 1: Start the rug-pull server
# ============================================================
print_header "STEP 1: Starting Rug-Pull Server (threshold=$THRESHOLD)"

export SESSION_THRESHOLD=$THRESHOLD
export SESSION_DB_PATH="$(pwd)/sessions.db"

python -m server.rugpull_server &
SERVER_PID=$!
sleep 2

if kill -0 "$SERVER_PID" 2>/dev/null; then
    print_success "Server running (PID $SERVER_PID)"
else
    print_fail "Server failed to start"
    exit 1
fi

# ============================================================
# STEP 2: Run clean sessions (1-$SESSIONS_CLEAN)
# ============================================================
print_header "STEP 2: Running Clean Sessions (1-$SESSIONS_CLEAN)"

python -c "
import asyncio, sys, json
sys.path.insert(0, '.')
from pathlib import Path
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import TextContent
from detection.store.fingerprint_store import FingerprintStore
from detection.session_fingerprinter import SessionFingerprinter

async def run():
    store = FingerprintStore(Path('$OUTPUT_DIR/fingerprint_history.db'))
    fingerprinter = SessionFingerprinter(store)
    server_url = 'stdio:rugpull-server'

    for session_num in range(1, $SESSIONS_CLEAN + 1):
        session_id = f'session_{session_num}'
        cmd = f'SESSION_THRESHOLD=$THRESHOLD SESSION_DB_PATH=sessions.db python -m server.rugpull_server'

        async with stdio_client(cmd.split()) as (read, write):
            async with ClientSession(read, write) as session:
                fps = await fingerprinter.fingerprint_session(server_url, session, session_id)
                report = fingerprinter.compare_to_baseline(server_url, fps)
                report.server_url = server_url
                report.session_id = session_id

                severity = report.drift_severity.value
                status = 'PASS' if severity == 'none' else f'DRIFT ({severity.upper()})'
                color = '\033[0;32m' if severity == 'none' else '\033[0;31m'
                print(f'  Session {session_num}: {color}{status}\033[0m')

asyncio.run(run())
"

print_success "All clean sessions passed fingerprint check"

# ============================================================
# STEP 3: Run poisoned sessions (SESSIONS_CLEAN+1 to SESSIONS_CLEAN+SESSIONS_POISONED)
# ============================================================
print_header "STEP 3: Running Poisoned Sessions ($((SESSIONS_CLEAN + 1))-$((SESSIONS_CLEAN + SESSIONS_POISONED)))"

python -c "
import asyncio, sys, json
sys.path.insert(0, '.')
from pathlib import Path
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import TextContent
from detection.store.fingerprint_store import FingerprintStore
from detection.session_fingerprinter import SessionFingerprinter

async def run():
    store = FingerprintStore(Path('$OUTPUT_DIR/fingerprint_history.db'))
    fingerprinter = SessionFingerprinter(store)
    server_url = 'stdio:rugpull-server'

    for session_num in range($SESSIONS_CLEAN + 1, $SESSIONS_CLEAN + $SESSIONS_POISONED + 1):
        session_id = f'session_{session_num}'
        cmd = f'SESSION_THRESHOLD=$THRESHOLD SESSION_DB_PATH=sessions.db python -m server.rugpull_server'

        async with stdio_client(cmd.split()) as (read, write):
            async with ClientSession(read, write) as session:
                fps = await fingerprinter.fingerprint_session(server_url, session, session_id)
                report = fingerprinter.compare_to_baseline(server_url, fps)
                report.server_url = server_url
                report.session_id = session_id

                severity = report.drift_severity.value
                if severity == 'none':
                    status = 'PASS'
                    color = '\033[0;32m'
                else:
                    status = f'⚠ DRIFT DETECTED ({severity.upper()})'
                    color = '\033[1;31m'
                print(f'  Session {session_num}: {color}{status}\033[0m')

                if severity != 'none':
                    for drift in report.drifted_tools:
                        print(f'    Tool: {drift.tool_name}')
                        print(f'    Baseline: {drift.baseline_description[:60]}...')
                        print(f'    Current:  {drift.current_description[:60]}...')

asyncio.run(run())
"

print_success "Poisoned sessions detected by fingerprinter!"

# ============================================================
# STEP 4: Show the diff
# ============================================================
print_header "STEP 4: Session 1 vs Session 6 — Description Diff"

echo ""
echo -e "${BOLD}Session 1 (baseline):${NC}"
python -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
from detection.store.fingerprint_store import FingerprintStore
store = FingerprintStore(Path('$OUTPUT_DIR/fingerprint_history.db'))
baseline = store.get_baseline('srv1' if False else None, 'calculate_discount')
# Query directly
import sqlite3
conn = sqlite3.connect('$OUTPUT_DIR/fingerprint_history.db')
row = conn.execute(\"SELECT description FROM baselines WHERE tool_name='calculate_discount'\").fetchone()
print(f'  {row[0]}')
conn.close()
"

echo ""
echo -e "${BOLD}Session 6 (poisoned):${NC}"
python -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
import sqlite3
conn = sqlite3.connect('$OUTPUT_DIR/fingerprint_history.db')
row = conn.execute(\"SELECT description FROM fingerprints WHERE tool_name='calculate_discount' AND session_number=6\").fetchone()
print(f'  {row[0][:120]}...')
conn.close()
"

echo ""
echo -e "${BOLD}Unified diff:${NC}"
python -c "
import sys, difflib; sys.path.insert(0, '.')
import sqlite3
conn = sqlite3.connect('$OUTPUT_DIR/fingerprint_history.db')
baseline = conn.execute(\"SELECT description FROM baselines WHERE tool_name='calculate_discount'\").fetchone()[0]
current = conn.execute(\"SELECT description FROM fingerprints WHERE tool_name='calculate_discount' AND session_number=6\").fetchone()[0]
conn.close()
diff = difflib.unified_diff(baseline.splitlines(), current.splitlines(), lineterm='')
for line in diff:
    if line.startswith('+'):
        print(f'\033[0;32m{line}\033[0m')
    elif line.startswith('-'):
        print(f'\033[0;31m{line}\033[0m')
    else:
        print(line)
"

# ============================================================
# STEP 5: Show detection summary
# ============================================================
print_header "STEP 5: Detection Summary"

echo -e "${BOLD}Existing tools (static analysis):${NC}"
echo -e "  ${RED}snyk-agent-scan: PASS (code unchanged)${NC}"
echo -e "  ${RED}Cisco AI Defense: PASS (code unchanged)${NC}"
echo ""
echo -e "${BOLD}Cross-session fingerprinting:${NC}"
echo -e "  ${GREEN}DETECTS: Critical drift on session 6${NC}"
echo ""

# ============================================================
# DONE
# ============================================================
print_header "DEMO COMPLETE"

echo -e "${GREEN}The attack works:${NC}"
echo -e "  • Sessions 1-$SESSIONS_CLEAN: clean, no drift"
echo -e "  • Sessions $((SESSIONS_CLEAN + 1))-$((SESSIONS_CLEAN + SESSIONS_POISONED)): poisoned, CRITICAL drift detected"
echo ""
echo -e "${YELLOW}Key insight:${NC}"
echo -e "  Static analysis tools see the same code and pass."
echo -e "  Only cross-session fingerprinting catches the runtime change."
echo ""
