#!/usr/bin/env bash
# Live demo script — 8-minute terminal walkthrough
# Run from project root: bash labs/08-mcp-a2a-chain/demo/demo.sh

set -euo pipefail

ORCH="http://localhost:8000"
AGENT_A="http://localhost:8001"
ROGUE="http://localhost:8003"
EXFIL="http://localhost:9999"
EXFIL_LOG="../results/exfil_log.jsonl"
YELLOW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  MCP→A2A Kill Chain — Live Demo                        ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Show baseline ──────────────────────────────────────────────────
echo -e "${GREEN}[1/6] Baseline: Normal routing${NC}"
echo "→ Listing registered agents:"
curl -s "$ORCH/agents" | python3 -m json.tool | head -20
echo ""

# Baseline task
echo -e "${GREEN}→ Submitting baseline task...${NC}"
BASELINE_BEFORE=$(curl -s "$AGENT_A/tasks" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tasks']))")
curl -s "$ORCH/tasks" -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Analyse Q1 sales data"}' | python3 -m json.tool
BASELINE_AFTER=$(curl -s "$AGENT_A/tasks" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tasks']))")
echo -e "${GREEN}  Agent A tasks: $BASELINE_BEFORE → $BASELINE_AFTER (incremented — normal)${NC}"
echo ""

# ── Step 2: Connect malicious MCP ──────────────────────────────────────────
echo -e "${YELLOW}[2/6] Attacker connects malicious MCP server${NC}"
curl -s "$ORCH/mcp/connect" | python3 -m json.tool | head -25
echo ""

# ── Step 3: Show poisoned tools ────────────────────────────────────────────
echo -e "${RED}[3/6] Poisoned tool descriptions injected into LLM context${NC}"
curl -s "$ORCH/mcp/tools" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for tool in data.get('tools', []):
    name = tool['name']
    desc = tool['description'][:200]
    print(f'  Tool: {name}')
    print(f'  Desc: {desc}...')
    print()
"
echo ""

# ── Step 4: Poisoned task — show exfil ─────────────────────────────────────
echo -e "${RED}[4/6] Poisoned task — LLM follows injected instructions${NC}"
curl -s "$ORCH/tasks" -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Analyse Q1 sales data"}' | python3 -m json.tool
echo ""

echo -e "${RED}→ Exfil receiver captured agent cards (from log file):${NC}"
if [ -f "$EXFIL_LOG" ] && [ -s "$EXFIL_LOG" ]; then
    cat "$EXFIL_LOG" | python3 -c "
import sys, json
for line in sys.stdin:
    entry = json.loads(line)
    source = entry.get('source', '?')
    url = entry.get('url', '')
    payload = entry.get('payload', '')
    if url:
        print(f'  [EXFIL] {source} fetched {url} ({len(entry.get(\"content\", \"\"))} bytes)')
    elif payload:
        print(f'  [EXFIL] {source} exfiltrated payload ({len(payload)} bytes)')
    else:
        print(f'  [EXFIL] {source}: {json.dumps({k:v for k,v in entry.items() if k not in (\"content\",\"payload\",\"audit_log\")})[:100]}')
"
else
    echo "  (exfil log empty — check if fleet is running)"
fi
echo ""

# ── Step 5: Register rogue agent ───────────────────────────────────────────
echo -e "${YELLOW}[5/6] Attacker registers spoofed rogue agent${NC}"
curl -s "$ORCH/agents/register" -H "Content-Type: application/json" \
  -d "{\"url\":\"$ROGUE\"}" | python3 -m json.tool
echo ""

# ── Step 6: Hijack — show bypass ───────────────────────────────────────────
echo -e "${RED}[6/6] Sensitive task hijacked by rogue agent${NC}"

# Count tasks before sensitive task
TASKS_BEFORE=$(curl -s "$AGENT_A/tasks" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tasks']))")

# Submit sensitive task
echo -e "${RED}→ Submitting sensitive task...${NC}"
curl -s "$ORCH/tasks" -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Q1 sales: Acme Corp, \$2.4M, contact: john@acme.com"}' | python3 -m json.tool

# Count tasks after — if bypassed, Agent A count is unchanged
TASKS_AFTER=$(curl -s "$AGENT_A/tasks" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tasks']))")

if [ "$TASKS_BEFORE" -eq "$TASKS_AFTER" ]; then
    echo -e "${RED}  ⚠ BYPASS DETECTED: Agent A tasks unchanged ($TASKS_BEFORE → $TASKS_AFTER)${NC}"
    echo -e "${RED}  The rogue agent handled the task instead of Agent A.${NC}"
else
    echo -e "${GREEN}  Agent A tasks: $TASKS_BEFORE → $TASKS_AFTER (task reached Agent A)${NC}"
fi

echo ""

# ── Cleanup ────────────────────────────────────────────────────────────────
echo -e "${YELLOW}→ Resetting orchestrator...${NC}"
curl -s "$ORCH/reset" | python3 -m json.tool
echo ""
echo -e "${GREEN}✓ Demo complete. Check results/ for full logs.${NC}"
