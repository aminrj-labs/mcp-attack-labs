#!/usr/bin/env bash
# Stop all fleet processes
set -euo pipefail

pkill -f "agent_a_server.py" 2>/dev/null || true
pkill -f "agent_b_server.py" 2>/dev/null || true
pkill -f "orchestrator_server.py" 2>/dev/null || true
pkill -f "exfil_receiver.py" 2>/dev/null || true
pkill -f "rogue_agent_server.py" 2>/dev/null || true
echo "All processes stopped."
