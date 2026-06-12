#!/usr/bin/env bash
# Start all fleet services (agents A, B, orchestrator, exfil receiver)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Add project root to Python path so all modules can find config.py
export PYTHONPATH="${PYTHONPATH:-}:$PROJECT_DIR"

echo "Starting fleet..."

# Start Agent A
(cd "$SCRIPT_DIR/agent_a" && python3 agent_a_server.py) &
echo "  Agent A (8001) started"

# Start Agent B
(cd "$SCRIPT_DIR/agent_b" && python3 agent_b_server.py) &
echo "  Agent B (8002) started"

# Start Orchestrator
(cd "$SCRIPT_DIR/orchestrator" && python3 orchestrator_server.py) &
echo "  Orchestrator (8000) started"

# Start Exfil Receiver
(cd "$PROJECT_DIR/attack" && python3 exfil_receiver.py) &
echo "  Exfil Receiver (9999) started"

# Wait for services to be ready
sleep 2

echo "Fleet ready. Health check: curl http://localhost:8000/health"
