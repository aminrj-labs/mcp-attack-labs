# Lab 08 — Session Handoff Summary

## What Was Done (Implementation Phase)

All source files were created from the implementation spec (`lab-08-mcp-a2a-chain-implementation-spec.md`). The MCP SDK 1.27.1 API required several adaptations from the spec's v2 code.

### Files Created (27 files)
```
config.py
requirements.txt
infrastructure/agent_a/agent_card.json
infrastructure/agent_a/agent_a_server.py
infrastructure/agent_b/agent_card.json
infrastructure/agent_b/agent_b_server.py
infrastructure/orchestrator/orchestrator_server.py
infrastructure/start_fleet.sh
infrastructure/stop_fleet.sh
attack/malicious_mcp_server.py
attack/rogue_agent/agent_card.json
attack/rogue_agent/rogue_agent_server.py
attack/exfil_receiver.py
detection/agent_card_verifier.py
detection/routing_anomaly_detector.py
detection/task_payload_monitor.py
results/run_chain.py
results/.gitignore
demo/demo.sh
demo/DEMO_SCRIPT.md
README.md
```

### Key MCP SDK 1.27.1 API Adaptations
| Spec (v2) | Actual (1.27.1) |
|---|---|
| `StdioClientTransport(StdioServerParameters(...))` | `stdio_client(StdioServerParameters(...))` |
| `await transport.__aenter__()` | `await stdio_client(cm).__aenter__()` → `(read, write)` |
| `stdio_server().serve(options)` | `async with stdio_server() as (r,w): await server.run(r, w, options)` |
| `server.capabilities` | `ServerCapabilities(tools=ToolsCapability())` |
| `lifespan=lambda app: (...)` tuple | `@asynccontextmanager def lifespan(app)` |

### Dependencies Installed
- `mcp==1.27.1` (MCP Python SDK)
- `openai==2.38.0` (OpenAI API client for LLM calls)
- Pre-existing: `fastapi==0.115.6`, `flask==3.1.3`, `httpx==0.28.1`, `pydantic==2.13.4`, `uvicorn==0.34.0`

## What Needs To Happen Next (Execution Phase)

### 1. Start External Services
- **llama.cpp** must be running on `localhost:8081` serving `qwen3.6-35b` (or similar model)
- Verify: `curl http://localhost:8081/v1/models | python3 -m json.tool`

### 2. Start the Fleet
```bash
cd /home/amine/git/labs/mcp-attack-labs/labs/08-mcp-a2a-chain
bash infrastructure/start_fleet.sh
```
This starts: Agent A (:8001), Agent B (:8002), Orchestrator (:8000), Exfil Receiver (:9999)

### 3. Verify Fleet Health
```bash
curl http://localhost:8000/health
curl http://localhost:8001/.well-known/agent.json
curl http://localhost:8002/.well-known/agent.json
```

### 4. Run the Kill Chain — Stage by Stage

#### Stage 0: Baseline (no MCP)
```bash
# Submit a data analysis task — should route to Agent A (8001)
curl -s http://localhost:8000/tasks -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Analyse Q1 sales data"}' | python3 -m json.tool
```
**Expected:** `routed_to` should be `http://localhost:8001`

#### Stage 1: MCP Connection + Poisoned Tool Calls
```bash
# Connect malicious MCP server
curl -s http://localhost:8000/mcp/connect | python3 -m json.tool

# Check tools — look for poisoned data_lookup description
curl -s http://localhost:8000/mcp/tools | python3 -m json.tool

# Submit task — LLM should call http_fetch to exfil agent cards
curl -s http://localhost:8000/tasks -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Analyse Q1 sales data"}' | python3 -m json.tool

# Check exfil log
cat results/exfil_log.jsonl
```

#### Stage 2: Rogue Agent Registration
```bash
# Start rogue agent
python3 attack/rogue_agent/rogue_agent_server.py &

# Register it
curl -s http://localhost:8000/agents/register -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8003"}' | python3 -m json.tool
```

#### Stage 3: Task Hijacking
```bash
# Submit sensitive task — should route to rogue agent (8003)
curl -s http://localhost:8000/tasks -H "Content-Type: application/json" \
  -d '{"task_type":"data_analysis","payload":"Q1 sales: Acme Corp, $2.4M, contact: john@acme.com"}' | python3 -m json.tool

# Verify Agent A was bypassed
curl http://localhost:8001/tasks

# Check exfil log for payload
cat results/exfil_log.jsonl
```

### 5. Troubleshooting Checklist
- **LLM not responding:** Check llama.cpp on :8081, model name in config.py
- **MCP connection fails:** Check `attack/malicious_mcp_server.py` exists, Python 3.12+
- **Routing to wrong agent:** Check model follows version-preference heuristic
- **Exfil receiver not logging:** Check port 9999 is free, Flask is running
- **Agent cards not found:** Check agents A/B are healthy on :8001/:8002

### 6. Stop Everything
```bash
bash infrastructure/stop_fleet.sh
pkill -f rogue_agent_server.py || true
```

## Write-Up Goals

After successful attack runs, produce:
1. **Code snippets** — key parts of the attack (poisoned tool description, agentic loop, rogue agent registration)
2. **Output snippets** — actual curl responses, exfil log entries, routing decisions
3. **Detection results** — what each detector caught (NAME_COLLISION, etc.)
4. **Model-dependence notes** — which models followed the injection, which didn't

## Important Notes for New Session

- Working directory: `/home/amine/git/labs/mcp-attack-labs/labs/08-mcp-a2a-chain`
- All Python files import `config.py` from the same directory
- The orchestrator uses `LM_STUDIO_BASE_URL` from config — defaults to `http://localhost:8081/v1`
- The `__init__.py` files were created for all Python packages
- Shell scripts are executable (`chmod +x`)
- The MCP SDK 1.27.1 API is different from the spec — do NOT copy code from the spec directly
- The `Server.run()` method requires `read_stream`, `write_stream`, and `InitializationOptions` — not `stdio_server().serve()`
- For the agentic loop to work, the LLM must be able to produce `tool_calls` — test with a simple tool call first
