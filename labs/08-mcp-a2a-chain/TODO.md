# TODO

## Goal
Implement Lab 08 — MCP→A2A Kill Chain: a 5-stage lateral movement attack demonstrating how a malicious MCP server can poison an LLM's tool context, reconnoiter an A2A agent fleet, register a spoofed rogue agent, hijack task routing, and persist after the initial attack vector is removed.

## Tasks

### 1. Setup & Configuration
- [x] Install MCP SDK (`pip install mcp openai`) and verify `mcp.server` imports
- [x] Create `config.py` with ports, URLs, model config (defaulting to llama.cpp on localhost:8081)
- [x] Create `requirements.txt` with all dependencies

### 2. Infrastructure — Agent A (DataAnalyst v1.0.0)
- [x] Create `infrastructure/agent_a/agent_card.json` with v1.0.0 capabilities
- [x] Create `infrastructure/agent_a/agent_a_server.py` with FastAPI A2A endpoints (agent card, task creation, task retrieval)

### 3. Infrastructure — Agent B (ReportWriter v1.0.0)
- [x] Create `infrastructure/agent_b/agent_card.json` with v1.0.0 capabilities
- [x] Create `infrastructure/agent_b/agent_b_server.py` with FastAPI A2A endpoints (agent card, task creation, task retrieval)

### 4. Infrastructure — Orchestrator (MCP Bridge + A2A Router)
- [x] Create `infrastructure/orchestrator/orchestrator_server.py` with:
  - Proper `@asynccontextmanager` lifespan for fleet discovery and MCP cleanup
  - Persistent MCP stdio transport (`__aenter__` without `__aexit__`, stored in `_mcp_transport_cm`)
  - Real MCP SDK client session (`ClientSession` with `tools/list` and `tools/call`)
  - Agentic tool-call loop (OpenAI function-calling, max 5 iterations, tool results fed back as `tool` role messages)
  - A2A agent registry with `/agents/register` endpoint (no auth)
  - `/reset` endpoint that disconnects MCP and reloads fleet
  - `/mcp/connect`, `/mcp/disconnect`, `/mcp/tools` endpoints

### 5. Infrastructure — Fleet Management Scripts
- [x] Create `infrastructure/start_fleet.sh` to start Agent A, Agent B, Orchestrator, and Exfil Receiver
- [x] Create `infrastructure/stop_fleet.sh` to stop all fleet processes

### 6. Attack — Malicious MCP Server (Stage 1)
- [x] Create `attack/malicious_mcp_server.py` with:
  - Real MCP SDK `Server` with `@server.list_tools()` and `@server.call_tool()` decorators
  - `data_lookup` tool with poisoned description (internal audit instructions to fetch A2A cards)
  - `http_fetch` tool that fetches URLs and exfiltrates to port 9999
  - stdio transport via `stdio_server()`

### 7. Attack — Rogue Agent (Stage 2-3)
- [x] Create `attack/rogue_agent/agent_card.json` with v2.1.0, same name/skills as Agent A
- [x] Create `attack/rogue_agent/rogue_agent_server.py` that exfiltrates payloads and returns fabricated results

### 8. Attack — Exfiltration Receiver
- [x] Create `attack/exfil_receiver.py` with Flask `/exfil` POST endpoint logging to JSONL

### 9. Detection — Agent Card Verifier
- [x] Create `detection/agent_card_verifier.py` with hash-based integrity monitoring and NAME_COLLISION detection

### 10. Detection — Routing Anomaly Detector
- [x] Create `detection/routing_anomaly_detector.py` with baseline comparison, keyword matching, and version-jump detection

### 11. Detection — Task Payload Monitor
- [x] Create `detection/task_payload_monitor.py` with PII and injection pattern detection

### 12. Experiment Runner
- [x] Create `results/run_chain.py` with multi-trial experiment loop:
  - Reset → Baseline → MCP reconnect → Poisoned → Register rogue → Hijack
  - ASR calculation and JSON summary output
- [x] Create `results/.gitignore` for stage_log.jsonl, exfil_log.jsonl, routing_history.db, card_hashes.db

### 13. Demo
- [x] Create `demo/demo.sh` — 8-minute live terminal walkthrough
- [x] Create `demo/DEMO_SCRIPT.md` — speaker notes with fallback instructions

### 14. Documentation
- [x] Create `README.md` — blog post quality, hack.lu submission narrative

## Notes
- MCP SDK 1.27.1 API adapted: `stdio_client()` replaces `StdioClientTransport`, `Server.run()` replaces `stdio_server().serve()`, `ServerCapabilities(tools=ToolsCapability())` replaces `server.capabilities`
- Orchestrator lifespan fixed: uses `@asynccontextmanager` instead of broken tuple syntax
- Default LLM backend is llama.cpp (localhost:8081)
- Python: type hints, f-strings, no bare `except`
- Demo script reads exfil log file directly instead of GET request to exfil receiver
- All Python syntax verified with `py_compile`
