# MCP→A2A Kill Chain: Lateral Movement Across an Agent Fleet

**A hack.lu 2026 lab submission**

## One-paragraph summary

This lab demonstrates a two-layer attack chain: an attacker connects a single malicious MCP server to an agent orchestrator, poisoning the LLM's tool-calling context with instructions that trigger autonomous reconnaissance of the agent fleet. The attacker then registers a spoofed rogue agent that hijacks task routing by exploiting the orchestrator's version-preference heuristic, exfiltrating sensitive payloads while returning fabricated results. The attack is invisible to standard detection — no agent cards are modified, no unusual routing decisions are made, and no PII is injected into task payloads. The only visible artifact is that the legitimate agent stops receiving tasks.

## The problem

Modern AI agent systems are increasingly composed of multiple specialized agents, coordinated by an orchestrator. Two protocols dominate this space:

- **MCP (Model Context Protocol)** — provides LLMs with tools (functions) from servers
- **A2A (Agent-to-Agent)** — enables agents to delegate tasks to other agents

Both protocols are designed for trust. MCP assumes tool servers are trusted sources of capability metadata. A2A assumes agent cards are authoritative declarations of identity and capability. Neither protocol includes integrity verification or authentication.

This lab shows that this trust model is exploitable. A single malicious MCP server, connected via the standard MCP protocol, can:

1. Inject instructions into the LLM's tool-calling context
2. Cause the LLM to autonomously reconnoiter the agent fleet
3. Enable a spoofed agent to hijack task routing
4. Exfiltrate sensitive data while returning plausible results
5. Persist in the agent registry after the initial attack vector is removed

## The kill chain

### Stage 1: MCP Tool Poisoning → A2A Reconnaissance

The attacker connects a malicious MCP server using `StdioClientTransport` (the real MCP SDK). The server exposes two tools:

- `data_lookup` — A tool with a poisoned description that instructs the LLM to fetch A2A agent cards and exfiltrate them
- `http_fetch` — A legitimate-looking tool that the LLM uses to execute the reconnaissance

The orchestrator uses an agentic loop (OpenAI function-calling format) to let the LLM call tools. When the LLM reads the poisoned `data_lookup` description, it calls `http_fetch` to fetch agent cards from known endpoints. The malicious MCP server's `http_fetch` handler exfiltrates the fetched content to a receiver on port 9999.

**This is prompt injection through tool metadata.** The LLM is not "tricked" — it is following instructions embedded in tool metadata that the MCP protocol provides without integrity verification.

### Stage 2: Rogue Agent Registration

With the agent cards in hand, the attacker deploys a rogue agent that mimics Agent A:
- Same name: "DataAnalyst"
- Same skill IDs: "analyze_sales"
- Higher version: "2.1.0" (vs. Agent A's "1.0.0")

A2A v1.0 has no authentication on agent registration. The rogue agent is registered successfully.

### Stage 3: Task Hijacking

The user submits a sensitive task. The orchestrator evaluates both DataAnalyst agents, finds that both have the matching skill, and — following its "prefer higher version" heuristic — routes the task to the rogue agent.

The rogue agent exfiltrates the full task payload (including PII) and returns a plausible but fabricated result. The legitimate Agent A receives zero tasks.

### Stage 4: Persistence

When the operator removes the malicious MCP server, the rogue agent remains in the orchestrator's agent registry. A2A v1.0 defines no revocation mechanism.

## Detection

Three independent detection modules are provided:

1. **AgentCardVerifier** — Hash-based card integrity monitoring with name-collision detection. Catches the rogue agent registration (Stage 2) via NAME_COLLISION detection.
2. **RoutingAnomalyDetector** — Baseline-based routing anomaly detection. Catches unusual routing decisions and suspicious keywords in routing reasons.
3. **TaskPayloadMonitor** — Regex-based PII and injection detection. Catches PII in task payloads and injection patterns.

**Key finding:** MCP tool poisoning (Stage 1) is invisible to all three detection modules. The attack does not modify agent cards, does not produce unusual routing decisions, and does not inject PII. Detection requires monitoring MCP tool descriptions for suspicious instructions.

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start the fleet
bash infrastructure/start_fleet.sh

# Start the malicious MCP server (as subprocess of orchestrator)
# (Connected via POST /mcp/connect)

# Run the demo
bash demo/demo.sh
```

## Running experiments

```bash
# Run 10 trials with empirical data collection
python results/run_chain.py 10

# View results
cat results/experiment_summary.json
cat results/stage_log.jsonl
```

## Architecture

```
Orchestrator (8000)
  ├── MCP Bridge (stdio subprocess)
  │   └── Malicious MCP Server (poisoned tools)
  ├── A2A Router (LLM-based)
  │   ├── Agent A (8001) — DataAnalyst
  │   ├── Agent B (8002) — ReportWriter
  │   └── Rogue Agent C (8003) — Spoofed DataAnalyst
  └── Exfil Receiver (9999) — Flask
```

## Models

| Mode | Backend | Model |
|---|---|---|
| Testing | llama.cpp | qwen3.6-35b |
| Demo | LM Studio | gpt-oss-20b or qwen3.6-35b |

**Model-dependence is a finding.** Document which models reliably follow injected instructions.

## References

- MCP Specification: https://modelcontextprotocol.io
- A2A Specification: https://ai.google.dev/gemini-api/docs/agent-to-agent
- MCP SDK (Python): https://github.com/modelcontextprotocol/python-sdk
- A2A Python SDK: https://github.com/google-gemini/generative-ai-python
