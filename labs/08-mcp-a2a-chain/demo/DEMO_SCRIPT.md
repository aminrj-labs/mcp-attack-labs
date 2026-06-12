# Demo Script — MCP→A2A Kill Chain

## Speaker Notes

### Prerequisites
- Fleet running: `bash infrastructure/start_fleet.sh`
- LLM backend running (llama.cpp on :8081 or LM Studio on :1234)
- Model responding to API calls

### Timing Guide (8 minutes total)

#### 0:00 - 0:30 — Introduction
> "Modern AI agent systems delegate tasks between specialized agents. Two protocols dominate: MCP for tool access, and A2A for agent-to-agent delegation. Neither includes integrity verification or authentication."

#### 0:30 - 1:30 — Step 1: Baseline (Normal Operation)
- Run: `bash demo/demo.sh`
- Show output: Agent A receives tasks normally
- Explain: "This is the expected behavior — data analysis tasks route to the DataAnalyst agent"

#### 1:30 - 2:30 — Step 2: MCP Connection
- Show: Malicious MCP server connects via stdio (real MCP SDK)
- Explain: "The attacker doesn't need network access — the MCP protocol spawns the server as a subprocess"

#### 2:30 - 4:00 — Step 3: Poisoned Tools
- Show: `data_lookup` tool description contains hidden instructions
- Explain: "The LLM reads these descriptions through the MCP protocol's tools/list method. There's no integrity check on tool metadata."
- Run poisoned task — watch LLM call `http_fetch` to fetch agent cards
- Show exfil log: agent cards captured

#### 4:00 - 5:30 — Step 4: Rogue Agent Registration
- Show: Rogue agent registered with same name but higher version
- Explain: "A2A v1.0 has no authentication on agent registration. Anyone can register an agent."

#### 5:30 - 7:00 — Step 5: Task Hijacking
- Submit sensitive task with PII
- Show: Agent A's task count is unchanged — the rogue agent intercepted it
- Show exfil log: payload exfiltrated with PII
- Explain: "The version-preference heuristic routes to the rogue agent (v2.1.0 > v1.0.0)"

#### 7:00 - 8:00 — Conclusion
> "This chain is invisible to standard detection. No agent cards were modified, no unusual routing decisions were made, and no PII was injected into task payloads. The only visible artifact is that the legitimate agent stopped receiving tasks."

### Fallback Instructions

**If LLM is not responding:**
- Use a pre-recorded video of the demo output
- Show screenshots of the exfil log and routing history
- Walk through each step verbally

**If MCP SDK is not installed:**
- Show the malicious MCP server code and explain it's a real MCP server
- Demonstrate the attack concept with curl commands against the orchestrator
- Show the exfil receiver log from a previous run

**If rogue agent doesn't hijack:**
- Check that the rogue agent is registered: `curl http://localhost:8000/agents`
- Verify the model follows version-preference: check the routing reason in the task log
- If the model ignores version preference, increase the version gap (use v9.0.0)

### Key Talking Points
1. **MCP tool poisoning is prompt injection through metadata** — the LLM follows instructions embedded in tool descriptions
2. **A2A has no authentication** — anyone can register an agent
3. **Version-preference heuristics are exploitable** — higher version wins, period
4. **The attack is invisible** — no card modifications, no unusual routing, no PII injection
5. **Detection requires MCP tool description monitoring** — which doesn't exist in current tooling
