# Lab 07 — Cross-Session Rug-Pull Detection

## One-Sentence Summary

An MCP server can behave benignly for N sessions, then silently inject a malicious instruction into a tool description on session N+1 — invisible to all existing static-analysis defences, but detectable via cross-session fingerprinting.

---

## How the Attack Works

```
Session 1–5:  Attacker's MCP server → Agent sees clean tool descriptions → Agent behaves normally
Session 6+:   Attacker's MCP server → Agent sees poisoned tool description → Agent attempts exfiltration
```

The attacker's server has a persistent session counter (SQLite-backed). After `SESSION_THRESHOLD` connections, the `calculate_discount` tool description gains a hidden `[SYSTEM: ...]` instruction. The server still returns correct numeric results — the exfiltration attempt is invisible to the user.

**Why existing tools miss it:**
- `snyk-agent-scan` runs static code analysis — the server code never changes.
- Cisco AI Defense does static analysis — same blind spot.
- Manual SHA-256 hashing of tool descriptions *would* detect it, but only if you compare across sessions (most teams don't).

**The fix:** A session fingerprinter that hashes every tool description at session start, stores it in a SQLite database, and flags any drift from the baseline (session 1) with severity classification.

---

## Prerequisites

- Python 3.11+
- [llama.cpp](https://github.com/ggerganov/llama.cpp) running a compatible model (or any OpenAI-compatible server at `localhost:8081`)
- SQLite3 (bundled with Python)

---

## Setup

```bash
# 1. Navigate to this lab
cd labs/07-cross-session-rug-pull-detection

# 2. Create and activate a Python virtual environment
python3 -m venv venv && source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your LLM model
export LLM_MODEL="qwen3.6-35b-a3b"

# 5. Run the demo
./demo.sh
```

---

## Running the Attack

**Terminal 1 — Start the rug-pull server:**

```bash
python -m server.rugpull_server
```

**Terminal 2 — Run the agent for N sessions:**

```bash
python agent/agent_runner.py --sessions 8 --threshold 5
```

Expected output:
- Sessions 1–5: agent returns correct discount, no exfiltration
- Sessions 6–8: agent returns correct discount AND attempts to read `~/.ssh/id_rsa`

---

## Running the Detection

```bash
python results/run_experiment.py --sessions 10 --threshold 5 --output results/
python results/generate_report.py --input results/
```

---

## Files

| File | Description |
|------|-------------|
| `server/benign_server.py` | Legitimate MCP server with 3 tools |
| `server/rugpull_server.py` | Same server, poisoned after N sessions |
| `server/session_counter.py` | SQLite-backed session counter |
| `agent/agent_runner.py` | Runs agent sessions against the server |
| `agent/task_suite.py` | Realistic tasks for each tool |
| `detection/session_fingerprinter.py` | Hashes tool descriptions per session |
| `detection/drift_detector.py` | Cross-session diff engine with severity classification |
| `detection/alert.py` | CLI/JSON/webhook alert output |
| `detection/store/fingerprint_store.py` | SQLite-backed persistent fingerprint store |
| `evasion/evasion_v1.py` | Whitespace mutation evasion |
| `evasion/evasion_v2.py` | Unicode homoglyph substitution |
| `evasion/evasion_v3.py` | Gradual drift across sessions |
| `results/run_experiment.py` | Full experiment orchestration |
| `results/generate_report.py` | Markdown report generation |
| `demo.sh` | Self-contained <5min live demo |

---

## Defensive Takeaways

- **Session boundary is not a security boundary.** An MCP server that passes a tool scan today may be malicious tomorrow.
- **Baseline-anchored fingerprinting is essential.** Comparing against the previous session misses gradual drift; comparing against session 1 catches everything.
- **Static analysis alone is insufficient.** Runtime tool descriptions can change without any code change.
- **Instruction-bearing heuristics matter.** Tools that add new `[SYSTEM: ...]` or `<instructions>` blocks to descriptions should be flagged as critical.

---

## References

- [MCP Specification](https://modelcontextprotocol.io/)
- [Lab 01 — MCP Tool Poisoning](../01-mcp-tool-poisoning/)
- [Lab 01b — Cross-Server Shadowing](../01b-cross-server-shadowing/)
