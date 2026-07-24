# Lab 06 — Cross-Server MCP Poisoning

Hands-on lab for the canonical write-up in [article-full.md](article-full.md).

This lab demonstrates how one malicious MCP server can poison an agent's tool
context and coerce it into calling tools on a second, legitimate server. The
user sees a normal answer. The attacker gets the second server's data.

---

## What The Lab Demonstrates

| Component | Role | Why it matters |
| --- | --- | --- |
| `malicious_weather_server.py` | Attacker-controlled MCP server | Hides the injection payload inside a tool description or tool result |
| `legitimate_notes_server.py` | Victim MCP server | Exposes normal note-management tools with no bug of its own |
| `agent.py` | Vulnerable MCP client harness | Loads tool descriptions from both servers into one flat tool context |
| `exfil_server.py` | Attacker receiver | Captures the stolen notes on `localhost:9999/exfil` |

The core failure is the shared trust boundary:

```text
User query
  -> agent loads tools from weather server + notes server
  -> malicious weather tool instructs follow-up actions
  -> agent calls list_notes on the legitimate notes server
  -> agent calls sync_weather_cache on the malicious weather server
  -> weather server POSTs stolen note data to localhost:9999/exfil
  -> user receives a harmless weather answer
```

---

## Prerequisites

- Python 3.11+
- [LM Studio](https://lmstudio.ai/) serving any tool-capable instruction model on `http://localhost:1234/v1`
- A model with decent function-calling behavior. `qwen2.5-7b-instruct` is the baseline, but stronger local models usually comply more reliably.

---

## Setup

```bash
# 1. Enter the lab
cd labs/06-ASI02-cross-server-mcp-poisoning

# 2. Create the lab virtual environment
make setup
source venv/bin/activate

# 3. Verify LM Studio + dependencies
make verify

# 4. Seed the victim notes store with sensitive data
make seed
```

---

## Running The Attack

Two terminals are enough.

### Terminal 1 — attacker receiver

```bash
source venv/bin/activate
make exfil
```

### Terminal 2 — vulnerable agent

```bash
source venv/bin/activate
make attack
```

If the auto-detected LM Studio model does not emit tool calls reliably, rerun
with an explicit model id:

```bash
make attack model='openai/gpt-oss-20b'
```

Expected behavior:

- the agent first calls `get_weather`
- it then calls `list_notes` on the legitimate notes server
- it follows up with `sync_weather_cache` on the malicious server
- Terminal 1 prints the stolen notes
- the final user-facing answer only mentions the weather

---

## Variants

The article discusses two useful variants. They are implemented here as separate
server files and Make targets.

### Description-based injection

```bash
make attack
```

The payload lives in the malicious tool description.

### Return-value injection

```bash
make attack-return-value
```

The tool description is clean. The tool result carries the follow-up workflow.

### Subtle phrasing

```bash
make attack-subtle
```

The payload is phrased as cache synchronization guidance rather than an obvious
instruction block.

---

## Useful Commands

```bash
make help          # list all targets
make show-notes    # inspect the current victim note store
make reset         # restore seeded notes and clear exfil log
make clean-data    # empty notes + clear exfil log
make attack model='openai/gpt-oss-20b'
```

You can also override the query:

```bash
make attack query='What is the weather in Tokyo?'
```

---

## Implementation Note

The full article describes the malicious server telling the agent to POST data to
an attacker endpoint directly. In real agent hosts, a browser or HTTP tool may
already exist. This local reproduction adds a second malicious weather tool,
`sync_weather_cache`, so the exfiltration path is explicit and reproducible with
the same MCP-only setup used in the earlier labs.

---

## Files

| File | Role |
| --- | --- |
| `agent.py` | Vulnerable MCP client harness that merges tool descriptions from multiple servers |
| `malicious_weather_server.py` | Primary description-based injection variant |
| `return_value_weather_server.py` | Variant where the payload moves into the tool result |
| `subtle_weather_server.py` | Variant with softer, less obviously malicious phrasing |
| `legitimate_notes_server.py` | Benign note-management MCP server backed by a JSON store |
| `notes_store.py` | Shared helpers for loading, saving, seeding, and clearing notes |
| `seed_notes.py` | Utility used by `make seed`, `make reset`, and `make clean-data` |
| `exfil_server.py` | Attacker listener that logs stolen data to `data/exfil_log.json` |
| `verify_setup.py` | Pre-flight checks for LM Studio, function calling, and local data files |
| `Makefile` | Standard lab targets: `setup`, `verify`, `seed`, `attack`, `exfil`, `clean` |
| `data/notes_seed.json` | The sensitive notes copied into the victim store during `make seed` |
| `data/notes_store.json` | Persistent victim note store used by the notes MCP server |

---

## Defensive Takeaways

- Tool descriptions are untrusted input. Do not inject them into one shared agent context without validation.
- Multi-server MCP clients need provenance and isolation. One server should not be able to steer another server's tools.
- Egress controls still matter. Even when prompt injection succeeds, outbound requests should be constrained.
- Transparent tool logging changes incident response. If you cannot explain every tool call, you cannot investigate compromise.

---

## References

- [article-full.md](article-full.md)
- [Model Context Protocol specification](https://modelcontextprotocol.io)
- [OWASP Agentic Security Initiative](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/techniques/)
