# MCP Attack Labs

Hands-on, locally reproducible security labs for **Model Context Protocol (MCP)
and agentic AI systems**. Each lab stages a real attack technique against a
purpose-built vulnerable target, shows it working end to end, and pairs it with
the defense that stops it.

Everything runs on your own machine against a local model. **No cloud APIs, no
API keys, no data leaves your laptop.**

> These labs map to the [OWASP Top 10 for Agentic Applications / Agentic Security
> Initiative](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
> and [MITRE ATLAS](https://atlas.mitre.org/). Framework mappings are noted inside
> each lab.

---

## ⚠️ Responsible use — read first

This repository contains **intentionally vulnerable code and working attack
tooling**, published for **education, defensive research, and authorized security
testing only**.

- **Run it in isolation.** Use a local VM or a disposable dev machine. Do **not**
  deploy any component to a shared, staging, or internet-facing host.
- **The targets are deliberately insecure.** They exist to be exploited. Never
  reuse this code, or patterns from it, in production.
- **The "attacker" servers stay local.** Exfil receivers bind to `localhost` and
  the payloads/credentials in the labs are **synthetic** — no real secrets, no
  real people, no real systems.
- **Only attack systems you own or are explicitly authorized to test.** You are
  responsible for how you use these techniques. Using them against systems
  without permission is illegal.

By using this repository you agree to use it lawfully and ethically. See
[LICENSE](./LICENSE) and [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Who this is for

Security engineers, red/blue teamers, MCP and agent developers, and researchers
who want to *see* how agentic attacks actually work — not just read about them —
and understand the controls that defeat them.

---

## Labs

| # | Lab | What it demonstrates | Status |
|---|-----|----------------------|--------|
| 01 | [MCP Tool Poisoning](./labs/01-mcp-tool-poisoning/) | Hidden instructions in an MCP tool description → silent file read + exfiltration | ✅ Complete |
| 01b | [Cross-Server Shadowing](./labs/01b-cross-server-shadowing/) | One MCP server's tool description "shadows" another server's tool to hijack it | 🚧 Work in progress |
| 02 | [DockerDash](./labs/02-docker-dash/) | Prompt injection via Docker image labels → container destruction + inventory exfil | ✅ Complete |
| 03 | [Red Team Assessment](./labs/03-red-team-assessment/) | Automated agentic red-teaming with PyRIT + Promptfoo (crescendo exfil, TAP tool abuse) | ✅ Complete |
| 04 | [RAG Security](./labs/04-rag-security/) | Knowledge-base poisoning · indirect prompt injection · cross-tenant data leakage | ✅ Complete |
| 05 | [Agentic Memory Attacks](./labs/05-agentic-memory-attacks/) | Persistent memory poisoning · cross-agent trust abuse · context-window overflow | ✅ Complete |
| 06 | [Cross-Server MCP Poisoning](./labs/06-ASI02-cross-server-mcp-poisoning/) | One malicious MCP server steers the agent into abusing a second, trusted server | ✅ Complete |
| 07 | [MCP → A2A Kill Chain](./labs/07-mcp-to-a2a-kill-chain/) | Five-stage chain: tool poisoning → rogue A2A agent registration → routing hijack → lateral movement → persistence after server removal | 🔨 In development |

**Status legend:** ✅ Complete & runnable · 🚧 Work in progress (partial) · 🔨 In
active development · 🗓 Planned. Status is stated honestly at the top of each
lab's README, and per-stage where a lab is multi-stage. Nothing here is presented
as working unless it runs.

> **On the five-stage kill chain (Lab 07):** this is being built stage by stage.
> Each stage is labeled by status inside the lab — implemented stages are runnable
> and demonstrated; stages still in design say so plainly. Labs 01, 01b and 06
> already demonstrate the tool-description-poisoning primitive the chain starts
> from.

---

## Attack surface coverage

```
User  →  Agent  →  MCP Tools  →  Memory / Context  →  Other Agents (A2A)  →  External Systems

Lab 01  ─────────── MCP tool descriptions (protocol layer)
Lab 01b ─────────── Cross-server tool shadowing
Lab 02  ─────────────────────── Container metadata (supply chain)
Lab 03  ──── Agent pipeline (automated assessment)
Lab 04  ─────────────────────────────────── RAG / vector store
Lab 05  ─────────────────────── Agent memory + multi-agent trust
Lab 06  ─────────── Shared tool context across trusted MCP servers
Lab 07  ─────────── MCP → A2A trust boundary (multi-stage kill chain)
```

---

## Prerequisites

Common to every lab:

- **Python 3.11+**
- A **local OpenAI-compatible LLM endpoint** with tool/function calling. Either:
  - **[Ollama](https://ollama.com/)** (default) — serves on `http://localhost:11434/v1`
  - **[LM Studio](https://lmstudio.ai/)** — serves on `http://localhost:1234/v1`
- **Node.js 18+** (labs that use npm-based MCP servers or Promptfoo)

A capable instruction model with reliable function calling. `qwen2.5-7b-instruct`
is the baseline; some attacks only comply with a stronger model such as
`gpt-oss-20b`. Larger models generally reproduce the attacks more reliably.

### Selecting your backend

Every agent reads its endpoint from environment variables, so you can point a lab
at either backend without editing code:

```bash
# Ollama (default — nothing to set)
# LM Studio:
export LLM_BASE_URL="http://localhost:1234/v1"
export MODEL="qwen2.5-7b-instruct"   # or the model id your backend exposes
```

---

## Quick start (fastest working attack)

Lab 06 has the smoothest end-to-end run — two terminals and a Makefile.

```bash
cd labs/06-ASI02-cross-server-mcp-poisoning
make setup            # create venv + install deps
source venv/bin/activate
make verify           # check your local LLM + function calling
make seed             # plant synthetic "sensitive" notes in the victim server

# Terminal 1 — attacker's receiver
make exfil

# Terminal 2 — vulnerable agent
make attack
```

You'll watch the agent answer a harmless weather question while silently leaking
the victim server's notes to the attacker's listener in Terminal 1.

New to the topic? **Lab 01** is the gentlest introduction to the core primitive
(a poisoned tool description) — start there for the "why," then come back here for
the "how far it goes."

---

## Repository layout

```
labs/
  00-template/     scaffolding for a new lab (copy this to start one)
  01-.../          each lab: README + runnable code + defenses + write-up
  ...
```

Every lab follows the same structure so you always know where to look:

1. **What it demonstrates** — the attack and why it works
2. **Prerequisites** — what you need beyond the common set
3. **Setup / run** — copy-paste steps
4. **Expected outcome** — what success looks like
5. **Defense / mitigation** — the control that stops it

---

## Adding a lab

Copy `labs/00-template/`, fill in the README against the five sections above, add
your code and its defense, and append a row to the table above with an honest
status. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## License

[MIT](./LICENSE) — for educational and authorized-testing use. The responsible-use
expectations above are part of using this project.
