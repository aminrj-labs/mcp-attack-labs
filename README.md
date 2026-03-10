# MCP Attack Labs

A growing collection of hands-on security labs exploring AI attack techniques — from MCP
tool poisoning to RAG injection to agentic memory exploitation. Fully reproducible locally,
no cloud APIs required.

---

## Labs

| # | Lab | Attack Surface | Core Technique | Difficulty |
|---|-----|---------------|----------------|------------|
| 01 | [MCP Tool Poisoning](./labs/01-mcp-tool-poisoning/) | MCP protocol layer | Hidden instructions in tool descriptions → silent file exfiltration | Beginner |
| 02 | [DockerDash](./labs/02-docker-dash/) | Container supply chain | Prompt injection via Docker image labels → container destruction + inventory exfil | Intermediate |
| 03 | [Red Team Assessment](./labs/03-red-team-assessment/) | Agentic AI pipeline | Automated red-teaming with PyRIT + Promptfoo → crescendo exfil + TAP tool abuse | Intermediate |
| 04 | [RAG Security](./labs/04-rag-security/) | Knowledge / retrieval layer | Knowledge poisoning · indirect prompt injection · cross-tenant data leakage | Intermediate |
| 05 | [Agentic Memory Attacks](./labs/05-agentic-memory-attacks/) | Agent memory & trust boundaries | Persistent memory poisoning · cross-agent trust exploitation · context overflow | Advanced |

Each lab is self-contained: its own `README.md`, attack code, defense code, blog post, and Jupyter playbook.

---

## Attack Surface Coverage

```
┌──────────────────────────────────────────────────────────────────────┐
│  User  →  Agent  →  Tools  →  Memory / Context  →  External Systems  │
│                                                                       │
│  Lab 01: ──────── MCP tools (protocol layer)                         │
│  Lab 02: ──────────────────── Container meta-data (supply chain)     │
│  Lab 03: ──── Agent pipeline  (automated assessment)                 │
│  Lab 04: ─────────────────────────────── RAG / vector DB             │
│  Lab 05: ─────────────────────── Agent memory + multi-agent trust    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Common Prerequisites

Every lab requires:
- Python 3.11+
- [LM Studio](https://lmstudio.ai/) with a loaded model (local inference)
- Node.js 18+ (for MCP servers and Promptfoo)

Lab-specific requirements (Docker, additional models, ports) are listed in each lab's README.

---

## Quick Start by Blog Post

| Blog post | Lab |
|-----------|-----|
| MCP Tool Poisoning | [Lab 01 →](./labs/01-mcp-tool-poisoning/) |
| DockerDash: Supply Chain Prompt Injection | [Lab 02 →](./labs/02-docker-dash/) |
| Red Teaming Agentic AI | [Lab 03 →](./labs/03-red-team-assessment/) |
| RAG Security Architecture: The Attack Surface Hiding in Your Knowledge Base | [Lab 04 →](./labs/04-rag-security/) |

---

## Adding a Lab

Copy `labs/00-template/` as a starting point. Fill in the README, add your code,
and append a row to the table above.
