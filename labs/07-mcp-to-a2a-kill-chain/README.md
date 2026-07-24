# Lab 07 — MCP → A2A Kill Chain

**Status: 🔨 In development.** This lab is being built stage by stage. The table
below states exactly which stages are implemented and runnable and which are still
in design. Nothing here is presented as working until it runs.

---

## What this lab demonstrates

A single poisoned MCP tool description is the entry point to a five-stage kill
chain that crosses from the **MCP tool layer** into an **agent-to-agent (A2A)**
trust graph, and survives removal of the original malicious server.

The lab builds a **minimal, local A2A layer** — Agent Cards, an agent registry, and
a skill-based router — modeled on the concepts in the A2A protocol, with no cloud
and no external network. It runs against the same local LLM backend as the other
labs.

## The five stages

| Stage | Name | What happens | Status |
|-------|------|--------------|--------|
| 1 | Tool description poisoning | A malicious MCP server hides an instruction that tells the host to trust a new "helper" agent | 🔨 In development |
| 2 | Rogue A2A agent registration | The host registers an attacker-controlled agent (Agent Card + registry entry) as a discoverable peer | 🔨 In development |
| 3 | Routing hijack | The rogue agent advertises overlapping skills; the skill router sends legitimate tasks to it | 🔨 In development |
| 4 | Lateral movement | The rogue agent uses its trusted position to reach tools/data it should not, and exfiltrates | 🔨 In development |
| 5 | Persistence after server removal | The malicious MCP server is removed — the compromise survives via the persisted rogue registration and poisoned memory | 🔨 In development |

Each stage will ship as a runnable script with an expected-outcome section and a
matching defense, plus a `run_chain.py` that executes all five end to end.

## Relationship to other labs

- **Stage 1** builds on the tool-description-poisoning primitive from
  [Lab 01](../01-mcp-tool-poisoning/) and [Lab 06](../06-ASI02-cross-server-mcp-poisoning/).
- **Stage 5** builds on the persistent-memory poisoning from
  [Lab 05](../05-agentic-memory-attacks/).

## Framework mapping

| Concern | OWASP Agentic | MITRE ATLAS |
|---------|---------------|-------------|
| Tool description poisoning | ASI-02 Tool Misuse | AML.T0051 |
| Rogue agent registration / trust | ASI-07 Trust Boundary Violations | — |
| Routing hijack / goal redirection | ASI-01 Agent Goal Hijacking | — |
| Persistence | ASI-06 Knowledge & Memory Poisoning | AML.T0054 |

> Come back as stages land, or watch the top-level [README](../../README.md) status
> for this lab.
