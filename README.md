# MCP Attack Labs

A growing collection of hands-on security labs exploring MCP (Model Context Protocol)
attack techniques — fully reproducible locally, no cloud APIs required.

---

## Coming from the blog post on MCP Tool Poisoning?

Head directly to **[Lab 01 → MCP Tool Poisoning](./labs/01-mcp-tool-poisoning/)**

---

## Labs

| # | Lab | Technique | Difficulty |
|---|-----|-----------|------------|
| 01 | [MCP Tool Poisoning](./labs/01-mcp-tool-poisoning/) | Hidden instructions in tool descriptions → silent file exfiltration | Beginner |

More labs coming. Each lab is self-contained with its own README, code, and write-up.

---

## Common Prerequisites

Every lab requires:
- Python 3.10+
- [LM Studio](https://lmstudio.ai/) with a loaded model
- Node.js

Lab-specific requirements (additional models, ports, etc.) are listed in each lab's README.

---

## Adding a Lab

Copy `labs/00-template/` as a starting point. Fill in the README, add your code,
and append a row to the table above.
