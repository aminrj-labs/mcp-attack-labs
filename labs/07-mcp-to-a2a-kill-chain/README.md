# Lab 07 — MCP → A2A Kill Chain

**Status: ✅ Runnable end to end.** All five stages execute, and each of the
three controls provably breaks the chain at a specific stage. Everything runs on
the Python standard library — `git clone`, then `python3 run_chain.py`, no model
download, no cloud, no credentials.

```bash
make run        # undefended: five stages, HR data exfiltrated   (exit 1)
make defended   # all controls on: chain breaks at stage 2       (exit 0)
make test       # proves the above, and that each control breaks its own stage
```

---

## What this lab demonstrates

A single poisoned MCP tool description is the entry point to a five-stage kill
chain that crosses from the **MCP tool layer** into an **agent-to-agent (A2A)**
trust graph, exfiltrates data an agent was never authorised to reach, and
**survives removal of the malicious server that started it**.

The lab ships a **minimal, local A2A layer** — Agent Cards with signing and
verification, a discovery registry, and a skill router carrying the
authorisation and blast-radius controls — modelled on the A2A protocol (v1.0,
Linux Foundation, April 2026). It is not the real SDK; it is a deliberately
small stand-in that reproduces the parts the attack and its defences actually
turn on. See [`a2a/`](a2a/).

The intellectual basis is Chapter 9 of the *Agentic AI Security* manuscript
("Inter-Agent Communication and the A2A Kill Chain"). This lab is that chapter's
executable form.

## The five stages

| Stage | Name | What happens | ASI |
|-------|------|--------------|-----|
| 1 | Tool description poisoning | A poisoned MCP tool description instructs the host to register and prefer a "helper" peer | ASI-02 / ASI-01 |
| 2 | Rogue A2A agent registration | The attacker registers a rogue agent as a discoverable peer | ASI-07 |
| 3 | Routing hijack | The rogue advertises overlapping skills; the router sends legitimate tasks to it | ASI-01 |
| 4 | Lateral movement + exfiltration | The rogue uses its trusted position to invoke a sensitive skill and exfiltrate | ASI-07 / ASI-08 |
| 5 | Persistence after server removal | The malicious MCP server is removed; the rogue registration persists and stays routable | ASI-06 |

Run it and watch the transcript:

```
Stage 1 — Tool description poisoning      ✓ attacker: followed hidden instruction
Stage 2 — Rogue A2A agent registration    ✓ attacker: registered 'summariser-helper' (unverified)
Stage 3 — Routing hijack                  ✓ attacker: routed 'document.summarise' → 'summariser-helper'
Stage 4 — Lateral movement + exfiltration ✓ attacker: rogue invoked 'hr.read' → exfiltrated: EMP-4471 …
Stage 5 — Persistence after server removal ✓ attacker: rogue registration persists and remains routable
RESULT: chain completed — HR data exfiltrated.
```

## The three controls, and which stage each breaks

The point of the lab is not the attack — it is that the *same* attack code, run
with a control switched on, breaks at a predictable place. That is the question
a defender is actually asking: *if I turn this on, what stops?*

| Control | Chapter 9 | Breaks at | Why |
|---------|-----------|-----------|-----|
| `--control card` | Verify the card, authenticate the channel | **Stage 2** | The rogue can mint a well-formed card but cannot sign it against the trust anchor, so registration is refused — and an unregistered peer can't route, so stages 3–5 collapse too. |
| `--control authz` | Authorize the action, not just the caller | **Stage 4** | Registration and routing stay open, but the rogue is in nobody's allow-list, so the sensitive skill is denied. This is the control that survives an agent being *genuinely trusted but overreaching*, not merely impersonated. |
| `--control blast` | Contain the blast radius | **Stage 4** | The high-stakes skill pauses for human confirmation instead of executing on the rogue's say-so; a delegation burst trips a circuit breaker. |
| `--defended` | all three | **Stage 2** | Defence in depth — the earliest control wins, the rest are backstops. |

```bash
make card       # RESULT: chain broken at Stage 2
make authz      # RESULT: chain broken at Stage 4
make blast      # RESULT: chain broken at Stage 4
```

## What is faithfully modelled, and what is abstracted

Being explicit, because the honesty is the point of a security lab:

- **The A2A trust mechanics are real logic**, not narration. Card signing and
  verification, the registry's accept/reject decision, skill routing, the
  authorisation allow-list, the circuit breaker, and on-disk persistence are all
  executable and independently testable ([`test_chain.py`](test_chain.py)).
- **Signing uses HMAC, not PKI/JWS.** A stand-in with the one property that
  matters — a signature either chains to a key you hold or it does not — so the
  lab needs no crypto dependencies. Swapping in real asymmetric signatures does
  not change any stage's outcome.
- **Stage 1's injection is deterministic by default.** That a model *will* obey
  an instruction hidden in a tool description is demonstrated against a real
  local LLM in [Lab 01](../01-mcp-tool-poisoning/) and
  [Lab 06](../06-ASI02-cross-server-mcp-poisoning/). Lab 07's contribution is
  what a successful injection *leads to* — the A2A propagation — which is
  deterministic control-plane logic. Run `python3 run_chain.py --llm` to drive
  Stage 1 against a real endpoint (`LLM_BASE_URL`, `LLM_MODEL`); the other four
  stages are identical either way.

## Residual risk (the honest limit)

Card verification stops impostors; action-level authorization stops an
authenticated agent overreaching; blast-radius controls limit a cascade that
starts anyway. None of this fixes **identity provenance over time**: an agent
whose identity was legitimate yesterday and is subverted today still presents a
valid-looking card. Decentralised-identity and Know-Your-Agent approaches are
still early. The honest 2026 position: you can make the inter-agent edge much
harder to abuse and much easier to see; you cannot yet make agent identity
self-proving over its lifetime. Instrument the edge accordingly.

## Files

| Path | What |
|------|------|
| [`a2a/cards.py`](a2a/cards.py) | Agent Cards + signing/verification (Control 1) |
| [`a2a/registry.py`](a2a/registry.py) | Discovery registry + persistence (stages 2, 5) |
| [`a2a/router.py`](a2a/router.py) | Skill router + authorization + blast radius (Controls 2, 3) |
| [`mcp_entry.py`](mcp_entry.py) | Poisoned tool description + agent brain (stage 1) |
| [`killchain.py`](killchain.py) | The five stages executed against the A2A layer |
| [`defenses.py`](defenses.py) | The three controls as one toggleable config |
| [`run_chain.py`](run_chain.py) | CLI transcript runner |
| [`test_chain.py`](test_chain.py) | Executable proof of every claim above |

## Framework mapping

| Concern | OWASP Agentic | MITRE ATLAS |
|---------|---------------|-------------|
| Tool description poisoning | ASI-02 Tool Misuse | AML.T0051 |
| Rogue agent registration / trust | ASI-07 Trust Boundary Violation | — |
| Routing hijack / goal redirection | ASI-01 Agent Goal Hijacking | — |
| Cascading failure across agents | ASI-08 Cascading Failures | — |
| Persistence | ASI-06 Knowledge & Memory Poisoning | AML.T0054 |

## Relationship to other labs

- **Stage 1** builds on the tool-description-poisoning primitive from
  [Lab 01](../01-mcp-tool-poisoning/) and [Lab 06](../06-ASI02-cross-server-mcp-poisoning/).
- **Stage 5** builds on the persistent-state poisoning theme from
  [Lab 05](../05-agentic-memory-attacks/).
