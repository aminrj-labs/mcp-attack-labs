# hack.lu 2026 — Submission Package

*Prepared for Amine Raji, May 27, 2026*

**Deadline: 2026-05-31 23:59 Luxembourg time** (4 days)
**Submission portal: https://pretalx.com/hack-lu-2026/**
**Conference: October 20–23, 2026, Parc Hotel Alvisse, Luxembourg**
**Format: 20-min talk + 10-min Q&A · workshops also accepted · lightning talks 5 min**

---

## Part 1 — What hack.lu rewards (and what to avoid)

Pulled from the 2025 schedule and the 2026 CFP text.

**Reviewers reward:**

1. **Original attack research** with reproducible artifacts (Gerste's Ollama GGUF memory corruption, Salfer's AutoSAlfER, Widevine L3 DFA, postmark-mcp). They want vulnerabilities and chains that hadn't been published before the talk.
2. **Open-source release on the day of the talk.** Tools, rules, lab code, detection signatures. Alexandre Dulaunoy and the CIRCL/MISP crowd run this conference; they explicitly favor open source over commercial.
3. **Live demos**, not slide-only. The 2025 program is dense with hands-on demos and workshop sessions (Hardware Hacking, Maldoc, Sysdiagnose, MISP API, OpenSSH, Lockpicking).
4. **Empirical data**, not vibes. Incident counts, ASR numbers, CVE references, reproduction methodology.
5. **Threat intelligence relevance.** The CTI Summit runs alongside the main track. Anything tied to detection, MISP, GCVE, or open-source security tooling gets a second pathway in.
6. **EU venue framing.** EU AI Act, NIS2, sovereign AI, regulated industries all resonate in Luxembourg.

**Reviewers are skeptical of:**

- Vendor pitches and product demos
- Pure methodology decks without a demo or lab
- "AI is dangerous, here is OWASP Top 10" survey talks
- Anything that reads like a conference circuit rerun

**Sweet spot for AI security at hack.lu:**
> "Here is a novel attack class, here is empirical data from real systems, here is a live demo, here is the open-source lab and detection signature I am releasing today."

---

## Part 2 — The six proposals, ranked by fit

| # | Title | Format | Fit | Status |
|---|---|---|---|---|
| **1** | **The MCP→A2A Kill Chain: Lateral Movement Across an Agent Fleet** | 20-min talk | **Strongest** | Build the lab in 4 weeks before Oct |
| **2** | **Breaking and Defending the Model Context Protocol — Hands-On Workshop** | Workshop (3–4 hr) | **Strong** | Labs already exist |
| **3** | **Cross-Session Rug-Pull Detection: How an MCP Server Changes Behavior Across Reboots and Nobody Notices** | 20-min talk | **Strong** | Module in progress, ship by Oct |
| **4** | **Poisoning the Knowledge Base: RAG Pipelines That Survive Sanitization** | 20-min talk | **Solid** | Lab 04 already exists |
| **5** | **Detecting AI Agent Compromise from Syscalls: Open-Source Falco Rules for Claude Code, Gemini CLI, and Codex** | 20-min talk (CTI Summit) | **Solid** | Rules need to be written |
| **6** | **The Sixth Attack Class: What a Year of MCP Production Data Says the Protocol Can't Fix** | 20-min talk | **Backup** | Reuse OWASP Stockholm material |

**Recommended submission combo:** #1 + #2. Different tracks, different review pipelines, complementary stories. If you have appetite for a third, add #5 (CTI Summit route).

---

## Part 3 — The proposals

Each proposal below has a paste-ready abstract for Pretalx, a positioning paragraph for the private reviewer notes field, and a list of deliverables you commit to shipping.

---

### Proposal 1 — The MCP→A2A Kill Chain: Lateral Movement Across an Agent Fleet

**Format:** 20-minute main-track talk
**Track:** hack.lu main / AI at large
**Why this wins:** This is novel research that has not been published yet. You announced it as upcoming in the OWASP Stockholm post. A2A v1.0 was formalized in March 2026. The MCP→A2A attack chain has zero practitioner labs in the public record. hack.lu rewards "first to demo" disproportionately.

**Abstract (paste-ready, ~280 words):**

> The Model Context Protocol gave AI agents tools. The Agent-to-Agent protocol, formalized as A2A v1.0 in March 2026, gave them coordination. Together they form a two-layer attack surface that nobody has published a kill chain for — yet.
>
> This talk presents the first public end-to-end demonstration of a kill chain that begins with a single poisoned MCP tool description, abuses the A2A capability advertisement layer, and propagates laterally across a fleet of three coordinated agents — exfiltrating credentials none of the individual agents are authorized to access.
>
> The attack composes three primitives that are each individually documented but have never been combined in public research: MCP tool description poisoning (Invariant Labs, April 2025), A2A capability spoofing (formal analysis by Maloyan and Namiot, January 2026, arXiv:2601.17549), and cross-agent trust laundering through the A2A delegation channel. Every primitive has working lab code. The chain works against agents built on LangGraph, CrewAI, and a custom A2A implementation. End-to-end attack success rate is measured across fifteen trials per configuration and three foundation models, with the prompt sequences captured for reproduction.
>
> The talk ships an open-source lab — extending github.com/aminrj-labs/mcp-attack-labs with a sixth lab covering the full chain — and proposes four specification changes: A2A capability attestation, MCP server-of-origin binding, namespace scoping at the agent harness layer, and signed inter-agent messages. Five of the six attack variants have controls deployable today. The sixth is the line where the agent ecosystem becomes structurally responsible for fixing this.
>
> Lab code, demo recordings, and reproduction notes ship on the day of the talk.

**Private notes to reviewers (250 words):**

> This is the natural follow-up to my OWASP Stockholm 2026 talk on MCP. That talk covered the protocol-level gaps; this talk covers what happens when those gaps cascade through the A2A trust layer above MCP. A2A v1.0 was finalized in March 2026 and no practitioner-grade attack research has been published against it yet — this would be the first.
>
> I have published reproducible MCP attack research at github.com/aminrj-labs/mcp-attack-labs (5 labs, Python + Jupyter, fully reproducible locally with LM Studio, no cloud APIs). The new chain extends that repo. I lead cloud cybersecurity at Volvo Cars (15+ years securing critical systems in banking, defense, aerospace, automotive; PhD; CISSP) and run an independent AI security practice under Molntek targeting the EU market.
>
> Demo is terminal-based, single-screen, reproducible offline. Three windows, three agents, one exfiltration channel — visible attack chain in under two minutes. No cloud dependency. The audience can clone and reproduce the attack the same evening.
>
> Speaker availability is unconditional across the four conference days. I will travel from Gothenburg.

**Deliverables shipped on talk day:**

- Lab 06 in `mcp-attack-labs` covering the full chain, with three agent harness implementations
- Empirical results: 15 trials × 3 foundation models, raw transcripts published
- Four proposed protocol changes filed as RFCs / GitHub issues against MCP and A2A working groups
- Demo recording mirrored on the conference archive
- Blog post on aminrj.com cross-linking the talk

---

### Proposal 2 — Breaking and Defending the Model Context Protocol: A Hands-On Workshop

**Format:** 3–4 hour workshop
**Track:** hack.lu training / workshop
**Why this wins:** Workshops at hack.lu 2025 included Hardware Hacking, Sysdiagnose, OpenSSH, MISP API, Maldoc analysis, and Lockpicking. There is no AI/MCP workshop on the 2025 program — open white space. You have the labs already written and tested.

**Abstract (paste-ready, ~250 words):**

> Two hours of theory followed by three hours of you breaking real MCP servers and shipping the controls that block the attacks.
>
> By the end of the workshop, every participant will have reproduced five attack classes on their laptop and deployed working defenses against all of them. The lab environment runs fully locally — LM Studio with a quantized model, Docker, and the open-source `mcp-attack-labs` repository. No cloud APIs, no shared GPU, no API keys. Everything offline.
>
> The five labs:
>
> 1. **Tool description poisoning** — embed instructions in tool metadata, exfiltrate an SSH key from a "math" agent
> 2. **Cross-server shadowing** — one malicious server, one trusted server, exfil through the trusted channel
> 3. **DockerDash supply chain** — Docker LABEL injection through an AI build assistant
> 4. **RAG poisoning** — single-document indirect injection that affects every retrieval downstream
> 5. **Agentic memory exploitation** — persistent poisoning across sessions, multi-agent trust break
>
> Each lab pairs an attack with a working defense: `mcp-scan` for description analysis, SHA-256 hash pinning for rug-pull detection, network egress allowlists for exfiltration containment, per-server namespace scoping, and signed inter-agent messages.
>
> Participants leave with a hardened agent harness configuration, a CI pipeline that fails the build on tool description drift, and a runbook they can deploy in production on Monday.
>
> Hands-on. No vendor demos. No slideware after the first hour.

**Logistics (Pretalx field):**

- Duration: 3.5 hours including a 20-minute break
- Audience size: 20–40 (workshop room dependent)
- Prerequisites for attendees: laptop, 16 GB RAM, Docker, Python 3.11+, LM Studio pre-installed (instructions sent two weeks prior)
- Materials: GitHub repo cloneable in advance, Jupyter playbooks, one PDF runbook per lab
- Skill level: intermediate (familiarity with Python and command line assumed; AI experience not required)

**Why I can deliver this:**

- All 5 labs are written, tested, and live at github.com/aminrj-labs/mcp-attack-labs
- I have taught a related course ("Securing Agentic AI Systems") with the same lab base
- I delivered the underlying research as a talk at OWASP Stockholm on May 19, 2026 — this is the workshop version

**Deliverables shipped on workshop day:**

- Pre-workshop email to registrants with setup instructions (T-14 days)
- Cheat sheet PDF for each of the 5 labs (printed handouts)
- Tagged release of `mcp-attack-labs` versioned `v1.0-hacklu2026`
- Survey at the end for follow-up materials

---

### Proposal 3 — Cross-Session Rug-Pull Detection: When an MCP Server Changes Behavior Across Reboots and Nobody Notices

**Format:** 20-minute main-track talk
**Track:** hack.lu main / AI at large
**Why this wins:** This is the second piece of research you mentioned as in-progress in the OWASP Stockholm post. It is a specific, narrow, technically sharp contribution: a detection module with measurable false-positive and false-negative rates, released as open source. hack.lu loves "specific tool that solves a specific problem."

**Abstract (paste-ready, ~270 words):**

> The postmark-mcp rug-pull (September 2025) worked because every existing MCP description-pinning tool compares the current handshake against the previous handshake, not against the original baseline. If an adversary drifts the description across ten sessions — small edits, never large enough to alert — no current tool catches it. Five hundred organizations running postmark-mcp confirmed this in production over eight days. Three thousand to fifteen thousand emails per day were exfiltrated through a description that drifted, not flipped.
>
> This talk presents a cross-session rug-pull detection module that persists description hashes against the *original* baseline in SQLite, not the *previous* session. Drift is detected at the byte level, the semantic level (cosine similarity over field embeddings), and the structural level (schema-tree edit distance). False-positive rate is measured against a dataset of 200 legitimately maintained MCP servers from a six-month observation window. False-negative rate is measured against 12 synthetic gradual-drift attack scenarios derived from the postmark-mcp timeline.
>
> The module ships as a standalone CLI (`mcp-drift-detect`) and as a CI plugin for the major agent harnesses (LangGraph, CrewAI, Claude Desktop config). Detection latency is sub-second per server. Storage cost is approximately 4 KB per server-week.
>
> The talk includes a live reproduction of the postmark-mcp drift timeline against a synthetic email server, demonstrates two evasion attempts that defeat single-session pinning but trip the cross-session module, and walks through three deployment patterns: local CI, agent harness plugin, and a small daemon for production MCP gateways.
>
> Open-source release on the day of the talk under the MIT license.

**Deliverables shipped on talk day:**

- `mcp-drift-detect` v0.1 release on GitHub
- Evaluation dataset (legit + synthetic attacks) for reproducibility
- Integration recipes for Claude Desktop, LangGraph, and a Kubernetes sidecar pattern

---

### Proposal 4 — Poisoning the Knowledge Base: RAG Pipelines That Survive Every Sanitization Step You Have

**Format:** 20-minute main-track talk
**Track:** hack.lu main / AI at large
**Why this wins:** RAG is everywhere in 2026 production AI. The attack surface is the most under-modeled in your taxonomy. Lab 04 already exists, and the cross-tenant data leakage angle is fresh.

**Abstract (paste-ready, ~270 words):**

> Every defense paper recommends "sanitize the corpus." Every sanitization layer I tested has a bypass.
>
> This talk walks through four bypass classes against RAG ingestion pipelines, each demonstrated end to end against a working LangGraph + pgvector + Postgres stack. The attacks succeed even when the corpus is run through HTML stripping, markdown sanitization, zero-width Unicode filtering, and a regex pass for known prompt-injection patterns:
>
> 1. **Structural injection via document metadata fields** — corpus indexes title, author, and abstract separately; instructions in author bio reach the model context
> 2. **Embedding-space steering** — semantic-similar phrasing that does not match any regex but reliably retrieves on adversarial queries
> 3. **Cross-tenant retrieval leakage** — multi-tenant RAG with shared embedding index, single misconfigured filter, all tenants reachable
> 4. **Indirect injection through retrieved citations** — model reads a citation footnote in retrieved doc A as an instruction, retrieves doc B, exfiltrates
>
> Each attack is reproducible from `mcp-attack-labs/labs/04-rag-security`. The talk presents attack success rates across three foundation models (15 trials each), the corpus-level controls that work (provenance metadata enforced at retrieval, retrieval-time output validation, embedding anomaly detection), and one architectural pattern that closes the cross-tenant variant: per-tenant embedding namespace with cryptographic isolation.
>
> The talk closes with a deployable detection pipeline based on retrieval-time embedding distance anomalies, packaged as an open-source library that drops into LangChain and LlamaIndex with three lines of code.
>
> No vendor product slides. Working code. Reproducible results.

**Deliverables shipped on talk day:**

- Lab 04 v2 in `mcp-attack-labs` with the four bypass variants
- Open-source detection library (`rag-poison-detect`) for LangChain/LlamaIndex
- Public dataset of poisoned corpora for benchmarking

---

### Proposal 5 — Detecting AI Coding Agent Compromise from Syscalls: Open-Source Falco Rules for Claude Code, Gemini CLI, and Codex

**Format:** 20-minute talk
**Track:** **CTI Summit** (parallel track — this is your strongest CTI Summit angle)
**Why this wins:** The CTI Summit explicitly wants "Open source tooling used in threat intelligence" and "Use of open source tools (such as MISP) into SOC, CSIRT, or any security organisation." This is the syscall-level detection angle — eBPF, Falco — that the threat intel and SOC crowd loves. Sysdig published initial Falco rules for AI coding agents but coverage is thin. You can extend it with a published ruleset.

**Abstract (paste-ready, ~260 words):**

> AI coding agents — Claude Code, Gemini CLI, Codex CLI, Cursor with agentic mode — execute code, modify files, and make network calls on behalf of developers. They run with the developer's permissions. When they go off the rails or get compromised through tool poisoning, detecting it has fallen to one signal: did the developer notice?
>
> This talk presents a published Falco ruleset for runtime detection of compromised AI coding agents based on syscall-level behavioral baselines. The rules cover three classes:
>
> 1. **Exfiltration via legitimate channels** — agent opens a network socket to a destination not in the project's git remote graph
> 2. **Credential access** — agent reads from `~/.ssh/`, `~/.aws/`, `~/.config/`, or the OS keyring without an explicit prompt
> 3. **Lateral file system access** — agent walks out of the project root, reads parent directories, accesses other developer projects on the same machine
>
> The ruleset is derived from a 90-day behavioral baseline collected on a workstation running Claude Code, Gemini CLI, and a custom LangGraph agent against open-source projects. True-positive and false-positive rates are reported against a synthetic test corpus including the tool-poisoning attacks from `mcp-attack-labs`.
>
> The talk demonstrates Lab 01 (MCP tool poisoning) running live, with Falco firing in under 200 ms on the suspicious syscall sequence. It walks through deployment patterns for individual developer machines, CI runners, and Kubernetes Jobs that invoke agents in build pipelines.
>
> Open-source ruleset, baseline collection scripts, and the synthetic test corpus all ship under Apache 2.0 on the day of the talk.

**Deliverables shipped on talk day:**

- `ai-agent-falco-rules` GitHub repo with 24+ rules
- Baseline collection harness for reproducing the behavioral profile
- Synthetic adversarial test corpus
- Integration recipe for Falcosidekick → MISP for IOC enrichment

---

### Proposal 6 (Backup) — The Sixth Attack Class: What a Year of MCP Production Data Says the Protocol Cannot Fix

**Format:** 20-minute talk
**Track:** hack.lu main
**Why this is a backup:** You just gave a version of this at OWASP Stockholm on May 19. hack.lu reviewers can find that talk online. If you submit this as the main pitch, the reviewer notes need to make clear what's *new* relative to the Stockholm version — otherwise it reads as a circuit rerun. The OX Security 200,000-instance disclosure and any post-Stockholm CVEs from the past 60 days give you a genuine update path.

**Abstract (paste-ready, ~260 words):**

> One year of empirical data on the Model Context Protocol: 30+ CVEs in a 60-day window, 24,008 leaked secrets across public configs, ~200,000 internet-exposed STDIO instances disclosed by OX Security in April 2026, and one in-the-wild incident (postmark-mcp) confirmed against 500 organizations. The pattern is consistent: the specification places tool descriptions outside its trust boundary but provides no mechanism for hosts to enforce that boundary, and a year of attack research has demonstrated the consequences across six attack classes.
>
> This talk presents updated production data covering the period since OWASP Stockholm (May 2026), including a new attack class disclosed in [specific month, fill in at time of submission], and reports on the response from the MCP specification working group on the four protocol-level proposals filed against the spec to date.
>
> Five of the six attack classes have controls deployable today. The sixth — cross-server shadowing in a flat namespace — requires specification changes and has been open against the spec for fourteen months. The talk closes with a benchmark of three published proposals (server-of-origin binding, cryptographic description attestation, namespace scoping) measured against the six attack classes, and an honest assessment of which protocol-level changes are politically viable and which are not.
>
> Lab code at github.com/aminrj-labs/mcp-attack-labs covers every attack class demonstrated. The benchmark harness and protocol proposal test suite ship on the day of the talk.

**Position relative to OWASP Stockholm:** new empirical data (60 additional days), new attack class, working-group response, and a benchmark harness that did not exist in the May version.

---

## Part 4 — Pretalx submission tactics

The Pretalx form for hack.lu typically requests:

1. **Title** — keep it under 80 characters, lead with the most concrete technical noun ("MCP→A2A Kill Chain" not "Securing Multi-Agent Systems")
2. **Abstract (public)** — what attendees see. 200–300 words. Lead with the demo or the empirical claim. End with what the audience leaves with.
3. **Description / outline (private to reviewers)** — minute-by-minute breakdown with demo timings. This is where reviewers decide. Show you have a real 20 minutes of content, not a 40-minute talk crammed in.
4. **Reviewer notes** — bio, prior speaking, why you specifically can deliver this, willingness to travel, any conflicts
5. **Track selection** — main vs. CTI Summit vs. workshop
6. **Language** — English (the conference language)

**Do:**

- Lead the abstract with the concrete attack or empirical claim. "Three windows on the screen. One agent answers a math question. The other exfiltrates an SSH key. Nothing was clicked." — that's the opening you used at OWASP Stockholm and it works.
- Name specific tools you'll ship: `mcp-drift-detect`, `rag-poison-detect`, `ai-agent-falco-rules`. Concrete artifact names signal you'll actually deliver.
- Mention empirical data: "15 trials per model, 3 model families, ASR reported with confidence intervals."
- Cite the conference's culture: open source, reproducibility, EU-grounded. Don't say it overtly — let it show in the abstract style.
- Mention your OWASP Stockholm talk in the reviewer notes (signals practitioner credibility) — but the hack.lu submission must be different content.

**Do not:**

- Use marketing language ("revolutionary," "next-gen," "AI-powered security platform")
- Include vendor names except when essential (e.g., naming the SDK being attacked)
- Submit a methodology talk without a demo
- Submit anything that depends on internal Volvo work — the disclosure boundary is real and hack.lu reviewers will spot it
- Promise more than you can ship — every lab you commit to must actually exist by talk day

---

## Part 5 — Suggested combined submission

Submit these three on Pretalx, in this order of priority:

1. **Proposal 1 (MCP→A2A Kill Chain)** — main-track 20-min talk. Novel research. Highest signal.
2. **Proposal 2 (Workshop)** — workshop slot. Different review queue. Uses labs you already have.
3. **Proposal 5 (Falco Rules)** — CTI Summit talk. Different track. Different reviewers.

If all three were accepted, that's three distinct deliverables across three days — heavy but doable if you start the lab build now. If only one or two come through, you still have a strong presence.

**Hold Proposals 3, 4, and 6 in reserve** in case a reviewer comes back with "this is interesting but we'd like to see a different angle" — that happens, and a backup pitch ready to go in 24 hours wins those slots.

---

## Part 6 — 4-day execution checklist

| Day | Action |
|---|---|
| **Today (May 27)** | Draft full Pretalx submission for Proposal 1. Validate the MCP→A2A attack chain claims against the Maloyan-Namiot paper (arXiv:2601.17549) and A2A v1.0 spec. Confirm Lab 06 timeline is realistic. |
| **May 28** | Submit Proposal 1. Draft Proposal 2 (workshop). The workshop logistics field is detailed — block 2 hours for it. |
| **May 29** | Submit Proposal 2. Draft Proposal 5 (CTI Summit). Falco rules can lean on Sysdig's published baseline, but mention your own 90-day baseline data. |
| **May 30** | Submit Proposal 5. Re-read all three submissions for tone consistency. Confirm bio is updated across all three. |
| **May 31** | Final pass. Submit before noon UTC to avoid last-hour Pretalx queue issues (the 2025 CFP had a "one day left" reminder, suggesting bunching). |

---

## Part 7 — Speaker bio (paste-ready, 100 words)

> Amine Raji, PhD, CISSP, is a Cloud Cybersecurity Lead at Volvo Cars and the founder of Molntek, an independent AI security practice focused on the EU market. He has 15+ years securing critical systems across banking, defense, aerospace, and automotive, and has spent the last two years on practitioner-grade AI and agentic security research. He publishes the AI Security Intelligence newsletter, maintains the open-source `mcp-attack-labs` repository, and recently delivered "MCP Security: One Year In" at OWASP Stockholm 2026. He writes at aminrj.com and lives in Gothenburg, Sweden.

---

*End of submission package.*
