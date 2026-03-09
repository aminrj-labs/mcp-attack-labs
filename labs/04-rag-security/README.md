# Lab 04 — RAG Security: The Attack Surface Hiding in Your Knowledge Base

Hands-on lab for the article
[RAG Security Architecture: The Attack Surface Hiding in Your Knowledge Base](blog-post.md).

Three reproducible attacks against a **ChromaDB + LM Studio** RAG stack, measured
against a five-layer defense architecture, 100 % local — no cloud APIs required.

---

## What the Lab Demonstrates

| Attack | Technique | Vulnerable success rate | After all defenses |
|---|---|---|---|
| **Attack 1** | Knowledge Base Poisoning | 19/20 (95 %) | 2/20 (10 %) |
| **Attack 2** | Indirect Prompt Injection — marker-based | 11/20 (55 %) | 0/20 (0 %) |
| **Attack 2** | Indirect Prompt Injection — **semantic** | 14/20 (70 %) | 3/20 (15 %) |
| **Attack 3** | Cross-Tenant Data Leakage | 20/20 (100 %) | 0/20 (0 %) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Target: Vulnerable RAG pipeline  (vulnerable_rag.py)            │
│  ├─ LLM       : Qwen2.5-7B-Instruct  via LM Studio :1234        │
│  ├─ Embedding : all-MiniLM-L6-v2  (sentence-transformers)        │
│  └─ Vector DB : ChromaDB persistent  (./chroma_db/)              │
│                                                                  │
│  Attacker infrastructure                                         │
│  └─ Exfil server  http://localhost:9999                          │
│                                                                  │
│  Hardened pipeline  (hardened_rag.py)                            │
│  ├─ Layer 1  defenses/sanitize_ingestion.py                      │
│  ├─ Layer 2  defenses/access_controlled_retrieval.py             │
│  ├─ Layer 3  defenses/hardened_prompt.py                         │
│  ├─ Layer 4  defenses/output_monitor.py                          │
│  └─ Layer 5  defenses/embedding_anomaly_detection.py             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | |
| [LM Studio](https://lmstudio.ai/) 0.3.x+ | Load `qwen2.5-7b-instruct` (Q4_K_M), enable server on port 1234 |
| ~6 GB RAM / VRAM | For the model |

---

## Setup

```bash
# 1. Navigate to this lab
cd labs/04-rag-security

# 2. Create virtual environment and install dependencies
make setup
source venv/bin/activate

# 3. Start LM Studio and load qwen2.5-7b-instruct, then verify
curl http://localhost:1234/v1/models

# 4. Seed the knowledge base with legitimate company documents
make seed
```

---

## Running the Attacks

Each attack is self-contained and resets cleanly.  Run them in order for the
best narrative flow.

### Quick start (two terminals)

**Terminal 1 — exfil listener (optional, needed for Attack 2):**
```bash
source venv/bin/activate
python exfil_server.py
```

**Terminal 2 — attacks:**
```bash
source venv/bin/activate

# Attack 1: Knowledge Base Poisoning
make attack1

# Attack 2: Indirect Prompt Injection (all 4 variants)
make attack2

# Attack 3: Cross-Tenant Data Leakage
make attack3
```

### Or run everything at once
```bash
make measure-all
```

---

## Attack Details

### Attack 1 — Knowledge Base Poisoning

Injects three coordinated fake financial documents that override the legitimate
Q4 2025 summary (`$24.7M` revenue → fabricated `$8.3M` loss) for every financial
query.  Demonstrates the PoisonedRAG two-condition model: retrieval condition +
generation condition.

```bash
make attack1
# look for: ⚠️  POISONING SUCCESS
```

### Attack 2 — Indirect Prompt Injection via Retrieved Context

Plants LLM instructions inside documents.  Four variants of increasing
detection difficulty:

| ID | Variant | Detectable by regex? |
|---|---|---|
| `inject-001` | HTML comment | ✅ Yes |
| `inject-002` | Admin-note brackets | ✅ Yes |
| `inject-003` | Dashed system delimiter | ✅ Yes |
| `inject-004` | **Semantic injection** — pure natural language policy text | ❌ No |

```bash
make attack2          # start exfil listener first: make exfil
# look for: ⚠️  INJECTION INDICATORS DETECTED
```

### Attack 3 — Cross-Tenant Data Leakage

Simulates an engineering employee asking questions that retrieve:
- HR compensation data (salary bands, CEO pay)
- Attorney-client privileged litigation details
- Board-level M&A pipeline ($45M acquisition targets)

No technical skill required — just semantic similarity to restricted documents.

```bash
make attack3
# look for: 🚨 DATA LEAKAGE CONFIRMED
```

---

## Defense Tests

After running the attacks, test the hardened pipeline:

```bash
# alice (engineer) — should NOT see salary data (blocked by Layer 2)
make hardened-alice

# bob (HR manager) — SHOULD see salary data
make hardened-bob

# carol (legal) — SHOULD see litigation docs
make hardened-carol

# alice tries M&A data — should be blocked
make hardened-alice-ma
```

---

## Defense Layer Summary

| Layer | File | Stops |
|---|---|---|
| 1 — Ingestion sanitization | `defenses/sanitize_ingestion.py` | Attack 2 marker-based (fully) |
| 2 — Access-controlled retrieval | `defenses/access_controlled_retrieval.py` | Attack 3 (fully) |
| 3 — Hardened prompt | `defenses/hardened_prompt.py` | Attack 2 partial (~50–70 % reduction) |
| 4 — Output monitoring | `defenses/output_monitor.py` | Detects/blocks exfil URLs, salary data, leaked system info |
| 5 — Embedding anomaly detection | `defenses/embedding_anomaly_detection.py` | Attack 1 (95 % → 20 %) |

---

## File Structure

```
labs/04-rag-security/
├── vulnerable_rag.py              # Deliberately insecure base RAG pipeline
├── attack1_knowledge_poisoning.py # Attack 1
├── attack2_indirect_injection.py  # Attack 2 (4 variants)
├── attack3_cross_tenant_leakage.py# Attack 3
├── hardened_rag.py                # All 5 defense layers combined
├── exfil_server.py                # Attacker-controlled data capture server
├── requirements.txt
├── Makefile                       # make help for all targets
├── blog-post.md                   # Full article
└── defenses/
    ├── __init__.py
    ├── sanitize_ingestion.py          # Layer 1
    ├── access_controlled_retrieval.py # Layer 2
    ├── hardened_prompt.py             # Layer 3
    ├── output_monitor.py              # Layer 4
    └── embedding_anomaly_detection.py # Layer 5
```

---

## Key Findings

1. **Cross-tenant leakage requires zero technical skill** — 100 % success from
   asking semantically relevant questions with no special encoding.

2. **Embedding anomaly detection is the missing layer** — most teams run
   Layers 1–4 but skip Layer 5, which reduces poisoning success alone from
   95 % to 20 %.

3. **Semantic injection is the hard problem** — `inject-004` bypasses all
   regex/pattern defenses because it is grammatically indistinguishable from a
   real policy document.  The 15 % residual after all five layers requires
   ML-based intent classifiers (Llama Guard 3, NeMo Guardrails) or human review.

4. **Access control is a structural defense, not a heuristic** — it is the
   only layer that fully stops leakage by preventing unauthorised data from
   entering the context window at all.

---

## References

- PoisonedRAG (USENIX Security 2025) — https://github.com/sleeepeer/PoisonedRAG
- OWASP LLM08:2025 — Vector and Embedding Weaknesses
- MITRE ATLAS AML.T0043 / AML.T0048 / AML.T0051
- Full reference list in [blog-post.md](blog-post.md#references-and-further-reading)
