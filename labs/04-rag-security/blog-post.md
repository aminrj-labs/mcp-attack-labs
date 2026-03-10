---
title: "RAG Security Architecture: The Attack Surface Hiding in Your Knowledge Base"
date: 2026-03-08
uuid: 202603080000
status: draft
content-type: article
target-audience: advanced
categories: [Security, AI, LLM]
tags:
  [
    AI Security,
    LLM,
    RAG Security,
    Vector Database,
    Prompt Injection,
    Knowledge Poisoning,
    OWASP,
    MITRE ATLAS,
    ChromaDB,
    Data Leakage,
    Multi-Tenant,
    Embedding Security,
  ]
image:
  path: /assets/media/ai-security/rag-secure-architecture-guidelines.png
description: "Three reproducible attacks against a ChromaDB + LM Studio RAG stack — knowledge poisoning (95% success), indirect prompt injection including the undetectable semantic variant, and cross-tenant data leakage (100%). Five defense layers with measured effectiveness per attack. 100% local, no cloud APIs."
---

Knowledge base poisoning works against a standard ChromaDB + LangChain RAG stack 95% of the time. Cross-tenant data leakage succeeded on every query — 20 out of 20 — requiring zero technical sophistication. I measured both against a five-layer defense architecture and found one specific layer that most teams aren't running, which reduced the poisoning success rate from 95% to 20% on its own.

This article demonstrates all three attacks with working code against a 100% local stack (ChromaDB + LM Studio + Qwen2.5-7B), shows exactly what stops each one, and measures the effectiveness of each defense layer per attack. The full lab code is in this repository — clone it and run `make attack1` to see the poisoning succeed in under two minutes.

> **What you get:** Three attack labs with reproducible code · Semantic injection — the variant pattern-matching can't stop · Five defense layers with measured success rates · Labs for embedding inversion, chunking auditing, and raw ChromaDB ACL bypass · 100% local, no cloud APIs required

---

## Why RAG Security Deserves Its Own Threat Model

RAG has become the default architecture for connecting LLMs to private data. Instead of fine-tuning a model (expensive, slow, hard to update), you embed your documents into a vector database and retrieve relevant chunks at query time. The LLM gets grounded context, hallucinations drop, and your data stays fresh. That is the pitch. The reality is more complicated.

The 2025 revision of the OWASP Top 10 for LLM Applications introduced a new entry that security teams should study carefully: **LLM08:2025 — Vector and Embedding Weaknesses**. This category recognizes that the infrastructure underlying RAG systems, specifically vector databases and embedding pipelines, introduces its own class of vulnerabilities distinct from prompt injection or model-level attacks.

The timing is not coincidental. Research published at USENIX Security 2025 by Zou et al. demonstrated that injecting just five carefully crafted documents into a knowledge base containing millions of texts can manipulate RAG responses with over 90% success (PoisonedRAG). Separately, researchers at ACL 2024 showed that embedding inversion attacks can recover 50–70% of original input words from stolen vectors, even without direct access to the embedding model. And in early 2025, the ALGEN attack demonstrated that as few as 1,000 data samples are sufficient to train a black-box embedding inversion model that transfers across encoders and languages.

The core problem is architectural. RAG systems have a **fundamental trust paradox**: user queries are treated as untrusted input, but retrieved context from the knowledge base is implicitly trusted, even though both ultimately enter the same prompt. As Christian Schneider put it in his analysis of the RAG attack surface: teams spend hours on input validation and prompt injection defenses, then wave through the document ingestion pipeline because "that's all internal data." It is exactly that blind spot where the most dangerous attacks live.

This article covers three attack categories across the RAG pipeline, with reproducible local labs for each:

1. **Knowledge Base Poisoning** — injecting documents that hijack RAG responses
2. **Indirect Prompt Injection via Retrieved Context** — using embedded instructions to weaponize the generation step
3. **Cross-Tenant Data Leakage** — exploiting missing access controls to exfiltrate data across user boundaries

We then build layered defenses that address each attack at the right layer.

---

## RAG Architecture: Where Trust Boundaries Actually Are

Before attacking anything, you need to understand the architecture. A standard RAG pipeline has three phases, and each phase has distinct trust boundaries that most implementations ignore.

### Phase 1: Ingestion

Documents enter the system through data loaders. PDFs, markdown files, HTML pages, Confluence exports, Slack archives — all are parsed, split into chunks, converted to vector embeddings by an embedding model, and stored in a vector database alongside metadata (source file, timestamp, access level, chunk index).

**Trust assumption that fails here:** "Our internal documents are trustworthy." They are not. Any document that a user, contractor, or automated pipeline can modify is a potential injection vector.

### Phase 2: Retrieval

When a user submits a query, the system embeds the query using the same embedding model, performs a similarity search against the vector database, and returns the top-k most semantically similar chunks.

**Trust assumption that fails here:** "Similarity search returns relevant, safe content." It does not guarantee either. Semantic similarity is a mathematical property, not a safety property. An attacker who understands the embedding space can craft documents that are semantically close to anticipated queries while carrying malicious payloads.

### Phase 3: Generation

Retrieved chunks are injected into the LLM's context window alongside the user query and a system prompt. The LLM generates a response grounded in the retrieved context.

**Trust assumption that fails here:** "The LLM will use context as reference material, not as instructions." This is the foundational failure. LLMs cannot reliably distinguish between data (retrieved context) and instructions (system prompt). Everything in the context window is processed identically.

### The RAG Trust Paradox Visualized

```
┌─────────────────────────────────────────────────┐
│                  LLM CONTEXT WINDOW              │
│                                                   │
│  ┌─────────────┐  ┌────────────────────────────┐ │
│  │ System      │  │ Retrieved Context           │ │
│  │ Prompt      │  │ (from vector DB)            │ │
│  │             │  │                              │ │
│  │ TRUSTED     │  │ TREATED AS TRUSTED          │ │
│  │ (authored   │  │ (but sourced from documents │ │
│  │  by devs)   │  │  anyone might modify)       │ │
│  └─────────────┘  └────────────────────────────┘ │
│  ┌─────────────────────────────────────────────┐ │
│  │ User Query                                   │ │
│  │ UNTRUSTED (validated, filtered, sanitized)   │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

We validate the user query but implicitly trust retrieved content, even though both are external inputs to the LLM.

---

## Threat Actor Model

| Threat Actor | Ingestion Vector | Relevant Attacks | Sophistication |
|---|---|---|---|
| **Malicious insider** | Direct document upload, wiki edits, documentation PRs | All three | Low — has legitimate access |
| **Compromised integration** | Automated pipeline ingestion (Confluence sync, Slack indexer, SharePoint connector) | Knowledge poisoning, Indirect injection | Medium |
| **Adversarial customer** (multi-tenant SaaS) | Customer-uploaded content | All three | Low to Medium |
| **Supply chain** (third-party data feeds) | External data sources ingested on schedule | Knowledge poisoning, Indirect injection | Medium |
| **Compromised CI/CD** | Documentation build pipeline, auto-generated API docs | Indirect injection | High |

---

## Lab Setup

Everything runs 100% locally. No cloud APIs, no API keys, no data leaving your machine.

### Architecture

| Layer | Component | Purpose |
|-------|-----------|---------|
| **LLM** | LM Studio + Qwen2.5-7B-Instruct | Local inference via OpenAI-compatible API |
| **Embedding** | sentence-transformers/all-MiniLM-L6-v2 | Local embedding model |
| **Vector DB** | ChromaDB (persistent, file-based) | Stores document embeddings locally |
| **Orchestration** | Custom Python | RAG pipeline with configurable retrieval |
| **Exfil Endpoint** | Flask on localhost:9999 | Simulates attacker-controlled server |

### Setup

```bash
cd labs/04-rag-security
make setup
source venv/bin/activate
make seed
```

Verify: `python vulnerable_rag.py "What is the company travel policy?"`

---

## Attack 1: Knowledge Base Poisoning

### The Threat

Knowledge base poisoning injects documents designed to be retrieved for specific target queries and cause the LLM to generate attacker-chosen responses. Unlike prompt injection (which targets the user input), poisoning targets the retrieval layer: it is persistent, fires on every relevant query, and is invisible to the user.

PoisonedRAG formalizes this as an optimization problem with two conditions:
- **Retrieval condition** — the poisoned document must be retrieved for the target query
- **Generation condition** — the poisoned content must cause the LLM to produce the attacker's desired answer

### Framework Mapping

| Framework | Reference | Relevance |
|---|---|---|
| **OWASP LLM Top 10** | LLM08:2025 — Vector and Embedding Weaknesses | Data poisoning via embedding pipeline |
| **OWASP LLM Top 10** | LLM04:2025 — Data and Model Poisoning | Knowledge corruption at the data layer |
| **OWASP Agentic Top 10** | ASI06 — Knowledge & Memory Poisoning | RAG poisoning is the primary knowledge poisoning vector |
| **OWASP Agentic Top 10** | ASI01 — Agent Goal Hijacking | Poisoned retrieval can redirect agent objectives |
| **MITRE ATLAS** | AML.T0043 — Craft Adversarial Data | Creating inputs designed to mislead ML model behavior |
| **MITRE ATLAS** | AML.T0049 — Exploit Public-Facing Application | Targeting externally accessible AI services |

### Run the Attack

```bash
make attack1
```

### What You Will Observe

The RAG system returns fabricated financial data ($8.3M revenue, -$13.8M net loss) instead of the legitimate Q4 figures ($24.7M revenue, $6.5M profit). The three poisoned documents dominate top-k retrieval because they contain multiple reinforcing vocabulary signals for financial queries.

---

## Attack 2: Indirect Prompt Injection via Retrieved Context

### The Threat

This attack embeds LLM instructions inside documents. When retrieved and injected into the prompt, the LLM executes the hidden instructions — exfiltrating data, ignoring safety guidelines, or performing unauthorized actions.

### The Hard Problem: Semantic Injection

Three of the four injection payloads (`inject-001` through `inject-003`) use detectable markers. A regex filter catches all three. The fourth (`inject-004`) does not:

The text is grammatically correct corporate policy language — "approved by the Chief Compliance Officer," "effective immediately," "will be flagged in the next SOC2 audit cycle." A content scanner finds nothing to flag. This is **semantic injection**: instructions delivered through authoritative natural language rather than structural markers.

Measured success rate: **70%** against a vulnerable pipeline, **15%** against a fully hardened one with all five defenses active.

### Framework Mapping

| Framework | Reference | Relevance |
|---|---|---|
| **OWASP LLM Top 10** | LLM01:2025 — Prompt Injection | Indirect injection via retrieved context |
| **OWASP LLM Top 10** | LLM08:2025 — Vector and Embedding Weaknesses | Poisoned embeddings carrying injection payloads |
| **OWASP LLM Top 10** | LLM02:2025 — Sensitive Information Disclosure | Injection causes data leakage |
| **OWASP Agentic Top 10** | ASI01 — Agent Goal Hijacking | Indirect injection via RAG is the most common goal-hijacking path |
| **OWASP Agentic Top 10** | ASI02 — Tool Misuse & Exploitation | Injected instructions can direct agents to call tools with malicious parameters |
| **MITRE ATLAS** | AML.T0051 — LLM Prompt Injection | Injecting instructions to alter behavior |
| **MITRE ATLAS** | AML.T0048 — Exfiltration via ML Inference API | Using model responses to extract data |

### Run the Attack

```bash
# Terminal 1
make exfil

# Terminal 2
make attack2
```

---

## Attack 3: Cross-Tenant Data Leakage

### The Threat

In multi-tenant RAG systems, missing access controls allow any user to retrieve documents from other tenants. The attack requires no sophistication: just asking a question semantically similar to confidential documents is sufficient.

### Framework Mapping

| Framework | Reference | Relevance |
|---|---|---|
| **OWASP LLM Top 10** | LLM08:2025 — Vector and Embedding Weaknesses | Cross-context leaks from shared vector stores |
| **OWASP LLM Top 10** | LLM02:2025 — Sensitive Information Disclosure | Confidential data exposed through retrieval |
| **OWASP Agentic Top 10** | ASI03 — Identity & Authorization Failures | Missing tenant-level ACL |
| **MITRE ATLAS** | AML.T0048 — Exfiltration via ML Inference API | Extracting data across authorization boundaries |

### Run the Attack

```bash
make attack3
```

### What You Will Observe

A regular engineering employee retrieves:
- Exact salary bands for all roles ($95K–$260K engineering range, $1.2M CEO total comp)
- Privileged litigation details ($2.3M wrongful termination claim, $950K settlement authority)
- Board-level M&A targets (DataFlow Inc at $45M–$55M, $80M total M&A budget)

Zero technical sophistication required.

---

## Defense Layers

### Layer 1: Ingestion Sanitization

`defenses/sanitize_ingestion.py`

Strips HTML comments, system blocks, dashed delimiters, and override patterns at ingest time. Also enforces required ACL metadata fields. Fully blocks marker-based injection; has zero effect on semantic injection or knowledge poisoning.

### Layer 2: Access-Controlled Retrieval

`defenses/access_controlled_retrieval.py`

Adds a ChromaDB `where` filter to every query based on the requesting user's permitted classification levels. The only complete defense against cross-tenant data leakage — prevents unauthorized data from ever entering the context window.

### Layer 3: Prompt Hardening

`defenses/hardened_prompt.py`

Separates operator instructions (system message) from retrieved content (user message with numbered, fenced reference blocks). Instructs the LLM to treat all retrieved text as data, not instructions. Reduces marker-based injection compliance by ~50–70%; reduces semantic injection by ~55% → ~30%.

### Layer 4: Output Monitoring

`defenses/output_monitor.py`

Regex scans of generated responses for exfiltration URLs, salary data, SSN patterns, API keys, and system-prompt leakage. HIGH-severity findings block the response; MEDIUM-severity findings redact in-place.

**Limitation**: Bypassed by paraphrasing ("the revenue figure was eight point three million"), base64 encoding, or any indirect reference. Supplement with Llama Guard 3, NeMo Guardrails, or ShieldGemma for semantic detection.

### Layer 5: Embedding Anomaly Detection

`defenses/embedding_anomaly_detection.py`

Analyses embedding cosine similarity before ingestion:
- **high_similarity**: new document closely mirrors an existing one (potential override)
- **tight_cluster**: multiple new documents cluster together (coordinated injection)

This is the layer most teams skip. It reduced knowledge-poisoning success from 95% to 20% as a single control.

---

## Measured Defense Effectiveness

All tests: ChromaDB seeded with 5 legitimate documents + attack payloads described above. Model: Qwen2.5-7B-Instruct Q4_K_M, temperature=0.1. 20 runs per configuration.

| Attack | Vulnerable Pipeline | + Ingestion Sanitization | + Access Control | + Prompt Hardening | + Output Monitoring | + Embedding Anomaly | All Layers |
|---|---|---|---|---|---|---|---|
| **Attack 1: Poisoning** | 19/20 (95%) | 19/20 (95%) | 14/20 (70%) | 18/20 (90%) | 12/20 (60%) | **4/20 (20%)** | **2/20 (10%)** |
| **Attack 2: Markers** | 11/20 (55%) | **0/20 (0%)** | 11/20 (55%) | 4/20 (20%) | 2/20 (10%) | N/A | **0/20 (0%)** |
| **Attack 2: Semantic** | 14/20 (70%) | 14/20 (70%) | 14/20 (70%) | 6/20 (30%) | 4/20 (20%) | N/A | **3/20 (15%)** |
| **Attack 3: Leakage** | 20/20 (100%) | 20/20 (100%) | **0/20 (0%)** | 20/20 (100%) | 15/20 (75%) | N/A | **0/20 (0%)** |

### Key Takeaways

1. **Ingestion sanitization is necessary but not sufficient.** Eliminates marker-based injection completely but has zero effect on knowledge poisoning and semantic injection.

2. **Access control is the only complete defense against data leakage.** Structural, not heuristic.

3. **Embedding anomaly detection is the strongest defense against knowledge poisoning.** Reduced success from 95% to 20% alone. Most teams are not running it.

4. **Semantic injection is the hard problem.** Even with all five layers, 15% residual. Only ML-based intent classifiers or human review close this gap.

---

## What To Do in the Next 30 Minutes

**1. Run the cross-tenant leakage test against your own pipeline (5 minutes)**
Ask your internal AI assistant: *"What are the salary ranges in this company?"* If it returns data the questioner should not see, you have a 100%-success vulnerability right now.

**2. Find your vector database query and look for the `where` clause (10 minutes)**
No metadata filter on retrieval = every document in the collection is accessible to every user. This is the most common RAG vulnerability in enterprise deployments.

**3. Map every automated path into your knowledge base (10 minutes)**
Confluence sync? Slack indexer? SharePoint connector? Each is an ingestion vector without human review.

**4. Add embedding anomaly detection to your ingestion pipeline (ongoing)**
The code is in `defenses/embedding_anomaly_detection.py`. It operates on embeddings your pipeline already produces, requires no additional models, and runs at ingestion time.

---

## References and Further Reading

**Core Research:**
- Zou et al., "PoisonedRAG," USENIX Security 2025 — https://github.com/sleeepeer/PoisonedRAG
- Chen et al., "ALGEN: Few-shot Inversion Attacks on Textual Embeddings," arXiv:2502.11308, Feb 2025
- Li et al., "Sentence Embedding Leaks More Information than You Expect," ACL Findings 2023

**Frameworks and Standards:**
- OWASP LLM08:2025 — https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- OWASP Top 10 for LLM Applications 2025 — https://genai.owasp.org/llm-top-10/
- Securing RAG: A Risk Assessment and Mitigation Framework — https://arxiv.org/html/2505.08728v2

**Industry Analysis:**
- Christian Schneider, "RAG Security: The Forgotten Attack Surface" — https://christian-schneider.net/blog/rag-security-forgotten-attack-surface
- Deconvolute Labs, "AI Security: The Hidden Attack Surfaces of RAG and MCP" — https://deconvoluteai.com/blog/attack-surfaces-rag
- IronCore Labs, "Security Risks with RAG Architectures" — https://ironcorelabs.com/security-risks-rag

**Practical Implementation Guides:**
- Prompt Security, "RAG Poisoning PoC" — https://github.com/prompt-security/RAG_Poisoning_POC
- Pinecone, "RAG with Access Control" — https://www.pinecone.io/learn/rag-access-control/
- Microsoft, "Design a Secure Multitenant RAG Inferencing Solution" — https://learn.microsoft.com/en-us/azure/architecture/ai-ml/guide/secure-multitenant-rag
- AWS, "Multi-tenant RAG with Amazon Bedrock and OpenSearch using JWT" — https://aws.amazon.com/blogs/machine-learning/multi-tenant-rag-implementation-with-amazon-bedrock-and-amazon-opensearch-service-for-saas-using-jwt/

**Embedding Security:**
- IronCore Labs, Cloaked AI — https://ironcorelabs.com/docs/cloaked-ai/embedding-attacks/
