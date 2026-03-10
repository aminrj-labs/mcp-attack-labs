"""
Deliberately vulnerable RAG pipeline for security research.

Supports the article:
  "RAG Security Architecture: The Attack Surface Hiding in Your Knowledge Base"

Architecture:
  - LLM       : LM Studio + Qwen2.5-7B-Instruct (OpenAI-compatible API)
  - Embedding : sentence-transformers/all-MiniLM-L6-v2  (local, no API key)
  - Vector DB : ChromaDB persistent (file-based, ./chroma_db)
  - Retrieval : cosine similarity, top-k = 3

VULNERABILITIES (intentional):
  1. No content validation or sanitization at ingest
  2. No access-control filtering at retrieval
  3. No instruction/context boundary in generation prompt

DO NOT use this code in production.
"""

import os
import sys
import chromadb
from chromadb.utils import embedding_functions
from openai import OpenAI

# ── Configuration ──────────────────────────────────────────────────────────────
CHROMA_DIR       = "./chroma_db"
COLLECTION_NAME  = "company_docs"
LM_STUDIO_URL    = "http://localhost:1234/v1"
TOP_K            = 3

# Auto-detect whichever model is loaded in LM Studio; fall back to the default.
# Override by setting the LM_STUDIO_MODEL env var: LM_STUDIO_MODEL=my-model python ...
def _detect_model() -> str:
    env_model = os.environ.get("LM_STUDIO_MODEL", "")
    if env_model:
        return env_model
    try:
        _c = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
        models = _c.models.list().data
        if models:
            detected = models[0].id
            print(f"[Config] Using LM Studio model: {detected}", flush=True)
            return detected
    except Exception:
        pass
    return "qwen2.5-7b-instruct"   # static fallback

MODEL = _detect_model()

# ── Embedding model (local — no API key) ───────────────────────────────────────
embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# ── Vector database ─────────────────────────────────────────────────────────────
chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)


def get_or_create_collection():
    return chroma_client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )


# ── Document ingestion (NO SANITIZATION — VULNERABLE) ─────────────────────────
def ingest_documents(documents: list[dict]) -> None:
    """
    Add documents to the vector database without any content validation.

    Each document dict: {"id": str, "text": str, "metadata": dict}

    VULNERABILITY: No content checks, no sanitization, no ACL metadata
    enforcement — anything goes into the knowledge base unchallenged.
    """
    collection = get_or_create_collection()
    collection.upsert(
        ids=[d["id"] for d in documents],
        documents=[d["text"] for d in documents],
        metadatas=[d.get("metadata", {}) for d in documents],
    )
    print(f"[Ingest] Added {len(documents)} document(s) to '{COLLECTION_NAME}'")


# ── Retrieval (NO ACCESS CONTROL — VULNERABLE) ────────────────────────────────
def retrieve(query: str, n_results: int = TOP_K) -> list[str]:
    """
    Return top-k documents by cosine similarity.

    VULNERABILITY: No user-based filter.  All documents are visible to
    every query regardless of classification or department ownership.
    """
    collection = get_or_create_collection()
    results = collection.query(
        query_texts=[query],
        n_results=n_results,
    )
    return results["documents"][0] if results["documents"] else []


# ── Generation (NO OUTPUT FILTERING — VULNERABLE) ────────────────────────────
def generate(query: str, context_docs: list[str]) -> str:
    """
    Generate a response by injecting retrieved context directly into the prompt.

    VULNERABILITY: Retrieved content — which may contain injected instructions —
    is placed into the LLM context with no sanitization or boundary markers.
    The LLM cannot distinguish between data and instructions.
    """
    llm = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")

    context = "\n\n---\n\n".join(context_docs)

    # VULNERABLE PROMPT: retrieved text and user query share the same context
    # with no indication that the retrieved text is mere reference material.
    prompt = f"""You are a helpful company assistant. Use the following \
context documents to answer the user's question. If the context doesn't \
contain relevant information, say so.

CONTEXT:
{context}

USER QUESTION: {query}

ANSWER:"""

    response = llm.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,
        temperature=0.1,
    )
    return response.choices[0].message.content


# ── Full RAG pipeline ──────────────────────────────────────────────────────────
def ask(query: str) -> str:
    """Retrieve → Generate (vulnerable pipeline)."""
    docs = retrieve(query)
    if not docs:
        return "No relevant documents found."

    print(f"[Retrieve] Found {len(docs)} chunk(s)")
    for i, doc in enumerate(docs):
        print(f"  Chunk {i + 1}: {doc[:80]}...")

    return generate(query, docs)


# ── Seed data ──────────────────────────────────────────────────────────────────
def seed_legitimate_data() -> None:
    """Populate the knowledge base with five clean company documents."""
    documents = [
        {
            "id": "policy-001",
            "text": (
                "Company Travel Policy (Effective January 2026)\n"
                "All employees must book travel through the approved portal at travel.company.com.\n"
                "Flights over $500 require manager approval. International travel requires VP approval\n"
                "and a completed security briefing. Hotel stays are capped at $200/night for domestic\n"
                "and $300/night for international travel. Receipts must be submitted within 14 days."
            ),
            "metadata": {
                "source": "hr-policies",
                "department": "hr",
                "classification": "internal",
            },
        },
        {
            "id": "policy-002",
            "text": (
                "Company IT Security Policy (Effective March 2026)\n"
                "All employees must use company-issued laptops with full-disk encryption enabled.\n"
                "Personal devices may not be used to access company systems. Multi-factor authentication\n"
                "is mandatory for all cloud services. Passwords must be at least 16 characters.\n"
                "SSH keys must be rotated every 90 days. Report security incidents to security@company.com."
            ),
            "metadata": {
                "source": "it-security",
                "department": "it",
                "classification": "internal",
            },
        },
        {
            "id": "policy-003",
            "text": (
                "Q4 2025 Financial Summary (Confidential)\n"
                "Revenue: $24.7M (up 12% YoY). Operating costs: $18.2M. Net profit: $6.5M.\n"
                "New customer acquisition: 847 accounts. Churn rate: 3.2% (down from 4.1%).\n"
                "Key growth driver: Enterprise tier adoption increased 34%.\n"
                "Projected Q1 2026 revenue: $26.1M based on current pipeline."
            ),
            "metadata": {
                "source": "finance",
                "department": "finance",
                "classification": "confidential",
            },
        },
        {
            "id": "policy-004",
            "text": (
                "Employee Benefits Overview (2026)\n"
                "Health insurance: Company covers 90% of premiums for employees, 75% for dependents.\n"
                "401(k): Company matches up to 6% of salary. Vesting schedule: 2 years.\n"
                "PTO: 20 days for 0-3 years tenure, 25 days for 3-7 years, 30 days for 7+ years.\n"
                "Parental leave: 16 weeks paid for primary caregiver, 8 weeks for secondary."
            ),
            "metadata": {
                "source": "hr-benefits",
                "department": "hr",
                "classification": "internal",
            },
        },
        {
            "id": "eng-001",
            "text": (
                "API Rate Limiting Configuration\n"
                "Production API endpoints enforce the following rate limits:\n"
                "- Free tier: 100 requests/minute, 10,000 requests/day\n"
                "- Pro tier: 1,000 requests/minute, 100,000 requests/day\n"
                "- Enterprise tier: Custom limits, minimum 10,000 requests/minute\n"
                "Rate limit headers: X-RateLimit-Remaining, X-RateLimit-Reset\n"
                "Exceeded limits return HTTP 429 with Retry-After header."
            ),
            "metadata": {
                "source": "engineering",
                "department": "engineering",
                "classification": "internal",
            },
        },
    ]
    ingest_documents(documents)
    print(f"[Seed] Loaded {len(documents)} legitimate document(s)")


# ── CLI entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        seed_legitimate_data()
    elif len(sys.argv) > 1:
        answer = ask(" ".join(sys.argv[1:]))
        print(f"\n[Answer]\n{answer}")
    else:
        print("Usage:")
        print("  python vulnerable_rag.py seed              # load sample data")
        print("  python vulnerable_rag.py 'your question'   # ask a question")
