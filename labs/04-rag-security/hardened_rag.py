"""
Hardened RAG pipeline — all five defense layers active
=======================================================

Compare the output of this file with vulnerable_rag.py to observe
the difference each layer makes.

Usage:
  # Seed data first (run once)
  python vulnerable_rag.py seed

  # Then run with: python hardened_rag.py <user_id> <question>
  python hardened_rag.py alice "What are the salary ranges for engineers?"
  python hardened_rag.py bob   "What are the salary ranges for engineers?"
  python hardened_rag.py carol "What lawsuits is the company involved in?"

Defense layers applied:
  Layer 1 — sanitize_ingestion          : strip injection patterns at ingest
  Layer 2 — access_controlled_retrieval : metadata-filtered ChromaDB queries
  Layer 3 — hardened_prompt             : explicit instruction/context separation
  Layer 4 — output_monitor              : scan generated text for leakage
  Layer 5 — embedding_anomaly_detection : cosine cluster analysis at ingest
"""

import sys
import chromadb
from chromadb.utils import embedding_functions
from openai import OpenAI

from defenses.sanitize_ingestion import secure_ingest
from defenses.access_controlled_retrieval import secure_retrieve
from defenses.hardened_prompt import build_hardened_prompt
from defenses.output_monitor import enforce_output_policy
from defenses.embedding_anomaly_detection import gate_ingestion

# ── Configuration ──────────────────────────────────────────────────────────────
CHROMA_DIR      = "./chroma_db"
COLLECTION_NAME = "company_docs"
LM_STUDIO_URL   = "http://localhost:1234/v1"
MODEL           = "qwen2.5-7b-instruct"

embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)


def _get_collection():
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )


# ── Secure ingest (Layers 1 + 5) ──────────────────────────────────────────────
def ingest_secure(new_docs: list[dict]) -> None:
    """
    Ingest documents with text sanitization (Layer 1) and embedding-level
    anomaly detection (Layer 5).
    """
    print("\n[Secure Ingest] Running Layer 1 — content sanitization")
    sanitized = secure_ingest(new_docs)

    if not sanitized:
        print("[Secure Ingest] No documents survived sanitization.")
        return

    collection = _get_collection()

    print("\n[Secure Ingest] Running Layer 5 — embedding anomaly detection")
    approved = gate_ingestion(sanitized, collection)

    if not approved:
        print("[Secure Ingest] No documents approved after anomaly gate.")
        return

    collection.add(
        ids=[d["id"] for d in approved],
        documents=[d["text"] for d in approved],
        metadatas=[d.get("metadata", {}) for d in approved],
    )
    print(
        f"\n[Secure Ingest] ✅ {len(approved)}/{len(new_docs)} document(s) added to collection"
    )


# ── Secure ask (Layers 2 + 3 + 4) ─────────────────────────────────────────────
def ask_secure(query: str, user_id: str) -> str:
    """
    Full hardened RAG pipeline:
      Layer 2 → access-controlled retrieval
      Layer 3 → hardened prompt construction
                (LLM inference)
      Layer 4 → output monitoring / enforcement
    """
    print(f"\n[Secure RAG] user='{user_id}'  query='{query}'")

    # Layer 2 — filtered retrieval
    print("\n[Layer 2] Access-controlled retrieval")
    docs = secure_retrieve(query, user_id)
    if not docs:
        return "No authorised documents found for your query."

    # Layer 3 — hardened prompt
    messages = build_hardened_prompt(query, docs)

    # Generate
    llm = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
    response = llm.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=500,
        temperature=0.1,
    )
    raw_answer = response.choices[0].message.content

    # Layer 4 — output monitoring
    print("\n[Layer 4] Output monitoring")
    safe_answer = enforce_output_policy(raw_answer)

    return safe_answer


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python hardened_rag.py <user_id> <question>")
        print("\nAvailable users: alice  bob  carol  dave")
        print("\nExample:")
        print('  python hardened_rag.py alice "What are the salary ranges?"')
        sys.exit(1)

    uid   = sys.argv[1]
    query = " ".join(sys.argv[2:])

    answer = ask_secure(query, uid)
    print(f"\n[Answer]\n{answer}")
