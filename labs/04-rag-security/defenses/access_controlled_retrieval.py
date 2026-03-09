"""
Defense Layer 2 — Access-Controlled Retrieval
==============================================
Adds a ChromaDB `where` filter to every retrieval call so that users
only receive documents whose classification level they are authorised
to see.

Stops:
  Attack 3 (cross-tenant leakage) — fully (100 % block)
  Attack 1 (knowledge poisoning)  — partial (limits placement surface)
  Attack 2 (injection)            — no direct effect
"""

import chromadb
from chromadb.utils import embedding_functions

# ── Embedding model (must match the one used at ingestion time) ────────────────
embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

CHROMA_DIR      = "./chroma_db"
COLLECTION_NAME = "company_docs"

# ── User permission model ──────────────────────────────────────────────────────
# Maps user_id → set of classification levels that user may retrieve.
USER_PERMISSIONS: dict[str, dict] = {
    "alice": {
        "department": "engineering",
        "role": "engineer",
        "classification_access": ["public", "internal"],
    },
    "bob": {
        "department": "hr",
        "role": "hr-manager",
        "classification_access": ["public", "internal", "confidential", "restricted"],
    },
    "carol": {
        "department": "legal",
        "role": "legal-counsel",
        "classification_access": ["public", "internal", "confidential", "privileged"],
    },
    "dave": {
        "department": "executive",
        "role": "ceo",
        "classification_access": [
            "public", "internal", "confidential", "restricted", "privileged"
        ],
    },
}


def secure_retrieve(query: str, user_id: str, n_results: int = 3) -> list[str]:
    """
    Retrieve documents filtered to the caller's authorised classification levels.

    ChromaDB `where` clause ensures the similarity search only considers
    documents the user is allowed to see — even if higher-classification
    documents are more semantically similar to the query.

    Returns an empty list for unknown users.
    """
    user = USER_PERMISSIONS.get(user_id)
    if not user:
        print(f"  ❌ RETRIEVAL DENIED — unknown user: '{user_id}'")
        return []

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
    )

    allowed = user["classification_access"]
    where_filter = {"$or": [{"classification": cls} for cls in allowed]}

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where=where_filter,
    )

    docs  = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0]  if results["metadatas"]  else []

    print(
        f"  [ACL] '{user_id}' ({user['role']}) — "
        f"permitted levels: {allowed}"
    )
    print(f"  [ACL] {len(docs)} document(s) returned after access-control filter")
    for i, (doc, meta) in enumerate(zip(docs, metas)):
        print(
            f"    Doc {i + 1}: [{meta.get('classification', '?')}] "
            f"{doc[:60]}..."
        )

    return docs
