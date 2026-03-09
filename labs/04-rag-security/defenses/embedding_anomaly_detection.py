"""
Defense Layer 5 — Embedding-Level Anomaly Detection
=====================================================
Analyses the vector embeddings of *new* documents before they are
ingested, looking for two coordinated-injection signals:

  high_similarity   — new doc is very similar to an existing doc on
                       the same topic (potential content override)
  tight_cluster     — multiple new docs cluster tightly with each
                       other (PoisonedRAG-style coordinated injection)

This is the layer that reduces knowledge-poisoning success from 95 %
to 20 % as a standalone control.  Text-level sanitization (Layer 1)
has zero effect on the poisoned financial documents because they contain
no detectable structural markers.

Stops:
  Attack 1 (knowledge poisoning, coordinated) — strong (95 % → 20 %)
  Attack 2 (injection)                        — no direct effect
  Attack 3 (cross-tenant leakage)             — no effect
"""

import numpy as np
import chromadb
from chromadb.utils import embedding_functions

embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# Thresholds (tune per deployment — tighter = more false positives)
DEFAULT_SIMILARITY_THRESHOLD = 0.85  # flag new doc if it mirrors an existing one
DEFAULT_CLUSTER_THRESHOLD    = 0.90  # flag pairs of new docs that cluster tightly


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    va, vb = np.array(a, dtype=float), np.array(b, dtype=float)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    return float(np.dot(va, vb) / denom) if denom > 0 else 0.0


def check_embedding_anomalies(
    new_docs: list[dict],
    collection,
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    cluster_threshold: float    = DEFAULT_CLUSTER_THRESHOLD,
) -> list[dict]:
    """
    Check *new_docs* for embedding-level anomalies.

    Returns a list of finding dicts with keys:
        doc_id, type, severity, detail, recommendation
    """
    findings: list[dict] = []

    if not new_docs:
        return findings

    texts         = [d["text"] for d in new_docs]
    new_embeddings = embed_fn(texts)

    for i, (doc, embedding) in enumerate(zip(new_docs, new_embeddings)):
        doc_id = doc.get("id", f"new-{i}")

        # ── Check 1: high similarity to existing documents ──────────────────
        try:
            existing = collection.query(
                query_embeddings=[embedding],
                n_results=3,
            )
            distances = existing.get("distances", [[]])[0]
            ex_docs   = existing.get("documents", [[]])[0]

            for dist, ex_text in zip(distances, ex_docs):
                sim = 1.0 - dist  # convert cosine distance → similarity
                if sim > similarity_threshold:
                    findings.append({
                        "doc_id": doc_id,
                        "type": "high_similarity",
                        "severity": "HIGH",
                        "detail": (
                            f"New doc is {sim:.1%} similar to existing: "
                            f"'{ex_text[:80]}...'"
                        ),
                        "recommendation": "Review — potential content override / displacement attack",
                    })
        except Exception as exc:
            # Collection may be empty on first run
            print(f"  [Embedding Check] Skipped existing-doc check for {doc_id}: {exc}")

        # ── Check 2: tight internal cluster among new documents ─────────────
        for j in range(i + 1, len(new_embeddings)):
            inter_sim = _cosine_similarity(embedding, new_embeddings[j])
            if inter_sim > cluster_threshold:
                peer_id = new_docs[j].get("id", f"new-{j}")
                findings.append({
                    "doc_id": f"{doc_id}  ↔  {peer_id}",
                    "type": "tight_cluster",
                    "severity": "MEDIUM",
                    "detail": (
                        f"Documents cluster at {inter_sim:.1%} similarity "
                        f"(threshold {cluster_threshold:.0%})"
                    ),
                    "recommendation": (
                        "Multiple co-ingested docs targeting the same semantic space — "
                        "possible coordinated injection"
                    ),
                })

    return findings


def gate_ingestion(new_docs: list[dict], collection) -> list[dict]:
    """
    Gate function: run anomaly checks and return only safe documents.

    HIGH-severity findings block the individual document.
    MEDIUM-severity findings are logged but do not block (queue for review).
    """
    findings = check_embedding_anomalies(new_docs, collection)

    if not findings:
        print(f"  [Embedding Check] All {len(new_docs)} document(s) passed anomaly detection")
        return new_docs

    blocked_ids: set[str] = set()

    for f in findings:
        level_icon = "🚨" if f["severity"] == "HIGH" else "⚠️ "
        print(f"  {level_icon} [{f['severity']}] {f['type']} — {f['doc_id']}")
        print(f"       {f['detail']}")
        print(f"       Action: {f['recommendation']}")
        if f["severity"] == "HIGH":
            # Block documents identified in single-doc HIGH findings
            # (tight_cluster findings list a pair; only block the new doc)
            candidate = f["doc_id"].split("↔")[0].strip()
            blocked_ids.add(candidate)

    approved = [d for d in new_docs if d.get("id") not in blocked_ids]
    print(
        f"  [Embedding Check] {len(approved)}/{len(new_docs)} document(s) approved; "
        f"{len(blocked_ids)} blocked for human review"
    )
    return approved
