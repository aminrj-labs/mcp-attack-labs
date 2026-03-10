"""
verify_setup.py — Pre-flight checks for the RAG Security Lab.

Validates:
  1. LM Studio reachable at localhost:1234 and the expected model is loaded
  2. Embedding model (all-MiniLM-L6-v2) downloads and produces a valid vector
  3. ChromaDB can be created, written to, and queried
  4. Flask available (exfil server dependency)

Usage:
  python verify_setup.py
  make verify
"""

import sys
import time

SEP   = "=" * 60
OK    = "  ✅"
FAIL  = "  ❌"
WARN  = "  ⚠️ "

def _header(title: str) -> None:
    print(f"\n{SEP}\n  {title}\n{SEP}")


# ── Check 1: LM Studio ────────────────────────────────────────────────────────
def check_lm_studio() -> bool:
    _header("Check 1 — LM Studio connectivity")
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
        models = client.models.list()
        ids = [m.id for m in models.data]

        if not ids:
            print(f"{FAIL} LM Studio is reachable but no models are loaded.")
            print(f"       Fix: Open LM Studio → load any instruction-tuned model → enable server (port 1234)")
            return False

        print(f"  Models loaded in LM Studio: {ids}")

        # Prefer qwen2.5-7b-instruct family; accept any loaded model as fallback.
        preferred = next((m for m in ids if "qwen2.5-7b" in m.lower() and "coder" not in m.lower()), None)
        active    = preferred or ids[0]

        if preferred:
            print(f"{OK} Found preferred model: '{active}'")
        else:
            print(f"{WARN} qwen2.5-7b-instruct not found — using first available model: '{active}'")
            print(f"       The pipeline auto-detects the loaded model, so this will still work.")
            print(f"       For best results matching the blog's numbers, load qwen2.5-7b-instruct Q4_K_M.")
        return True

    except Exception as exc:
        print(f"{FAIL} Cannot reach LM Studio at http://localhost:1234")
        print(f"       Error: {exc}")
        print(f"       Fix:   Open LM Studio → load a model → enable server (port 1234)")
        return False


# ── Check 2: Quick LLM inference ─────────────────────────────────────────────
def check_inference() -> bool:
    _header("Check 2 — LLM inference (quick round-trip)")
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
        t0 = time.time()
        resp = client.chat.completions.create(
            model="qwen2.5-7b-instruct",
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=10,
            temperature=0.0,
        )
        elapsed = time.time() - t0
        answer = resp.choices[0].message.content.strip()
        print(f"  Response: '{answer}'  ({elapsed:.1f}s)")
        print(f"{OK} LLM inference working")
        return True
    except Exception as exc:
        print(f"{FAIL} Inference failed: {exc}")
        return False


# ── Check 3: Embedding model ──────────────────────────────────────────────────
def check_embeddings() -> bool:
    _header("Check 3 — Embedding model (all-MiniLM-L6-v2)")
    try:
        from chromadb.utils import embedding_functions
        print("  Loading all-MiniLM-L6-v2 (first run downloads ~90 MB)…")
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        vecs = ef(["The quick brown fox jumps over the lazy dog"])
        dim = len(vecs[0])
        print(f"  Embedding dimension: {dim}")
        if dim == 384:
            print(f"{OK} Embedding model ready (dim=384)")
            return True
        else:
            print(f"{WARN} Unexpected embedding dimension: {dim} (expected 384)")
            return False
    except Exception as exc:
        print(f"{FAIL} Embedding model failed: {exc}")
        return False


# ── Check 4: ChromaDB ─────────────────────────────────────────────────────────
def check_chromadb() -> bool:
    _header("Check 4 — ChromaDB (persistent, file-based)")
    import tempfile, os, shutil
    tmp = tempfile.mkdtemp(prefix="rag_verify_")
    try:
        import chromadb
        from chromadb.utils import embedding_functions

        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        client = chromadb.PersistentClient(path=tmp)
        col = client.get_or_create_collection(
            name="verify_test",
            embedding_function=ef,
            metadata={"hnsw:space": "cosine"},
        )
        col.upsert(
            ids=["doc-1"],
            documents=["This is a test document about security."],
            metadatas=[{"source": "test", "classification": "internal"}],
        )
        results = col.query(query_texts=["security testing"], n_results=1)
        retrieved = results["documents"][0][0]
        print(f"  Write + query round-trip succeeded.")
        print(f"  Retrieved: '{retrieved[:60]}…'")
        print(f"{OK} ChromaDB working correctly")
        return True
    except Exception as exc:
        print(f"{FAIL} ChromaDB test failed: {exc}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── Check 5: Flask ────────────────────────────────────────────────────────────
def check_flask() -> bool:
    _header("Check 5 — Flask (exfil server dependency)")
    try:
        import flask
        print(f"  Flask version: {flask.__version__}")
        print(f"{OK} Flask available")
        return True
    except ImportError as exc:
        print(f"{FAIL} Flask not found: {exc}")
        print(f"       Run: pip install flask")
        return False


# ── Summary ───────────────────────────────────────────────────────────────────
def main() -> None:
    print(SEP)
    print("  RAG Security Lab — Setup Verification")
    print(SEP)

    results = {
        "LM Studio connectivity":  check_lm_studio(),
        "LLM inference":           check_inference(),
        "Embedding model":         check_embeddings(),
        "ChromaDB":                check_chromadb(),
        "Flask":                   check_flask(),
    }

    print(f"\n{SEP}")
    print("  Summary")
    print(SEP)

    all_ok = True
    for name, passed in results.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon}  {name}")
        if not passed:
            all_ok = False

    print()
    if all_ok:
        print("  All checks passed.  Run 'make seed' to populate the knowledge base.")
    else:
        print("  One or more checks failed.  Fix the issues above before running attacks.")
        sys.exit(1)


if __name__ == "__main__":
    main()
