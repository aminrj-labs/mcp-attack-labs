# RAG Security Lab — Makefile
#
# Requires:
#   - Python 3.11+  virtual environment activated (source venv/bin/activate)
#   - LM Studio serving qwen2.5-7b-instruct on localhost:1234

.PHONY: help setup verify seed reset attack1 attack2 attack3 exfil \
        compare compare-attack1 compare-attack3 \
        hardened-alice hardened-bob hardened-carol \
        hardened-alice-legal hardened-alice-ma \
        measure measure-all-stats notebook \
        clean-db clean

PYTHON := python3
n      ?= 20          # default iteration count for measure targets
attack ?= 1           # default attack for make measure attack=N

# ──────────────────────────────────────────────────────────────────────────────
help:                  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make verify && make seed && make attack1"

# ──────────────────────────────────────────────────────────────────────────────
setup:                 ## Create venv and install all dependencies
	$(PYTHON) -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r requirements.txt
	@echo ""
	@echo "✅  Environment ready."
	@echo "    Run: source venv/bin/activate"
	@echo "    Then: make verify"

# ──────────────────────────────────────────────────────────────────────────────
verify:                ## Check LM Studio, embeddings, and ChromaDB before running attacks
	$(PYTHON) verify_setup.py

# ──────────────────────────────────────────────────────────────────────────────
seed:                  ## Populate the knowledge base with legitimate company docs
	$(PYTHON) vulnerable_rag.py seed

reset:                 ## Wipe ChromaDB and re-seed with clean legitimate documents
	@echo "=== Resetting knowledge base ==="
	rm -rf ./chroma_db
	$(PYTHON) vulnerable_rag.py seed
	@echo "✅  Knowledge base reset to clean state"

# ──────────────────────────────────────────────────────────────────────────────
attack1:               ## Attack 1 — Knowledge Base Poisoning (95% success)
	@echo "=== Attack 1: Knowledge Base Poisoning ==="
	$(PYTHON) attack1_knowledge_poisoning.py

attack2:               ## Attack 2 — Indirect Prompt Injection (all 4 variants)
	@echo "=== Attack 2: Indirect Prompt Injection ==="
	$(PYTHON) attack2_indirect_injection.py

attack3:               ## Attack 3 — Cross-Tenant Data Leakage (100% success)
	@echo "=== Attack 3: Cross-Tenant Data Leakage ==="
	$(PYTHON) attack3_cross_tenant_leakage.py

# ──────────────────────────────────────────────────────────────────────────────
exfil:                 ## Start the attacker exfil listener on localhost:9999
	$(PYTHON) exfil_server.py

# ──────────────────────────────────────────────────────────────────────────────
compare:               ## Side-by-side: same query on vulnerable vs hardened pipeline
	@echo ""
	@echo "=== Comparing: vulnerable vs hardened (Attack 3 scenario) ==="
	@echo ">>> Vulnerable pipeline — alice queries salary data:"
	$(PYTHON) vulnerable_rag.py "What are the salary ranges for engineers?"
	@echo ""
	@echo ">>> Hardened pipeline — alice queries salary data (should be blocked):"
	$(PYTHON) hardened_rag.py alice "What are the salary ranges for engineers?"
	@echo ""
	@echo ">>> Hardened pipeline — bob (HR) queries salary data (should succeed):"
	$(PYTHON) hardened_rag.py bob "What are the salary ranges for engineers?"

compare-attack1:       ## Side-by-side: poisoning on vulnerable vs hardened (anomaly detection)
	@echo ""
	@echo "=== Comparing: Attack 1 — vulnerable vs hardened ingestion ==="
	@echo ">>> Seeding and injecting via vulnerable pipeline:"
	$(MAKE) reset
	$(PYTHON) attack1_knowledge_poisoning.py
	@echo ""
	@echo ">>> Querying vulnerable pipeline:"
	$(PYTHON) vulnerable_rag.py "What was company revenue in Q4 2025?"
	@echo ""
	@echo ">>> Now testing hardened ingestion (anomaly detection should block poisoned docs):"
	$(MAKE) reset
	$(PYTHON) -c "\
from hardened_rag import ingest_secure; \
from attack1_knowledge_poisoning import POISONED_DOCS; \
ingest_secure(POISONED_DOCS)"
	@echo ""
	@echo ">>> Querying hardened pipeline (should return legitimate data):"
	$(PYTHON) hardened_rag.py alice "What was company revenue in Q4 2025?"

compare-attack3:       ## Side-by-side: cross-tenant leakage blocked by ACL
	@echo ""
	@echo "=== Comparing: Attack 3 — vulnerable vs hardened retrieval ==="
	$(MAKE) reset
	$(PYTHON) attack3_cross_tenant_leakage.py
	@echo ""
	@echo ">>> Same query through hardened pipeline (alice — should be blocked):"
	$(PYTHON) hardened_rag.py alice "What are the salary ranges for engineers?"

# ──────────────────────────────────────────────────────────────────────────────
# Hardened pipeline tests — must run 'make seed' or 'make reset' first
hardened-alice:        ## Hardened: alice (engineer) queries restricted salary data
	$(PYTHON) hardened_rag.py alice "What are the salary ranges for engineers?"

hardened-bob:          ## Hardened: bob (HR) queries salary data (should succeed)
	$(PYTHON) hardened_rag.py bob "What are the salary ranges for engineers?"

hardened-carol:        ## Hardened: carol (legal) queries litigation docs
	$(PYTHON) hardened_rag.py carol "What lawsuits is the company involved in?"

hardened-alice-legal:  ## Hardened: alice (engineer) tries to query legal docs (blocked)
	$(PYTHON) hardened_rag.py alice "What lawsuits is the company involved in?"

hardened-alice-ma:     ## Hardened: alice (engineer) tries to query M&A data (blocked)
	$(PYTHON) hardened_rag.py alice "What companies is the company looking to acquire?"

# ──────────────────────────────────────────────────────────────────────────────
measure:               ## Measure success rate for one attack (attack=1|2|3, n=20)
	@echo "=== Measuring Attack $(attack), n=$(n) iterations ==="
	$(PYTHON) measure.py --attack $(attack) --n $(n)

measure-all-stats:     ## Measure all three attacks (n=20 by default, override with n=N)
	@echo "=== Measuring all attacks, n=$(n) iterations each ==="
	$(PYTHON) measure.py --all --n $(n)

# ──────────────────────────────────────────────────────────────────────────────
notebook:              ## Launch the interactive Jupyter playbook
	jupyter notebook PLAYBOOK.ipynb

# ──────────────────────────────────────────────────────────────────────────────
# Run all attacks then all hardened defenses — produces narrative output
measure-all:           ## Run all attacks + all hardened tests sequentially (no stats)
	@echo ""
	@echo "═══  Seeding knowledge base  ═══"
	$(MAKE) seed
	@echo ""
	@echo "═══  Attack 1 — Knowledge Poisoning  ═══"
	$(MAKE) attack1
	@echo ""
	@echo "═══  Resetting for Attack 2  ═══"
	$(MAKE) reset
	@echo ""
	@echo "═══  Attack 2 — Indirect Injection  ═══"
	$(MAKE) attack2
	@echo ""
	@echo "═══  Resetting for Attack 3  ═══"
	$(MAKE) reset
	@echo ""
	@echo "═══  Attack 3 — Cross-Tenant Leakage  ═══"
	$(MAKE) attack3
	@echo ""
	@echo "═══  Hardened pipeline tests  ═══"
	$(MAKE) hardened-alice
	$(MAKE) hardened-bob
	$(MAKE) hardened-carol
	$(MAKE) hardened-alice-legal
	$(MAKE) hardened-alice-ma

# ──────────────────────────────────────────────────────────────────────────────
clean-db:              ## Delete the ChromaDB persistent store (reset all data)
	rm -rf ./chroma_db
	@echo "✅  chroma_db removed"

clean:                 ## Remove venv, chroma_db, and __pycache__
	rm -rf venv chroma_db
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅  Environment cleaned"
