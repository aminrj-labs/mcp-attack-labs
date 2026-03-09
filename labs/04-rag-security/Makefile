# RAG Security Lab — Makefile
#
# Requires:
#   - Python 3.11+  virtual environment activated (source venv/bin/activate)
#   - LM Studio serving qwen2.5-7b-instruct on localhost:1234

.PHONY: help setup seed attack1 attack2 attack3 exfil \
        defense1 defense2 defense3 defense4 defense5 \
        hardened-alice hardened-bob hardened-carol \
        clean-db clean

PYTHON := python3

# ──────────────────────────────────────────────────────────────────────────────
help:                  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make seed && make attack1"

# ──────────────────────────────────────────────────────────────────────────────
setup:                 ## Create venv and install all dependencies
	$(PYTHON) -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r requirements.txt
	@echo ""
	@echo "✅  Environment ready.  Run: source venv/bin/activate"

# ──────────────────────────────────────────────────────────────────────────────
seed:                  ## Populate the knowledge base with legitimate company docs
	$(PYTHON) vulnerable_rag.py seed

# ──────────────────────────────────────────────────────────────────────────────
attack1:               ## Attack 1 — Knowledge Base Poisoning (95 % success)
	@echo "=== Attack 1: Knowledge Base Poisoning ==="
	$(PYTHON) attack1_knowledge_poisoning.py

attack2:               ## Attack 2 — Indirect Prompt Injection (all 4 variants)
	@echo "=== Attack 2: Indirect Prompt Injection ==="
	$(PYTHON) attack2_indirect_injection.py

attack3:               ## Attack 3 — Cross-Tenant Data Leakage (100 % success)
	@echo "=== Attack 3: Cross-Tenant Data Leakage ==="
	$(PYTHON) attack3_cross_tenant_leakage.py

# ──────────────────────────────────────────────────────────────────────────────
exfil:                 ## Start the attacker exfil listener on localhost:9999
	$(PYTHON) exfil_server.py

# ──────────────────────────────────────────────────────────────────────────────
# Hardened pipeline tests — must run 'make seed' first
hardened-alice:        ## Hardened: alice (engineer) queries restricted salary data
	$(PYTHON) hardened_rag.py alice "What are the salary ranges for engineers?"

hardened-bob:          ## Hardened: bob (HR) queries salary data (should succeed)
	$(PYTHON) hardened_rag.py bob "What are the salary ranges for engineers?"

hardened-carol:        ## Hardened: carol (legal) queries litigation docs
	$(PYTHON) hardened_rag.py carol "What lawsuits is the company involved in?"

hardened-alice-legal:  ## Hardened: alice (engineer) tries to query legal docs (should be blocked)
	$(PYTHON) hardened_rag.py alice "What lawsuits is the company involved in?"

hardened-alice-ma:     ## Hardened: alice (engineer) tries to query M&A data (should be blocked)
	$(PYTHON) hardened_rag.py alice "What companies is the company looking to acquire?"

# ──────────────────────────────────────────────────────────────────────────────
# Run all attacks then all hardened defenses — produces the measurement table
measure-all:           ## Run all attacks + all hardened tests sequentially
	@echo ""
	@echo "═══  Seeding knowledge base  ═══"
	$(MAKE) seed
	@echo ""
	@echo "═══  Attack 1 — Knowledge Poisoning  ═══"
	$(MAKE) attack1
	@echo ""
	@echo "═══  Attack 2 — Indirect Injection  ═══"
	$(MAKE) attack2
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
