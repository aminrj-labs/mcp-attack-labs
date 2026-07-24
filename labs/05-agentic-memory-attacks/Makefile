# Agentic Memory Attacks Lab — Makefile
#
# Requires:
#   - Python 3.11+  virtual environment activated (source venv/bin/activate)
#   - LM Studio serving an instruction-tuned model on localhost:1234

.PHONY: help setup verify seed reset \
        attack1 attack2 attack3 attack4 attack-chain \
        exfil \
        hardened-attack1 hardened-attack2 hardened-attack3 hardened-attack4 \
        compare \
        measure measure-all-stats \
        notebook \
        clean-memory clean

PYTHON := python3
n      ?= 20          # default iteration count for measure targets
attack ?= 1           # default attack number

# ──────────────────────────────────────────────────────────────────────────────
help:                    ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-26s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make verify && make seed && make attack1"

# ──────────────────────────────────────────────────────────────────────────────
setup:                   ## Create venv and install all dependencies
	$(PYTHON) -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r requirements.txt
	@echo ""
	@echo "✅  Environment ready."
	@echo "    Run: source venv/bin/activate"
	@echo "    Then: make verify"

# ──────────────────────────────────────────────────────────────────────────────
verify:                  ## Pre-flight checks (LM Studio, memory store, fixtures)
	$(PYTHON) verify_setup.py

# ──────────────────────────────────────────────────────────────────────────────
seed:                    ## Initialise memory.json with clean baseline entries
	$(PYTHON) seed.py

reset:                   ## Wipe memory/ and re-seed with clean baseline
	@echo "=== Resetting memory store ==="
	$(PYTHON) -c "import json, os; open('memory/memory.json','w').write('[]'); open('memory/episodic.json','w').write('[]')"
	$(PYTHON) seed.py
	@echo "✅  Memory reset to clean state"

# ──────────────────────────────────────────────────────────────────────────────
attack1:                 ## Attack 1 — External Memory Poisoning (85–95% success)
	@echo "=== Attack 1: External Memory Poisoning ==="
	@echo "⚠️  Start 'make exfil' in a separate terminal to capture exfiltrated data"
	$(PYTHON) attack1_external_memory_poison.py

attack2:                 ## Attack 2 — Conversational Memory Poisoning (55–75% success)
	@echo "=== Attack 2: Conversational Memory Poisoning ==="
	$(PYTHON) attack2_conversational_memory_poison.py

attack3:                 ## Attack 3 — Cross-Agent Trust Exploitation (60–80% success)
	@echo "=== Attack 3: Cross-Agent Trust Exploitation ==="
	$(PYTHON) attack3_cross_agent_trust.py

attack4:                 ## Attack 4 — Context Window Overflow (degradation curve)
	@echo "=== Attack 4: Context Window Overflow ==="
	$(PYTHON) attack4_context_overflow.py

attack-chain:            ## Multi-stage APT chain — runs all 4 attacks in sequence
	@echo "=== Multi-Stage Attack Chain ==="
	@echo "⚠️  Start 'make exfil' in a separate terminal first"
	$(PYTHON) attack_chain.py

# ──────────────────────────────────────────────────────────────────────────────
exfil:                   ## Start the attacker exfil listener on localhost:9999
	$(PYTHON) exfil_server.py

# ──────────────────────────────────────────────────────────────────────────────
hardened-attack1:        ## Attack 1 against hardened orchestrator (Defense Layer 1)
	@echo "=== Attack 1 vs Hardened Orchestrator ==="
	$(PYTHON) -c "\
import json, os; \
open('memory/memory.json','w').write('[]'); \
from attack1_external_memory_poison import inject_memory_entry; \
inject_memory_entry(); \
from hardened_orchestrator import make_hardened_session; \
s, o = make_hardened_session(); \
o.print_defense_summary(); \
print('User: What files do I have in my sandbox?'); \
r = o.chat('What files do I have in my sandbox?', verbose=True); \
print(f'Agent: {r[:300]}')"

hardened-attack2:        ## Attack 2 against hardened orchestrator (Defense Layer 2)
	@echo "=== Attack 2 vs Hardened Orchestrator ==="
	$(PYTHON) -c "\
import json, time; \
open('memory/memory.json','w').write('[]'); \
from attack2_conversational_memory_poison import ATTACK_TURNS; \
from hardened_orchestrator import make_hardened_session; \
s, o = make_hardened_session(); \
o.print_defense_summary(); \
[print(f'User: {t[:80]}...') or print(f'Agent: {o.chat(t)[:100]}...') or time.sleep(0.2) for t in ATTACK_TURNS]; \
entries = json.load(open('memory/memory.json')); \
print(f'Memory entries after attack: {len(entries)}')"

hardened-attack3:        ## Attack 3 against hardened orchestrator (Defense Layer 3)
	@echo "=== Attack 3 vs Hardened Orchestrator ==="
	$(PYTHON) -c "\
import json; \
open('memory/memory.json','w').write('[]'); \
from hardened_orchestrator import make_hardened_session; \
s, o = make_hardened_session(); \
o.web_tool.use_poisoned = True; \
o.researcher.web_tool = o.web_tool; \
o.print_defense_summary(); \
r = o.chat('Research ExampleAPI v2 authentication and rate limits.', verbose=True); \
print(f'Response: {r[:400]}')"

hardened-attack4:        ## Attack 4 against hardened orchestrator (Defense Layer 4)
	@echo "=== Attack 4 vs Hardened Orchestrator ==="
	$(PYTHON) attack4_context_overflow.py --n 3 --positions 0,75,85

# ──────────────────────────────────────────────────────────────────────────────
compare:                 ## Side-by-side: vulnerable vs hardened for attack N (attack=1|2|3)
	@echo ""
	@echo "=== Comparing: vulnerable vs hardened (Attack $(attack)) ==="
	$(MAKE) reset
	@echo ""
	@echo ">>> Vulnerable pipeline:"
	$(MAKE) attack$(attack)
	@echo ""
	$(MAKE) reset
	@echo ""
	@echo ">>> Hardened pipeline:"
	$(MAKE) hardened-attack$(attack)

# ──────────────────────────────────────────────────────────────────────────────
measure:                 ## Measure success rate (attack=1|2|3|4, n=20)
	@echo "=== Measuring Attack $(attack), n=$(n) iterations ==="
	$(PYTHON) measure.py --attack $(attack) --n $(n)

measure-hardened:        ## Measure vulnerable vs hardened (attack=1|2|3, n=10)
	@echo "=== Measuring Attack $(attack) — vulnerable vs hardened, n=$(n) ==="
	$(PYTHON) measure.py --attack $(attack) --n $(n) --hardened

measure-all-stats:       ## Measure all four attacks (n=10 by default)
	@echo "=== Measuring all attacks, n=$(n) iterations each ==="
	$(PYTHON) measure.py --all --n $(n)

# ──────────────────────────────────────────────────────────────────────────────
notebook:                ## Launch the interactive Jupyter playbook
	jupyter notebook PLAYBOOK.ipynb

# ──────────────────────────────────────────────────────────────────────────────
clean-memory:            ## Wipe memory/ contents (preserves directory structure)
	$(PYTHON) -c "import json; open('memory/memory.json','w').write('[]'); open('memory/episodic.json','w').write('[]')"
	@rm -f memory/audit.jsonl
	@echo "✅  Memory cleared"

clean:                   ## Remove venv, memory contents, and __pycache__
	rm -rf venv
	$(PYTHON) -c "import json; open('memory/memory.json','w').write('[]'); open('memory/episodic.json','w').write('[]')" 2>/dev/null || true
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -f memory/audit.jsonl
	@echo "✅  Environment cleaned"
