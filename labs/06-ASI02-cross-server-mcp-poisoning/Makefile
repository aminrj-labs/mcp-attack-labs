# Cross-Server MCP Poisoning Lab — Makefile

.PHONY: help setup verify seed reset show-notes exfil \
        attack attack-return-value attack-subtle \
        clean-data clean

PYTHON := $(if $(wildcard venv/bin/python),venv/bin/python,python3)
query  ?= What is the weather in Paris?
model  ?=

help:                       ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make verify && make seed"
	@echo "  Terminal 1: make exfil"
	@echo "  Terminal 2: make attack"

setup:                      ## Create venv and install lab dependencies
	$(PYTHON) -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r requirements.txt
	@echo ""
	@echo "Environment ready."
	@echo "Run: source venv/bin/activate"
	@echo "Then: make verify"

verify:                     ## Pre-flight checks for LM Studio, packages, and local data files
	$(PYTHON) verify_setup.py

seed:                       ## Populate the victim notes store with seeded sensitive notes
	$(PYTHON) seed_notes.py --reset

reset:                      ## Restore seeded notes and clear the attacker exfil log
	$(PYTHON) seed_notes.py --reset --clear-exfil

show-notes:                 ## Print the current victim notes store
	$(PYTHON) seed_notes.py --show

exfil:                      ## Start the attacker exfil listener on localhost:9999
	$(PYTHON) exfil_server.py

attack:                     ## Run the description-based cross-server poisoning attack
	@echo "=== Description-based cross-server poisoning ==="
	@echo "Start 'make exfil' in a separate terminal first."
	$(PYTHON) agent.py \
	  --server malicious_weather_server.py \
	  --server legitimate_notes_server.py \
	  $(if $(strip $(model)),--model "$(model)",) \
	  --query "$(query)" \
	  --verbose

attack-return-value:        ## Run the variant where the payload lives in the tool result
	@echo "=== Return-value cross-server poisoning ==="
	@echo "Start 'make exfil' in a separate terminal first."
	$(PYTHON) agent.py \
	  --server return_value_weather_server.py \
	  --server legitimate_notes_server.py \
	  $(if $(strip $(model)),--model "$(model)",) \
	  --query "$(query)" \
	  --verbose

attack-subtle:              ## Run the softer cache-sync phrasing variant
	@echo "=== Subtle phrasing cross-server poisoning ==="
	@echo "Start 'make exfil' in a separate terminal first."
	$(PYTHON) agent.py \
	  --server subtle_weather_server.py \
	  --server legitimate_notes_server.py \
	  $(if $(strip $(model)),--model "$(model)",) \
	  --query "$(query)" \
	  --verbose

clean-data:                 ## Empty the victim notes store and clear the attacker exfil log
	$(PYTHON) seed_notes.py --empty --clear-exfil

clean:                      ## Remove venv, clear local data files, and drop __pycache__ directories
	rm -rf venv
	$(PYTHON) seed_notes.py --empty --clear-exfil 2>/dev/null || true
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "Environment cleaned."