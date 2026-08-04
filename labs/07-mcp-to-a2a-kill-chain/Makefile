.PHONY: run defended card authz blast test clean

run:            ## Undefended: all five stages complete, HR data exfiltrated
	python3 run_chain.py

defended:       ## All controls on: chain breaks at stage 2
	python3 run_chain.py --defended

card:           ## Control 1 only (card verification)
	python3 run_chain.py --control card

authz:          ## Control 2 only (action authorization)
	python3 run_chain.py --control authz

blast:          ## Control 3 only (blast-radius containment)
	python3 run_chain.py --control blast

test:           ## Prove undefended completes and each control breaks its stage
	python3 -m pytest test_chain.py -v

clean:
	rm -rf state __pycache__ .pytest_cache a2a/__pycache__
