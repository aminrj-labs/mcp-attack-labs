#!/usr/bin/env python3
"""Run the MCP -> A2A kill chain and print the stage-by-stage transcript.

    python run_chain.py                 # undefended: all five stages succeed
    python run_chain.py --defended      # all controls on: chain breaks
    python run_chain.py --control card  # one control at a time (card|authz|blast)
    python run_chain.py --llm           # drive Stage 1 against a real local LLM

The undefended run is the attack. The defended runs are the point: each control
breaks the chain at a specific stage, which is the thing a defender actually
wants to know — "if I turn this on, what stops?"
"""

from __future__ import annotations

import argparse
import sys

from defenses import Controls
from killchain import run_chain

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def _controls_from_args(args: argparse.Namespace) -> Controls:
    if args.defended:
        return Controls.all()
    if args.control == "card":
        return Controls(require_signed_cards=True)
    if args.control == "authz":
        return Controls(enforce_authorization=True)
    if args.control == "blast":
        return Controls(circuit_breaker_threshold=3, human_in_the_loop=True)
    return Controls.none()


def main() -> int:
    parser = argparse.ArgumentParser(description="MCP -> A2A five-stage kill chain")
    parser.add_argument("--defended", action="store_true", help="enable all controls")
    parser.add_argument(
        "--control",
        choices=["card", "authz", "blast"],
        help="enable a single control to see which stage it breaks",
    )
    parser.add_argument("--llm", action="store_true", help="drive Stage 1 with a real LLM")
    args = parser.parse_args()

    controls = _controls_from_args(args)
    print(f"\n{BOLD}MCP -> A2A Kill Chain{RESET}")
    print(f"controls: {controls.summary()}")
    print(f"stage 1 brain: {'live LLM' if args.llm else 'deterministic'}\n")

    run = run_chain(controls, use_llm=args.llm)

    for r in run.results:
        mark = f"{RED}✓ attacker{RESET}" if r.attacker_succeeded else f"{GREEN}✗ blocked{RESET}"
        print(f"  Stage {r.number} — {r.name}")
        print(f"    {DIM}{r.asi}{RESET}")
        print(f"    {mark}: {r.detail}\n")

    if run.compromised:
        print(f"{RED}{BOLD}RESULT: chain completed — HR data exfiltrated.{RESET}")
        broke_at = None
    else:
        broke_at = next((r.number for r in run.results if not r.attacker_succeeded), None)
        print(
            f"{GREEN}{BOLD}RESULT: chain broken at Stage {broke_at}.{RESET} "
            f"Sensitive data never left."
        )
    print()
    # Exit code encodes the security outcome, so `make` / CI can assert on it:
    # 0 = chain broken (good), 1 = compromise reached (the undefended attack).
    return 1 if run.compromised else 0


if __name__ == "__main__":
    sys.exit(main())
