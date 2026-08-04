"""Tests that pin the claim: undefended the chain completes, and each control
breaks the stage it is supposed to.

These are the executable version of the lab's promise. If a change lets the
defended chain leak, or lets a control stop breaking its stage, a test fails.
Stdlib + pytest only; no network, no model.

    pytest test_chain.py -v
"""

from __future__ import annotations

from defenses import Controls
from killchain import run_chain


def _stage(run, n):
    return next(r for r in run.results if r.number == n)


def test_undefended_chain_completes_and_exfiltrates():
    run = run_chain(Controls.none())
    assert run.compromised, "undefended chain should reach exfiltration"
    for n in range(1, 6):
        assert _stage(run, n).attacker_succeeded, f"stage {n} should succeed undefended"


def test_card_verification_breaks_stage_2():
    """Control 1: a rogue card that does not chain to the trust anchor is
    rejected at registration, and everything downstream collapses."""
    run = run_chain(Controls(require_signed_cards=True))
    assert not _stage(run, 2).attacker_succeeded, "rogue registration must be rejected"
    assert not _stage(run, 3).attacker_succeeded, "no rogue -> no routing hijack"
    assert not _stage(run, 4).attacker_succeeded, "no rogue -> no lateral movement"
    assert not _stage(run, 5).attacker_succeeded, "nothing rogue persists"
    assert not run.compromised


def test_authorization_breaks_stage_4():
    """Control 2 authorizes the *action*, not just the caller. The rogue still
    registers (Control 1 off) and the summarise task still routes to it (the
    caller doc-assistant is legitimately allowed to summarise) — but when the
    rogue reaches for the sensitive skill, authorization denies it. This is
    exactly the book's point: authorization is what survives an agent being
    genuinely trusted-but-overreaching, and it breaks the chain at lateral
    movement, not before."""
    run = run_chain(Controls(enforce_authorization=True))
    assert _stage(run, 2).attacker_succeeded, "registration still open without Control 1"
    assert _stage(run, 3).attacker_succeeded, "entry-skill routing still reaches the rogue"
    assert not _stage(run, 4).attacker_succeeded, "sensitive skill denied to unauthorised rogue"
    assert not run.compromised


def test_blast_radius_controls_stop_exfiltration():
    """Control 3: even with registration and routing open, the high-stakes
    skill pauses for a human rather than executing on the rogue's say-so."""
    run = run_chain(Controls(circuit_breaker_threshold=3, human_in_the_loop=True))
    assert not _stage(run, 4).attacker_succeeded, "high-stakes skill must not auto-execute"
    assert not run.compromised


def test_all_controls_break_the_chain_early():
    run = run_chain(Controls.all())
    assert not run.compromised
    broke_at = next(r.number for r in run.results if not r.attacker_succeeded)
    assert broke_at == 2, "with all controls, the chain should break at the first trust decision"


def test_stage1_always_lands_deterministically():
    """Stage 1 models a successful injection; it is not gated by any of the
    A2A controls (those act later). It should land in every configuration."""
    for controls in (Controls.none(), Controls.all()):
        assert _stage(run_chain(controls), 1).attacker_succeeded
