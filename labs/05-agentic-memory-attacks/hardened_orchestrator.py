"""
hardened_orchestrator.py — AssistantOS with all five defense layers active.

Drop-in replacement for the vulnerable Orchestrator for testing defenses.

Defense layers loaded:
  1. MemoryIntegrity        — HMAC-signs every write; quarantines unsigned reads
  2. MemorySourceGuard      — blocks memory writes containing URLs / instruction verbs
  3. AgentMessageSandbox    — fences and sanitises sub-agent results
  4. ContextFreshness       — re-injects system prompt; summarises old context
  5. AuditLog               — append-only JSONL tool-call log with anomaly scanner

Usage:
  from hardened_orchestrator import make_hardened_session, HardenedOrchestrator

  session, orchestrator = make_hardened_session()
  reply = orchestrator.chat("List my sandbox files.")
"""

import os

from assistantos.session import Session
from assistantos.orchestrator import Orchestrator

from defenses.memory_integrity      import MemoryIntegrity
from defenses.memory_source_guard   import MemorySourceGuard
from defenses.agent_message_sandbox import AgentMessageSandbox
from defenses.context_freshness     import ContextFreshness
from defenses.audit_log             import AuditLog

# Context limit detection for ContextFreshness
_LM_STUDIO_URL = "http://localhost:1234/v1"


def _detect_context_limit() -> int:
    try:
        from openai import OpenAI
        client = OpenAI(base_url=_LM_STUDIO_URL, api_key="lm-studio")
        models = client.models.list().data
        if models:
            ctx = getattr(models[0], "context_length", None)
            if ctx and isinstance(ctx, int):
                return ctx
    except Exception:
        pass
    return 4096


def build_defense_layers(
    signing_key: str = None,
    reinject_every: int = 5,
    context_limit: int = None,
    print_anomalies: bool = True,
) -> dict:
    """Construct and return all five defense layer instances."""
    ctx = context_limit or _detect_context_limit()
    return {
        "memory_integrity":      MemoryIntegrity(signing_key=signing_key),
        "memory_source_guard":   MemorySourceGuard(strict=False),
        "agent_message_sandbox": AgentMessageSandbox(log_detections=True),
        "context_freshness":     ContextFreshness(
            reinject_every=reinject_every,
            context_limit_tokens=ctx,
        ),
        "audit_log": AuditLog(print_anomalies=print_anomalies),
    }


class HardenedOrchestrator(Orchestrator):
    """Orchestrator subclass that always loads all five defense layers."""

    def __init__(
        self,
        session: Session,
        use_poisoned_web: bool = False,
        **defense_kwargs,
    ):
        defense_layers = build_defense_layers(**defense_kwargs)
        super().__init__(
            session=session,
            defense_layers=defense_layers,
            use_poisoned_web=use_poisoned_web,
        )

    def print_defense_summary(self) -> None:
        """Print a brief status summary of all active defense layers."""
        print("\n  ── Defense layer status ──────────────────────────────")
        print("  ✅ Layer 1 — Memory Integrity (HMAC-SHA256)")
        print("  ✅ Layer 2 — Memory Source Guard (value blocklist)")
        print("  ✅ Layer 3 — Agent Message Sandbox (cross-agent fencing)")
        print(
            f"  ✅ Layer 4 — Context Freshness "
            f"(reinject every {self.defense_layers['context_freshness'].reinject_every} turns)"
        )
        al = self.defense_layers["audit_log"]
        print(f"  ✅ Layer 5 — Audit Log ({al.path})")
        print("  ─────────────────────────────────────────────────────\n")


def make_hardened_session(**defense_kwargs) -> tuple[Session, HardenedOrchestrator]:
    """Convenience factory for test scripts."""
    session      = Session(defense_layers=build_defense_layers(**defense_kwargs))
    orchestrator = HardenedOrchestrator(session, **defense_kwargs)
    return session, orchestrator
